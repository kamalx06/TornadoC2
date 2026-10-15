//go:build !windows

package syscalls

// Indirect syscalls are a Windows technique. On Linux the kernel
// entry is via the `syscall` instruction (x86-64) or `svc #0`
// (aarch64) — Go's runtime issues these directly, and there is no
// userland stub layer to bypass.

import (
    "errors"
    "syscall"
    "unsafe"
)

var errNotWindows = errors.New("indirect syscalls require Windows")

// NtAllocateVirtualMemory maps to mmap on Linux for the common case.
// For the in-process use (own process), this is functionally
// equivalent to the Windows call.
func NtAllocateVirtualMemory(processHandle uintptr,
    baseAddress *uintptr, zeroBits uintptr,
    regionSize *uintptr, allocationType, protect uint32) error {

    if processHandle != ^uintptr(0) {
        return errors.New(
            "NtAllocateVirtualMemory: only self-process is supported")
    }
    addr, _, errno := syscall.Syscall6(
        syscall.SYS_MMAP,
        *baseAddress,
        *regionSize,
        uintptr(protect),
        uintptr(allocationType),
        ^uintptr(0),
        0)
    if errno != 0 {
        return errno
    }
    *baseAddress = addr
    return nil
}

// NtWriteVirtualMemory is memcpy in-process.
func NtWriteVirtualMemory(processHandle uintptr,
    baseAddress uintptr, buffer unsafe.Pointer,
    size uintptr, bytesWritten *uintptr) error {

    if processHandle != ^uintptr(0) {
        return errors.New(
            "NtWriteVirtualMemory: only self-process is supported")
    }
    dst := unsafe.Pointer(baseAddress)
    for i := uintptr(0); i < size; i++ {
        *(*byte)(unsafe.Pointer(uintptr(dst) + i)) =
            *(*byte)(unsafe.Pointer(uintptr(buffer) + i))
    }
    if bytesWritten != nil {
        *bytesWritten = size
    }
    return nil
}

// NtCreateThreadEx is not portable. On Linux, use a goroutine or
// clone(2) directly.
func NtCreateThreadEx(threadHandle *uintptr,
    desiredAccess uintptr,
    objectAttributes uintptr,
    processHandle uintptr,
    startRoutine uintptr,
    argument uintptr,
    createFlags uintptr,
    zeroBits uintptr,
    stackSize uintptr,
    maximumStackSize uintptr,
    attributeList uintptr) error {
    return errNotWindows
}