//go:build windows && amd64
#include "textflag.h"

// indirectSyscall executes a Windows x64 syscall through ntdll's
// `syscall` instruction without entering the (hookable) stub
// prologue.
//
// Go declaration:
//   func indirectSyscall(ssn uint32, syscallAddr uintptr,
//       a1..a11 uintptr) (r1, r2 uintptr)
//
// Windows x64 syscall ABI:
//   RAX=SSN, R10=a1, RDX=a2, R8=a3, R9=a4
//   [RSP+0x28]=a5 ... [RSP+0x58]=a11
//
// The caller's non-volatile registers are untouched (only R11 and
// the ABI-volatile argument registers are written).
TEXT ·indirectSyscall(SB),NOSPLIT,$0-120
    PUSHQ R12
    MOVL ssn+0(FP), AX
    MOVQ syscallAddr+8(FP), R11
    MOVQ a1+16(FP), R10
    MOVQ a2+24(FP), DX
    MOVQ a3+32(FP), R8
    MOVQ a4+40(FP), R9

    // 0x60 reserves a5..a11. After the CALL pushes 8 bytes the
    // kernel reads a5 at [RSP+0x28]. RSP is 16-byte aligned at
    // the CALL site (the push made RSP 0 mod 16; 0x60 keeps it).
    SUBQ $0x60, SP
    MOVQ a5+48(FP), R12
    MOVQ R12, 0x20(SP)
    MOVQ a6+56(FP), R12
    MOVQ R12, 0x28(SP)
    MOVQ a7+64(FP), R12
    MOVQ R12, 0x30(SP)
    MOVQ a8+72(FP), R12
    MOVQ R12, 0x38(SP)
    MOVQ a9+80(FP), R12
    MOVQ R12, 0x40(SP)
    MOVQ a10+88(FP), R12
    MOVQ R12, 0x48(SP)
    MOVQ a11+96(FP), R12
    MOVQ R12, 0x50(SP)

    CALL R11
    ADDQ $0x60, SP
    POPQ R12

    MOVQ AX, ret+104(FP)
    MOVQ DX, ret1+112(FP)
    RET
