//go:build ev_stackspoof && windows && amd64
#include "textflag.h"

// spoofCall(p *args)
//
// Builds a synthetic chain over the real one, then jumps to the
// target:
//
//   [B+0x00] gadget 0        (target's return address)
//   [B+0x08] 32-byte shadow
//   [B+0x28] args 5..11      (7 stack slots)
//   [B+0x60] gadget 1
//   [B+0x90] gadget 1
//   [B+0xc0] spoofExit
//   [B+0xc8] saved R12,R13,R14,R15,BX
//
// B = entry SP - 0xf0. spoofExit restores the registers, advances SP
// to the original return address and returns to Go with RAX intact.
// No PUSH/POP pair spans symbols, so the assembler stays happy.
TEXT ·spoofCall(SB), NOSPLIT, $0-8
    MOVQ p+0(FP), BX
    SUBQ $0xf0, SP

    MOVQ R12, 0xc8(SP)
    MOVQ R13, 0xd0(SP)
    MOVQ R14, 0xd8(SP)
    MOVQ R15, 0xe0(SP)
    MOVQ BX, 0xe8(SP)

    MOVQ 0x28(SP), R10        // placeholder to keep BX live
    MOVQ 0(BX), R12           // target
    MOVQ 8(BX), CX
    MOVQ 16(BX), DX
    MOVQ 24(BX), R8
    MOVQ 32(BX), R9

    MOVQ 40(BX), R10
    MOVQ R10, 0x28(SP)
    MOVQ 48(BX), R10
    MOVQ R10, 0x30(SP)
    MOVQ 56(BX), R10
    MOVQ R10, 0x38(SP)
    MOVQ 64(BX), R10
    MOVQ R10, 0x40(SP)
    MOVQ 72(BX), R10
    MOVQ R10, 0x48(SP)
    MOVQ 80(BX), R10
    MOVQ R10, 0x50(SP)
    MOVQ 88(BX), R10
    MOVQ R10, 0x58(SP)

    LEAQ ·spoofGadget0(SB), R10
    MOVQ R10, 0x00(SP)
    LEAQ ·spoofGadget1(SB), R10
    MOVQ R10, 0x60(SP)
    LEAQ ·spoofGadget1(SB), R10
    MOVQ R10, 0x90(SP)
    LEAQ ·spoofExit(SB), R10
    MOVQ R10, 0xc0(SP)

    JMP R12

TEXT ·spoofGadget0(SB), NOSPLIT, $0-0
    ADDQ $0x58, SP
    RET

TEXT ·spoofGadget1(SB), NOSPLIT, $0-0
    ADDQ $0x28, SP
    RET

TEXT ·spoofExit(SB), NOSPLIT, $0-0
    MOVQ 0xc8(SP), R12
    MOVQ 0xd0(SP), R13
    MOVQ 0xd8(SP), R14
    MOVQ 0xe0(SP), R15
    MOVQ 0xe8(SP), BX
    MOVQ AX, 96(BX)           // args.result
    ADDQ $0x28, SP            // skip the save block
    RET                       // to the original caller
