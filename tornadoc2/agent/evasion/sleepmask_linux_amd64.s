//go:build linux && amd64
#include "textflag.h"

// maskedSleepStub — invoke SYS_nanosleep(2) directly.
//
// No Go runtime function executes between entering and returning
// from this stub, so it is safe to call while .text is encrypted.
//
// Signature: func maskedSleepStub(ms uint32)
//
// The syscall number for nanosleep on Linux amd64 is 35 (see
// /usr/include/x86_64-linux-gnu/asm/unistd_64.h). The argument
// is a pointer to struct timespec { tv_sec int64; tv_nsec int64 }.
//
// The frame is 24 bytes: 16 for the timespec, 8 to keep RSP
// 16-byte aligned before SYSCALL. Linux does not require SYSCALL
// alignment, but a signal delivered during the sleep does, and the
// kernel restores the interrupted frame on the same stack.
TEXT ·maskedSleepStub(SB), NOSPLIT, $0-8
    SUBQ $24, SP

    // Load ms (zero-extended into RAX).
    MOVL ms+0(FP), AX

    // seconds    = ms / 1000
    // nanosecond = (ms % 1000) * 1000000
    MOVQ AX, AX
    MOVQ $1000, CX
    XORQ DX, DX
    DIVQ CX                // RAX = seconds, RDX = ms % 1000

    MOVQ AX, 0(SP)         // tv_sec
    MOVQ DX, AX
    MOVQ $1000000, CX
    MULQ CX                // RAX = nanoseconds
    MOVQ AX, 8(SP)         // tv_nsec

    // SYS_nanosleep(struct timespec *req, struct timespec *rem)
    MOVQ $35, AX           // SYS_nanosleep
    MOVQ SP, DI            // arg1 = &timespec
    XORQ SI, SI            // arg2 = NULL
    SYSCALL

    ADDQ $24, SP
    RET
    