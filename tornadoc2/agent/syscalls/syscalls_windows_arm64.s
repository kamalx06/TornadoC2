//go:build windows && arm64
#include "textflag.h"

// indirectSyscall is not used on arm64 (ntSyscall falls back to
// syscall.SyscallN), but the symbol must exist for the common
// declaration. Keep the frame size in sync with the Go decl.
TEXT ·indirectSyscall(SB),NOSPLIT,$0-120
    MOVD $0, ret+104(FP)
    MOVD $0, ret1+112(FP)
    RET
