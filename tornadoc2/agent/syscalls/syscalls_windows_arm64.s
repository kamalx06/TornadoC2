//go:build windows && arm64
#include "textflag.h"

// Indirect syscalls on Windows arm64 are structurally different
// from amd64: ARM64 uses the SVC instruction with a 16-bit immediate
// for the SSN, not a register. The technique still works — parse the
// stub for its `SVC #<imm>` and jump to the SVC's address — but the
// assembly is nontrivial and Go's ARM64 assembler does not expose
// the raw SVC encoding. Phase 2 ships amd64 only; arm64 falls
// through to a direct syscall via syscall.SyscallN.
//
// When arm64 support is added: allocate an RWX page, write the
// register setup + SVC #imm + RET bytes, call it. The immediate is
// resolvable from the target function's stub using the same PE
// parsing as amd64.

TEXT ·indirectSyscall(SB),NOSPLIT,$0-80
    // Placeholder that never fires — the arm64 build of
    // syscalls_windows.go's ntSyscall falls back to a direct call.
    MOVD $0, R0
    MOVD $0, R1
    RET