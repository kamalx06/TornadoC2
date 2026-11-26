//go:build windows && arm64
#include "textflag.h"

// maskedSleepStub is unused on arm64 (MaskedSleep takes the plain
// sleep path before calling it) but the symbol must link.
TEXT ·maskedSleepStub(SB), NOSPLIT, $0-4
    RET
