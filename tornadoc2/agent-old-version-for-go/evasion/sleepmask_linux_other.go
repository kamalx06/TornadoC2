//go:build linux && !amd64

package evasion

import (
    "fmt"
    "sync"
    "time"
)

var linuxArchWarnOnce sync.Once

// maskedSleepBasicLinux on a non-amd64 Linux target warns once and
// falls back to a plain sleep. The assembly stub is amd64-only,
// and the ELF layout differs enough between architectures that a
// single implementation is not possible without per-arch
// assembly.
func maskedSleepBasicLinux(maskType string, ms uint32) error {
    linuxArchWarnOnce.Do(func() {
        fmt.Printf("[evasion] sleep mask %q is only implemented on "+
            "linux/amd64; falling back to plain sleep on this "+
            "architecture.\n", maskType)
    })
    time.Sleep(time.Duration(ms) * time.Millisecond)
    return nil
}