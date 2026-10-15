//go:build windows

package evasion

import (
    "fmt"
    "syscall"
)

type ustring struct {
    Length        uint32
    MaximumLength uint32
    Buffer        uintptr
}

var (
    advapi32              = syscall.NewLazyDLL("advapi32.dll")
    procSystemFunction032 = advapi32.NewProc("SystemFunction032")
)

// NativeRC4Addr returns the address of SystemFunction032 so the
// assembly stubs can invoke it directly without a GetProcAddress
// walk while memory is encrypted.
func NativeRC4Addr() (uintptr, error) {
    if err := procSystemFunction032.Find(); err != nil {
        return 0, fmt.Errorf("resolve SystemFunction032: %w", err)
    }
    return procSystemFunction032.Addr(), nil
}

const NativeRC4KeyLen = 16