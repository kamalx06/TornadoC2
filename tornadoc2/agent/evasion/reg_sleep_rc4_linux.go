//go:build sleep_rc4 && linux

package evasion

func init() { maskFns["rc4"] = func(ms uint32) error { return maskedSleepBasicLinux("rc4", ms) } }
