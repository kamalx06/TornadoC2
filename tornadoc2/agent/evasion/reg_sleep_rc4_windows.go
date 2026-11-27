//go:build sleep_rc4 && windows

package evasion

func init() { maskFns["rc4"] = func(ms uint32) error { return maskedSleepBasic("rc4", ms) } }
