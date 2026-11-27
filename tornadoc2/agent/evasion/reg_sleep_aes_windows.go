//go:build sleep_aes && windows

package evasion

func init() { maskFns["aes-ctr"] = func(ms uint32) error { return maskedSleepBasic("aes-ctr", ms) } }
