//go:build sleep_aes && linux

package evasion

func init() {
	maskFns["aes-ctr"] = func(ms uint32) error { return maskedSleepBasicLinux("aes-ctr", ms) }
}
