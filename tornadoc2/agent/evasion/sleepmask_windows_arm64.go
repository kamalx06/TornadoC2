//go:build (sleep_cronos || sleep_hwbp) && windows && arm64

package evasion

import "time"

func maskedSleepCronos(ms uint32) error {
	time.Sleep(time.Duration(ms) * time.Millisecond)
	return nil
}

func maskedSleepHWBP(ms uint32) error {
	time.Sleep(time.Duration(ms) * time.Millisecond)
	return nil
}

func init() {
	if _, ok := maskFns["cronos"]; !ok {
		maskFns["cronos"] = maskedSleepCronos
	}
	if _, ok := maskFns["hwbp"]; !ok {
		maskFns["hwbp"] = maskedSleepHWBP
	}
}
