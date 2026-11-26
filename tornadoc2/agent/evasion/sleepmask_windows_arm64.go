//go:build windows && arm64

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
