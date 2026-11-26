//go:build linux && amd64

package evasion

import (
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if RunMaskHelper() {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestMaskedSleepRoundTrip(t *testing.T) {
	for _, mode := range []string{"rc4", "aes-ctr"} {
		start := time.Now()
		if err := MaskedSleep(mode, 25); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if d := time.Since(start); d < 20*time.Millisecond {
			t.Fatalf("%s slept %v, want >= 20ms", mode, d)
		}
	}
}

func TestTextSection(t *testing.T) {
	base, size, err := TextSection()
	if err != nil || base == 0 || size == 0 {
		t.Fatalf("TextSection: %#x %#x %v", base, size, err)
	}
}
