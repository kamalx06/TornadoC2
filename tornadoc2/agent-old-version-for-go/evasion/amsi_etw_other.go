//go:build !windows

package evasion

func ApplyWindowsEvasion(amsi, etw bool) error { return nil }