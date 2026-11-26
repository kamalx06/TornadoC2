//go:build windows

package evasion

// RunMaskHelper is a no-op on Windows: the mask runs in-process.
func RunMaskHelper() bool { return false }
