//go:build !windows

package spoof

import "syscall"

// The spoof shim is windows/amd64 only; elsewhere fall back to the
// first three arguments, which is all any current caller passes on
// those platforms.
func call(target uintptr, a [11]uintptr) uintptr {
	r, _, _ := syscall.Syscall(target, a[0], a[1], a[2])
	return r
}
