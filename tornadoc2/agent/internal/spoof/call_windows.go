//go:build windows

package spoof

import "syscall"

func call(target uintptr, a [11]uintptr) uintptr {
	if !available || !enabled {
		r, _, _ := syscall.SyscallN(target, a[:]...)
		return r
	}
	p := args{target: target, a: a}
	spoofCall(&p)
	return p.result
}
