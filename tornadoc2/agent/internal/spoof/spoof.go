// Package spoof calls a Windows API through a synthetic return-address
// chain so a stack walker sees kernel32/ntdll frames instead of a
// single Go frame.
//
// The assembly shim is only linked with `ev_stackspoof` on windows/amd64.
// Everywhere else the same helpers fall back to syscall.SyscallN, so
// call sites do not need build tags.
package spoof

// args mirrors the register and stack slots of the shim. Eleven
// arguments covers NtCreateThreadEx; the first four go in RCX/RDX/
// R8/R9, the rest land on the shadowed stack block.
type args struct {
	target uintptr
	a      [11]uintptr
	result uintptr
}

// Call4 invokes target with up to four register arguments through the
// spoofed chain when available.
func Call4(target, a1, a2, a3, a4 uintptr) uintptr {
	return call(target, [11]uintptr{a1, a2, a3, a4})
}

// Call11 invokes target with eleven arguments: four in registers and
// seven on the stack.
func Call11(target uintptr, a [11]uintptr) uintptr {
	return call(target, a)
}

var enabled = true

// SetEnabled turns the shim off for this build; calls then go through
// syscall.SyscallN. Used by the evasion config switch.
func SetEnabled(on bool) { enabled = on && available }

// Available reports whether the shim is linked.
func Available() bool { return available }
