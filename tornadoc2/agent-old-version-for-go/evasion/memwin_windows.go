//go:build windows

package evasion

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	mwPageReadWrite   = 0x04
	mwPageExecuteRead = 0x20
	mwPageExecuteRW   = 0x40
)

var (
	mwKernel32 = syscall.NewLazyDLL("kernel32.dll")

	mwProcVirtualProtect   = mwKernel32.NewProc("VirtualProtect")
	mwProcGetModuleHandleW = mwKernel32.NewProc("GetModuleHandleW")
)

func protectRegion(addr, size uintptr, newProtect uint32) (uint32, error) {
	var old uint32
	r, _, errno := mwProcVirtualProtect.Call(
		addr, size, uintptr(newProtect),
		uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return 0, fmt.Errorf("VirtualProtect(0x%x, %d, 0x%x): %w",
			addr, size, newProtect, errno)
	}
	return old, nil
}