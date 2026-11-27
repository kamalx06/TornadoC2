//go:build windows

package update

import (
	"syscall"
	"unsafe"
)

var (
	kernel32    = syscall.NewLazyDLL("kernel32.dll")
	moveFileExW = kernel32.NewProc("MoveFileExW")
)

const (
	moveReplaceExisting  = 0x1
	moveDelayUntilReboot = 0x4
)

// replaceFile swaps a running executable. Windows refuses a plain
// rename over a mapped image; MoveFileEx with DELAY_UNTIL_REBOOT
// succeeds and completes on the next boot if the image is still
// mapped.
func replaceFile(src, dst string) error {
	s, _ := syscall.UTF16PtrFromString(src)
	d, _ := syscall.UTF16PtrFromString(dst)
	r, _, err := moveFileExW.Call(uintptr(unsafe.Pointer(s)),
		uintptr(unsafe.Pointer(d)),
		moveReplaceExisting|moveDelayUntilReboot)
	if r != 0 {
		return nil
	}
	// The target is mapped. Renaming a running image is allowed,
	// so move it aside and put the new file in its place.
	old, _ := syscall.UTF16PtrFromString(dst + ".old")
	r, _, err = moveFileExW.Call(uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(old)), moveReplaceExisting)
	if r == 0 {
		return err
	}
	r, _, err = moveFileExW.Call(uintptr(unsafe.Pointer(s)),
		uintptr(unsafe.Pointer(d)), moveReplaceExisting)
	if r == 0 {
		return err
	}
	return nil
}
