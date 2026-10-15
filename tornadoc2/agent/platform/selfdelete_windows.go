//go:build windows

package platform

import (
	"os"
	"syscall"
)

func SelfDelete() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	path, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(
		path,
		syscall.GENERIC_READ|0x00010000, // GENERIC_READ | DELETE
		0x00000001|0x00000004,           // FILE_SHARE_READ | FILE_SHARE_DELETE
		nil,
		syscall.OPEN_EXISTING,
		0x04000000, // FILE_FLAG_DELETE_ON_CLOSE
		0,
	)
	if err != nil {
		return err
	}
	_ = h
	return nil
}