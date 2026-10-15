//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

func executeInMemory(payload []byte) error {
	fd, err := memfdCreate("payload")
	if err != nil {
		return execViaShm(payload)
	}
	defer syscall.Close(fd)
	if _, err := syscall.Write(fd, payload); err != nil {
		return err
	}
	if err := syscall.Fchmod(fd, 0700); err != nil {
		return err
	}
	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	cmd := exec.Command(path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func execViaShm(payload []byte) error {
	f, err := os.CreateTemp("/dev/shm", ".stage")
	if err != nil {
		return err
	}
	path := f.Name()
	if _, err := f.Write(payload); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Chmod(0700); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	f.Close()
	cmd := exec.Command(path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		os.Remove(path)
		return err
	}
	os.Remove(path)
	return nil
}

func memfdCreate(name string) (int, error) {
	var nr uintptr
	switch runtime.GOARCH {
	case "amd64":
		nr = 319
	case "386":
		nr = 356
	case "arm64", "riscv64":
		nr = 279
	case "arm":
		nr = 385
	default:
		return -1, fmt.Errorf("unsupported arch")
	}
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	r, _, errno := syscall.Syscall(nr,
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(0x0001), 0)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}