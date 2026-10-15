//go:build windows

package evasion

import (
	"syscall"
	"unsafe"
)

var (
	adKernel32 = syscall.NewLazyDLL("kernel32.dll")
	adNtdll    = syscall.NewLazyDLL("ntdll.dll")

	procIsDebuggerPresent          = adKernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = adKernel32.NewProc("CheckRemoteDebuggerPresent")
	procNtQueryInformationProcess  = adNtdll.NewProc("NtQueryInformationProcess")
)

const (
	processDebugPort         = 7
	processDebugObjectHandle = 0x1E
	processDebugFlags        = 0x1F
)

func DebuggerDetected() bool {
	signals := 0

	if isDebuggerPresent() {
		signals++
	}
	if checkRemoteDebuggerPresent() {
		signals++
	}
	if ntQueryDebugPort() {
		signals++
	}
	if ntQueryDebugObjectHandle() {
		signals++
	}
	if !ntQueryDebugFlags() { // DebugFlags == 0 means debugging
		signals++
	}

	return signals >= 2
}

func isDebuggerPresent() bool {
	r, _, _ := procIsDebuggerPresent.Call()
	return r != 0
}

func checkRemoteDebuggerPresent() bool {
	hProcess, _, _ := procGetCurrentProcess.Call()
	var present int32
	r, _, _ := procCheckRemoteDebuggerPresent.Call(
		hProcess, uintptr(unsafe.Pointer(&present)))
	if r == 0 {
		return false
	}
	return present != 0
}

func ntQueryDebugPort() bool {
	hProcess, _, _ := procGetCurrentProcess.Call()
	var port uintptr
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		hProcess,
		processDebugPort,
		uintptr(unsafe.Pointer(&port)),
		unsafe.Sizeof(port),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return false
	}
	return port != 0
}

func ntQueryDebugObjectHandle() bool {
	hProcess, _, _ := procGetCurrentProcess.Call()
	var handle uintptr
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		hProcess,
		processDebugObjectHandle,
		uintptr(unsafe.Pointer(&handle)),
		unsafe.Sizeof(handle),
		uintptr(unsafe.Pointer(&retLen)),
	)
	// STATUS_PORT_NOT_SET (0xC0000353) means no debugger.
	if status != 0 {
		return false
	}
	return handle != 0
}

func ntQueryDebugFlags() bool {
	hProcess, _, _ := procGetCurrentProcess.Call()
	var flags uintptr
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		hProcess,
		processDebugFlags,
		uintptr(unsafe.Pointer(&flags)),
		unsafe.Sizeof(flags),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return true // can't query -> assume clean to avoid FP
	}
	return flags != 0
}