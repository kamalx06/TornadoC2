//go:build windows

package evasion

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	vmAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	vmProcRegOpenKeyExW = vmAdvapi32.NewProc("RegOpenKeyExW")
	vmProcRegCloseKey   = vmAdvapi32.NewProc("RegCloseKey")
	vmProcRegEnumKeyExW = vmAdvapi32.NewProc("RegEnumKeyExW")
	vmProcRegQueryValueExW = vmAdvapi32.NewProc("RegQueryValueExW")
)

// Windows registry constants.
const (
	hkeyLocalMachine = 0x80000002
	keyRead          = 0x20019
)

func InVM() bool {
	score := 0

	// High confidence
	if registrySmbiosIsHypervisor() {
		score += 3
	}
	if vmToolRegistryKeys() {
		score += 3
	}
	if scsiDeviceVendor() {
		score += 3
	}

	// Medium confidence
	if vmMacAddress() {
		score += 2
	}
	if hypervisorDriverServices() {
		score += 2
	}

	// Weak confidence
	if vmGuestProcesses() {
		score++
	}

	return score >= 4
}

func registrySmbiosIsHypervisor() bool {
	key := `HARDWARE\DESCRIPTION\System\BIOS`
	h, ok := openKey(key)
	if !ok {
		return false
	}
	defer vmProcRegCloseKey.Call(h)

	values := []string{
		"SystemManufacturer",
		"SystemProductName",
		"BIOSVendor",
		"BIOSVersion",
		"BaseBoardManufacturer",
		"BaseBoardProduct",
	}
	markers := []string{
		"vmware",
		"virtualbox", "innotek", "vbox",
		"qemu", "kvm",
		"xen", "xensource",
		"bochs",
		"parallels",
		"bhyve",
		"amazon ec2",
		"google compute engine",
		"digitalocean",
		"openstack",
	}
	for _, v := range values {
		val, ok := queryStringValue(h, v)
		if !ok {
			continue
		}
		lower := strings.ToLower(val)
		for _, m := range markers {
			if strings.Contains(lower, m) {
				return true
			}
		}
	}
	return false
}

func vmToolRegistryKeys() bool {
	keys := []string{
		`SOFTWARE\VMware, Inc.\VMware Tools`,
		`SOFTWARE\Oracle\VirtualBox Guest Additions`,
		`SYSTEM\CurrentControlSet\Services\VBoxGuest`,
		`SYSTEM\CurrentControlSet\Services\VBoxMouse`,
		`SYSTEM\CurrentControlSet\Services\vmci`,
		`SYSTEM\CurrentControlSet\Services\vmhgfs`,
		`SYSTEM\CurrentControlSet\Services\vmx86`,
		`SYSTEM\CurrentControlSet\Services\vmmouse`,
		`SYSTEM\CurrentControlSet\Services\vmrawdsk`,
		`SYSTEM\CurrentControlSet\Services\vmusbmouse`,
		`SYSTEM\CurrentControlSet\Services\vm3dmp`,
		`SYSTEM\CurrentControlSet\Services\qemu-ga`,
		`SYSTEM\CurrentControlSet\Services\vioscsi`,
		`SYSTEM\CurrentControlSet\Services\viostor`,
		`SYSTEM\CurrentControlSet\Services\vmbus`,
		`SYSTEM\CurrentControlSet\Services\vmicheartbeat`,
		`SYSTEM\CurrentControlSet\Services\xenevtchn`,
	}
	for _, k := range keys {
		if regKeyExists(k) {
			return true
		}
	}
	return false
}

func scsiDeviceVendor() bool {
	base := `SYSTEM\CurrentControlSet\Enum\SCSI`
	h, ok := openKey(base)
	if !ok {
		return false
	}
	defer vmProcRegCloseKey.Call(h)

	needles := []string{
		"vmware", "vbox", "virtualbox", "qemu",
		"xen", "parallels", "virtio", "hyper-v",
		"msft virtual", "vmscsi",
	}
	var idx uint32
	for {
		nameBuf := make([]uint16, 256)
		nameLen := uint32(len(nameBuf))
		r, _, _ := vmProcRegEnumKeyExW.Call(
			h, uintptr(idx),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
			0, 0, 0, 0,
		)
		if r != 0 {
			break
		}
		name := strings.ToLower(syscall.UTF16ToString(nameBuf))
		for _, n := range needles {
			if strings.Contains(name, n) {
				return true
			}
		}
		idx++
	}
	return false
}

func hypervisorDriverServices() bool {
	keys := []string{
		`SYSTEM\CurrentControlSet\Services\VBoxWddm`,
		`SYSTEM\CurrentControlSet\Services\VBoxNetAdp`,
		`SYSTEM\CurrentControlSet\Services\VBoxNetFlt`,
		`SYSTEM\CurrentControlSet\Services\vmnetbridge`,
		`SYSTEM\CurrentControlSet\Services\vmci`,
		`SYSTEM\CurrentControlSet\Services\vpci`,
		`SYSTEM\CurrentControlSet\Services\storvsc`,
		`SYSTEM\CurrentControlSet\Services\netvsc`,
		`SYSTEM\CurrentControlSet\Services\vmbus`,
		`SYSTEM\CurrentControlSet\Services\winhv`,
	}
	for _, k := range keys {
		if regKeyExists(k) {
			return true
		}
	}
	return false
}

func vmGuestProcesses() bool {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	createSnapshot := kernel.NewProc("CreateToolhelp32Snapshot")
	process32First := kernel.NewProc("Process32FirstW")
	process32Next := kernel.NewProc("Process32NextW")
	closeHandle := kernel.NewProc("CloseHandle")

	const th32csSnapProcess = 0x00000002
	snap, _, _ := createSnapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == uintptr(^uint(0)) {
		return false
	}
	defer closeHandle.Call(snap)

	type processEntry32 struct {
		Size              uint32
		CntUsage          uint32
		ProcessID         uint32
		DefaultHeapID     uintptr
		ModuleID          uint32
		CntThreads        uint32
		ParentProcessID   uint32
		PriClassBase      int32
		Flags             uint32
		ExeFile           [260]uint16
	}
	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	needles := []string{
		"vmtoolsd.exe",
		"vmwaretray.exe",
		"vmwareuser.exe",
		"vboxservice.exe",
		"vboxtray.exe",
		"vboxclient.exe",
		"xenservice.exe",
		"qemu-ga.exe",
	}
	r, _, _ := process32First.Call(
		snap, uintptr(unsafe.Pointer(&entry)))
	for r != 0 {
		name := strings.ToLower(syscall.UTF16ToString(entry.ExeFile[:]))
		for _, n := range needles {
			if name == n {
				return true
			}
		}
		r, _, _ = process32Next.Call(
			snap, uintptr(unsafe.Pointer(&entry)))
	}
	return false
}

func openKey(path string) (uintptr, bool) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	var h uintptr
	r, _, _ := vmProcRegOpenKeyExW.Call(
		hkeyLocalMachine,
		uintptr(unsafe.Pointer(pathPtr)),
		0, keyRead,
		uintptr(unsafe.Pointer(&h)),
	)
	if r != 0 || h == 0 {
		return 0, false
	}
	return h, true
}

func queryStringValue(hKey uintptr, name string) (string, bool) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", false
	}
	var dataType, dataLen uint32
	dataBuf := make([]uint16, 512)
	dataLen = uint32(len(dataBuf) * 2)
	r, _, _ := vmProcRegQueryValueExW.Call(
		hKey,
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&dataType)),
		uintptr(unsafe.Pointer(&dataBuf[0])),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if r != 0 {
		return "", false
	}
	
	if dataType != 1 && dataType != 2 {
		return "", false
	}
	return syscall.UTF16ToString(dataBuf), true
}

func regKeyExists(path string) bool {
	h, ok := openKey(path)
	if !ok {
		return false
	}
	vmProcRegCloseKey.Call(h)
	return true
}