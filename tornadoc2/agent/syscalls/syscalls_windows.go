//go:build windows

package syscalls

import (
    "encoding/binary"
    "errors"
    "fmt"
    "sync"
    "syscall"
    "unsafe"
)

var (
    ntdll                       = syscall.NewLazyDLL("ntdll.dll")
    ntdllBase       uintptr
    syscallInstr    uintptr
    ntdllInitOnce   sync.Once
    ntdllInitErr    error
)

func initNtdll() error {
    ntdllInitOnce.Do(func() {
        h, err := syscall.LoadLibrary("ntdll.dll")
        if err != nil {
            ntdllInitErr = fmt.Errorf("LoadLibrary(ntdll): %w", err)
            return
        }
        defer syscall.FreeLibrary(h)
        ntdllBase = uintptr(h)
        addr, err := findSyscallInstruction(ntdllBase)
        if err != nil {
            ntdllInitErr = err
            return
        }
        syscallInstr = addr
    })
    return ntdllInitErr
}

func findSyscallInstruction(base uintptr) (uintptr, error) {
    eLfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
    peHeader := base + uintptr(eLfanew)
    if *(*uint32)(unsafe.Pointer(peHeader)) != 0x00004550 {
        return 0, errors.New("bad PE signature")
    }

    sizeOfOptHdr := *(*uint16)(unsafe.Pointer(peHeader + 0x14))
    numSections := *(*uint16)(unsafe.Pointer(peHeader + 0x06))
    sectionTable := peHeader + 0x18 + uintptr(sizeOfOptHdr)

    for i := uintptr(0); i < uintptr(numSections); i++ {
        sect := sectionTable + i*40
        var name string
        nameBytes := (*[8]byte)(unsafe.Pointer(sect))
        for _, b := range nameBytes {
            if b == 0 {
                break
            }
            name += string(b)
        }
        if name != ".text" {
            continue
        }
        va := *(*uint32)(unsafe.Pointer(sect + 12))
        vsize := *(*uint32)(unsafe.Pointer(sect + 8))
        start := base + uintptr(va)
        end := start + uintptr(vsize)

        if uintptr(vsize) > 8*1024*1024 {
            end = start + 8*1024*1024
        }
        for p := start; p+3 <= end; p++ {
            if *(*byte)(unsafe.Pointer(p)) == 0x0F &&
                *(*byte)(unsafe.Pointer(p+1)) == 0x05 &&
                *(*byte)(unsafe.Pointer(p+2)) == 0xC3 {
                return p, nil
            }
        }
    }
    return 0, errors.New("no syscall; ret sequence found in ntdll")
}

func resolveSSN(funcName string) (uint32, error) {
    if err := initNtdll(); err != nil {
        return 0, err
    }

    proc := ntdll.NewProc(funcName)
    if err := proc.Find(); err != nil {
        return 0, fmt.Errorf("resolve %s: %w", funcName, err)
    }
    addr := proc.Addr()

    prologue := make([]byte, 8)
    for i := range prologue {
        prologue[i] = *(*byte)(unsafe.Pointer(addr + uintptr(i)))
    }

    if prologue[0] == 0x4C && prologue[1] == 0x8B &&
        prologue[2] == 0xD1 && prologue[3] == 0xB8 {
        return binary.LittleEndian.Uint32(prologue[4:8]), nil
    }

    return 0, fmt.Errorf(
        "%s appears to be hooked (prologue %02X %02X %02X %02X)",
        funcName, prologue[0], prologue[1], prologue[2], prologue[3])
}

func indirectSyscall(ssn uint32, syscallAddr uintptr,
    a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr)

func ntSyscall(name string, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, error) {
    if err := initNtdll(); err != nil {
        return 0, 0, err
    }
    ssn, err := resolveSSN(name)
    if err != nil {
        return 0, 0, err
    }
    r1, r2 := indirectSyscall(ssn, syscallInstr,
        a1, a2, a3, a4, a5, a6)
    return r1, r2, nil
}

func NtAllocateVirtualMemory(processHandle uintptr,
    baseAddress *uintptr, zeroBits uintptr,
    regionSize *uintptr, allocationType, protect uint32) error {

    r1, _, err := ntSyscall("NtAllocateVirtualMemory",
        processHandle,
        uintptr(unsafe.Pointer(baseAddress)),
        zeroBits,
        uintptr(unsafe.Pointer(regionSize)),
        uintptr(allocationType),
        uintptr(protect))
    if r1 != 0 {
        return fmt.Errorf("NtAllocateVirtualMemory status 0x%X (err %v)",
            r1, err)
    }
    return nil
}

func NtWriteVirtualMemory(processHandle uintptr,
    baseAddress uintptr, buffer unsafe.Pointer,
    size uintptr, bytesWritten *uintptr) error {

    r1, _, _ := ntSyscall("NtWriteVirtualMemory",
        processHandle,
        baseAddress,
        uintptr(buffer),
        size,
        uintptr(unsafe.Pointer(bytesWritten)),
        0)
    if r1 != 0 {
        return fmt.Errorf("NtWriteVirtualMemory status 0x%X", r1)
    }
    return nil
}

func NtCreateThreadEx(threadHandle *uintptr,
    desiredAccess uintptr,
    objectAttributes uintptr,
    processHandle uintptr,
    startRoutine uintptr,
    argument uintptr,
    createFlags uintptr,
    zeroBits uintptr,
    stackSize uintptr,
    maximumStackSize uintptr,
    attributeList uintptr) error {

    r1, _, _ := ntSyscall("NtCreateThreadEx",
        uintptr(unsafe.Pointer(threadHandle)),
        desiredAccess,
        objectAttributes,
        processHandle,
        startRoutine,
        argument,
    )
    if r1 != 0 {
        return fmt.Errorf("NtCreateThreadEx status 0x%X", r1)
    }
    return nil
}