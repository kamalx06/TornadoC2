// Package peimg does the small amount of PE header arithmetic needed
// to place bytes in an already-mapped image. It is pure Go so the
// logic is testable off Windows.
package peimg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	sectHeaderSize = 40
	exeFlag        = 0x20000000
	// MaxHeaders bounds the size read before the section table is
	// trusted; real images are far below this.
	MaxHeaders = 0x10000
)

var errBad = errors.New("malformed PE image")

// Layout returns the section count, the offset of the section table
// and the total header size.
func Layout(img []byte) (nsec uint16, secOff uint32, total uint32, err error) {
	if len(img) < 0x40 || img[0] != 'M' || img[1] != 'Z' {
		return 0, 0, 0, fmt.Errorf("%w: no MZ", errBad)
	}
	e := binary.LittleEndian.Uint32(img[0x3c:])
	if e < 0x40 || uint64(e)+24 > uint64(len(img)) {
		return 0, 0, 0, fmt.Errorf("%w: bad e_lfanew", errBad)
	}
	if string(img[e:e+4]) != "PE\x00\x00" {
		return 0, 0, 0, fmt.Errorf("%w: bad signature", errBad)
	}
	coff := e + 4
	nsec = binary.LittleEndian.Uint16(img[coff+2:])
	optSize := binary.LittleEndian.Uint16(img[coff+16:])
	if optSize < 64 {
		return 0, 0, 0, fmt.Errorf("%w: short optional header", errBad)
	}
	secOff = coff + 20 + uint32(optSize)
	total = secOff + uint32(nsec)*sectHeaderSize
	if total > MaxHeaders || uint64(total) > uint64(len(img)) {
		return 0, 0, 0, fmt.Errorf("%w: header table past image", errBad)
	}
	return nsec, secOff, total, nil
}

// ExecutableSection returns the largest executable section that can
// hold want bytes.
func ExecutableSection(img []byte, want uint32) (off, size uint32, err error) {
	nsec, secOff, _, err := Layout(img)
	if err != nil {
		return 0, 0, err
	}
	for i := uint16(0); i < nsec; i++ {
		s := img[secOff+uint32(i)*sectHeaderSize:]
		if binary.LittleEndian.Uint32(s[36:])&exeFlag == 0 {
			continue
		}
		va := binary.LittleEndian.Uint32(s[12:])
		vs := binary.LittleEndian.Uint32(s[16:])
		if vs < want || vs <= size {
			continue
		}
		off, size = va, vs
	}
	if size == 0 {
		return 0, 0, fmt.Errorf("no executable section >= %d bytes",
			want)
	}
	return off, size, nil
}

// CheckText requires a section's raw size to cover its virtual size,
// so a copy of VirtualSize bytes is backed by real file bytes.
func CheckText(img []byte, rva uint32) error {
	nsec, secOff, _, err := Layout(img)
	if err != nil {
		return err
	}
	for i := uint16(0); i < nsec; i++ {
		s := img[secOff+uint32(i)*sectHeaderSize:]
		va := binary.LittleEndian.Uint32(s[12:])
		vs := binary.LittleEndian.Uint32(s[16:])
		rs := binary.LittleEndian.Uint32(s[20:])
		if rva < va || rva >= va+vs {
			continue
		}
		if rs < vs {
			return fmt.Errorf("section raw %d < virtual %d", rs, vs)
		}
		return nil
	}
	return fmt.Errorf("rva 0x%x outside sections", rva)
}
