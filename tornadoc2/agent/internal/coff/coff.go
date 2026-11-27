// Package coff validates the COFF header and section table of a BOF
// before the loader touches it. Pure Go so the checks fuzz on any OS.
package coff

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	headerSize   = 20
	sectionSize  = 40
	symbolSize   = 18
	maxSections  = 96
	machineAMD64 = 0x8664
	machineI386  = 0x014c
)

var errBad = errors.New("malformed COFF")

// ValidateHeader bounds-checks everything the loader indexes before
// allocation: machine, section count, section table and the symbol
// and string tables when present.
func ValidateHeader(raw []byte) error {
	if len(raw) < headerSize {
		return fmt.Errorf("%w: shorter than a header", errBad)
	}
	machine := binary.LittleEndian.Uint16(raw[0:])
	if machine != machineAMD64 && machine != machineI386 {
		return fmt.Errorf("%w: machine 0x%04x", errBad, machine)
	}
	nsec := int(binary.LittleEndian.Uint16(raw[2:]))
	if nsec < 1 || nsec > maxSections {
		return fmt.Errorf("%w: %d sections", errBad, nsec)
	}
	if headerSize+nsec*sectionSize > len(raw) {
		return fmt.Errorf("%w: section table truncated", errBad)
	}
	symOff := int(binary.LittleEndian.Uint32(raw[8:]))
	nsym := int(binary.LittleEndian.Uint32(raw[12:]))
	if nsym > 0 {
		end := symOff + nsym*symbolSize
		if symOff < headerSize || end > len(raw) || end < symOff {
			return fmt.Errorf("%w: symbol table out of bounds", errBad)
		}
		// The string table follows the symbols: a 4-byte length
		// then bytes, and must itself be inside the file.
		if end+4 > len(raw) {
			return fmt.Errorf("%w: string table missing", errBad)
		}
		strLen := int(binary.LittleEndian.Uint32(raw[end:]))
		if strLen < 4 || end+strLen > len(raw) {
			return fmt.Errorf("%w: string table truncated", errBad)
		}
	}
	return nil
}

// Sections returns count and table offset after validation.
func Sections(raw []byte) (int, int) {
	return int(binary.LittleEndian.Uint16(raw[2:])), headerSize
}
