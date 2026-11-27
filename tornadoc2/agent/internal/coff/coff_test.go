package coff

import (
	"encoding/binary"
	"testing"
)

func valid() []byte {
	b := make([]byte, 20+40)
	binary.LittleEndian.PutUint16(b[0:], machineAMD64)
	binary.LittleEndian.PutUint16(b[2:], 1)
	return b
}

func TestValid(t *testing.T) {
	if err := ValidateHeader(valid()); err != nil {
		t.Fatal(err)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":   {},
		"short":   make([]byte, 10),
		"machine": append([]byte{0, 0}, make([]byte, 40)...),
		"nosect":  valid()[:20],
		"trunc":   valid()[:30],
	}
	for name, raw := range cases {
		if err := ValidateHeader(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzValidate(f *testing.F) {
	f.Add(valid())
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if err := ValidateHeader(raw); err == nil {
			n, off := Sections(raw)
			if n < 1 || off+n*40 > len(raw) {
				t.Fatalf("validated but table out of range")
			}
		}
	})
}
