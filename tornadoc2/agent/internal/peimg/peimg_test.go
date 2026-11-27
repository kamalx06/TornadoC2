package peimg

import (
	"encoding/binary"
	"testing"
)

// build makes a minimal valid PE with one executable section.
func build(rawSize, virtSize uint32) []byte {
	img := make([]byte, 0x400)
	img[0], img[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(img[0x3c:], 0x80)
	copy(img[0x80:], "PE\x00\x00")
	coff := 0x84
	binary.LittleEndian.PutUint16(img[coff+2:], 1)   // sections
	binary.LittleEndian.PutUint16(img[coff+16:], 64) // optional size
	sec := coff + 20 + 64
	copy(img[sec:], ".text")
	binary.LittleEndian.PutUint32(img[sec+12:], 0x1000) // VA
	binary.LittleEndian.PutUint32(img[sec+16:], virtSize)
	binary.LittleEndian.PutUint32(img[sec+20:], rawSize)
	binary.LittleEndian.PutUint32(img[sec+36:], 0x60000020)
	return img
}

func TestLayoutAndFind(t *testing.T) {
	img := build(0x2000, 0x1000)
	n, secOff, total, err := Layout(img)
	if err != nil || n != 1 || secOff == 0 || total == 0 {
		t.Fatalf("Layout: %v n=%d", err, n)
	}
	off, size, err := ExecutableSection(img, 0x100)
	if err != nil || off != 0x1000 || size != 0x1000 {
		t.Fatalf("Find: %v off=%x size=%x", err, off, size)
	}
	if _, _, err := ExecutableSection(img, 0x2000); err == nil {
		t.Fatal("expected too-large rejection")
	}
	if err := CheckText(img, 0x1000); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTextRawTooSmall(t *testing.T) {
	img := build(0x100, 0x1000)
	if err := CheckText(img, 0x1000); err == nil {
		t.Fatal("expected raw<virtual rejection")
	}
}

func TestBadImages(t *testing.T) {
	for name, img := range map[string][]byte{
		"empty": {},
		"no_mz": {'X', 'Y'},
		"bad_e": append([]byte("MZ"), make([]byte, 100)...),
		"short": build(0x1000, 0x1000)[:0x90],
	} {
		if _, _, _, err := Layout(img); err == nil {
			t.Errorf("%s: expected error", name)
		}
		if _, _, err := ExecutableSection(img, 1); err == nil {
			t.Errorf("%s: expected section error", name)
		}
	}
}

func TestNoExecutableSection(t *testing.T) {
	img := build(0x1000, 0x1000)
	sec := 0x84 + 20 + 64
	binary.LittleEndian.PutUint32(img[sec+36:], 0x40000040)
	if _, _, err := ExecutableSection(img, 1); err == nil {
		t.Fatal("expected no-executable error")
	}
}
