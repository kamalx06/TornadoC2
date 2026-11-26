//go:build windows && amd64

package syscalls

import (
	"testing"
	"unsafe"
)

const (
	memCommit     = 0x1000
	memReserve    = 0x2000
	pageReadWrite = 0x04
)

func TestResolveSSN(t *testing.T) {
	ssn, err := resolveSSN("NtClose")
	if err != nil {
		t.Fatalf("resolveSSN(NtClose): %v", err)
	}
	if ssn == 0 {
		t.Fatal("NtClose SSN is zero")
	}
}

func TestAllocateWrite(t *testing.T) {
	var base uintptr
	size := uintptr(0x1000)
	if err := NtAllocateVirtualMemory(^uintptr(0), &base, 0,
		&size, memCommit|memReserve, pageReadWrite); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if base == 0 {
		t.Fatal("null allocation")
	}
	buf := []byte("tornado")
	var written uintptr
	if err := NtWriteVirtualMemory(^uintptr(0), base,
		unsafe.Pointer(&buf[0]), uintptr(len(buf)),
		&written); err != nil {
		t.Fatalf("write: %v", err)
	}
	if written != uintptr(len(buf)) {
		t.Fatalf("wrote %d/%d", written, len(buf))
	}
}
