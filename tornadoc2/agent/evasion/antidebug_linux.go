//go:build linux

package evasion

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func DebuggerDetected() bool {
	signals := 0

	if tracerPidNonZero() {
		signals++
	}
	if ptraceSelfAttachFails() {
		signals++
	}
	if debuggerEnvVarsPresent() {
		signals++
	}
	if parentLooksLikeDebugger() {
		signals++
	}

	return signals >= 2
}

func tracerPidNonZero() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
		pid, err := strconv.Atoi(val)
		if err != nil {
			return false
		}
		return pid != 0
	}
	return false
}

func ptraceSelfAttachFails() bool {
	// PTRACE_TRACEME = 0
	r, _, errno := syscall.Syscall6(
		syscall.SYS_PTRACE,
		0, // PTRACE_TRACEME
		0, 0, 0,
		0, 0,
	)
	if r != 0 && errno == syscall.EPERM {
		return true
	}
	syscall.Syscall6(syscall.SYS_PTRACE, 17, 0, 0, 0, 0, 0) // PTRACE_DETACH
	return false
}

func debuggerEnvVarsPresent() bool {
	suspicious := []string{
		"LD_DEBUG",
		"LD_PRELOAD",
		"GDB",
		"LLDB",
		"STRACE",
		"RUST_BACKTRACE",
	}
	for _, name := range suspicious {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

func parentLooksLikeDebugger() bool {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 4 {
		return false
	}
	ppid := fields[3]

	cmdline, err := os.ReadFile("/proc/" + ppid + "/cmdline")
	if err != nil {
		return false
	}
	parts := strings.Split(string(cmdline), "\x00")
	if len(parts) == 0 {
		return false
	}
	name := parts[0]
	lower := strings.ToLower(name)
	for _, dbg := range []string{"gdb", "lldb", "strace", "ltrace", "radare2", "r2", "ida"} {
		if strings.Contains(lower, dbg) {
			return true
		}
	}
	return false
}