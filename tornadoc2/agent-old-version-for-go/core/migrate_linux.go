//go:build linux

package core

import (
	"os"
	"os/exec"
	"syscall"
)

// spawnDetached launches a detached copy of the binary at exePath.
//
// On Linux, "detached" means a new process group (Setpgid). This
// survives the parent's exit and survives any signal sent to the
// parent's process group — which matters when the handler is
// running under a service manager whose default KillMode is
// "control-group". A true setsid(2) would break the parent-child
// relationship entirely, but the Go runtime does not expose a
// pre-exec hook for it, and Setpgid is enough: the parent is
// about to exit, and systemd reparents the child to PID 1.
//
// stdin/stdout/stderr are redirected to /dev/null. Without this,
// the child holds the parent's terminal open — visible in `ps`
// as a lingering fd to a tty, and a reason for an operator to
// notice the migration.
func spawnDetached(exePath, readyPath string) (int, error) {
	cmd := exec.Command(exePath)
	cmd.Env = append(os.Environ(),
		migrateReadyEnv+"="+readyPath)

	if devnull, err := os.OpenFile(os.DevNull,
		os.O_RDWR, 0); err == nil {
		cmd.Stdin = devnull
		cmd.Stdout = devnull
		cmd.Stderr = devnull
		defer devnull.Close()
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid

	go func() { _ = cmd.Wait() }()

	return pid, nil
}