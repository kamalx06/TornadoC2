//go:build windows

package core

import (
	"os"
	"os/exec"
	"syscall"
)

const (
	createBreakawayFromJob = 0x01000000
	detachedProcess        = 0x00000008
	createNewProcessGroup  = 0x00000200
)

// spawnDetached launches a detached copy of the binary at exePath.
//
// On Windows, "detached" needs three creation flags working
// together:
//
//   - CREATE_BREAKAWAY_FROM_JOB: the child is not bound to any
//     job object the parent belongs to. Without this, a parent
//     under a job with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE takes
//     the child down with it — a common default in modern service
//     managers and CI runners.
//
//   - DETACHED_PROCESS: the child has no console. Equivalent in
//     effect to the Linux /dev/null redirect, and it prevents the
//     child from inheriting the parent's console handle.
//
//   - CREATE_NEW_PROCESS_GROUP: the child is in its own process
//     group, so a Ctrl-C or a targeted CTRL_BREAK to the parent's
//     group does not touch it.
//
// The parent's file path stays on disk while the child runs — the
// kernel holds an implicit handle to the image — and is removed
// by SelfDelete's FILE_FLAG_DELETE_ON_CLOSE when the child exits.
// This matches the stager's Windows behaviour exactly.
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
		CreationFlags: createBreakawayFromJob |
			detachedProcess |
			createNewProcessGroup,
		HideWindow: true,
	}

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	go func() { _ = cmd.Wait() }()
	return pid, nil
}