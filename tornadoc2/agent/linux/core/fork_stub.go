//go:build linux

package core

import (
	"context"

	"tornadoc2/agent/protocol"
)

func (a *Agent) forkVerb(_ context.Context, t protocol.Task) Result {
	return Result{ID: t.ID, Error: "fork is Windows-only"}
}
