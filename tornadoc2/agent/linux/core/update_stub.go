//go:build !update && linux

package core

import (
	"context"

	"tornadoc2/agent/protocol"
)

func (a *Agent) updateVerb(_ context.Context, t protocol.Task) Result {
	return Result{ID: t.ID,
		Error: "update is not compiled into this agent"}
}
