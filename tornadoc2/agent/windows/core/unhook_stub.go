//go:build !ev_unhook

package core

import (
	"context"

	"tornadoc2/agent/protocol"
)

func (a *Agent) unhookVerb(_ context.Context, t protocol.Task) Result {
	return Result{ID: t.ID,
		Error: "unhook is not compiled into this agent"}
}
