//go:build !persist_registry && !persist_task && !persist_service && windows

package core

import (
	"context"

	"tornadoc2/agent/protocol"
)

func (a *Agent) persistVerb(_ context.Context, t protocol.Task) Result {
	return Result{ID: t.ID,
		Error: "persistence is not compiled into this agent"}
}
