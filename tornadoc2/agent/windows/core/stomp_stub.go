//go:build !ev_stomp

package core

import (
	"context"

	"tornadoc2/agent/protocol"
)

func (a *Agent) stompVerb(_ context.Context, t protocol.Task) Result {
	return Result{ID: t.ID,
		Error: "stomp is not compiled into this agent"}
}
