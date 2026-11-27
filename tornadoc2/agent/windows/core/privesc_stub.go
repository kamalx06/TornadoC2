//go:build windows

package core

import (
	"context"

	"tornadoc2/agent/protocol"
)

func (a *Agent) privescVerb(_ context.Context, t protocol.Task) Result {
	return Result{ID: t.ID,
		Error: "privesc is Linux-only in this build"}
}
