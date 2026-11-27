//go:build update && linux

package core

import (
	"context"

	"tornadoc2/agent/internal/update"
	"tornadoc2/agent/protocol"
)

func (a *Agent) updateVerb(ctx context.Context, t protocol.Task) Result {
	return update.Run(ctx, t, a.serverPub)
}
