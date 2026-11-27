//go:build linux

package core

import (
	"context"

	"tornadoc2/agent/protocol"
)

func (a *Agent) jumpVerb(_ context.Context, t protocol.Task) protocol.Result {
	return protocol.Result{ID: t.ID,
		Error: "jump requires a Windows agent"}
}
