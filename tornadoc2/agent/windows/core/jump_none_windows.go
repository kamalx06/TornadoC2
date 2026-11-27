//go:build !jump_psexec && !jump_winrm && !jump_wmi && !jump_scshell && windows

package core

import (
	"context"
	"errors"

	"tornadoc2/agent/protocol"
)

type jumpSpec struct{}

func (a *Agent) jumpVerb(_ context.Context, t protocol.Task) protocol.Result {
	return protocol.Result{ID: t.ID,
		Error: "jump is not compiled into this agent"}
}

var _ = errors.New
