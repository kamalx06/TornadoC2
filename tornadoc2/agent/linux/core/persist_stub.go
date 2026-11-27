//go:build !persist_systemd && !persist_cron && !persist_profile && linux

package core

import (
	"context"
	"errors"

	"tornadoc2/agent/protocol"
)

func (a *Agent) persistVerb(_ context.Context, t protocol.Task) Result {
	return Result{ID: t.ID,
		Error: "persistence is not compiled into this agent"}
}

var _ = errors.New
