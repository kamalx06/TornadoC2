//go:build !wasm_host

package core

import (
	"context"

	"tornadoc2/agent/protocol"
)

// isExtensionVerb recognises the four extension verbs even when
// the host is not compiled in. An operator who types `extension
// list` gets "wasm extensions not built into this agent", not
// "unknown verb: extension list". The verb is part of the
// catalogue; the host that implements it is not.
func isExtensionVerb(verb string) bool {
	switch verb {
	case "extension_register", "extension_call",
		"extension_list", "extension_unload":
		return true
	}
	return false
}

const extensionsNotBuilt = "wasm extensions not built into this agent " +
	"(rebuild with --wasm-extensions)"

func (a *Agent) extensionRegister(t protocol.Task) Result {
	return Result{ID: t.ID, Error: extensionsNotBuilt}
}

func (a *Agent) extensionCall(ctx context.Context,
	t protocol.Task) Result {
	return Result{ID: t.ID, Error: extensionsNotBuilt}
}

func (a *Agent) extensionList(t protocol.Task) Result {
	return Result{ID: t.ID, Error: extensionsNotBuilt}
}

func (a *Agent) extensionUnload(t protocol.Task) Result {
	return Result{ID: t.ID, Error: extensionsNotBuilt}
}