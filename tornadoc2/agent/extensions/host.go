// Package extensions hosts sandboxed WASM extension modules.
//
// One Host owns one wazero runtime. Modules import only the
// versioned `env` ABI, get a fixed memory ceiling and a per-call
// deadline. More than one module can run concurrently; calls to
// the same module are serialised.
package extensions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	ABIVersion   = 1
	MaxModule    = 2 << 20
	MaxRead      = 8 << 20
	MemoryPages  = 256
	DefaultLimit = 5 * time.Second
)

type Info struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
	ABI    int    `json:"abi"`
	Loaded bool   `json:"loaded"`
	Pages  uint32 `json:"pages"`
}

type moduleState struct {
	mu   sync.Mutex
	out  []byte
	args []string
	info Info
	mod  api.Module
}

type Host struct {
	mu      sync.RWMutex
	rt      wazero.Runtime
	modules map[string]*moduleState
	closed  bool
}

func New(ctx context.Context) (*Host, error) {
	h := &Host{modules: map[string]*moduleState{}}
	h.rt = wazero.NewRuntimeWithConfig(ctx,
		wazero.NewRuntimeConfigInterpreter().
			WithMemoryLimitPages(MemoryPages).
			WithCloseOnContextDone(true))
	_, err := h.rt.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(h.hostOut).Export("host_out").
		NewFunctionBuilder().WithFunc(h.hostRead).Export("host_read").
		NewFunctionBuilder().WithFunc(h.hostSize).Export("host_size").
		NewFunctionBuilder().WithFunc(h.hostEnv).Export("host_env").
		NewFunctionBuilder().WithFunc(h.hostArgs).Export("host_args").
		NewFunctionBuilder().WithFunc(h.hostErr).Export("host_err").
		NewFunctionBuilder().WithFunc(h.hostTime).Export("host_time_ms").
		Instantiate(ctx)
	if err != nil {
		_ = h.rt.Close(ctx)
		return nil, err
	}
	return h, nil
}

func (h *Host) state(m api.Module) *moduleState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.modules[m.Name()]
}

func mem(m api.Module, ptr, ln uint32) ([]byte, bool) {
	if ln == 0 {
		return []byte{}, true
	}
	return m.Memory().Read(ptr, ln)
}

func (h *Host) hostOut(_ context.Context, m api.Module, ptr, ln uint32) int32 {
	st := h.state(m)
	b, ok := mem(m, ptr, ln)
	if !ok || st == nil {
		return -4
	}
	st.out = append(st.out, b...)
	return int32(len(b))
}

func (h *Host) hostErr(_ context.Context, m api.Module, ptr, ln uint32) int32 {
	st := h.state(m)
	b, ok := mem(m, ptr, ln)
	if !ok || st == nil {
		return -4
	}
	st.out = append(st.out, b...)
	return int32(len(b))
}

func (h *Host) hostRead(_ context.Context, m api.Module,
	pathPtr, pathLen, bufPtr, bufCap uint32) int32 {
	if bufCap == 0 {
		return -3
	}
	if bufCap > MaxRead {
		bufCap = MaxRead
	}
	p, ok := mem(m, pathPtr, pathLen)
	if !ok {
		return -4
	}
	f, err := os.Open(string(p))
	if err != nil {
		return -1
	}
	defer f.Close()
	buf := make([]byte, bufCap)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return -1
	}
	if !m.Memory().Write(bufPtr, buf[:n]) {
		return -4
	}
	return int32(n)
}

func (h *Host) hostSize(_ context.Context, m api.Module,
	pathPtr, pathLen uint32) int32 {
	p, ok := mem(m, pathPtr, pathLen)
	if !ok {
		return -4
	}
	fi, err := os.Stat(string(p))
	if err != nil || fi.IsDir() {
		return -1
	}
	return int32(fi.Size())
}

func (h *Host) hostEnv(_ context.Context, m api.Module,
	namePtr, nameLen, bufPtr, bufCap uint32) int32 {
	p, ok := mem(m, namePtr, nameLen)
	if !ok {
		return -4
	}
	v := os.Getenv(string(p))
	if uint32(len(v)) > bufCap {
		v = v[:bufCap]
	}
	if !m.Memory().Write(bufPtr, []byte(v)) {
		return -4
	}
	return int32(len(v))
}

func (h *Host) hostArgs(_ context.Context, m api.Module,
	bufPtr, bufCap uint32) int32 {
	st := h.state(m)
	if st == nil {
		return -4
	}
	v := strings.Join(st.args, "\x00")
	if uint32(len(v)) > bufCap {
		v = v[:bufCap]
	}
	if !m.Memory().Write(bufPtr, []byte(v)) {
		return -4
	}
	return int32(len(v))
}

func (h *Host) hostTime(_ context.Context, _ api.Module) int64 {
	return time.Now().UnixMilli()
}

func (h *Host) Load(ctx context.Context, name string,
	raw []byte) (Info, error) {
	if err := validName(name); err != nil {
		return Info{}, err
	}
	if len(raw) > MaxModule {
		return Info{}, fmt.Errorf("module is %d bytes; max %d",
			len(raw), MaxModule)
	}
	if len(raw) < 8 || !bytes.Equal(raw[:4], []byte("\x00asm")) ||
		!bytes.Equal(raw[4:8], []byte{1, 0, 0, 0}) {
		return Info{}, errors.New("not a WASM 1.0 module")
	}
	sum := sha256.Sum256(raw)
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return Info{}, errors.New("host closed")
	}
	h.mu.Unlock()

	cfg := wazero.NewModuleConfig().WithName(name)
	mod, err := h.rt.InstantiateWithConfig(ctx, raw, cfg)
	if err != nil {
		return Info{}, fmt.Errorf("instantiate: %w", err)
	}
	if mod.ExportedFunction("run") == nil {
		_ = mod.Close(ctx)
		return Info{}, errors.New("module does not export run()")
	}
	if abi := mod.ExportedFunction("abi_version"); abi != nil {
		v, err := abi.Call(ctx)
		if err != nil || len(v) == 0 || uint32(v[0]) != ABIVersion {
			_ = mod.Close(ctx)
			return Info{}, fmt.Errorf("unsupported ABI version")
		}
	}
	info := Info{Name: name, SHA256: hex.EncodeToString(sum[:]),
		Size: len(raw), ABI: ABIVersion, Loaded: true}
	st := &moduleState{mod: mod, info: info}

	h.mu.Lock()
	old := h.modules[name]
	h.modules[name] = st
	h.mu.Unlock()
	if old != nil {
		_ = old.mod.Close(ctx)
	}
	return info, nil
}

func (h *Host) Call(ctx context.Context, name string,
	args []string, limit time.Duration) ([]byte, int, error) {
	h.mu.RLock()
	st := h.modules[name]
	h.mu.RUnlock()
	if st == nil {
		return nil, 0, fmt.Errorf("not loaded: %s", name)
	}
	if limit <= 0 || limit > DefaultLimit {
		limit = DefaultLimit
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	fn := st.mod.ExportedFunction("run")
	if fn == nil {
		return nil, 0, errors.New("missing run")
	}
	st.out = st.out[:0]
	st.args = args

	cctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	code, err := fn.Call(cctx)
	if err != nil {
		return nil, 0, fmt.Errorf("call: %w", err)
	}
	out := append([]byte(nil), st.out...)
	rc := 0
	if len(code) > 0 {
		rc = int(int32(uint32(code[0])))
	}
	return out, rc, nil
}

func (h *Host) List() []Info {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Info, 0, len(h.modules))
	for _, st := range h.modules {
		out = append(out, st.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (h *Host) Info(name string) (Info, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	st := h.modules[name]
	if st == nil {
		return Info{}, false
	}
	return st.info, true
}

func (h *Host) Unload(ctx context.Context, name string) error {
	h.mu.Lock()
	st := h.modules[name]
	if st != nil {
		delete(h.modules, name)
	}
	h.mu.Unlock()
	if st == nil {
		return os.ErrNotExist
	}
	return st.mod.Close(ctx)
}

func (h *Host) Close(ctx context.Context) error {
	h.mu.Lock()
	h.closed = true
	mods := h.modules
	h.modules = map[string]*moduleState{}
	h.mu.Unlock()
	for _, st := range mods {
		_ = st.mod.Close(ctx)
	}
	return h.rt.Close(ctx)
}

func validName(name string) error {
	if name == "" || len(name) > 64 {
		return errors.New("name must be 1-64 characters")
	}
	for _, r := range name {
		if !(r == '_' || r == '-' || r == '.' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9')) {
			return errors.New("name may contain only letters, digits, '_', '-', '.'")
		}
	}
	return nil
}
