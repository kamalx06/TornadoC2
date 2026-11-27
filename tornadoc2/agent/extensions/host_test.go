package extensions

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, h *Host, name, file string) Info {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	info, err := h.Load(context.Background(), name, raw)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestEchoAndArgs(t *testing.T) {
	h, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())

	info := load(t, h, "echo", "echo.wasm")
	if info.SHA256 == "" || !info.Loaded {
		t.Fatalf("bad info %+v", info)
	}
	out, rc, err := h.Call(context.Background(), "echo", nil, time.Second)
	if err != nil || rc != 0 || string(out) != "ok" {
		t.Fatalf("echo out=%q rc=%d err=%v", out, rc, err)
	}

	load(t, h, "args", "args.wasm")
	out, rc, err = h.Call(context.Background(), "args",
		[]string{"one", "two"}, time.Second)
	if err != nil || rc != 7 || string(out) != "one\x00two" {
		t.Fatalf("args out=%q rc=%d err=%v", out, rc, err)
	}
}

func TestExampleFromDocs(t *testing.T) {
	h, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	load(t, h, "hello", "example.wasm")
	out, rc, err := h.Call(context.Background(), "hello", nil, time.Second)
	if err != nil || rc != 0 || string(out) != "hello from wasm" {
		t.Fatalf("out=%q rc=%d err=%v", out, rc, err)
	}
}

func TestRejects(t *testing.T) {
	h, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	for name, file := range map[string]string{
		"no_run": "no_run.wasm", "bad_abi": "bad_abi.wasm",
		"bad_import": "bad_import.wasm", "big": "bigmem.wasm",
	} {
		raw, _ := os.ReadFile("testdata/" + file)
		if _, err := h.Load(context.Background(), name, raw); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	raw, _ := os.ReadFile("testdata/no_run.wasm")
	if _, err := h.Load(context.Background(), "notwasm",
		raw[:10]); err == nil {
		t.Error("truncated module accepted")
	}
}

func TestLoopTimeoutDoesNotWedge(t *testing.T) {
	h, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	load(t, h, "loop", "loop.wasm")
	load(t, h, "echo", "echo.wasm")

	start := time.Now()
	_, _, err = h.Call(context.Background(), "loop", nil, 250*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "context deadline") {
		t.Fatalf("expected deadline, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("call took %v", time.Since(start))
	}
	out, _, err := h.Call(context.Background(), "echo", nil, time.Second)
	if err != nil || string(out) != "ok" {
		t.Fatalf("echo after loop: %q %v", out, err)
	}
}

func TestUnloadReload(t *testing.T) {
	h, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	load(t, h, "echo", "echo.wasm")
	if err := h.Unload(context.Background(), "echo"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Info("echo"); ok {
		t.Fatal("still loaded")
	}
	load(t, h, "echo", "echo.wasm")
	if _, _, err := h.Call(context.Background(), "echo", nil, time.Second); err != nil {
		t.Fatal(err)
	}
}
