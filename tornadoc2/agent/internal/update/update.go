//go:build update && (linux || windows)

package update

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"tornadoc2/agent/protocol"
)

const maxUpdateBytes = 96 << 20

func Run(ctx context.Context, t protocol.Task,
	pub *ecdsa.PublicKey) protocol.Result {
	if len(t.Args) < 3 {
		return protocol.Result{ID: t.ID,
			Error: "update <url> <sha256> <sig_b64> [--no-restart]"}
	}
	url, want := t.Args[0], strings.ToLower(strings.TrimSpace(t.Args[1]))
	sigB64 := strings.TrimSpace(t.Args[2])
	if len(want) != 64 {
		return protocol.Result{ID: t.ID, Error: "sha256 must be 64 hex chars"}
	}
	if pub == nil {
		return protocol.Result{ID: t.ID,
			Error: "no server public key; cannot verify the update"}
	}
	restart := true
	for _, arg := range t.Args[3:] {
		if arg == "--no-restart" {
			restart = false
		}
	}

	self, err := os.Executable()
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: "download: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.Result{ID: t.ID,
			Error: fmt.Sprintf("download: HTTP %d", resp.StatusCode)}
	}

	tmp := self + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0o700)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(
		resp.Body, maxUpdateBytes+1))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	if n > maxUpdateBytes {
		_ = os.Remove(tmp)
		return protocol.Result{ID: t.ID, Error: "payload exceeds 96 MiB"}
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		_ = os.Remove(tmp)
		return protocol.Result{ID: t.ID,
			Error: "sha256 mismatch: got " + got[:16] + "…"}
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) == 0 {
		_ = os.Remove(tmp)
		return protocol.Result{ID: t.ID, Error: "bad signature"}
	}
	// The signer signs the canonical {"digest":"<hex>"} bytes.
	canonical := []byte(`{"digest":"` + got + `"}`)
	digest := sha256.Sum256(canonical)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		_ = os.Remove(tmp)
		return protocol.Result{ID: t.ID,
			Error: "signature does not match the digest"}
	}

	// Keep a rollback copy of the running binary.
	old := self + ".old"
	_ = os.Remove(old)
	if data, rerr := os.ReadFile(self); rerr == nil {
		_ = os.WriteFile(old, data, 0o700)
	}
	if err := replaceFile(tmp, self); err != nil {
		return protocol.Result{ID: t.ID,
			Error: "install (file locked? run --no-restart): " + err.Error()}
	}

	out := "updated " + got[:16] + "… (rollback at " + old + ")\n"
	if !restart {
		return protocol.Result{ID: t.ID, Output: base64.StdEncoding.EncodeToString([]byte(out))}
	}
	cmd := exec.Command(self)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return protocol.Result{ID: t.ID, Error: "restart: " + err.Error()}
	}
	_ = cmd.Process.Release()
	out += fmt.Sprintf("restarted as pid %d\n", cmd.Process.Pid)

	go func() {
		time.Sleep(1500 * time.Millisecond)
		os.Exit(0)
	}()
	return protocol.Result{ID: t.ID, Output: base64.StdEncoding.EncodeToString([]byte(out))}
}
