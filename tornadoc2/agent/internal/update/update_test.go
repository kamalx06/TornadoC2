//go:build update && linux

package update

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"tornadoc2/agent/protocol"
)

func signer(t *testing.T, digest string) (*ecdsa.PublicKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"digest":"` + digest + `"}`)
	sum := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey, base64.StdEncoding.EncodeToString(sig)
}

func serve(t *testing.T, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write(body)
		}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func selfPath(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return self
}

func TestUpdateSuccess(t *testing.T) {
	self := selfPath(t)
	payload := []byte("new binary")
	url := serve(t, payload)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	pub, sig := signer(t, digest)

	task := protocol.Task{ID: "1",
		Args: []string{url, digest, sig, "--no-restart"}}
	res := Run(context.Background(), task, pub)
	if res.Error != "" {
		t.Fatalf("error: %s", res.Error)
	}
	got, _ := os.ReadFile(self)
	if string(got) != string(payload) {
		t.Fatal("binary not replaced")
	}
	if _, err := os.Stat(self + ".old"); err != nil {
		t.Fatal("rollback copy missing")
	}
}

func TestUpdateDigestMismatch(t *testing.T) {
	_ = selfPath(t)
	url := serve(t, []byte("payload"))
	pub, sig := signer(t, strings.Repeat("0", 64))
	res := Run(context.Background(), protocol.Task{ID: "1",
		Args: []string{url, hex.EncodeToString(make([]byte, 32)), sig,
			"--no-restart"}}, pub)
	if res.Error == "" {
		t.Fatal("expected digest error")
	}
}

func TestUpdateBadSignature(t *testing.T) {
	_ = selfPath(t)
	payload := []byte("payload")
	url := serve(t, payload)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	_, sig := signer(t, digest)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	res := Run(context.Background(), protocol.Task{ID: "1",
		Args: []string{url, digest, sig, "--no-restart"}},
		&other.PublicKey)
	if res.Error == "" {
		t.Fatal("expected signature error")
	}
}

func TestUpdateNeedsArgsAndKey(t *testing.T) {
	if res := Run(context.Background(), protocol.Task{},
		nil); res.Error == "" {
		t.Fatal("expected usage error")
	}
	url := serve(t, []byte("x"))
	if res := Run(context.Background(),
		protocol.Task{Args: []string{url,
			hex.EncodeToString(make([]byte, 32)), "AA=="}},
		nil); res.Error == "" {
		t.Fatal("expected missing key error")
	}
}
