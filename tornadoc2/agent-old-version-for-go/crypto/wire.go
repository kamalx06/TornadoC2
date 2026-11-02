package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

const wireVersion = "v2"

var wireInfo = []byte("tornadoc2-wire-v2")

type WireSession struct {
	mu   sync.Mutex
	peer *ecdh.PublicKey   // server's long-lived public key
	priv *ecdh.PrivateKey  // current ephemeral keypair
	key  []byte            // shared secret for `priv`
}

func NewWireSession(serverPubB64 string) (*WireSession, error) {
	if serverPubB64 == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, err
	}
	w := &WireSession{peer: peer}
	if _, err := w.RotateEphemeral(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *WireSession) RotateEphemeral() (string, error) {
	if w == nil {
		return "", nil
	}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := priv.ECDH(w.peer)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(shared)
	h.Write(wireInfo)
	sum := h.Sum(nil)

	w.mu.Lock()
	w.priv = priv
	w.key = sum
	w.mu.Unlock()

	return base64.StdEncoding.EncodeToString(
		priv.PublicKey().Bytes()), nil
}

func (w *WireSession) EpkBase64() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	pub := w.priv.PublicKey().Bytes()
	w.mu.Unlock()
	return base64.StdEncoding.EncodeToString(pub)
}

func (w *WireSession) EncryptRequest(plaintext []byte) ([]byte, error) {
	if w == nil {
		return plaintext, nil
	}
	epk, err := w.RotateEphemeral()
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	key := append([]byte(nil), w.key...)
	w.mu.Unlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, iv, plaintext, []byte(wireVersion))
	env := map[string]string{
		"enc": wireVersion,
		"epk": epk,
		"iv":  base64.StdEncoding.EncodeToString(iv),
		"ct":  base64.StdEncoding.EncodeToString(ct),
	}
	return json.Marshal(env)
}

// IsEnvelope reports whether body parses as a wire envelope.
//
// It answers one question only: did the server choose to encrypt
// this response, or did it send plaintext? It does not validate
// the enc version, the IV, the ciphertext, or the GCM tag — that
// is DecryptResponse's job.
//
// The distinction matters on pivot transports. A child's tasks
// request carries no epk (there is no header channel through a
// pivot), so the server has no shared secret to encrypt with and
// responds in plaintext. The pivot tunnel's own AEAD is the
// integrity layer for that hop; the wire envelope is absent by
// design, not by tampering. Without this helper, DecryptResponse
// raises "encrypted session, response has no enc field" and the
// child treats a legitimate plaintext response as a failure.
//
// The check is deliberately lenient: any non-empty "enc" field
// counts as an envelope, and DecryptResponse then decides whether
// the version and ciphertext are acceptable. A future v3 envelope
// would answer true here and be rejected with a version error
// inside DecryptResponse, which is the correct diagnostic.
func IsEnvelope(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var probe struct {
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return probe.Enc != ""
}

func (w *WireSession) DecryptResponse(body []byte) ([]byte, bool, error) {
	if w == nil {
		return body, false, nil
	}
	var env struct {
		Enc string `json:"enc"`
		IV  string `json:"iv"`
		CT  string `json:"ct"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, false, fmt.Errorf(
			"wire: encrypted session, response is not JSON: %w", err)
	}
	if env.Enc == "" {
		return nil, false, errors.New(
			"wire: encrypted session, response has no enc field")
	}
	if env.Enc != wireVersion {
		return nil, false, fmt.Errorf(
			"wire: encrypted session, unsupported enc %q (want %q)",
			env.Enc, wireVersion)
	}
	if env.IV == "" || env.CT == "" {
		return nil, false, errors.New(
			"wire: envelope missing iv or ct")
	}
	iv, err := base64.StdEncoding.DecodeString(env.IV)
	if err != nil {
		return nil, false, fmt.Errorf("wire: bad iv: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, false, fmt.Errorf("wire: bad ct: %w", err)
	}
	w.mu.Lock()
	key := append([]byte(nil), w.key...)
	w.mu.Unlock()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false, err
	}
	pt, err := gcm.Open(nil, iv, ct, []byte(wireVersion))
	if err != nil {
		return nil, false, fmt.Errorf("wire: decrypt failed: %w", err)
	}
	return pt, true, nil
}