package pivot

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"golang.org/x/crypto/hkdf"
)

const PivotVersion = "v2"
var hkdfInfo = []byte("tornadoc2-pivot-v1")
const TimestampSkew = 300 * time.Second

type FrameIO interface {
	WriteFrame(body []byte) error
	ReadFrame() ([]byte, error)
}

type HelloMsg struct {
	Version     string `json:"pivot"`
	Fingerprint string `json:"fingerprint"`
	PubKey      string `json:"pubkey"` // base64 SPKI DER
	Epk         string `json:"epk"`
	Sig         string `json:"sig"`
	Ts          int64  `json:"ts"`
}

type AckMsg struct {
	Version string `json:"pivot,omitempty"`
	Epk string `json:"epk"`
	Sig string `json:"sig"`
	Ts  int64  `json:"ts"`
}

type ErrMsg struct {
	Error string `json:"error"`
}

func childSigningPayload(fingerprint, childEpk string, ts int64) []byte {
	return []byte(fmt.Sprintf(
		"tornadoc2-pivot-child-v2|%s|%s|%d",
		fingerprint, childEpk, ts))
}

func parentSigningPayload(fingerprint, childEpk,
	parentEpk string, ts int64) []byte {
	return []byte(fmt.Sprintf(
		"tornadoc2-pivot-parent-v2|%s|%s|%s|%d",
		fingerprint, childEpk, parentEpk, ts))
}

func generateECDHKeypair() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

func encodeECDHPublic(pub *ecdh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub.Bytes())
}

func decodeECDHPublic(b64 string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPublicKey(raw)
}

// ecdsaToECDH converts an ECDSA P-256 private key to the
// crypto/ecdh representation used for the handshake. The raw byte
// slice below is zeroed, but NewPrivateKey copies it into the
// internal state of the returned *ecdh.PrivateKey, which has no
// exported API for zeroing. The copy is left to the GC. This is a
// limitation of crypto/ecdh, not a defect in this package.
func ecdsaToECDH(priv *ecdsa.PrivateKey) (*ecdh.PrivateKey, error) {
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("pivot: pivot key must be P-256")
	}
	raw := make([]byte, 32)
	priv.D.FillBytes(raw)
	defer zeroBytes(raw)
	return ecdh.P256().NewPrivateKey(raw)
}

func signPayload(priv *ecdsa.PrivateKey, payload []byte) (
	[]byte, error) {

	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, priv, digest[:])
}

func verifySignature(pub *ecdsa.PublicKey, payload, sig []byte) bool {
	digest := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

func deriveSession(shared []byte, r role) (*Session, error) {
	defer zeroBytes(shared)

	reader := hkdf.New(sha256.New, shared, nil, hkdfInfo)
	okm := make([]byte, 64)
	if _, err := io.ReadFull(reader, okm); err != nil {
		return nil, err
	}
	defer zeroBytes(okm)

	return &Session{
		role:          r,
		childToParent: append([]byte(nil), okm[0:32]...),
		parentToChild: append([]byte(nil), okm[32:64]...),
		sendSeq:       1,
		recvSeq:       1,
	}, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func withinSkew(ts int64) bool {
	now := time.Now().Unix()
	skew := int64(TimestampSkew / time.Second)
	return ts >= now-skew && ts <= now+skew
}