package pivot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)	

func ClientHandshake(io FrameIO,
	signingKey *ecdsa.PrivateKey,
	parentPubKey *ecdsa.PublicKey,
	fingerprint string) (*Session, error) {

	if signingKey == nil {
		return nil, errors.New(
			"pivot: child has no identity signing key")
	}
	if parentPubKey == nil {
		return nil, errors.New(
			"pivot: child has no pivot public key")
	}
	if parentPubKey.Curve != elliptic.P256() {
		return nil, errors.New(
			"pivot: parent public key must be P-256")
	}
	if fingerprint == "" {
		return nil, errors.New("pivot: empty fingerprint")
	}

	epkPriv, err := generateECDHKeypair()
	if err != nil {
		return nil, fmt.Errorf("pivot: ephemeral: %w", err)
	}
	epkB64 := encodeECDHPublic(epkPriv.PublicKey())

	pubDER, err := x509.MarshalPKIXPublicKey(
		&signingKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("pivot: marshal pubkey: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)

	ts := time.Now().Unix()
	payload := childSigningPayload(fingerprint, epkB64, ts)
	sig, err := signPayload(signingKey, payload)
	if err != nil {
		return nil, fmt.Errorf("pivot: sign hello: %w", err)
	}

	hello := HelloMsg{
		Version:     PivotVersion,
		Fingerprint: fingerprint,
		PubKey:      pubB64,
		Epk:         epkB64,
		Sig:         base64.StdEncoding.EncodeToString(sig),
		Ts:          ts,
	}
	helloBytes, err := json.Marshal(hello)
	if err != nil {
		return nil, err
	}
	if err := io.WriteFrame(helloBytes); err != nil {
		return nil, fmt.Errorf("pivot: send hello: %w", err)
	}

	raw, err := io.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("pivot: read ack: %w", err)
	}
	var probe struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &probe)
	if probe.Error != "" {
		return nil, fmt.Errorf("pivot: parent refused: %s",
			probe.Error)
	}
	var ack AckMsg
	if err := json.Unmarshal(raw, &ack); err != nil {
		return nil, fmt.Errorf("pivot: parse ack: %w", err)
	}

	if ack.Version != "" && ack.Version != PivotVersion {
		return nil, fmt.Errorf(
			"pivot: parent sent version %q, expected %q",
			ack.Version, PivotVersion)
	}

	if !withinSkew(ack.Ts) {
		return nil, errors.New(
			"pivot: ack timestamp outside window")
	}
	parentPayload := parentSigningPayload(
		fingerprint, epkB64, ack.Epk, ack.Ts)
	parentSig, err := base64.StdEncoding.DecodeString(ack.Sig)
	if err != nil {
		return nil, fmt.Errorf("pivot: bad ack sig b64: %w", err)
	}
	if !verifySignature(parentPubKey, parentPayload, parentSig) {
		return nil, errors.New(
			"pivot: parent signature invalid")
	}

	parentEPK, err := decodeECDHPublic(ack.Epk)
	if err != nil {
		return nil, fmt.Errorf("pivot: bad parent epk: %w", err)
	}
	shared, err := epkPriv.ECDH(parentEPK)
	if err != nil {
		return nil, fmt.Errorf("pivot: ecdh: %w", err)
	}

	return deriveSession(shared, roleChild)
}