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

type ParentHandshakeResult struct {
	Fingerprint string
	PubKey      *ecdsa.PublicKey
	Session     *Session
}

func ParentVerifyAndRespond(io FrameIO,
	pivotPrivKey *ecdsa.PrivateKey) (*ParentHandshakeResult, error) {

	if pivotPrivKey == nil {
		return nil, errors.New("pivot: parent has no pivot key")
	}

	raw, err := io.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("pivot: read hello: %w", err)
	}
	var hello HelloMsg
	if err := json.Unmarshal(raw, &hello); err != nil {
		return nil, fmt.Errorf("pivot: parse hello: %w", err)
	}

	refuse := func(reason string, err error) (
		*ParentHandshakeResult, error) {

		eb, _ := json.Marshal(ErrMsg{Error: reason})
		_ = io.WriteFrame(eb)
		return nil, err
	}

	if hello.Version != PivotVersion {
		return refuse("unsupported pivot version", fmt.Errorf(
			"pivot: peer sent version %q", hello.Version))
	}
	if hello.Fingerprint == "" || hello.Epk == "" ||
		hello.Sig == "" || hello.PubKey == "" {
		return refuse("malformed hello",
			errors.New("pivot: malformed hello"))
	}
	if !withinSkew(hello.Ts) {
		return refuse("timestamp outside window",
			errors.New("pivot: hello timestamp outside window"))
	}

	pubDER, err := base64.StdEncoding.DecodeString(hello.PubKey)
	if err != nil {
		return refuse("bad pubkey encoding",
			fmt.Errorf("pivot: decode pubkey: %w", err))
	}
	parsed, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return refuse("bad pubkey",
			fmt.Errorf("pivot: parse pubkey: %w", err))
	}
	childPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return refuse("pubkey is not ECDSA",
			errors.New("pivot: pubkey is not ECDSA"))
	}
	if childPub.Curve != elliptic.P256() {
		return refuse("pubkey is not P-256",
			errors.New("pivot: child pubkey is not P-256"))
	}

	sig, err := base64.StdEncoding.DecodeString(hello.Sig)
	if err != nil {
		return refuse("bad sig encoding",
			fmt.Errorf("pivot: decode sig: %w", err))
	}
	childPayload := childSigningPayload(hello.Fingerprint,
		hello.Epk, hello.Ts)
	if !verifySignature(childPub, childPayload, sig) {
		return refuse("signature invalid",
			errors.New("pivot: child signature invalid"))
	}

	pivotECDHPriv, err := ecdsaToECDH(pivotPrivKey)
	if err != nil {
		return refuse("parent key unusable", err)
	}
	childEPK, err := decodeECDHPublic(hello.Epk)
	if err != nil {
		return refuse("bad child epk",
			fmt.Errorf("pivot: decode child epk: %w", err))
	}
	shared, err := pivotECDHPriv.ECDH(childEPK)
	if err != nil {
		return refuse("ecdh failed",
			fmt.Errorf("pivot: ecdh: %w", err))
	}

	pivotECDHPub := pivotECDHPriv.PublicKey().Bytes()
	epkB64 := base64.StdEncoding.EncodeToString(pivotECDHPub)

	ts := time.Now().Unix()
	ackPayload := parentSigningPayload(hello.Fingerprint,
		hello.Epk, epkB64, ts)
	ackSig, err := signPayload(pivotPrivKey, ackPayload)
	if err != nil {
		return refuse("signing failed", err)
	}
	ack := AckMsg{
		Version: PivotVersion,
		Epk:     epkB64,
		Sig:     base64.StdEncoding.EncodeToString(ackSig),
		Ts:      ts,
	}
	ackBytes, err := json.Marshal(ack)
	if err != nil {
		return nil, err
	}
	if err := io.WriteFrame(ackBytes); err != nil {
		return nil, fmt.Errorf("pivot: send ack: %w", err)
	}

	sess, err := deriveSession(shared, roleParent)
	if err != nil {
		return nil, err
	}
	return &ParentHandshakeResult{
		Fingerprint: hello.Fingerprint,
		PubKey:      childPub,
		Session:     sess,
	}, nil
}