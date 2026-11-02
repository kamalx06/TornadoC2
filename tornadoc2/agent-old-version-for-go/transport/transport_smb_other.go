//go:build !windows

package transport

import (
	"crypto/ecdsa"
	"errors"

	"tornadoc2/agent/features"
	"tornadoc2/agent/protocol"
)

type smbTransport struct{}

func NewSMBTransport(pipeName string,
	agentPriv *ecdsa.PrivateKey,
	pivotPub *ecdsa.PublicKey,
	identity protocol.Identity,
	shaping *features.ShapingSpec) (*smbTransport, error) {

	return nil, errors.New(
		"smb transport requires a Windows target")
}

func (t *smbTransport) Name() string { return "smb" }

func (t *smbTransport) CheckIn(identity Identity,
	pubkeyPEM, identitySig string, identityTs int64,
	wire *WireSession) (*CheckinResponse, error) {
	return nil, errors.New(
		"smb transport requires a Windows target")
}

func (t *smbTransport) FetchTasks(
	wire *WireSession) ([]Task, error) {
	return nil, errors.New(
		"smb transport requires a Windows target")
}

func (t *smbTransport) PostResult(
	r Result, wire *WireSession) error {
	return errors.New("smb transport requires a Windows target")
}

func (t *smbTransport) Close() error { return nil }