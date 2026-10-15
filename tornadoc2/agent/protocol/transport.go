package protocol

import "tornadoc2/agent/crypto"

type Transport interface {
	Name() string
	CheckIn(id Identity, pubkey, sig string, ts int64,
		wire *crypto.WireSession) (*CheckinResponse, error)
	FetchTasks(wire *crypto.WireSession) ([]Task, error)
	PostResult(r Result, wire *crypto.WireSession) error
	Close() error
}