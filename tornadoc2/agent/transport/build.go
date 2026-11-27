package transport

import (
	"crypto/tls"
	"fmt"

	"tornadoc2/agent/features"
	"tornadoc2/agent/protocol"
)

// Options is the build-time material a transport constructor may
// consume. Only the tagged constructors for the selected
// transports are linked into the binary.
type Options struct {
	URL          string
	WSURL        string
	DNSDomain    string
	DNSResolver  string
	DoHResolver  string
	DoHHeader    string
	DoHUserAgent string
	ICMPHost     string
	Profile      protocol.Profile
	TLSConfig    *tls.Config
	Shaping      *features.ShapingSpec

	WGServerPubKey   string
	WGServerAddr     string
	WGAgentPrivKey   string
	WGTunnelIP       string
	WGInnerPort      string
	WGServerTunnelIP string
}

type constructor func(Options) (protocol.Transport, error)

var builders = map[string]constructor{}

func register(name string, c constructor) { builders[name] = c }

// Build constructs the named transport.
func Build(name string, o Options) (protocol.Transport, error) {
	c, ok := builders[name]
	if !ok {
		return nil, fmt.Errorf(
			"transport %q is not compiled into this agent", name)
	}
	return c(o)
}

// Built reports whether a constructor is linked in.
func Built(name string) bool {
	_, ok := builders[name]
	return ok
}
