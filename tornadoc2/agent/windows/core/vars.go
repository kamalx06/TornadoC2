//go:build windows

package core

var (
	DefaultURL      string
	DefaultProfile  string
	ServerPubKeyPem string
	ClientCertPem   string
	ClientKeyPem    string
	RootCAPem       string
	ProfileJSON     string
	AgentPrivKeyPem string

	TransportMode string
	DNSDomain     string
	DNSResolver   string
	ICMPHost      string
	DoHResolver   string
	DoHHostHeader string
	DoHUserAgent  string

	WebSocketURL string

	WireGuardServerPubKey   string
	WireGuardServerAddr     string
	WireGuardAgentPrivKey   string
	WireGuardTunnelIP       string
	WireGuardServerTunnelIP string
	WireGuardInnerPort      string

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

	IdentityRole string

	InjectorShellcodeB64 string

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
