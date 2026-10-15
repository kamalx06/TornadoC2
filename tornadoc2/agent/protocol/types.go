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
	Stager bool `json:"stager,omitempty"`
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