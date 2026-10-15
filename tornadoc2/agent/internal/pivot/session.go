package pivot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
)

type role uint8

const (
	roleUnspecified role = iota
	roleChild
	roleParent
)

type Session struct {
	role role

	childToParent []byte
	parentToChild []byte

	mu      sync.Mutex
	sendSeq uint64
	recvSeq uint64
}

type Frame struct {
	Seq uint64 `json:"seq"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
}

// String redacts the session keys. Without this, any %v/%+v format
// anywhere in the process would dump both 32-byte keys as decimal
// byte slices into a log file.
func (s *Session) String() string {
	return fmt.Sprintf("pivot.Session{role=%d}", s.role)
}

func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.childToParent {
		s.childToParent[i] = 0
	}
	for i := range s.parentToChild {
		s.parentToChild[i] = 0
	}
	runtime.KeepAlive(s.childToParent)
	runtime.KeepAlive(s.parentToChild)
	s.childToParent = nil
	s.parentToChild = nil
}

func seqErr(expected, got uint64) error {
	if got > expected {
		return fmt.Errorf("%w: expected %d, got %d",
			ErrSeqGap, expected, got)
	}
	return fmt.Errorf("%w: expected %d, got %d",
		ErrSeqRepeat, expected, got)
}

var ErrReplay = errors.New("pivot: sequence number out of order")

var ErrSeqGap = fmt.Errorf("%w: forward gap", ErrReplay)

var ErrSeqRepeat = fmt.Errorf("%w: replay", ErrReplay)

func (s *Session) checkRole(want role, method string) error {
	if s.role != roleUnspecified && s.role != want {
		return fmt.Errorf(
			"pivot: %s called on a %s session", method,
			map[role]string{
				roleChild:  "child",
				roleParent: "parent",
			}[s.role])
	}
	return nil
}

func (s *Session) EncryptChildToParent(plaintext []byte) (
	*Frame, error) {

	if err := s.checkRole(roleChild,
		"EncryptChildToParent"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.childToParent == nil {
		return nil, errors.New("pivot: session closed")
	}
	seq := s.sendSeq
	s.sendSeq++
	return sealFrame(s.childToParent, seq, plaintext)
}

func (s *Session) EncryptParentToChild(plaintext []byte) (
	*Frame, error) {

	if err := s.checkRole(roleParent,
		"EncryptParentToChild"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.parentToChild == nil {
		return nil, errors.New("pivot: session closed")
	}
	seq := s.sendSeq
	s.sendSeq++
	return sealFrame(s.parentToChild, seq, plaintext)
}

func (s *Session) DecryptChildToParent(f *Frame) ([]byte, error) {
	if err := s.checkRole(roleParent,
		"DecryptChildToParent"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Seq != s.recvSeq {
		return nil, seqErr(s.recvSeq, f.Seq)
	}
	pt, err := openFrame(s.childToParent, f)
	if err != nil {
		return nil, err
	}
	s.recvSeq++
	return pt, nil
}

func (s *Session) DecryptParentToChild(f *Frame) ([]byte, error) {
	if err := s.checkRole(roleChild,
		"DecryptParentToChild"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Seq != s.recvSeq {
		return nil, seqErr(s.recvSeq, f.Seq)
	}
	pt, err := openFrame(s.parentToChild, f)
	if err != nil {
		return nil, err
	}
	s.recvSeq++
	return pt, nil
}

func sealFrame(key []byte, seq uint64, plaintext []byte) (
	*Frame, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	var aad [8]byte
	binary.BigEndian.PutUint64(aad[:], seq)
	ct := gcm.Seal(nil, iv, plaintext, aad[:])
	return &Frame{
		Seq: seq,
		IV:  base64.StdEncoding.EncodeToString(iv),
		CT:  base64.StdEncoding.EncodeToString(ct),
	}, nil
}

func openFrame(key []byte, f *Frame) ([]byte, error) {
	iv, err := base64.StdEncoding.DecodeString(f.IV)
	if err != nil {
		return nil, fmt.Errorf("pivot: bad iv: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(f.CT)
	if err != nil {
		return nil, fmt.Errorf("pivot: bad ct: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var aad [8]byte
	binary.BigEndian.PutUint64(aad[:], f.Seq)
	pt, err := gcm.Open(nil, iv, ct, aad[:])
	if err != nil {
		return nil, fmt.Errorf("pivot: decrypt: %w", err)
	}
	return pt, nil
}

func EncodeFrame(f *Frame) ([]byte, error) {
	return json.Marshal(f)
}

func DecodeFrame(raw []byte) (*Frame, error) {
	var f Frame
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if f.Seq == 0 {
		return nil, errors.New("pivot: frame seq is zero")
	}
	if f.IV == "" || f.CT == "" {
		return nil, errors.New("pivot: frame missing iv or ct")
	}
	return &f, nil
}