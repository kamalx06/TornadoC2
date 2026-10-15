//go:build linux

package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func credValidateDispatch(ctx context.Context, kind, user,
	domain, value, target string) (string, string) {

	switch kind {

	case "plaintext":
		return validateLDAPBind(ctx, user, domain, value, target)

	case "ssh_key":
		return validateSSHKey(ctx, user, target, value)

	case "cert":
		return validateCertTLS(user, target, value, true)

	case "bearer":
		return validateBearerHTTP(user, target, value, true)

	case "ticket":
		return validateTicketL(value)

	case "ntlm", "lm":
		return "unsupported",
			"NT hash validation is Windows-only; run the " +
				"check from a Windows beacon"

	case "token":
		return "unsupported",
			"access token validation is Windows-only; run " +
				"the check from a Windows beacon"

	case "aes256", "aes128", "krbtgt":
		return "unsupported",
			fmt.Sprintf(
				"kind %q requires a hand-built Kerberos "+
					"AS-REQ with the raw key; not "+
					"implemented in this build", kind)

	default:
		return "unsupported",
			fmt.Sprintf("kind %q has no validation routine", kind)
	}
}

func validateLDAPBind(ctx context.Context, user, domain,
	password, target string) (string, string) {

	if user == "" {
		return "error", "missing user"
	}

	dialTargets := []string{}
	if target != "" {
		dialTargets = append(dialTargets, ensurePort(target, "389"))
	} else if domain != "" {
		_, addrs, err := net.LookupSRV("ldap", "tcp", domain)
		if err != nil {
			return "error",
				fmt.Sprintf(
					"could not resolve an LDAP server for "+
						"domain %q: %v", domain, err)
		}
		for _, a := range addrs {
			host := strings.TrimSuffix(a.Target, ".")
			dialTargets = append(dialTargets,
				fmt.Sprintf("%s:%d", host, a.Port))
		}
	} else {
		return "error",
			"plaintext validation needs either --target or a " +
				"domain to look up a DC for"
	}

	name := bindNameFor(user, domain)

	var lastErr string
	for _, t := range dialTargets {
		status, detail := ldapBindOnce(ctx, t, name, password)
		switch status {
		case "valid", "locked", "expired":
			// A definitive answer. Return it.
			return status, detail
		case "invalid":
			return status, detail
		}
		lastErr = detail
	}
	if lastErr == "" {
		lastErr = "no reachable LDAP server"
	}
	return "error", lastErr
}

func bindNameFor(user, domain string) string {
	if domain == "" {
		return user
	}
	if strings.Contains(domain, ".") {
		return user + "@" + domain
	}
	return domain + `\` + user
}

func ldapBindOnce(ctx context.Context, target, name,
	password string) (string, string) {

	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return "error",
			fmt.Sprintf("connect %s: %v", target, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(8 * time.Second))

	packet := encodeLDAPSimpleBind(name, password)
	if _, err := conn.Write(packet); err != nil {
		return "error", fmt.Sprintf("write: %v", err)
	}

	resp, err := readLDAPMessage(conn)
	if err != nil {
		return "error", fmt.Sprintf("read: %v", err)
	}

	code, errMsg, err := parseLDAPBindResponse(resp)
	if err != nil {
		return "error", fmt.Sprintf("parse: %v", err)
	}

	switch code {
	case 0: // success
		return "valid", target + " " + name
	case 49: // invalidCredentials
		if errMsg != "" {
			return "invalid", "LDAP invalidCredentials: " + errMsg
		}
		return "invalid", "LDAP invalidCredentials"
	case 51: // busy
		return "error", "LDAP server busy"
	case 52: // unavailable
		return "error", "LDAP server unavailable"
	case 53: // unwillingToPerform
		return "invalid",
			"LDAP unwillingToPerform: " + errMsg
	case 32: // noSuchObject
		return "invalid", "LDAP noSuchObject"
	case 12: // unavailableCriticalExtension
		return "error", "LDAP unavailableCriticalExtension"
	}
	return "error",
		fmt.Sprintf("LDAP result code %d: %s", code, errMsg)
}

func encodeLDAPSimpleBind(name, password string) []byte {
	nameBytes := []byte(name)
	passBytes := []byte(password)

	// Inner BindRequest content.
	var inner bytes.Buffer
	writeInteger(&inner, 3)         // version
	writeOctetString(&inner, nameBytes)
	writeContextTag(&inner, 0, passBytes) // [0] simple

	// Wrap in [APPLICATION 0] SEQUENCE.
	app0 := wrapTag(0x60, inner.Bytes())

	// Outer LDAPMessage SEQUENCE.
	var outer bytes.Buffer
	writeInteger(&outer, 1)         // messageID
	outer.Write(app0)

	return wrapTag(0x30, outer.Bytes())
}

func readLDAPMessage(conn net.Conn) ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if head[0] != 0x30 {
		return nil, fmt.Errorf("expected SEQUENCE, got 0x%02X",
			head[0])
	}
	var bodyLen int
	var lenBytes []byte
	if head[1]&0x80 == 0 {
		bodyLen = int(head[1])
	} else {
		n := int(head[1] & 0x7F)
		if n > 4 {
			return nil, errors.New("length field too large")
		}
		lb := make([]byte, n)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return nil, err
		}
		lenBytes = lb
		for _, b := range lb {
			bodyLen = bodyLen<<8 | int(b)
		}
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}

	full := make([]byte, 0, 2+len(lenBytes)+bodyLen)
	full = append(full, head...)
	full = append(full, lenBytes...)
	full = append(full, body...)
	return full, nil
}

func parseLDAPBindResponse(msg []byte) (int, string, error) {
	// msg is SEQUENCE { messageID INTEGER, BindResponse [APPLICATION 1] ... }
	_, outerContent, _ := readTLV(msg)
	if outerContent == nil {
		return 0, "", errors.New("malformed LDAP message")
	}

	// messageID INTEGER — skip.
	_, afterID, _ := readTLV(outerContent)
	if afterID == nil {
		return 0, "", errors.New("missing messageID")
	}

	// BindResponse [APPLICATION 1] — tag 0x61.
	tag, bindContent, _ := readTLV(afterID)
	if bindContent == nil {
		return 0, "", errors.New("missing BindResponse")
	}
	if tag != 0x61 {
		return 0, "", fmt.Errorf(
			"expected BindResponse (0x61), got 0x%02X", tag)
	}

	// resultCode ENUMERATED — tag 0x0A, always present.
	codeTag, codeBytes, afterCode := readTLV(bindContent)
	if codeBytes == nil {
		return 0, "", errors.New(
			"malformed BindResponse: no resultCode")
	}
	if codeTag != 0x0A {
		return 0, "", fmt.Errorf(
			"expected ENUMERATED (0x0A) for resultCode, got 0x%02X",
			codeTag)
	}
	code := 0
	for _, b := range codeBytes {
		code = code<<8 | int(b)
	}

	// matchedDN OCTET STRING — optional, skip.
	_, _, afterMatched := readTLV(afterCode)

	// errorMessage OCTET STRING — optional.
	_, errContent, _ := readTLV(afterMatched)
	return code, string(errContent), nil
}

func readTLV(data []byte) (byte, []byte, []byte) {
	if len(data) < 2 {
		return 0, nil, nil
	}
	tag := data[0]
	l := int(data[1])
	pos := 2
	if l&0x80 != 0 {
		n := l & 0x7F
		if n > 4 || pos+n > len(data) {
			return tag, nil, nil
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(data[pos])
			pos++
		}
	}
	if pos+l > len(data) {
		return tag, data[pos:], nil
	}
	return tag, data[pos : pos+l], data[pos+l:]
}

// writeInteger appends an INTEGER TLV.
func writeInteger(buf *bytes.Buffer, v int) {
	if v < 0x80 {
		buf.WriteByte(0x02)
		buf.WriteByte(1)
		buf.WriteByte(byte(v))
		return
	}
	if v < 0x8000 {
		buf.WriteByte(0x02)
		buf.WriteByte(2)
		buf.WriteByte(byte(v >> 8))
		buf.WriteByte(byte(v))
		return
	}
	buf.WriteByte(0x02)
	buf.WriteByte(4)
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
}

// writeOctetString appends an OCTET STRING TLV.
func writeOctetString(buf *bytes.Buffer, b []byte) {
	buf.WriteByte(0x04)
	writeLength(buf, len(b))
	buf.Write(b)
}

// writeContextTag appends a [N] context-tagged OCTET STRING.
func writeContextTag(buf *bytes.Buffer, tag int, b []byte) {
	buf.WriteByte(0x80 | byte(tag))
	writeLength(buf, len(b))
	buf.Write(b)
}

// wrapTag prepends a tag and length to body.
func wrapTag(tag byte, body []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(tag)
	writeLength(&out, len(body))
	out.Write(body)
	return out.Bytes()
}

// writeLength emits a BER length field.
func writeLength(buf *bytes.Buffer, n int) {
	if n < 0x80 {
		buf.WriteByte(byte(n))
		return
	}
	if n < 0x100 {
		buf.WriteByte(0x81)
		buf.WriteByte(byte(n))
		return
	}
	buf.WriteByte(0x82)
	buf.WriteByte(byte(n >> 8))
	buf.WriteByte(byte(n))
}

func ensurePort(target, defPort string) string {
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target
	}
	return net.JoinHostPort(target, defPort)
}

func validateSSHKey(ctx context.Context, user, target,
	keyPem string) (string, string) {

	if target == "" {
		return "error",
			"ssh_key validation requires --target <host[:port]>"
	}
	if user == "" {
		user = "root"
	}
	if keyPem == "" {
		return "error", "empty SSH key"
	}

	f, err := tempFileWithKey(keyPem)
	if err != nil {
		return "error", "could not stage key: " + err.Error()
	}
	defer removeAndZero(f)

	args := []string{
		"-i", f,
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=8",
		"-o", "PreferredAuthentications=publickey",
		"-o", "IdentitiesOnly=yes",
		user + "@" + target,
		"true",
	}

	cmd := exec.CommandContext(ctx, "ssh", args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))

	if err == nil {
		return "valid",
			fmt.Sprintf("SSH public-key auth succeeded for %s@%s",
				user, target)
	}

	low := strings.ToLower(text)
	switch {
	case strings.Contains(low, "permission denied"):
		return "invalid",
			"SSH key rejected: " + firstLine(text)
	case strings.Contains(low, "connection refused"),
		strings.Contains(low, "connection timed out"),
		strings.Contains(low, "no route to host"),
		strings.Contains(low, "could not resolve"):
		return "error",
			"SSH connect failed: " + firstLine(text)
	}
	return "error",
		"ssh exited nonzero: " + firstLine(text)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func validateCertTLS(user, target, value string,
	verifyHost bool) (string, string) {

	if target == "" {
		return "error",
			"cert validation requires --target <host:port>"
	}

	cert, err := parseCertValueLinux(value)
	if err != nil {
		return "error", err.Error()
	}

	return tlsClientAuthCheckLinux(target, cert, verifyHost)
}

func parseCertValueLinux(value string) (tls.Certificate, error) {
	if strings.HasPrefix(value, "pfx:") {
		return tls.Certificate{},
			errors.New(
				"PKCS#12 (.pfx) certificates are not supported; " +
					"convert to PEM and re-store")
	}
	cert, err := tls.X509KeyPair([]byte(value), []byte(value))
	if err != nil {
		return tls.Certificate{},
			fmt.Errorf(
				"could not parse cert value as PEM (cert + key "+
					"concatenated): %v", err)
	}
	return cert, nil
}

func tlsClientAuthCheckLinux(target string,
	cert tls.Certificate, verifyHost bool) (string, string) {

	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: !verifyHost,
		MinVersion:         tls.VersionTLS12,
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", target, cfg)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "certificate") ||
			strings.Contains(msg, "handshake") {
			return "invalid",
				"TLS handshake rejected: " + msg
		}
		return "error", "TLS dial failed: " + msg
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "error",
			"handshake completed but no server certificate"
	}
	leaf := state.PeerCertificates[0]
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	if days < 0 {
		return "invalid",
			fmt.Sprintf(
				"handshake completed but server cert expired "+
					"%d days ago", -days)
	}
	return "valid",
		fmt.Sprintf(
			"TLS handshake accepted; server=%s expires=%dd",
			leaf.Subject.CommonName, days)
}

func validateBearerHTTP(user, target, value string,
	verifyHost bool) (string, string) {

	url := target
	if url == "" {
		return "error",
			"bearer validation requires --target <url>"
	}
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return "error", "could not build request: " + err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+value)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !verifyHost,
			},
		},
		CheckRedirect: func(req *http.Request,
			via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "error", "request failed: " + err.Error()
	}
	defer resp.Body.Close()
	io.CopyN(io.Discard, resp.Body, 4096)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent,
		http.StatusFound, http.StatusMovedPermanently:
		return "valid",
			fmt.Sprintf("HTTP %d from %s", resp.StatusCode, url)
	case http.StatusUnauthorized, http.StatusForbidden:
		return "invalid",
			fmt.Sprintf("HTTP %d from %s — token rejected",
				resp.StatusCode, url)
	}
	return "error",
		fmt.Sprintf("HTTP %d from %s — inconclusive",
			resp.StatusCode, url)
}

func tempFileWithKey(pem string) (string, error) {
	dir := "/dev/shm"
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		dir = "/tmp"
	}
	f, err := os.CreateTemp(dir, "tc2-ssh-")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if _, err := f.WriteString(pem); err != nil {
		f.Close()
		os.Remove(name)
		return "", err
	}
	f.Close()
	os.Chmod(name, 0o600)
	return name, nil
}

func removeAndZero(path string) {
	if info, err := os.Stat(path); err == nil {
		size := info.Size()
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			zeros := make([]byte, 4096)
			remaining := size
			for remaining > 0 {
				n := int64(len(zeros))
				if remaining < n {
					n = remaining
				}
				f.Write(zeros[:n])
				remaining -= n
			}
			f.Sync()
			f.Close()
		}
	}
	os.Remove(path)
}

func validateTicketL(value string) (string, string) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "error", "ticket is not valid base64"
	}
	if len(raw) == 0 {
		return "error", "empty ticket"
	}
	info, err := parseTicket(raw)
	if err != nil {
		return "invalid", "ticket parse failed: " + err.Error()
	}
	return formatTicketResultL(info)
}

func formatTicketResultL(info ticketInfo) (string, string) {
	id := info.Realm + "\\" + info.Server
	if info.Server == "" {
		id = info.Realm
	}
	if info.HasTimes {
		remaining := time.Until(info.EndTime)
		if remaining < 0 {
			return "expired", fmt.Sprintf(
				"%s ticket for %s expired %s ago",
				info.Format, id, (-remaining).Round(time.Second))
		}
		return "valid", fmt.Sprintf(
			"%s ticket for %s; expires in %s",
			info.Format, id, remaining.Round(time.Second))
	}
	return "valid", fmt.Sprintf(
		"%s ticket for %s; %s", info.Format, id, info.Note)
}