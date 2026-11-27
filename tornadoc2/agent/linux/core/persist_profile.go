//go:build persist_profile && linux

package core

import (
	"fmt"
	"os"
	"path/filepath"
)

func init() {
	persisters["profile"] = persister{
		add: func(exe, tag string) (string, error) {
			if err := validTag(tag); err != nil {
				return "", err
			}
			path := filepath.Join(profileDir(), ".profile")
			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return "", err
			}
			defer f.Close()
			_, err = fmt.Fprintf(f,
				"\n# tornado:%s\n(setsid %s >/dev/null 2>&1 &)\n", tag, exe)
			return path, err
		},
		del: func(tag string) error {
			path := filepath.Join(profileDir(), ".profile")
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			lines := string(b)
			start := "# tornado:" + tag
			i := indexOf(lines, start)
			if i < 0 {
				return nil
			}
			j := indexOf(lines[i+len(start):], "# tornado:")
			if j < 0 {
				j = len(lines)
			} else {
				j += i + len(start)
			}
			return os.WriteFile(path, []byte(lines[:i]+lines[j:]), 0600)
		},
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
