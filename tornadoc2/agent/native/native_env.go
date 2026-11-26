package native

import (
	"os"
	"strings"
)

// stripChildEnv removes variables that describe the operator's
// session rather than the target environment.
func stripChildEnv(e string) bool {
	for _, p := range []string{
		"HISTFILE=", "HISTSIZE=", "HISTFILESIZE=",
		"HISTCONTROL=", "HISTIGNORE=", "HISTTIMEFORMAT=",
		"GODEBUG=", "GOTRACEBACK=", "GOCOVERDIR=",
		"OLDPWD=", "PWD=", "SHLVL=", "_=",
		"TERM_PROGRAM=", "WT_SESSION=", "TMUX=", "STY=",
		"SSH_CONNECTION=", "SSH_CLIENT=", "SSH_TTY=",
		"XDG_SESSION_TYPE=", "XDG_CURRENT_DESKTOP=",
		"DESKTOP_SESSION=",
	} {
		if strings.HasPrefix(e, p) {
			return true
		}
	}
	return false
}

func sanitizedEnv() []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+5)
	for _, e := range base {
		if stripChildEnv(e) {
			continue
		}
		out = append(out, e)
	}
	out = append(out,
		"HISTFILE=/dev/null",
		"HISTSIZE=0",
		"HISTFILESIZE=0",
		"HISTCONTROL=ignorespace",
		"HISTIGNORE=*",
		"HISTTIMEFORMAT=",
	)
	return out
}
