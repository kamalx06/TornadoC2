package native

import (
	"os"
	"strings"
)

func sanitizedEnv() []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+5)
	for _, e := range base {
		if strings.HasPrefix(e, "HISTFILE=") ||
			strings.HasPrefix(e, "HISTSIZE=") ||
			strings.HasPrefix(e, "HISTFILESIZE=") ||
			strings.HasPrefix(e, "HISTCONTROL=") ||
			strings.HasPrefix(e, "HISTIGNORE=") ||
			strings.HasPrefix(e, "HISTTIMEFORMAT=") {
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