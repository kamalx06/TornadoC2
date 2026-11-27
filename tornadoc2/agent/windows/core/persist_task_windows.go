//go:build persist_task && windows

package core

import (
	"fmt"
	"os/exec"
	"strings"
)

const taskPrefix = `\Tornado\`

func init() {
	persisters["task"] = persister{
		add: func(exe, tag string) (string, error) {
			name := taskPrefix + tag
			args := []string{"/create", "/f", "/tn", name,
				"/tr", quoteArg(exe), "/rl", "highest",
				"/sc", "onlogon"}
			if strings.HasSuffix(tag, ":system") {
				name = strings.TrimSuffix(name, ":system")
				args = []string{"/create", "/f", "/tn", name,
					"/tr", quoteArg(exe), "/ru", "SYSTEM",
					"/rl", "highest", "/sc", "onstart"}
			}
			out, err := exec.Command("schtasks", args...).
				CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("schtasks: %v (%s)", err, out)
			}
			return name, nil
		},
		del: func(tag string) error {
			name := strings.TrimSuffix(taskPrefix+tag, ":system")
			out, err := exec.Command("schtasks", "/delete", "/f",
				"/tn", name).CombinedOutput()
			if err != nil {
				return fmt.Errorf("schtasks: %v (%s)", err, out)
			}
			return nil
		},
	}
}
