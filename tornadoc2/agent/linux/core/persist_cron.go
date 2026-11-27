//go:build persist_cron && linux

package core

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func init() {
	persisters["cron"] = persister{
		add: func(exe, tag string) (string, error) {
			if err := validTag(tag); err != nil {
				return "", err
			}
			out, _ := exec.Command("crontab", "-l").Output()
			line := fmt.Sprintf("@reboot %s # tornado:%s", exe, tag)
			body := strings.TrimRight(string(out), "\n")
			if body != "" {
				body += "\n"
			}
			body += line + "\n"
			cmd := exec.Command("crontab", "-")
			cmd.Stdin = strings.NewReader(body)
			if err := cmd.Run(); err != nil {
				return "", err
			}
			return "crontab", nil
		},
		del: func(tag string) error {
			out, _ := exec.Command("crontab", "-l").Output()
			var keep []string
			for _, l := range strings.Split(string(out), "\n") {
				if !strings.Contains(l, "# tornado:"+tag) &&
					l != "" {
					keep = append(keep, l)
				}
			}
			cmd := exec.Command("crontab", "-")
			cmd.Stdin = strings.NewReader(strings.Join(keep, "\n") + "\n")
			return cmd.Run()
		},
	}
}

var _ = os.Getenv
