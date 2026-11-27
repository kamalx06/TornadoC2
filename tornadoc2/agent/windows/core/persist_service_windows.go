//go:build persist_service && windows

package core

import (
	"fmt"
	"os/exec"
	"strings"
)

func init() {
	persisters["service"] = persister{
		add: func(exe, tag string) (string, error) {
			name := "Tornado_" + tag
			out, err := exec.Command("sc", "create", name,
				"binPath=", quoteArg(exe), "start=", "auto").
				CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("sc create: %v (%s)", err, out)
			}
			out, err = exec.Command("sc", "start", name).
				CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("sc start: %v (%s) — "+
					"rebuild with the svc_host tag", err, out)
			}
			// 1053 (does not report to SCM) leaves the process
			// running but the service failed; surface it.
			q, _ := exec.Command("sc", "query", name).
				CombinedOutput()
			if !strings.Contains(string(q), "RUNNING") {
				return name, fmt.Errorf("service did not reach "+
					"RUNNING: %s", strings.TrimSpace(string(q)))
			}
			return name, nil
		},
		del: func(tag string) error {
			name := "Tornado_" + tag
			_ = exec.Command("sc", "stop", name).Run()
			out, err := exec.Command("sc", "delete", name).
				CombinedOutput()
			if err != nil {
				return fmt.Errorf("sc delete: %v (%s)", err, out)
			}
			return nil
		},
	}
}
