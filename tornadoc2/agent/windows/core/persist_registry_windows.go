//go:build persist_registry && windows

package core

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func init() {
	persisters["registry"] = persister{
		add: func(exe, tag string) (string, error) {
			k, err := registry.OpenKey(registry.CURRENT_USER, runKey,
				registry.SET_VALUE)
			if err != nil {
				return "", err
			}
			defer k.Close()
			name := "Tornado_" + tag
			if err := k.SetStringValue(name, quoteArg(exe)); err != nil {
				return "", err
			}
			return fmt.Sprintf("HKCU\\%s\\%s", runKey, name), nil
		},
		del: func(tag string) error {
			k, err := registry.OpenKey(registry.CURRENT_USER, runKey,
				registry.SET_VALUE)
			if err != nil {
				return err
			}
			defer k.Close()
			err = k.DeleteValue("Tornado_" + tag)
			if err == registry.ErrNotExist {
				return nil
			}
			return err
		},
	}
}
