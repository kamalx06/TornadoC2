//go:build linux

package platform

import "os"

func SelfDelete() error {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		exe, err = os.Executable()
		if err != nil {
			return err
		}
	}
	return os.Remove(exe)
}