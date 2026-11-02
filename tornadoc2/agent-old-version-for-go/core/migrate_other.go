//go:build !linux && !windows

package core

import "errors"

func spawnDetached(exePath, readyPath string) (int, error) {
	return 0, errors.New(
		"migrate is not implemented on this platform")
}