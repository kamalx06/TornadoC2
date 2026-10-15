//go:build !windows

package evasion

import "errors"

func PPIDSpoof() (bool, error) {
	return false, errors.New("ppid spoof not supported on this platform")
}