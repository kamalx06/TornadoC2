//go:build !linux && !windows

package main

import "errors"

func executeInMemory(_ []byte) error {
	return errors.New("stager not supported on this platform")
}