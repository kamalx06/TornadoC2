//go:build linux

package platform

import (
	"context"
	"errors"
)

func ExecShellcodeWindows(_ context.Context,
	_ string, _ int) (string, int, error) {
	return "", -1, errors.New(
		"shellcode execution requires a Windows target")
}