//go:build !linux && !windows

package native

import (
	"context"
	"errors"
)

func execELFInMemory(_ context.Context, _ string,
	_ []string) (string, int, error) {
	return "", -1,
		errors.New("elf in-memory execution not implemented on this platform")
}

func execPEInMemory(_ context.Context, _ string,
	_ []string) (string, int, error) {
	return "", -1,
		errors.New("pe in-memory execution requires Windows")
}

func execBOF(_ context.Context, _ []byte,
	_ string, _ []byte) (string, int, error) {
	return "", -1,
		errors.New("BOF execution requires a Windows target")
}