//go:build !windows

package platform

import (
	"context"
	"errors"
)

// IsWorkerMode always returns false on non-Windows targets.
// execute-assembly is a Windows-only verb; the worker pattern
// does not apply to Linux.
func IsWorkerMode() bool { return false }

// RunWorker is unreachable on non-Windows; core.Main only calls
// it when IsWorkerMode() is true, which never happens here. The
// function exists so the package compiles.
func RunWorker() {}

// ExecAssemblyOutOfProcess refuses on non-Windows. The verb's
// handler rejects non-Windows targets before calling this, so
// reaching here means a caller bypassed the platform gate.
func ExecAssemblyOutOfProcess(
	ctx context.Context,
	asmBytes []byte,
	argsString string,
	spawnTo string,
) (string, int, error) {
	return "", -1,
		errors.New("execute-assembly is Windows-only")
}