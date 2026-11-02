//go:build !windows

package core

import (
	"context"
	"errors"
)

type winHandle = uintptr

func closeStolenTokenOnExit() {}

func hasStolenToken() bool { return false }

func getStolenToken() (winHandle, string) { return 0, "" }

func execWithStolenToken(_ context.Context, _ string,
	_ []string) (string, int, error) {
	return "", -1, errors.New("token impersonation requires Windows")
}

func (a *Agent) stealTokenVerb(_ context.Context, t Task) Result {
	return Result{ID: t.ID,
		Error: "steal_token requires a Windows target"}
}