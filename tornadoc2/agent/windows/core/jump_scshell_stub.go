//go:build !jump_scshell && windows

package core

import (
	"context"
	"fmt"
)

func jumpSCShell(_ context.Context, _ *jumpSpec, _ string) (string, error) {
	return "", fmt.Errorf("jump scshell is not compiled into this agent")
}
