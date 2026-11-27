//go:build !jump_winrm && windows

package core

import (
	"context"
	"fmt"
)

func jumpWinRM(_ context.Context, _ *jumpSpec, _ string) (string, error) {
	return "", fmt.Errorf("jump winrm is not compiled into this agent")
}
