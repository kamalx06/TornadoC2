//go:build !jump_psexec && windows

package core

import (
	"context"
	"fmt"
)

func jumpPsexec(_ context.Context, _ *jumpSpec, _ string) (string, error) {
	return "", fmt.Errorf("jump psexec is not compiled into this agent")
}
