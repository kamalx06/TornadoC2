//go:build !jump_wmi && windows

package core

import (
	"context"
	"fmt"
)

func jumpWMI(_ context.Context, _ *jumpSpec, _ string) (string, error) {
	return "", fmt.Errorf("jump wmi is not compiled into this agent")
}
