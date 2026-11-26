//go:build windows

package core

import (
	"fmt"
	"strings"
)

const (
	platformName     = "windows"
	isWindows        = true
	supportsICMP     = false
	supportsTokens   = true
	supportsAssembly = true
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
)

func shellCommand(command string) (string, []string, string) {
	return "cmd.exe", []string{"/Q"}, command + "\n"
}

func shellScript(src string, args []string) (string, []string, string) {
	var preamble strings.Builder
	if len(args) > 0 {
		for i, arg := range args {
			if i >= 9 {
				break
			}
			safe := strings.ReplaceAll(arg, "%", "%%")
			fmt.Fprintf(&preamble, "set \"%d=%s\"\n", i+1, safe)
		}
	}
	return "cmd.exe", []string{"/Q"}, preamble.String() + src
}
