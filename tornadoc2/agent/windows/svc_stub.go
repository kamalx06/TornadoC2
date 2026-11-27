//go:build !svc_host && windows

package main

import "tornadoc2/agent/windows/core"

func runService(_ core.Config) bool { return false }
