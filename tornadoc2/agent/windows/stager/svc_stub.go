//go:build !svc_host && windows

package main

func runService() bool { return false }
