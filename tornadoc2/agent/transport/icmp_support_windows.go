//go:build windows && t_icmp

package transport

func supportsICMP() bool { return false }
