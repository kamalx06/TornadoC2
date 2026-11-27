//go:build linux && t_icmp

package transport

func supportsICMP() bool { return true }
