//go:build !linux && !windows

package platform

import "os"

func MachineID() string {
	h, _ := os.Hostname()
	return h
}