//go:build svc_host && windows

package main

import (
	"os"
	"time"

	"golang.org/x/sys/windows/svc"

	"tornadoc2/agent/windows/core"
)

const serviceName = "TornadoAgent"

type serviceHandler struct {
	cfg core.Config
}

func (h *serviceHandler) Execute(_ []string,
	r <-chan svc.ChangeRequest,
	changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	go core.Main(h.cfg)
	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			// Give the beacon a moment to finish an in-flight
			// check-in before the SCM kills the process tree.
			time.Sleep(2 * time.Second)
			os.Exit(0)
		}
	}
	return false, 0
}

// runService reports whether it took over the process.
func runService(cfg core.Config) bool {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false
	}
	if err := svc.Run(serviceName, &serviceHandler{cfg: cfg}); err != nil {
		return false
	}
	return true
}
