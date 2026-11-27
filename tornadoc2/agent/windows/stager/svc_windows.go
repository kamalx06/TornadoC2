//go:build svc_host && windows

package main

import (
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
)

type stagerService struct{}

func (h *stagerService) Execute(_ []string,
	r <-chan svc.ChangeRequest,
	changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	go runStager()
	changes <- svc.Status{State: svc.Running, Accepts: accepted}
	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			time.Sleep(2 * time.Second)
			os.Exit(0)
		}
	}
	return false, 0
}

func runService() bool {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false
	}
	return svc.Run("TornadoStager", &stagerService{}) == nil
}
