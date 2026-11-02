//go:build linux

package evasion

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func SandboxDetected() bool {
	score := 0

	// High confidence.
	if dmiVendorIsVM() {
		score += 3
	}
	if vmMacAddress() {
		score += 3
	}
	if hypervisorCPUFlag() {
		score += 3
	}
	if systemdDetectVirt() {
		score += 3
	}

	// Heuristics.
	if uptimeTooShort() {
		score++
	}
	if cpuCountTooLow() {
		score++
	}
	if tempFileCountTooLow() {
		score++
	}
	if suspiciousUsername() {
		score++
	}
	if suspiciousHostname() {
		score++
	}
	if lowMemory() {
		score++
	}
	if containerMarkers() {
		score++
	}

	return score >= 4
}

func dmiVendorIsVM() bool {
	files := []string{
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/board_vendor",
		"/sys/class/dmi/id/bios_vendor",
	}
	needles := []string{
		"vmware", "virtualbox", "innotek", "qemu", "kvm",
		"xen", "parallels", "bhyve", "bochs",
		"microsoft corporation", // Hyper-V
		"amazon ec2",
		"google compute engine",
		"openstack", "digitalocean",
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		val := strings.ToLower(strings.TrimSpace(string(data)))
		for _, n := range needles {
			if strings.Contains(val, n) {
				return true
			}
		}
	}
	return false
}

func vmMacAddress() bool {
	prefixes := []string{
		"00:05:69", "00:0c:29", "00:1c:14", "00:50:56", // VMware
		"08:00:27",                                     // VirtualBox
		"00:15:5d",                                     // Hyper-V
		"52:54:00",                                     // QEMU/KVM
		"00:16:3e",                                     // Xen
		"00:1c:42",                                     // Parallels
		"02:42",                                        // Docker
	}

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() == "lo" {
			continue
		}
		addr, err := os.ReadFile(
			filepath.Join("/sys/class/net", e.Name(), "address"))
		if err != nil {
			continue
		}
		mac := strings.ToLower(strings.TrimSpace(string(addr)))
		for _, p := range prefixes {
			if strings.HasPrefix(mac, p) {
				return true
			}
		}
	}
	return false
}

func hypervisorCPUFlag() bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "flags") ||
			strings.HasPrefix(line, "Features") {
			if strings.Contains(line, " hypervisor") {
				return true
			}
			break
		}
	}
	return false
}

func systemdDetectVirt() bool {
	paths := []string{
		"/usr/bin/systemd-detect-virt",
		"/bin/systemd-detect-virt",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		out, err := runCommand(p)
		if err != nil {
			return false
		}
		v := strings.ToLower(strings.TrimSpace(out))
		if v != "" && v != "none" {
			return true
		}
		return false
	}
	return false
}

func runCommand(path string) (string, error) {
	return runCommandImpl(path)
}

func runCommandImpl(path string) (string, error) {
	out, err := exec.Command(path).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func uptimeTooShort() bool {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return false
	}
	var secs float64
	if _, err := fmt.Sscanf(string(data), "%f", &secs); err != nil {
		return false
	}
	return secs < 90
}

func cpuCountTooLow() bool { return runtime.NumCPU() < 2 }

func tempFileCountTooLow() bool {
	dirs := []string{"/tmp"}
	if v := os.Getenv("TMPDIR"); v != "" {
		dirs = append(dirs, v)
	}
	count := 0
	for _, dir := range dirs {
		_ = filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !fi.IsDir() {
				count++
				if count >= 5 {
					return filepath.SkipDir
				}
			}
			return nil
		})
		if count >= 5 {
			return false
		}
	}
	return count < 5
}

func suspiciousUsername() bool {
	u := os.Getenv("USER")
	if u == "" {
		u = os.Getenv("LOGNAME")
	}
	u = strings.ToLower(u)
	if u == "" {
		return false
	}
	for _, n := range []string{
		"sandbox", "malware", "virus", "sample",
		"analyst", "cuckoo", "vmuser", "test",
	} {
		if u == n || strings.HasPrefix(u, n+"_") {
			return true
		}
	}
	return false
}

func suspiciousHostname() bool {
	h, err := os.Hostname()
	if err != nil {
		return false
	}
	l := strings.ToLower(h)
	for _, n := range []string{
		"sandbox", "malware", "cuckoo", "analysis",
		"ubuntu-", "debian-", "kali-", "user-",
	} {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

func lowMemory() bool {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		var kb uint64
		if _, err := fmt.Sscanf(line, "MemTotal: %d kB", &kb); err != nil {
			return false
		}
		gb := kb / 1048576
		return gb < 2
	}
	return false
}

func containerMarkers() bool {
	files := []string{
		"/.dockerenv",
		"/run/.containerenv",
		"/var/run/.containerenv",
	}
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := strings.ToLower(string(data))
		if strings.Contains(s, "docker") || strings.Contains(s, "lxc") {
			return true
		}
	}
	return false
}