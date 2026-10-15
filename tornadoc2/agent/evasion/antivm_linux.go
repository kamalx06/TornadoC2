//go:build linux

package evasion

import (
	"os"
	"strings"
)

func InVM() bool {
	score := 0

	// High confidence
	if dmiVendorIsHypervisor() {
		score += 3
	}
	if cpuinfoHypervisorFlag() {
		score += 3
	}
	if systemdDetectVirt() {
		score += 3
	}

	// Medium confidence
	if vmMacAddress() {
		score += 2
	}
	if hypervisorKernelModules() {
		score += 2
	}

	// Weak confidence
	if vmAgentBinaries() {
		score++
	}
	if vmSpecificPaths() {
		score++
	}

	return score >= 4
}

func dmiVendorIsHypervisor() bool {
	files := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor",
		"/sys/class/dmi/id/bios_vendor",
	}
	markers := []string{
		"vmware",
		"virtualbox", "innotek", "vbox",
		"qemu", "kvm",
		"xen", "xensource",
		"bochs",
		"parallels",
		"bhyve",
		"amazon ec2",
		"google compute engine",
		"digitalocean",
		"openstack",
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(string(data)))
		for _, m := range markers {
			if strings.Contains(lower, m) {
				return true
			}
		}
	}
	return false
}

func cpuinfoHypervisorFlag() bool {
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

func hypervisorKernelModules() bool {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	needles := []string{
		"vmw_", "vmxnet", "vmwgfx",
		"vboxguest", "vboxsf", "vboxvideo",
		"virtio_", "virito_pci",
		"xen_blk", "xen_net", "xennet",
		"hv_", "hyperv",
	}
	lower := strings.ToLower(string(data))
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

func vmAgentBinaries() bool {
	paths := []string{
		"/usr/bin/vmtoolsd",
		"/usr/bin/vmware-user-suid-wrapper",
		"/usr/sbin/vboxadd",
		"/usr/bin/VBoxClient",
		"/usr/sbin/xe-daemon",
		"/usr/bin/qemu-ga",
		"/usr/sbin/qemu-ga",
		"/usr/bin/hv_kvp_daemon",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func vmSpecificPaths() bool {
	paths := []string{
		"/proc/xen",
		"/sys/hypervisor",
		"/sys/bus/virtio",
		"/sys/module/vboxguest",
		"/sys/module/vmw_vmci",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}