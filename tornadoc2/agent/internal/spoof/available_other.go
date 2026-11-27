//go:build !(ev_stackspoof && windows && amd64)

package spoof

const available = false

func spoofCall(_ *args) {}
