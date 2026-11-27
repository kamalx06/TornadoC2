//go:build ev_stackspoof && windows && amd64

package spoof

const available = true

//go:noescape
func spoofCall(p *args)
