package protocol

import (
	"crypto/sha256"
	"encoding/hex"
)

func (i Identity) Fingerprint() string {
	h := sha256.New()
	for _, s := range []string{
		i.MachineID, i.Hostname, i.Username, i.OS,
	} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	if i.IdentityRole != "" {
		h.Write([]byte(i.IdentityRole))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}