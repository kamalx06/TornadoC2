//go:build !windows

package core

import (
	"crypto/ecdsa"
	"errors"
)

// smbRelay is the non-Windows stub for the SMB pivot listener.
// The real implementation lives in smb_relay_windows.go; that file
// is compiled only for GOOS=windows. On Linux this package still
// needs the type, the constructor, and the methods that main.go
// calls, so the code compiles against the same symbol names.
type smbRelay struct{}

// newSMBRelay mirrors the Windows signature. The two-value return
// is what main.go expects; the Linux path never reaches a working
// relay because SMB requires a Windows parent.
func newSMBRelay(parent *Agent, pipeName string,
	pivotPrivKey *ecdsa.PrivateKey) (*smbRelay, error) {

	return nil, errors.New(
		"smb pivot requires a Windows parent")
}

// start mirrors the Windows method so main.go's call site is the
// same on both platforms. On Linux this is never reached — the
// constructor above returns before start() is called.
func (r *smbRelay) start() error {
	return errors.New("smb pivot requires a Windows parent")
}