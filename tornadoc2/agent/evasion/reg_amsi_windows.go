//go:build ev_amsi && windows

package evasion

func init() { amsiFn = func() error { return PatchAMSIWithMethod(AMSIBoth) } }
