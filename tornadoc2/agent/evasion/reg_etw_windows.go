//go:build ev_etw && windows

package evasion

func init() { etwFn = func() error { return PatchETWWithMethod(ETWAll) } }
