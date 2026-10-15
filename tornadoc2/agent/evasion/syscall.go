// No build constraint: SetSyscallMethod and syscallMethod must exist
// on every platform because main.init() calls the setter
// unconditionally. Only the Windows syscall primitives read the
// variable; on other platforms it is inert state.

package evasion

// syscallMethod records the build-time choice between "direct" and
// "indirect" syscalls. Set once at process start via
// SetSyscallMethod, read by the Windows syscall primitives in the
// same package.
//
//   "direct"   — call the ntdll stub address directly
//   "indirect" — jump to the syscall instruction inside ntdll
//
// The value has no effect on Linux; the variable is still present so
// the code compiles without build-tagged call sites.
var syscallMethod = "direct"

// SetSyscallMethod records the build-time choice of direct vs
// indirect syscalls. Called from main.init(). Unknown values fall
// back to "direct" rather than erroring — a malformed flag should
// not prevent the beacon from starting.
func SetSyscallMethod(m string) {
	switch m {
	case "indirect":
		syscallMethod = "indirect"
	case "direct", "":
		syscallMethod = "direct"
	default:
		syscallMethod = "direct"
	}
}

// SyscallMethod returns the current setting. Exported so tests and
// the syscall primitives in other files can read it without a
// package-level getter collision.
func SyscallMethod() string { return syscallMethod }