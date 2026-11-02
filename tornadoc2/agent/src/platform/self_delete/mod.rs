//! Self-deletion of the running binary.
//!
//! Replaces `selfdelete_linux.go` + `selfdelete_windows.go`. Both
//! platform implementations expose `self_delete() ->
//! std::io::Result<()>`; the `#[cfg]` picks one.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub use linux::self_delete;

#[cfg(target_os = "windows")]
pub use windows::self_delete;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn self_delete() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "self_delete is not implemented on this platform",
    ))
}