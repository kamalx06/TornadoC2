//! In-process shellcode execution.
//!
//! Replaces `shellcode_exec_other.go` and
//! `shellcode_exec_windows.go`. The public function is
//! `exec_shellcode_windows(b64, wait_secs)` on every target; on
//! non-Windows it returns a specific error, matching the Go
//! tree's behaviour.

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "windows")]
pub use windows::exec_shellcode_windows;

#[cfg(not(target_os = "windows"))]
pub async fn exec_shellcode_windows(
    _b64: &str,
    _wait_secs: i32,
) -> Result<(String, i32), String> {
    Err("shellcode execution requires a Windows target".to_string())
}