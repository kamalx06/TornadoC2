//! Worker-process pattern for `execute-assembly`.
//!
//! Replaces `worker_windows.go` + `worker_other.go`. On Windows the
//! worker spawns the current binary as a fresh process, hands it the
//! .NET assembly via environment variables and a temp file, and reads
//! back the assembly's captured output and exit code from files the
//! worker writes. On other platforms every function returns an
//! "execute-assembly is Windows-only" error.

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(not(target_os = "windows"))]
pub mod other;

#[cfg(target_os = "windows")]
pub use windows::{
    exec_assembly_out_of_process, is_worker_mode, run_worker,
};

#[cfg(not(target_os = "windows"))]
pub use other::{
    exec_assembly_out_of_process, is_worker_mode, run_worker,
};