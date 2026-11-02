//! Non-Windows worker stubs.
//!
//! Replaces `worker_other.go`. `execute-assembly` is a Windows-only
//! verb; on Linux and macOS these functions exist so the crate
//! compiles, and return a specific error at runtime.

/// Always `false` on non-Windows targets.
///
/// `execute-assembly` is a Windows-only verb; the worker pattern
/// does not apply to Linux.
pub fn is_worker_mode() -> bool {
    false
}

/// Unreachable on non-Windows.
///
/// `run_agent` only calls `run_worker` when `is_worker_mode()`
/// returns `true`, which never happens here. The function exists so
/// the module compiles.
pub fn run_worker() -> i32 {
    0
}

/// Refuse on non-Windows.
///
/// The `execute_assembly` verb handler rejects non-Windows targets
/// before calling this, so reaching here means a caller bypassed
/// the platform gate.
pub async fn exec_assembly_out_of_process(
    _asm: &[u8],
    _args: &str,
    _spawn_to: &str,
) -> Result<(String, i32), String> {
    Err("execute-assembly is Windows-only".to_string())
}