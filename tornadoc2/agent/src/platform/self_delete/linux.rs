//! Self-deletion on Linux.
//!
//! Replaces `selfdelete_linux.go`. Unlinking the running binary
//! is safe on Linux: the kernel keeps the inode alive until the
//! last fd (including the executable mapping) is released, so
//! the process continues running normally after this returns.

use std::fs;

/// Delete the running binary.
///
/// Tries `/proc/self/exe` first; falls back to
/// [`std::env::current_exe`]. The `/proc` path is preferred
/// because it resolves to the actual inode even if the binary has
/// been renamed, hardlinked, or is running from a memfd.
///
/// # Errors
///
/// - `NotFound` — neither `/proc/self/exe` nor `current_exe`
///   produced a path (extremely unlikely on Linux).
/// - Anything else from `remove_file` — a permissions issue, or
///   the binary lives on a filesystem that refuses `unlink` on a
///   running executable.
pub fn self_delete() -> std::io::Result<()> {
    let exe = match fs::read_link("/proc/self/exe") {
        Ok(p) => p,
        Err(_) => std::env::current_exe()?,
    };
    fs::remove_file(exe)
}

#[cfg(test)]
mod tests {
    // A meaningful test would delete the test binary, which
    // would break the test runner. Instead, test the path
    // resolution logic in isolation.

    #[test]
    fn proc_self_exe_resolves() {
        let p = std::fs::read_link("/proc/self/exe").unwrap();
        assert!(p.exists());
    }

    #[test]
    fn current_exe_agrees_with_proc() {
        let a = std::fs::read_link("/proc/self/exe").unwrap();
        let b = std::env::current_exe().unwrap();
        // Both should resolve to the same inode (allowing for
        // symlink canonicalization).
        assert_eq!(
            std::fs::canonicalize(&a).unwrap(),
            std::fs::canonicalize(&b).unwrap(),
        );
    }
}