//! Self-deletion on Windows.
//!
//! Replaces `selfdelete_windows.go`. Windows refuses to unlink a
//! file that is mapped into a running process — the running image
//! holds an implicit handle to the executable. The delete-on-close
//! flag is the workaround: open the binary with
//! `FILE_FLAG_DELETE_ON_CLOSE`, do **not** close the handle, and
//! Windows deletes the file when the last handle (including the
//! image-mapping handle held by the kernel) closes at process
//! exit.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_FLAG_DELETE_ON_CLOSE, FILE_SHARE_DELETE,
    FILE_SHARE_READ, GENERIC_READ, OPEN_EXISTING,
};

/// Delete the running binary at process exit.
///
/// Opens the executable with `FILE_FLAG_DELETE_ON_CLOSE` and
/// leaves the handle open. The file survives until the last
/// handle closes, which happens when the process exits.
///
/// # Errors
///
/// - `current_exe` failure — unlikely on Windows.
/// - `CreateFileW` failure — typically a permissions issue, or
///   the executable lives on a read-only volume.
pub fn self_delete() -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle: HANDLE = unsafe {
        CreateFileW(
            wide.as_ptr(),
            // GENERIC_READ | DELETE — the DELETE access right
            // is required for FILE_FLAG_DELETE_ON_CLOSE to take
            // effect.
            GENERIC_READ | DELETE,
            // FILE_SHARE_READ | FILE_SHARE_DELETE — required so
            // the image mapping's own handle does not conflict.
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_DELETE_ON_CLOSE,
            std::ptr::null_mut() as *mut c_void,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    // Deliberately do not call CloseHandle. The handle must stay
    // open until the process exits; Windows fires the
    // delete-on-close flag when the last handle to the file
    // closes. The kernel's image-mapping handle keeps the file
    // alive until then regardless, but our handle is what
    // *requests* the deletion.
    Ok(())
}