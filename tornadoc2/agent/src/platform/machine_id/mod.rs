//! Machine identifier.
//!
//! One function per target family:
//!
//! - **Linux** — `/etc/machine-id`, falling back to
//!   `/var/lib/dbus/machine-id`.
//! - **Windows** — `reg query HKLM\SOFTWARE\Microsoft\Cryptography
//!   /v MachineGuid`, parsed out of the tool's stdout.
//! - **Everywhere else** — the OS hostname.
//!
//! Every branch returns an empty `String` on failure. The caller
//! mixes this value into the session fingerprint, and the server
//! has always accepted an empty machine id — it just means two
//! hosts of the same "unknown machine" class share a fingerprint
//! until a real id is available. Preserving the empty-on-failure
//! contract is what keeps the Rust port wire-compatible with the
//! Go tree during any mixed-fleet window.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::machine_id;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::machine_id;

// ---------------------------------------------------------------------
// Fallback: every target that is neither Linux nor Windows.
//
// In practice this is macOS and the BSDs — both unix — plus the
// non-unix targets the crate does not officially ship for (WASI,
// bare metal). The unix branch calls `gethostname(2)`, which is
// what Go's `os.Hostname()` calls on the same platforms, so the
// value is identical to the Go tree's.
// ---------------------------------------------------------------------

/// Return this machine's identifier on any target that is not
/// Linux or Windows.
///
/// # Return value
///
/// The OS hostname on success; an empty `String` when the hostname
/// cannot be read. Matches `os.Hostname()` in the Go tree, which
/// returns `""` and a non-nil error and is treated by the Go
/// caller as an empty identifier.
///
/// # Cargo feature note
///
/// `nix::unistd::gethostname` requires the `hostname` feature on
/// `nix 0.29`. The Linux and Windows agent builds do not compile
/// this branch and do not need the feature. To build for macOS,
/// the BSDs, or any other unix that is not Linux, add `"hostname"`
/// to the `nix` features list in `Cargo.toml`:
///
/// ```toml
/// nix = { version = "0.29", features = [..., "hostname"] }
/// ```
///
/// The alternative is `libc::gethostname`, which would require
/// `libc` on `cfg(unix)` rather than the current
/// `cfg(target_os = "linux")`. Either change is one line; pick
/// whichever is more convenient when macOS support is enabled.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn machine_id() -> String {
    #[cfg(unix)]
    {
        // `gethostname` writes the name into a caller-provided
        // buffer; nix owns the buffer and returns an `OsString`.
        // The `to_string_lossy` conversion matches the
        // "whatever bytes the OS gave us" spirit of Go's
        // `os.Hostname()` — a non-UTF-8 hostname (rare but legal)
        // becomes a string with replacement characters rather
        // than an empty result.
        match nix::unistd::gethostname() {
            Ok(name) => name.to_string_lossy().into_owned(),
            Err(_) => String::new(),
        }
    }

    #[cfg(not(unix))]
    {
        // No `gethostname` on non-unix targets. WASI and bare
        // metal do not ship an agent; the env-var fallback exists
        // only so `cargo check --target <non-unix>` does not
        // fail. Returns empty when `HOSTNAME` is unset, which is
        // the same "unknown machine" signal every other failure
        // path produces.
        std::env::var("HOSTNAME").unwrap_or_default()
    }
}