//! Linux machine identifier.
//!
//! Reads `/etc/machine-id` and falls back to
//! `/var/lib/dbus/machine-id` — the same two paths, in the same
//! order, as the Go tree. Both are world-readable files written by
//! `systemd-machine-id-setup` and `dbus-uuidgen` respectively, and
//! both hold a 32-character lowercase-hex string on every modern
//! distro. The two are supposed to hold the same value; when they
//! diverge (rare, usually a systemd install that skipped the
//! `machine-id` migration), the first path wins.

/// Return this machine's identifier.
///
/// Tries `/etc/machine-id` first, then `/var/lib/dbus/machine-id`.
/// Trims surrounding whitespace. Skips a path when it is
/// unreadable, non-UTF-8, or empty after trimming, and falls
/// through to the next.
///
/// # Return value
///
/// A non-empty lowercase-hex string on success; an empty `String`
/// when neither path yields a value. Callers mix the result into
/// the session fingerprint and treat empty as "unknown machine".
pub fn machine_id() -> String {
    // Order matters. `systemd`'s `/etc/machine-id` is the
    // canonical source on every distro that has one; the D-Bus
    // file is a legacy mirror that may lag behind or be absent
    // when `/etc/machine-id` is not. Reversing the order would
    // return a stale value on a host mid-migration.
    const PATHS: &[&str] = &["/etc/machine-id", "/var/lib/dbus/machine-id"];

    for path in PATHS {
        // `std::fs::read` returns `Err` for a missing or
        // unreadable file; skip and try the next path. A partial
        // read is impossible — `read` either returns the whole
        // file or errors.
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Machine-id files are ASCII hex; the UTF-8 check is
        // defensive. A file that fails it is almost certainly
        // corrupt or foreign, so try the next path rather than
        // propagate garbage into the fingerprint. Go's
        // `strings.TrimSpace(string(b))` would silently accept
        // invalid UTF-8 here (Go strings are byte sequences); we
        // are stricter, and the difference only shows up on a
        // corrupt file, where the Go behaviour would have been
        // wrong anyway.
        let text = match std::str::from_utf8(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // `str::trim` trims Unicode whitespace. On an ASCII hex
        // file this is exactly the set `strings.TrimSpace` trims
        // in the Go tree — trailing newline is the common case,
        // leading whitespace is rare but legal.
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    String::new()
}