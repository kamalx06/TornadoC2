//! Windows machine identifier.
//!
//! Reads `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` by
//! shelling out to `reg.exe`. Using the CLI rather than the
//! `windows` crate's registry APIs keeps the module tiny and
//! matches the Go tree; a `MachineGuid` read is a one-shot
//! operation at agent start, not a hot path, so the `CreateProcess`
//! cost is invisible.
//!
//! # Output format
//!
//! `reg query <key> /v <value>` prints three lines:
//!
//! ```text
//! \r\n
//! HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n
//!     MachineGuid    REG_SZ    xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\r\n
//! \r\n
//! ```
//!
//! The GUID is the last whitespace-separated field on the line
//! that mentions `MachineGuid`. Parsing is defensive: any line
//! containing `MachineGuid` with at least three whitespace-
//! separated fields yields the last field, so a change in
//! `reg.exe` formatting that only adds a column does not break
//! the read.

use std::process::Command;

/// Return this machine's identifier.
///
/// Runs `reg query HKLM\SOFTWARE\Microsoft\Cryptography /v
/// MachineGuid` and returns the GUID from the `MachineGuid` row.
///
/// # Return value
///
/// A GUID string on success; an empty `String` when `reg.exe` is
/// missing, the registry key is unreadable, the command exits
/// non-zero, or the output does not contain a parseable row.
/// Every failure mode collapses to the empty string; the caller
/// treats empty as "unknown machine" and continues.
pub fn machine_id() -> String {
    let output = match Command::new("reg")
        .args([
            "query",
            // Raw string so the two backslashes in the key path
            // survive without escaping.
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
    {
        Ok(o) => o,
        // `reg.exe` is a standard `System32` binary on every
        // supported Windows target; a missing binary means
        // something is deeply broken about the host and there is
        // nothing useful the agent can do from here.
        Err(_) => return String::new(),
    };

    // `reg.exe` exits non-zero when the key or the value does
    // not exist. Go's `cmd.Output()` maps that to an error the
    // caller ignored; match the behaviour by bailing.
    if !output.status.success() {
        return String::new();
    }

    // `from_utf8_lossy` on the assumption that `reg.exe` output
    // is ASCII on any locale — the GUID is always ASCII and the
    // surrounding tokens (`REG_SZ`, `MachineGuid`) are ASCII
    // regardless of the console code page. A non-UTF-8 byte in
    // the output would only come from an unexpected value name,
    // and replaces to U+FFFD rather than aborting the scan.
    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines() {
        if !line.contains("MachineGuid") {
            continue;
        }

        // `split_whitespace` splits on any run of Unicode
        // whitespace including `\r`, so `\r\n` line endings are
        // handled without a separate strip. Go's `strings.Fields`
        // behaves the same way. A well-formed output produces
        // three fields (`MachineGuid`, `REG_SZ`, `<guid>`); a
        // future format change that adds columns still yields
        // the GUID as the last field.
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 {
            return fields[fields.len() - 1].to_string();
        }
    }

    String::new()
}