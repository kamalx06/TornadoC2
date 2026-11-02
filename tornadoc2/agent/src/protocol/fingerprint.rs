//! Session fingerprint.
//!
//! Port of `protocol/fingerprint.go`. The fingerprint is
//! `hex(SHA-256(machine_id || 0 || hostname || 0 || username
//! || 0 || os || 0))[..32]`. If `identity_role` is non-empty,
//! it is appended the same way before the hash.
//!
//! # Why the role is conditional
//!
//! The fingerprint is the key the server uses to look up a
//! session. Two agents built from the same tree, run on the
//! same host under the same user, report identical
//! `machine_id` / `hostname` / `username` / `os` tuples and
//! would otherwise collide on one session. The role gives each
//! its own. An agent built without a role reproduces the
//! pre-role fingerprint exactly, so deployed sessions are not
//! invalidated by the field's existence.
//!
//! # Truncation
//!
//! The Go tree truncates to 32 hex characters (16 bytes),
//! accepting a 128-bit collision budget over the full 256-bit
//! digest. The Rust port preserves the truncation — the server
//! compares fingerprints as strings and does not care about
//! the underlying length.

use sha2::{Digest, Sha256};

use super::Identity;

impl Identity {
    /// Compute this identity's session fingerprint.
    ///
    /// The result is 32 lowercase hex characters. Two
    /// identities with the same `machine_id`, `hostname`,
    /// `username`, `os`, and `identity_role` produce the same
    /// fingerprint; any difference in any of those five fields
    /// produces a different one with overwhelming probability.
    ///
    /// The signature and timestamp from the check-in are
    /// deliberately excluded — they are per-check-in values,
    /// not per-machine. A new check-in from the same machine
    /// arrives at the same fingerprint.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        for s in [
            &self.machine_id,
            &self.hostname,
            &self.username,
            &self.os,
        ] {
            h.update(s.as_bytes());
            h.update([0u8]);
        }
        if !self.identity_role.is_empty() {
            h.update(self.identity_role.as_bytes());
            h.update([0u8]);
        }
        let digest = h.finalize();
        // 32 hex chars = 16 bytes of the digest.
        hex::encode(digest)[..32].to_string()
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Identity {
        Identity {
            machine_id: "mid".to_string(),
            hostname: "host".to_string(),
            username: "user".to_string(),
            os: "linux".to_string(),
            arch: "amd64".to_string(),
            proto: 1,
            kill_days: 30,
            work_start: 480,
            work_end: 1140,
            ..Default::default()
        }
    }

    #[test]
    fn fingerprint_is_32_hex_chars() {
        let fp = base().fingerprint();
        assert_eq!(fp.len(), 32);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = base().fingerprint();
        let b = base().fingerprint();
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_changes_with_any_base_field() {
        let baseline = base().fingerprint();
        for mutate in [
            |i: &mut Identity| i.machine_id = "other".to_string(),
            |i: &mut Identity| i.hostname = "other".to_string(),
            |i: &mut Identity| i.username = "other".to_string(),
            |i: &mut Identity| i.os = "windows".to_string(),
        ] {
            let mut i = base();
            mutate(&mut i);
            assert_ne!(
                i.fingerprint(),
                baseline,
                "mutation should change the fingerprint"
            );
        }
    }

    #[test]
    fn fingerprint_changes_when_role_set() {
        let without = base().fingerprint();
        let mut with = base();
        with.identity_role = "smb-child".to_string();
        assert_ne!(with.fingerprint(), without);
    }

    #[test]
    fn fingerprint_unchanged_by_other_fields() {
        // arch, proto, kill_days, work hours, stager, and
        // local_addr are not part of the fingerprint.
        let mut i = base();
        let baseline = i.fingerprint();
        i.arch = "arm64".to_string();
        i.proto = 2;
        i.kill_days = 1;
        i.work_start = 0;
        i.work_end = 0;
        i.stager = true;
        i.local_addr = "10.0.0.1:5555".to_string();
        assert_eq!(i.fingerprint(), baseline);
    }

    #[test]
    fn fingerprint_empty_role_matches_never_set() {
        // The "no role" path is the same whether the field was
        // never assigned or explicitly cleared.
        let a = base().fingerprint();
        let mut b = base();
        b.identity_role = String::new();
        assert_eq!(a, b.fingerprint());
    }
}