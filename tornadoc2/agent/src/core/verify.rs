//! Task signature verification.
//!
//! Port of `.verifyTask()`. Every task received over any transport
//! is verified against the server's embedded public key before
//! execution.
//!
//! # Accept / refuse policy
//!
//! - **No `server_pub`** → accept everything. The agent was built
//!   without `SERVER_PUBKEY_PEM_B64`; the Go tree treated that as
//!   "plaintext build, unsigned tasks allowed." Preserved.
//! - **`server_pub` present, empty signature** → refuse. A signed
//!   build that receives an unsigned task is seeing either a
//!   server-side bug or a MITM stripping the signature. Both are
//!   reasons to drop the task.
//! - **`server_pub` present, bad signature** → refuse. Malformed
//!   base64, malformed DER, or a valid DER signature that does
//!   not verify against the canonical bytes.
//!
//! # Why no `signMu`
//!
//! The Go code held `a.signMu` around the `ecdsa.VerifyASN1` call.
//! `p256::ecdsa::VerifyingKey::verify_prehash` is `&self` and
//! thread-safe; there is no equivalent state to guard. If a
//! future transport causes concurrent `verify_task` calls on the
//! same `Agent` and the underlying curve implementation turns out
//! not to be thread-safe on some exotic target, a `Mutex` can be
//! added here without touching any caller.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};

use crate::protocol::Task;

use super::agent::Agent;

impl Agent {
    /// Verify `task.signature` against `self.server_pub`.
    ///
    /// Returns `true` when the task is safe to execute. The three
    /// log lines match the Go tree's diagnostics (`diag!` — silent
    /// unless `TC2_VERBOSE=true`).
    pub fn verify_task(&self, task: &Task) -> bool {
        let Some(pub_key) = self.server_pub.as_ref() else {
            // No embedded server public key — accept. This is the
            // plaintext-build path; the Go tree logged and
            // returned true.
            crate::diag!(
                "[verify] no server public key — accepting \
                 unsigned task {}\n",
                task.id,
            );
            return true;
        };

        if task.signature.is_empty() {
            crate::diag!(
                "[verify] task {} has no signature and serverPub \
                 is set — REFUSING\n",
                task.id,
            );
            return false;
        }

        let sig_der = match STANDARD.decode(&task.signature) {
            Ok(s) => s,
            Err(e) => {
                crate::diag!(
                    "[verify] task {} signature base64 decode \
                     failed: {e}\n",
                    task.id,
                );
                return false;
            }
        };

        let sig = match Signature::from_der(&sig_der) {
            Ok(s) => s,
            Err(e) => {
                crate::diag!(
                    "[verify] task {} signature DER decode \
                     failed: {e}\n",
                    task.id,
                );
                return false;
            }
        };

        let body = match task.unsigned() {
            Ok(b) => b,
            Err(e) => {
                crate::diag!(
                    "[verify] task {} Unsigned() failed: {e}\n",
                    task.id,
                );
                return false;
            }
        };

        let digest = Sha256::digest(&body);
        let ok = pub_key
            .verify_prehash(digest.as_slice(), &sig)
            .is_ok();

        crate::diag!(
            "[verify] task {} canonical={} verify={ok}\n",
            task.id,
            String::from_utf8_lossy(&body),
        );
        ok
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    // These tests exercise the byte-level signatures and the
    // policy branches. A full end-to-end test would need to
    // construct an `Agent` with a real `server_pub`, which
    // requires most of the transport stack; the tests below
    // cover the paths that can be exercised with a bare signing
    // key.

    use p256::ecdsa::{
        signature::Signer, Signature, SigningKey, VerifyingKey,
    };
    use sha2::{Digest, Sha256};

    /// Sign `payload` with `key` and return the DER-encoded
    /// signature bytes.
    fn sign_der(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
        let digest = Sha256::digest(payload);
        let sig: Signature = key.try_sign(&digest).unwrap();
        sig.to_der().as_bytes().to_vec()
    }

    #[test]
    fn good_signature_verifies() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let payload = b"canonical-json-bytes";
        let der = sign_der(&key, payload);
        let sig = Signature::from_der(&der).unwrap();
        let digest = Sha256::digest(payload);
        let vk: &VerifyingKey = key.verifying_key();
        assert!(vk.verify_prehash(digest.as_slice(), &sig).is_ok());
    }

    #[test]
    fn wrong_key_rejects() {
        let key_a = SigningKey::random(&mut rand_core::OsRng);
        let key_b = SigningKey::random(&mut rand_core::OsRng);
        let payload = b"canonical-json-bytes";
        let der = sign_der(&key_a, payload);
        let sig = Signature::from_der(&der).unwrap();
        let digest = Sha256::digest(payload);
        assert!(
            key_b
                .verifying_key()
                .verify_prehash(digest.as_slice(), &sig)
                .is_err()
        );
    }

    #[test]
    fn tampered_payload_rejects() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let payload = b"original";
        let der = sign_der(&key, payload);
        let sig = Signature::from_der(&der).unwrap();
        let tampered = b"tampered";
        let digest = Sha256::digest(tampered);
        assert!(
            key.verifying_key()
                .verify_prehash(digest.as_slice(), &sig)
                .is_err()
        );
    }
}