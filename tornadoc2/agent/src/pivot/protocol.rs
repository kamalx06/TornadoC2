//! Pivot protocol primitives.
//!
//! Replaces `internal/pivot/protocol.go`. The public surface is:
//! the two version constants, the three message structs, the
//! `FrameIO` trait, and the crypto helpers (`sign_payload`,
//! `verify_signature`, `derive_session`, `within_skew`).
//!
//! # Two versions, on independent axes
//!
//! **Wire version** — `PIVOT_VERSION = "v2"`. Appears in the
//! `pivot` field of the hello and ack, and in the signing
//! payload domain separators (`tornadoc2-pivot-child-v2|…`,
//! `tornadoc2-pivot-parent-v2|…`). A change to the framing bumps
//! this.
//!
//! **KDF info** — `HKDF_INFO = "tornadoc2-pivot-v1"`. Used as the
//! HKDF info string. A change to the key derivation (different
//! hash, different expansion layout) bumps this without touching
//! the wire version, and vice versa. The two axes move
//! independently by design.
//!
//! ⚠️ **The README claims `HKDF_INFO` is `v2`.** The Go source
//! says `v1`. The Go source is authoritative for wire
//! compatibility — every deployed pivot parent and child uses
//! `v1` for HKDF. This port preserves `v1`. Fixing the Go code
//! to `v2` is a fleet-wide rebuild of every parent and child; not
//! something a port can do unilaterally.
//!
//! # The parent's ECDH contribution
//!
//! The client's ECDH is `epk_priv × ack.epk`, i.e., between the
//! child's ephemeral and the *parent's* value in the ack. Whether
//! `ack.epk` is the parent's fresh ephemeral or the static pivot
//! public key is a server-side decision, not a client-side one.
//! The client uses it for ECDH regardless, so it is wire-compatible
//! with either.
//!
//! The README says the parent uses its **static pivot public key**
//! in `ack.epk`, which would give ECDHE on the child side and
//! plain ECDH on the parent side, and no forward secrecy. If the
//! parent sends a fresh ephemeral instead, the handshake has
//! forward secrecy on both sides. The port does not decide — the
//! parent's `server.rs` will. The client does not care.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use p256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::session::{Role, Session};

// =====================================================================
// Constants
// =====================================================================

/// Wire version, sent in the `pivot` field of the hello and ack
/// and embedded in the signing payload domain separators.
pub const PIVOT_VERSION: &str = "v2";

/// HKDF info string. **See module doc — this is `v1`, not `v2`.**
pub const HKDF_INFO: &[u8] = b"tornadoc2-pivot-v1";

/// Handshake timestamp skew window, in seconds. Matches the Go
/// tree's `TimestampSkew = 300 * time.Second`.
pub const TIMESTAMP_SKEW_SECS: i64 = 300;

/// Maximum pivot frame body, enforced by the frame reader. Matches
/// the Go tree's 16 MiB cap (documented in the README, not in
/// `protocol.go`; the frame layer in `session.go` enforces it).
pub const MAX_FRAME_BODY: usize = 16 * 1024 * 1024;

// =====================================================================
// Errors
// =====================================================================

#[derive(Debug, thiserror::Error)]
pub enum PivotError {
    #[error("pivot: {0}")]
    Protocol(String),
    #[error("pivot io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pivot json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("pivot base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("pivot crypto: {0}")]
    Crypto(String),
    #[error("pivot version mismatch: got {got:?}, want {want:?}")]
    VersionMismatch { got: String, want: &'static str },
    #[error("pivot timestamp outside {0} s window")]
    Skew(i64),
    #[error("pivot parent refused: {0}")]
    Refused(String),
}

// =====================================================================
// Message types
// =====================================================================

/// Child → parent hello.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloMsg {
    /// Wire version. Field name on the wire is `pivot`.
    #[serde(rename = "pivot")]
    pub version: String,
    pub fingerprint: String,
    /// Base64 SPKI DER of the child's static identity signing key.
    #[serde(rename = "pubkey")]
    pub pubkey: String,
    /// Base64 SEC1 uncompressed point of the child's ephemeral
    /// ECDH public key.
    pub epk: String,
    /// Base64 ASN.1 DER ECDSA signature over
    /// [`child_signing_payload`].
    pub sig: String,
    pub ts: i64,
}

/// Parent → child ack.
///
/// `version` is `#[serde(default)]` + `skip_serializing_if`,
/// matching Go's `json:"pivot,omitempty"` — a string-valued
/// field omitted on the wire when empty.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AckMsg {
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "pivot")]
    pub version: String,
    pub epk: String,
    pub sig: String,
    pub ts: i64,
}

/// Parent → child refusal. The client parses this before
/// attempting to parse the ack, so a parent that returns
/// `{"error": "..."}` (instead of a well-formed ack) produces a
/// clear error rather than a JSON decode failure.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ErrMsg {
    #[serde(default)]
    pub error: String,
}

// =====================================================================
// FrameIO
// =====================================================================

/// The frame transport the handshake runs over.
///
/// `async_trait` because the SMB and TCP transports are async;
/// the frame operations are awaited at the call site. This differs
/// from the Go signature (`WriteFrame(body []byte) error`) only in
/// being `async`, which is invisible on the wire.
#[async_trait::async_trait]
pub trait FrameIO: Send {
    /// Write one frame.
    ///
    /// **The implementer is responsible for length prefixing.**
    /// The Go `FrameIO` did the same: `WriteFrame` in
    /// `transport_smb_windows.rs` writes a 4-byte BE length
    /// followed by the body. The protocol layer above does not
    /// know the framing.
    async fn write_frame(&mut self, body: &[u8]) -> std::io::Result<()>;

    /// Read one frame. The implementer strips the length prefix
    /// and enforces the 16 MiB cap.
    async fn read_frame(&mut self) -> std::io::Result<Vec<u8>>;
}

// =====================================================================
// Signing payloads
// =====================================================================

/// `tornadoc2-pivot-child-v2|{fingerprint}|{child_epk}|{ts}`.
///
/// The `child-v2` prefix is a domain separator: it prevents a
/// signature produced for a parent ack from being replayed as a
/// child hello, even if the two payloads share a similar layout.
pub fn child_signing_payload(
    fingerprint: &str,
    child_epk: &str,
    ts: i64,
) -> Vec<u8> {
    format!("tornadoc2-pivot-child-v2|{fingerprint}|{child_epk}|{ts}")
        .into_bytes()
}

/// `tornadoc2-pivot-parent-v2|{fingerprint}|{child_epk}|{parent_epk}|{ts}`.
///
/// Note the parent's signing payload is bound to the **child's**
/// ephemeral, not just the parent's own. That closes an ack-replay
/// window: a captured ack from a previous handshake carries a
/// signature over a different child ephemeral, so a replay against
/// a fresh hello fails verification.
pub fn parent_signing_payload(
    fingerprint: &str,
    child_epk: &str,
    parent_epk: &str,
    ts: i64,
) -> Vec<u8> {
    format!(
        "tornadoc2-pivot-parent-v2|{fingerprint}|{child_epk}|{parent_epk}|{ts}"
    )
    .into_bytes()
}

// =====================================================================
// Sign / verify
// =====================================================================

/// SHA-256 the payload, then ECDSA-P256 sign with a
/// non-deterministic nonce.
///
/// The returned `Signature` is the (r, s) representation; call
/// `.to_der()` to get the ASN.1 form that goes on the wire.
/// Matches Go's `ecdsa.SignASN1(rand.Reader, priv, digest[:])`.
pub fn sign_payload(
    key: &SigningKey,
    payload: &[u8],
) -> Result<Signature, PivotError> {
    let digest = Sha256::digest(payload);
    key.sign_prehash(&digest)
        .map_err(|e| PivotError::Crypto(format!("sign: {e}")))
}

/// Verify a signature over `payload` against `pub_key`.
///
/// `sig` is the ASN.1 DER form. Matches Go's
/// `ecdsa.VerifyASN1(pub, digest[:], sig)`.
pub fn verify_signature(
    pub_key: &VerifyingKey,
    payload: &[u8],
    sig_der: &[u8],
) -> bool {
    let Ok(sig) = Signature::from_der(sig_der) else {
        return false;
    };
    let digest = Sha256::digest(payload);
    pub_key.verify_prehash(&digest, &sig).is_ok()
}

// =====================================================================
// ECDH helpers
// =====================================================================

/// Generate a fresh P-256 ECDH keypair.
pub fn generate_ecdh_keypair(
) -> Result<SecretKey, PivotError> {
    Ok(SecretKey::random(&mut rand_core::OsRng))
}

/// Base64 the SEC1 uncompressed encoding of an ECDH public key.
pub fn encode_ecdh_public(pub_key: &PublicKey) -> String {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    STANDARD.encode(pub_key.to_encoded_point(false).as_bytes())
}

/// Decode a base64 SEC1 uncompressed ECDH public key.
pub fn decode_ecdh_public(b64: &str) -> Result<PublicKey, PivotError> {
    let raw = STANDARD.decode(b64)?;
    PublicKey::from_sec1_bytes(&raw)
        .map_err(|e| PivotError::Crypto(format!("ecdh pub: {e}")))
}

// =====================================================================
// Session derivation
// =====================================================================

/// Derive a [`Session`] from the ECDH shared secret.
///
/// `HKDF-SHA256(ikm=shared, salt=none, info=HKDF_INFO)` expands
/// the shared secret to 64 bytes: `[0..32]` is `child_to_parent`,
/// `[32..64]` is `parent_to_child`.
///
/// The 64-byte OKM and the shared secret are zeroed on drop.
pub fn derive_session(
    shared: &[u8],
    role: Role,
) -> Result<Session, PivotError> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(HKDF_INFO, okm.as_mut())
        .map_err(|e| PivotError::Crypto(format!("hkdf: {e}")))?;

    let mut child_to_parent = [0u8; 32];
    let mut parent_to_child = [0u8; 32];
    child_to_parent.copy_from_slice(&okm[0..32]);
    parent_to_child.copy_from_slice(&okm[32..64]);

    Ok(Session {
        role,
        child_to_parent: Zeroizing::new(child_to_parent),
        parent_to_child: Zeroizing::new(parent_to_child),
        send_seq: 1,
        recv_seq: 1,
    })
}

// =====================================================================
// Time helpers
// =====================================================================

/// Whether `ts` is within [`TIMESTAMP_SKEW_SECS`] of the current
/// Unix time.
///
/// `ts >= now - skew && ts <= now + skew`. A missing clock (before
/// 1970, or a system clock set to the past) yields a `now` of 0;
/// the comparison then rejects any timestamp after `skew`, which
/// is the right behaviour for a broken clock.
pub fn within_skew(ts: i64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    ts >= now - TIMESTAMP_SKEW_SECS && ts <= now + TIMESTAMP_SKEW_SECS
}

/// The current Unix time in seconds. Convenience for
/// `client_handshake`.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// =====================================================================
// SPKI encoding for the child public key
// =====================================================================

/// Return the base64 SPKI DER of `key`'s public half.
///
/// The Go tree used `x509.MarshalPKIXPublicKey(&key.PublicKey)` —
/// SPKI DER. The Rust equivalent is `EncodePublicKey::to_public_key_der`.
pub fn encode_spki_pubkey(key: &SigningKey) -> Result<String, PivotError> {
    let der = key
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| PivotError::Crypto(format!("spki: {e}")))?;
    Ok(STANDARD.encode(der.as_bytes()))
}

/// Parse a base64 SPKI DER into a `VerifyingKey`.
pub fn decode_spki_pubkey(b64: &str) -> Result<VerifyingKey, PivotError> {
    use p256::pkcs8::DecodePublicKey;
    let der = STANDARD.decode(b64)?;
    VerifyingKey::from_public_key_der(&der)
        .map_err(|e| PivotError::Crypto(format!("spki parse: {e}")))
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constants() {
        assert_eq!(PIVOT_VERSION, "v2");
        // The v1 here is deliberate. See the module doc.
        assert_eq!(HKDF_INFO, b"tornadoc2-pivot-v1");
    }

    #[test]
    fn child_signing_payload_format() {
        let p = child_signing_payload("fp", "epk", 123);
        assert_eq!(p, b"tornadoc2-pivot-child-v2|fp|epk|123");
    }

    #[test]
    fn parent_signing_payload_format() {
        let p = parent_signing_payload("fp", "cepk", "pepk", 456);
        assert_eq!(
            p,
            b"tornadoc2-pivot-parent-v2|fp|cepk|pepk|456"
        );
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let payload = b"test-payload";
        let sig = sign_payload(&key, payload).unwrap();
        let der = sig.to_der();
        assert!(verify_signature(
            key.verifying_key(),
            payload,
            der.as_bytes(),
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key_a = SigningKey::random(&mut rand_core::OsRng);
        let key_b = SigningKey::random(&mut rand_core::OsRng);
        let payload = b"test-payload";
        let sig = sign_payload(&key_a, payload).unwrap();
        let der = sig.to_der();
        assert!(!verify_signature(
            key_b.verifying_key(),
            payload,
            der.as_bytes(),
        ));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let sig = sign_payload(&key, b"original").unwrap();
        let der = sig.to_der();
        assert!(!verify_signature(
            key.verifying_key(),
            b"tampered",
            der.as_bytes(),
        ));
    }

    #[test]
    fn ecdh_round_trip() {
        let a = generate_ecdh_keypair().unwrap();
        let b = generate_ecdh_keypair().unwrap();
        let a_b64 = encode_ecdh_public(&a.public_key());
        let b_b64 = encode_ecdh_public(&b.public_key());

        let a2 = decode_ecdh_public(&b_b64).unwrap();
        let b2 = decode_ecdh_public(&a_b64).unwrap();

        let shared_a = p256::ecdh::diffie_hellman(
            a.to_nonzero_scalar(),
            a2.as_affine(),
        );
        let shared_b = p256::ecdh::diffie_hellman(
            b.to_nonzero_scalar(),
            b2.as_affine(),
        );
        assert_eq!(
            shared_a.raw_secret_bytes().as_slice(),
            shared_b.raw_secret_bytes().as_slice(),
        );
    }

    #[test]
    fn derive_session_symmetric() {
        let shared = b"0123456789abcdef0123456789abcdef";
        let child = derive_session(shared, Role::Child).unwrap();
        let parent = derive_session(shared, Role::Parent).unwrap();
        assert_eq!(
            child.child_to_parent.as_slice(),
            parent.child_to_parent.as_slice(),
        );
        assert_eq!(
            child.parent_to_child.as_slice(),
            parent.parent_to_child.as_slice(),
        );
        assert_eq!(child.send_seq, 1);
        assert_eq!(child.recv_seq, 1);
    }

    #[test]
    fn derive_session_distinct_halves() {
        let shared = b"0123456789abcdef0123456789abcdef";
        let s = derive_session(shared, Role::Child).unwrap();
        assert_ne!(
            s.child_to_parent.as_slice(),
            s.parent_to_child.as_slice(),
        );
    }

    #[test]
    fn within_skew_accepts_now() {
        assert!(within_skew(unix_now()));
    }

    #[test]
    fn within_skew_rejects_old() {
        assert!(!within_skew(unix_now() - 301));
    }

    #[test]
    fn within_skew_rejects_future() {
        assert!(!within_skew(unix_now() + 301));
    }

    #[test]
    fn spki_round_trip() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let b64 = encode_spki_pubkey(&key).unwrap();
        let parsed = decode_spki_pubkey(&b64).unwrap();
        assert_eq!(parsed, *key.verifying_key());
    }

    #[test]
    fn hello_msg_serialises_with_pivot_field() {
        let hello = HelloMsg {
            version: "v2".to_string(),
            fingerprint: "fp".to_string(),
            pubkey: "pk".to_string(),
            epk: "epk".to_string(),
            sig: "sig".to_string(),
            ts: 1,
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("\"pivot\":\"v2\""));
        assert!(!json.contains("\"version\""));
    }

    #[test]
    fn ack_omits_empty_version() {
        let ack = AckMsg {
            version: String::new(),
            epk: "e".to_string(),
            sig: "s".to_string(),
            ts: 1,
        };
        let json = serde_json::to_string(&ack).unwrap();
        assert!(!json.contains("\"pivot\""));
    }

    #[test]
    fn ack_with_version_serialises() {
        let ack = AckMsg {
            version: "v2".to_string(),
            epk: "e".to_string(),
            sig: "s".to_string(),
            ts: 1,
        };
        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("\"pivot\":\"v2\""));
    }
}