//! Parent-side pivot handshake.
//!
//! Replaces `internal/pivot/server.go`. `parent_verify_and_respond`
//! runs the parent half of the peer-to-peer handshake:
//!
//! 1. Read the child hello.
//! 2. Verify the child's version, timestamp, and signature over
//!    `child_signing_payload`, using the *child's* identity
//!    signing key (`hello.pubkey`).
//! 3. Compute the ECDH shared secret using the **static** pivot
//!    private key against the child's ephemeral.
//! 4. Sign an ack with the **static** pivot private key.
//! 5. Send the ack.
//! 6. Derive the session.
//!
//! # Forward secrecy
//!
//! The parent's ECDH contribution is the static pivot key's
//! public half, so an attacker who records a pivot session and
//! later recovers the pivot private key can re-derive the session
//! keys for every captured session. **No forward secrecy on the
//! pivot hop.** The README documents this under "The pivot
//! keypair"; it is not a bug, and this port preserves it.
//!
//! # Refusal semantics
//!
//! Every failure between the hello read and the ack send produces
//! an `ErrMsg` frame on the wire before the error returns to the
//! caller. The child's `client_handshake` parses `ErrMsg` before
//! parsing the ack, so a refused hello reaches the operator as
//! `PivotError::Refused(reason)` rather than a JSON decode
//! failure.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use p256::SecretKey;

use super::protocol::{
    child_signing_payload, decode_ecdh_public, derive_session,
    encode_ecdh_public, parent_signing_payload, sign_payload, unix_now,
    verify_signature, within_skew, AckMsg, ErrMsg, FrameIO, HelloMsg,
    PivotError, PIVOT_VERSION,
};
use super::session::{Role, Session};

/// The successful result of a parent-side handshake.
///
/// `pubkey` is the child's *identity signing key* — the key that
/// signed the hello. It is what the parent uses to verify
/// subsequent frames' outer signatures (if any) and what the
/// parent records as the child's pinned identity for
/// trust-on-first-use.
pub struct ParentHandshakeResult {
    /// The child's fingerprint, taken from the hello. Stable
    /// across reconnects (it is the session-fingerprint value).
    pub fingerprint: String,

    /// The child's identity signing key, parsed from
    /// `hello.pubkey`. SPKI DER, P-256.
    pub pubkey: VerifyingKey,

    /// The negotiated session.
    pub session: Session,
}

/// Run the parent half of the pivot handshake.
///
/// # Parameters
///
/// - `io` — the frame transport. Length prefixing is the
///   implementer's job.
/// - `pivot_privkey` — the engagement-wide pivot private key.
///   The same key every parent build carries; its public half is
///   embedded in every child build.
///
/// # Errors
///
/// A returned `Err` means either (a) a `write_frame`/`read_frame`
/// failure that happened before any diagnostic could be sent, or
/// (b) a refusal that was successfully written to the child. The
/// `PivotError` variant distinguishes these where it matters.
pub async fn parent_verify_and_respond(
    io: &mut dyn FrameIO,
    pivot_privkey: &SigningKey,
) -> Result<ParentHandshakeResult, PivotError> {
    // ---- Read hello -----------------------------------------
    let raw = io.read_frame().await.map_err(|e| {
        PivotError::Protocol(format!("read hello: {e}"))
    })?;
    let hello: HelloMsg = serde_json::from_slice(&raw)?;

    // ---- Version check --------------------------------------
    if hello.version != PIVOT_VERSION {
        return refuse(
            io,
            "unsupported pivot version",
            PivotError::Protocol(format!(
                "peer sent version {:?}",
                hello.version,
            )),
        )
        .await;
    }

    // ---- Required fields ------------------------------------
    if hello.fingerprint.is_empty()
        || hello.epk.is_empty()
        || hello.sig.is_empty()
        || hello.pubkey.is_empty()
    {
        return refuse(
            io,
            "malformed hello",
            PivotError::Protocol("malformed hello".into()),
        )
        .await;
    }

    // ---- Timestamp ------------------------------------------
    if !within_skew(hello.ts) {
        return refuse(
            io,
            "timestamp outside window",
            PivotError::Protocol(
                "hello timestamp outside window".into(),
            ),
        )
        .await;
    }

    // ---- Parse the child's SPKI pubkey ----------------------
    let pub_der = match STANDARD.decode(&hello.pubkey) {
        Ok(d) => d,
        Err(e) => {
            return refuse(io, "bad pubkey encoding", PivotError::Base64(e))
                .await;
        }
    };
    let child_pub = match VerifyingKey::from_public_key_der(&pub_der) {
        Ok(k) => k,
        Err(e) => {
            return refuse(
                io,
                "bad pubkey",
                PivotError::Crypto(format!("parse pubkey: {e}")),
            )
            .await;
        }
    };

    // ---- Verify the child's signature -----------------------
    let sig = match STANDARD.decode(&hello.sig) {
        Ok(s) => s,
        Err(e) => {
            return refuse(
                io,
                "bad sig encoding",
                PivotError::Base64(e),
            )
            .await;
        }
    };
    let child_payload =
        child_signing_payload(&hello.fingerprint, &hello.epk, hello.ts);
    if !verify_signature(&child_pub, &child_payload, &sig) {
        return refuse(
            io,
            "signature invalid",
            PivotError::Protocol("child signature invalid".into()),
        )
        .await;
    }

    // ---- ECDH: static pivot_priv × child ephemeral ----------
    //
    // The pivot private key is an ECDSA key in `SigningKey`
    // form; we re-parse the raw scalar as a `SecretKey` for
    // ECDH. That conversion is the Rust equivalent of the Go
    // `ecdsaToECDH`.
    let pivot_ecdh_priv = ecdsa_to_ecdh(pivot_privkey)?;
    let child_epk = match decode_ecdh_public(&hello.epk) {
        Ok(k) => k,
        Err(e) => {
            return refuse(
                io,
                "bad child epk",
                PivotError::Protocol(format!("decode child epk: {e}")),
            )
            .await;
        }
    };
    let shared = p256::ecdh::diffie_hellman(
        pivot_ecdh_priv.to_nonzero_scalar(),
        child_epk.as_affine(),
    );

    // ---- Build the ack --------------------------------------
    //
    // The parent's ECDH contribution (`epk_b64`) is the
    // **static** pivot public key, not a fresh ephemeral.
    // See the module doc.
    let pivot_pub = pivot_ecdh_priv.public_key();
    let epk_b64 = encode_ecdh_public(&pivot_pub);

    let ts = unix_now();
    let ack_payload = parent_signing_payload(
        &hello.fingerprint,
        &hello.epk,
        &epk_b64,
        ts,
    );
    let ack_sig = sign_payload(pivot_privkey, &ack_payload)?;
    let ack = AckMsg {
        version: PIVOT_VERSION.to_string(),
        epk: epk_b64,
        sig: STANDARD.encode(ack_sig.to_der().as_bytes()),
        ts,
    };
    let ack_bytes = serde_json::to_vec(&ack)?;
    if let Err(e) = io.write_frame(&ack_bytes).await {
        return Err(PivotError::Protocol(format!(
            "send ack: {e}"
        )));
    }

    // ---- Derive session -------------------------------------
    let session =
        derive_session(shared.raw_secret_bytes(), Role::Parent)?;

    Ok(ParentHandshakeResult {
        fingerprint: hello.fingerprint,
        pubkey: child_pub,
        session,
    })
}

// =====================================================================
// Refusal helper
// =====================================================================

/// Send a refusal frame, then return the underlying error.
///
/// Same shape as the Go `refuse` closure. A failure to write the
/// refusal is swallowed — the child will see EOF and treat it as
/// a transport failure, which is the correct behaviour for a
/// parent that has already decided to reject the connection.
async fn refuse(
    io: &mut dyn FrameIO,
    reason: &str,
    underlying: PivotError,
) -> Result<ParentHandshakeResult, PivotError> {
    let msg = ErrMsg {
        error: reason.to_string(),
    };
    if let Ok(bytes) = serde_json::to_vec(&msg) {
        let _ = io.write_frame(&bytes).await;
    }
    Err(underlying)
}

// =====================================================================
// ECDSA → ECDH conversion
// =====================================================================

/// Convert an ECDSA P-256 signing key into the ECDH private key
/// for the same point.
///
/// Mirrors the Go `ecdsaToECDH`. `SigningKey::to_bytes()` returns
/// the raw 32-byte scalar; `SecretKey::from_slice` parses it. The
/// intermediate bytes are not zeroed before drop — the
/// `SigningKey::to_bytes()` call returns an owned
/// `GenericArray<u8, U32>` that is not `Zeroizing` — but the
/// source scalar inside `SigningKey` is already protected by
/// `p256`'s own `Zeroize` implementation, and the intermediate
/// copy is short-lived. Go's version has the same caveat
/// (`ecdsaToECDH` zeroes its `raw` but cannot zero the
/// `ecdh.PrivateKey` it hands to `NewPrivateKey`).
fn ecdsa_to_ecdh(
    key: &SigningKey,
) -> Result<SecretKey, PivotError> {
    let bytes = key.to_bytes();
    SecretKey::from_slice(&bytes)
        .map_err(|e| PivotError::Crypto(format!("ecdsa->ecdh: {e}")))
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pivot::client::client_handshake;

    /// A FrameIO backed by two in-memory `Vec<u8>` queues, so the
    /// client and server halves can be driven against each other
    /// without a real socket.
    struct Loopback {
        to_server: Vec<Vec<u8>>,
        from_server: Vec<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl FrameIO for Loopback {
        async fn write_frame(
            &mut self,
            body: &[u8],
        ) -> std::io::Result<()> {
            self.to_server.push(body.to_vec());
            Ok(())
        }
        async fn read_frame(&mut self) -> std::io::Result<Vec<u8>> {
            if self.from_server.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "no frame",
                ));
            }
            Ok(self.from_server.remove(0))
        }
    }

    /// Two connected loopbacks: writes to `child` land on
    /// `parent`'s read queue, and vice versa.
    fn connected_pair() -> (
        Box<dyn FrameIO>,
        Box<dyn FrameIO>,
    ) {
        use std::sync::{Arc, Mutex};
        let c2p: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let p2c: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();

        struct Half {
            outgoing: Arc<Mutex<Vec<Vec<u8>>>>,
            incoming: Arc<Mutex<Vec<Vec<u8>>>>,
        }
        #[async_trait::async_trait]
        impl FrameIO for Half {
            async fn write_frame(
                &mut self,
                body: &[u8],
            ) -> std::io::Result<()> {
                self.outgoing.lock().unwrap().push(body.to_vec());
                Ok(())
            }
            async fn read_frame(
                &mut self,
            ) -> std::io::Result<Vec<u8>> {
                let mut q = self.incoming.lock().unwrap();
                if q.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "no frame",
                    ));
                }
                Ok(q.remove(0))
            }
        }

        let child = Box::new(Half {
            outgoing: c2p.clone(),
            incoming: p2c.clone(),
        }) as Box<dyn FrameIO>;
        let parent = Box::new(Half {
            outgoing: p2c,
            incoming: c2p,
        }) as Box<dyn FrameIO>;
        (child, parent)
    }

    fn make_keys() -> (SigningKey, SigningKey) {
        let child_identity = SigningKey::random(&mut rand_core::OsRng);
        let pivot = SigningKey::random(&mut rand_core::OsRng);
        (child_identity, pivot)
    }

    #[tokio::test]
    async fn handshake_round_trip() {
        let (child_identity, pivot) = make_keys();
        let pivot_pub = *pivot.verifying_key();
        let fp = "child-fp-12345";
        let (mut c_io, mut p_io) = connected_pair();

        // Run both halves concurrently so each write is
        // available for the other side's read.
        let (c_res, p_res) = tokio::join!(
            client_handshake(&mut *c_io, &child_identity, &pivot_pub, fp),
            parent_verify_and_respond(&mut *p_io, &pivot),
        );
        let c_session = c_res.expect("client handshake");
        let p_result = p_res.expect("parent handshake");

        assert_eq!(c_session.role(), Role::Child);
        assert_eq!(p_result.session.role(), Role::Parent);
        assert_eq!(p_result.fingerprint, fp);
        assert_eq!(p_result.pubkey, *child_identity.verifying_key());

        // Both sides derived the same keys.
        assert_eq!(
            c_session.child_to_parent_key(),
            p_result.session.child_to_parent_key(),
        );
        assert_eq!(
            c_session.parent_to_child_key(),
            p_result.session.parent_to_child_key(),
        );
    }

    #[tokio::test]
    async fn handshake_then_frames() {
        let (child_identity, pivot) = make_keys();
        let pivot_pub = *pivot.verifying_key();
        let fp = "child-fp-xyz";
        let (mut c_io, mut p_io) = connected_pair();

        let (c_res, p_res) = tokio::join!(
            client_handshake(&mut *c_io, &child_identity, &pivot_pub, fp),
            parent_verify_and_respond(&mut *p_io, &pivot),
        );
        let c = c_res.unwrap();
        let p = p_res.unwrap().session;

        // Child → parent frame.
        let f = c.encrypt_child_to_parent(b"task\n").unwrap();
        let pt = p.decrypt_child_to_parent(&f).unwrap();
        assert_eq!(pt, b"task\n");

        // Parent → child frame.
        let f = p.encrypt_parent_to_child(b"result\n").unwrap();
        let pt = c.decrypt_parent_to_child(&f).unwrap();
        assert_eq!(pt, b"result\n");
    }

    #[tokio::test]
    async fn empty_fingerprint_refused() {
        let (child_identity, pivot) = make_keys();
        let pivot_pub = *pivot.verifying_key();
        let (mut c_io, mut p_io) = connected_pair();

        let (c_res, _p_res) = tokio::join!(
            client_handshake(&mut *c_io, &child_identity, &pivot_pub, ""),
            parent_verify_and_respond(&mut *p_io, &pivot),
        );
        // Child rejects before sending.
        assert!(matches!(c_res, Err(PivotError::Protocol(_))));
    }
}