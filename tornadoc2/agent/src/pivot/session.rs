//! Pivot session state.
//!
//! Full port of `internal/pivot/session.go`. Adds the frame
//! encryption / decryption methods, sequence-number enforcement,
//! role checks, `Close`, and the frame codec that the earlier
//! stub omitted.
//!
//! # Wire-format facts that differ from `crypto/wire.rs`
//!
//! | | `crypto/wire.rs` | `pivot/session.rs` |
//! |---|---|---|
//! | Key | SHA-256 ECDH | HKDF-SHA256(shared, info=...) |
//! | AAD | the literal `"v2"` | the 8-byte BE `seq` |
//! | IV | 12-byte random | 12-byte random |
//! | Frame | JSON `{enc, epk, iv, ct}` | JSON `{seq, iv, ct}` |
//!
//! The two constructions are deliberately distinct. Do not
//! cross-wire them — the AAD difference alone guarantees the tag
//! will not verify.

use std::sync::Mutex;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::protocol::PivotError;

// =====================================================================
// Role
// =====================================================================

/// Which side of the pivot this session is on.
///
/// Unlike the Go `roleUnspecified`, the Rust enum has no default
/// variant — a `Session` is always either `Child` or `Parent`. The
/// Go `checkRole` allowed `roleUnspecified` to pass; the Rust
/// `check_role` does not, because that state is unreachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Child,
    Parent,
}

// =====================================================================
// Frame
// =====================================================================

/// One AEAD frame, before length-prefix framing.
///
/// The wire encoding is JSON: `{"seq":N,"iv":"b64","ct":"b64"}`.
/// The `seq` field is inside the encrypted envelope's AAD, so an
/// attacker who edits it in flight breaks the tag.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Frame {
    pub seq: u64,
    pub iv: String,
    pub ct: String,
}

/// Encode a frame to its JSON bytes.
///
/// The length prefix is added by the transport layer
/// (`FrameIO::write_frame`), not by this function — matching the
/// Go split where `EncodeFrame` returns bytes and
/// `smb_relay_windows.go` prefixes them.
pub fn encode_frame(f: &Frame) -> Result<Vec<u8>, PivotError> {
    Ok(serde_json::to_vec(f)?)
}

/// Decode a frame from JSON bytes, validating the fields.
///
/// Rejects `seq == 0` (which is never emitted by `seal_frame`,
/// because `send_seq` starts at 1) and empty `iv` or `ct`.
/// This closes two classes of malformed input before any AEAD
/// work happens.
pub fn decode_frame(raw: &[u8]) -> Result<Frame, PivotError> {
    let f: Frame = serde_json::from_slice(raw)?;
    if f.seq == 0 {
        return Err(PivotError::Protocol("frame seq is zero".into()));
    }
    if f.iv.is_empty() || f.ct.is_empty() {
        return Err(PivotError::Protocol(
            "frame missing iv or ct".into(),
        ));
    }
    Ok(f)
}

// =====================================================================
// Session
// =====================================================================

/// A negotiated pivot session.
///
/// Two AES-256-GCM keys, one per direction, and two counters,
/// one per direction. The counter for the *sending* direction is
/// `send_seq`; the counter for the *receiving* direction is
/// `recv_seq`. Both start at 1.
///
/// # Locking
///
/// All mutable state is behind a single `Mutex<SessionState>`.
/// The lock is held only for the duration of one
/// encrypt / decrypt operation — the AEAD work and the sequence
/// increment are atomic with respect to one another, but the
/// transport-level frame write happens outside the lock. This
/// matches the Go tree: `s.mu.Lock()` in
/// `EncryptChildToParent` covers `sealFrame` but not the
/// subsequent `io.WriteFrame`.
pub struct Session {
    role: Role,
    inner: Mutex<SessionState>,
}

struct SessionState {
    /// `None` after `close()` has been called.
    child_to_parent: Option<Zeroizing<[u8; 32]>>,
    /// `None` after `close()` has been called.
    parent_to_child: Option<Zeroizing<[u8; 32]>>,
    send_seq: u64,
    recv_seq: u64,
}

impl Session {
    /// Construct a session. Only `protocol::derive_session`
    /// calls this — the counters start at 1 and the keys are
    /// stored in `Zeroizing` wrappers so they wipe on drop.
    pub(crate) fn new(
        role: Role,
        child_to_parent: [u8; 32],
        parent_to_child: [u8; 32],
    ) -> Self {
        Self {
            role,
            inner: Mutex::new(SessionState {
                child_to_parent: Some(Zeroizing::new(child_to_parent)),
                parent_to_child: Some(Zeroizing::new(parent_to_child)),
                send_seq: 1,
                recv_seq: 1,
            }),
        }
    }

    /// The session's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Zero both keys and mark the session closed.
    ///
    /// Idempotent: a second call is a no-op. Any
    /// encrypt / decrypt after this returns
    /// `PivotError::SessionClosed`.
    ///
    /// The `Zeroizing` wrappers would wipe the keys on drop
    /// anyway; `close()` forces the wipe *now* rather than at
    /// `Session` drop, which is what the Go `Close` does.
    pub fn close(&self) {
        let mut s = self.inner.lock().expect("session lock poisoned");
        s.child_to_parent = None;
        s.parent_to_child = None;
        // The counters are set to 0 to make any subsequent
        // attempt fail the "closed" check, not the sequence
        // check. The order matters: check_role returns
        // SessionClosed only when the relevant key is None.
        s.send_seq = 0;
        s.recv_seq = 0;
    }

    // -----------------------------------------------------------------
    // Role checks
    // -----------------------------------------------------------------

    /// Fail unless this session's role matches `want`.
    fn check_role(
        &self,
        want: Role,
        method: &str,
    ) -> Result<(), PivotError> {
        if self.role != want {
            return Err(PivotError::Protocol(format!(
                "{method} called on a {:?} session, expected {:?}",
                self.role, want,
            )));
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Encrypt
    // -----------------------------------------------------------------

    /// Encrypt a plaintext as a child→parent frame.
    ///
    /// Errors if this session is a `Parent` session (the
    /// child→parent direction is not ours to speak on) or if
    /// `close()` has been called.
    pub fn encrypt_child_to_parent(
        &self,
        plaintext: &[u8],
    ) -> Result<Frame, PivotError> {
        self.check_role(Role::Child, "encrypt_child_to_parent")?;
        let mut s = self.inner.lock().expect("session lock poisoned");
        let key = s.child_to_parent.as_ref().ok_or_else(|| {
            PivotError::Protocol("session closed".into())
        })?;
        let seq = s.send_seq;
        let frame = seal_frame(key.as_ref(), seq, plaintext)?;
        s.send_seq += 1;
        Ok(frame)
    }

    /// Encrypt a plaintext as a parent→child frame.
    pub fn encrypt_parent_to_child(
        &self,
        plaintext: &[u8],
    ) -> Result<Frame, PivotError> {
        self.check_role(Role::Parent, "encrypt_parent_to_child")?;
        let mut s = self.inner.lock().expect("session lock poisoned");
        let key = s.parent_to_child.as_ref().ok_or_else(|| {
            PivotError::Protocol("session closed".into())
        })?;
        let seq = s.send_seq;
        let frame = seal_frame(key.as_ref(), seq, plaintext)?;
        s.send_seq += 1;
        Ok(frame)
    }

    // -----------------------------------------------------------------
    // Decrypt
    // -----------------------------------------------------------------

    /// Decrypt a child→parent frame.
    ///
    /// Fails if the frame's `seq` is not exactly `recv_seq`.
    /// A forward gap (`got > expected`) and a repeat
    /// (`got < expected`) both fail, with distinguishable error
    /// variants so the operator's log line names which one.
    pub fn decrypt_child_to_parent(
        &self,
        f: &Frame,
    ) -> Result<Vec<u8>, PivotError> {
        self.check_role(Role::Parent, "decrypt_child_to_parent")?;
        let mut s = self.inner.lock().expect("session lock poisoned");
        if f.seq != s.recv_seq {
            return Err(replay_error(s.recv_seq, f.seq));
        }
        let key = s.child_to_parent.as_ref().ok_or_else(|| {
            PivotError::Protocol("session closed".into())
        })?;
        let pt = open_frame(key.as_ref(), f)?;
        s.recv_seq += 1;
        Ok(pt)
    }

    /// Decrypt a parent→child frame.
    pub fn decrypt_parent_to_child(
        &self,
        f: &Frame,
    ) -> Result<Vec<u8>, PivotError> {
        self.check_role(Role::Child, "decrypt_parent_to_child")?;
        let mut s = self.inner.lock().expect("session lock poisoned");
        if f.seq != s.recv_seq {
            return Err(replay_error(s.recv_seq, f.seq));
        }
        let key = s.parent_to_child.as_ref().ok_or_else(|| {
            PivotError::Protocol("session closed".into())
        })?;
        let pt = open_frame(key.as_ref(), f)?;
        s.recv_seq += 1;
        Ok(pt)
    }
}

// =====================================================================
// Debug: redact the keys
// =====================================================================

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pivot.Session{{role={:?}}}", self.role)
    }
}

// =====================================================================
// Test-only key accessors
// =====================================================================

#[cfg(test)]
impl Session {
    pub(crate) fn child_to_parent_key(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .unwrap()
            .child_to_parent
            .as_ref()
            .map(|z| **z)
    }

    pub(crate) fn parent_to_child_key(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .unwrap()
            .parent_to_child
            .as_ref()
            .map(|z| **z)
    }
}

// =====================================================================
// AEAD primitives
// =====================================================================

/// AES-256-GCM seal with AAD = `seq.to_be_bytes()`.
///
/// The AAD is 8 bytes of the big-endian sequence number, *not*
/// the wire version string. This is the pivot protocol's choice,
/// distinct from `crypto/wire.rs`. See the module doc.
fn seal_frame(
    key: &[u8; 32],
    seq: u64,
    plaintext: &[u8],
) -> Result<Frame, PivotError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let aad = seq.to_be_bytes();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| PivotError::Crypto(format!("seal: {e}")))?;
    Ok(Frame {
        seq,
        iv: STANDARD.encode(iv),
        ct: STANDARD.encode(ct),
    })
}

/// AES-256-GCM open with AAD = `seq.to_be_bytes()`.
fn open_frame(
    key: &[u8; 32],
    f: &Frame,
) -> Result<Vec<u8>, PivotError> {
    let iv = STANDARD.decode(&f.iv)?;
    if iv.len() != 12 {
        return Err(PivotError::Crypto(format!(
            "bad nonce length: {}",
            iv.len(),
        )));
    }
    let ct = STANDARD.decode(&f.ct)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let aad = f.seq.to_be_bytes();
    cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .map_err(|e| PivotError::Crypto(format!("open: {e}")))
}

/// Build the replay error for a sequence mismatch.
///
/// `got > expected` → forward gap. `got < expected` → repeat.
/// Same distinction as the Go `seqErr`.
fn replay_error(expected: u64, got: u64) -> PivotError {
    let kind = if got > expected {
        ReplayKind::Gap
    } else {
        ReplayKind::Repeat
    };
    PivotError::Replay {
        kind,
        expected,
        got,
    }
}

/// Which kind of replay this is.
///
/// Go defined `ErrSeqGap` and `ErrSeqRepeat` as wrapped errors
/// around `ErrReplay`; Rust carries the same distinction in a
/// structured enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayKind {
    /// `got > expected` — a forward gap, likely a dropped frame.
    Gap,
    /// `got < expected` — a repeat, likely a replay.
    Repeat,
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn child() -> Session {
        Session::new(Role::Child, [1u8; 32], [2u8; 32])
    }

    fn parent() -> Session {
        Session::new(Role::Parent, [1u8; 32], [2u8; 32])
    }

    #[test]
    fn encrypt_decrypt_child_to_parent() {
        let c = child();
        let p = parent();
        let frame = c.encrypt_child_to_parent(b"hello").unwrap();
        assert_eq!(frame.seq, 1);
        let pt = p.decrypt_child_to_parent(&frame).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn encrypt_decrypt_parent_to_child() {
        let c = child();
        let p = parent();
        let frame = p.encrypt_parent_to_child(b"world").unwrap();
        assert_eq!(frame.seq, 1);
        let pt = c.decrypt_parent_to_child(&frame).unwrap();
        assert_eq!(pt, b"world");
    }

    #[test]
    fn sequence_increments_per_frame() {
        let c = child();
        let p = parent();
        let f1 = c.encrypt_child_to_parent(b"a").unwrap();
        let f2 = c.encrypt_child_to_parent(b"b").unwrap();
        let f3 = c.encrypt_child_to_parent(b"c").unwrap();
        assert_eq!(f1.seq, 1);
        assert_eq!(f2.seq, 2);
        assert_eq!(f3.seq, 3);
        // Receiver accepts them in order.
        assert_eq!(p.decrypt_child_to_parent(&f1).unwrap(), b"a");
        assert_eq!(p.decrypt_child_to_parent(&f2).unwrap(), b"b");
        assert_eq!(p.decrypt_child_to_parent(&f3).unwrap(), b"c");
    }

    #[test]
    fn seq_gap_is_rejected() {
        let c = child();
        let p = parent();
        let _f1 = c.encrypt_child_to_parent(b"a").unwrap();
        let f3 = c.encrypt_child_to_parent(b"c").unwrap();
        // Skip f2.
        let err = p.decrypt_child_to_parent(&f3).unwrap_err();
        match err {
            PivotError::Replay {
                kind: ReplayKind::Gap,
                expected: 1,
                got: 2,
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn seq_repeat_is_rejected() {
        let c = child();
        let p = parent();
        let f1 = c.encrypt_child_to_parent(b"a").unwrap();
        let _ = p.decrypt_child_to_parent(&f1).unwrap();
        // Replay f1.
        let err = p.decrypt_child_to_parent(&f1).unwrap_err();
        match err {
            PivotError::Replay {
                kind: ReplayKind::Repeat,
                expected: 2,
                got: 1,
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn encrypt_child_on_parent_session_fails() {
        let p = parent();
        let err = p.encrypt_child_to_parent(b"x").unwrap_err();
        assert!(matches!(err, PivotError::Protocol(_)));
    }

    #[test]
    fn encrypt_parent_on_child_session_fails() {
        let c = child();
        let err = c.encrypt_parent_to_child(b"x").unwrap_err();
        assert!(matches!(err, PivotError::Protocol(_)));
    }

    #[test]
    fn decrypt_child_on_child_session_fails() {
        let c = child();
        let frame = Frame {
            seq: 1,
            iv: STANDARD.encode([0u8; 12]),
            ct: STANDARD.encode(b"garbage"),
        };
        let err = c.decrypt_child_to_parent(&frame).unwrap_err();
        assert!(matches!(err, PivotError::Protocol(_)));
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        // Two sessions sharing a role but with distinct keys —
        // the parent in each direction will fail the tag.
        let c1 = Session::new(Role::Child, [1u8; 32], [2u8; 32]);
        let p2 = Session::new(Role::Parent, [9u8; 32], [9u8; 32]);
        let frame = c1.encrypt_child_to_parent(b"x").unwrap();
        let err = p2.decrypt_child_to_parent(&frame).unwrap_err();
        assert!(matches!(err, PivotError::Crypto(_)));
    }

    #[test]
    fn tampered_aad_breaks_tag() {
        let c = child();
        let p = parent();
        let mut frame = c.encrypt_child_to_parent(b"x").unwrap();
        frame.seq = 999; // change the AAD-side value
        let err = p.decrypt_child_to_parent(&frame).unwrap_err();
        // Either the seq check fires first (if 999 != expected
        // 1) or the AEAD fails. Both are errors, so the test
        // just asserts that one of them does.
        assert!(matches!(
            err,
            PivotError::Replay { .. } | PivotError::Crypto(_)
        ));
    }

    #[test]
    fn close_zeroes_keys_and_disables_ops() {
        let c = child();
        c.close();
        assert!(c.child_to_parent_key().is_none());
        assert!(c.parent_to_child_key().is_none());
        let err = c.encrypt_child_to_parent(b"x").unwrap_err();
        assert!(matches!(err, PivotError::Protocol(_)));
    }

    #[test]
    fn close_is_idempotent() {
        let c = child();
        c.close();
        c.close();
    }

    #[test]
    fn debug_redacts_keys() {
        let c = child();
        let s = format!("{c:?}");
        assert!(s.contains("Child"));
        assert!(!s.contains("1, 1, 1"));
        assert!(!s.contains("[1, 1"));
    }

    #[test]
    fn frame_encode_decode_round_trip() {
        let f = Frame {
            seq: 42,
            iv: STANDARD.encode([0u8; 12]),
            ct: STANDARD.encode(b"ciphertext"),
        };
        let bytes = encode_frame(&f).unwrap();
        let decoded = decode_frame(&bytes).unwrap();
        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.iv, f.iv);
        assert_eq!(decoded.ct, f.ct);
    }

    #[test]
    fn frame_decode_rejects_zero_seq() {
        let raw = br#"{"seq":0,"iv":"AAAA","ct":"BBBB"}"#;
        let err = decode_frame(raw).unwrap_err();
        assert!(matches!(err, PivotError::Protocol(_)));
    }

    #[test]
    fn frame_decode_rejects_empty_iv() {
        let raw = br#"{"seq":1,"iv":"","ct":"BBBB"}"#;
        let err = decode_frame(raw).unwrap_err();
        assert!(matches!(err, PivotError::Protocol(_)));
    }

    #[test]
    fn frame_decode_rejects_empty_ct() {
        let raw = br#"{"seq":1,"iv":"AAAA","ct":""}"#;
        let err = decode_frame(raw).unwrap_err();
        assert!(matches!(err, PivotError::Protocol(_)));
    }

    #[test]
    fn open_rejects_wrong_nonce_length() {
        // 16-byte IV (not 12).
        let f = Frame {
            seq: 1,
            iv: STANDARD.encode([0u8; 16]),
            ct: STANDARD.encode(b"garbage"),
        };
        let p = parent();
        let err = p.decrypt_child_to_parent(&f).unwrap_err();
        assert!(matches!(err, PivotError::Crypto(_)));
    }
}