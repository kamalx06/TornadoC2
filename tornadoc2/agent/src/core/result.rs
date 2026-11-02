//! Result signing and posting.
//!
//! Port of `.postResult()`. A `TaskResult` produced by
//! `dispatch.rs` is signed (if the agent has a signing key) and
//! handed to the currently-active transport.
//!
//! # Order of operations
//!
//! 1. If `self.agent_priv` is present, canonicalize the result
//!    via `TaskResult::signable()` and sign the bytes with
//!    SHA-256 + ECDSA-P256, DER-encoded. Store the base64 in
//!    `r.signature`.
//! 2. Post the (possibly-signed) result through the transport.
//!
//! The signature covers `{error, exit_code, id, output}` — the
//! same four fields on the wire, including `error` even when
//! empty. `signable()` emits the empty `error` unconditionally
//! because the Go `Result.Signable` does; the wire form omits it
//! via `skip_serializing_if`, but the signature is over the
//! canonical form, not the wire form.
//!
//! # Taking `&self`
//!
//! The Go method took `a *Agent` and mutated the local `r`. Rust
//! takes `&self` — nothing on `self` changes; only `r` is signed
//! and mutated before posting. This makes `post_result` callable
//! from a shared context and preserves the borrow semantics the
//! async `.await` needs (the returned future captures `&self`,
//! not `&mut self`).

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::protocol::TaskResult;

use super::agent::{Agent, AgentError};
use super::identity::sign_payload;

impl Agent {
    /// Sign `r` and post it through the active transport.
    ///
    /// A failure at any step short of the transport itself is
    /// logged via `diag!` and the result is posted unsigned. The
    /// transport error is the only one that propagates — it is
    /// the only one the caller (the run loop) acts on.
    pub async fn post_result(
        &self,
        mut r: TaskResult,
    ) -> Result<(), AgentError> {
        if let Some(priv_key) = self.agent_priv.as_ref() {
            match r.signable() {
                Ok(payload) => match sign_payload(priv_key, &payload)
                {
                    Ok(sig) => {
                        r.signature = STANDARD.encode(&sig);
                        crate::diag!(
                            "[result] signed {} bytes of canonical \
                             form with {} -byte signature\n",
                            payload.len(),
                            sig.len(),
                        );
                    }
                    Err(e) => {
                        crate::diag!(
                            "[result] signing failed: {e}\n"
                        );
                    }
                },
                Err(e) => {
                    crate::diag!(
                        "[result] Signable() failed: {e}\n"
                    );
                }
            }
        } else {
            crate::diag!(
                "[result] no agent private key — result unsigned\n"
            );
        }

        let t = self.transports[self.transport_index].as_ref();
        t.post_result(r, &self.wire).await?;
        Ok(())
    }
}