//! The transport trait.
//!
//! Port of `protocol/transport.go`. Every transport the agent
//! carries implements this trait. The engine, the run loop,
//! and the beacon registry hold `Box<dyn Transport>` and never
//! know which wire the bytes arrive on.
//!
//! # Why `async_trait`
//!
//! Rust 1.75 stabilised `async fn` in traits, but the resulting
//! trait is not object-safe without additional bounds.
//! `async_trait` boxes the future and adds `Send` bounds,
//! producing a `dyn`-compatible trait — which is what the
//! agent needs (`Vec<Box<dyn Transport>>`).
//!
//! # `WireSession` and the `Disabled` variant
//!
//! The Go trait accepted `*crypto.WireSession`, where `nil`
//! meant "wire encryption is off." The Rust trait accepts
//! `&WireSession`, where `WireSession::Disabled` is the
//! equivalent. `Disabled::encrypt_request` returns the
//! plaintext unchanged and `Disabled::decrypt_response` returns
//! the body as-is, so the transport can call the methods
//! unconditionally. The reference is zero-cost — passing
//! `&WireSession::Disabled` does not allocate.
//!
//! # Errors
//!
//! `TransportError` carries enough structure that the run loop
//! can distinguish a status-code rejection from a network
//! failure from a signature failure. The Go trait returned
//! `error`, which the caller string-matched against `"status
//! 400"` and friends; the Rust port removes that fragility.

use thiserror::Error;

use crate::crypto::wire::WireError;
use crate::features::shaping::ShapingError;

use super::{CheckinResponse, Identity, Task, TaskResult};

/// Errors from a transport operation.
///
/// The `Status` variant is the only one the run loop branches
/// on; everything else is logged and retried. `is_session_invalid`
/// is the branch predicate the Go tree implemented as a string
/// search on `"status 400"` and friends.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The server returned an HTTP status the transport did not
    /// expect. `got` is the actual status; `want` is what the
    /// profile declared.
    #[error("status {got} (wanted {want})")]
    Status { got: u16, want: u16 },

    /// The transport's underlying I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The HTTP client (reqwest, or whatever the transport
    /// uses) failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// Wire encryption or decryption failed.
    #[error("wire: {0}")]
    Wire(#[from] WireError),

    /// Shaping wrap or unwrap failed.
    #[error("shape: {0}")]
    Shape(#[from] ShapingError),

    /// JSON serialisation or deserialisation failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// The session cookie was invalid, the session expired, or
    /// the server responded with a status the run loop treats
    /// as "re-check-in" (400, 401, 403, 404).
    ///
    /// Carried separately from `Status` so the run loop can
    /// branch on it without re-deriving the check from the
    /// status code.
    #[error("session invalid: {0}")]
    SessionInvalid(String),

    /// Any other transport failure. The string is a diagnostic,
    /// not a structured error.
    #[error("{0}")]
    Other(String),
}

impl TransportError {
    /// Whether this error means "the session is no longer
    /// valid — re-check-in on the next tick."
    ///
    /// Matches the Go tree's `isSessionInvalid`: a 400, 401,
    /// 403, or 404 response. Any other error (network,
    /// timeout, 5xx) is retried without re-check-in.
    pub fn is_session_invalid(&self) -> bool {
        match self {
            Self::SessionInvalid(_) => true,
            Self::Status { got, .. } => {
                matches!(*got, 400 | 401 | 403 | 404)
            }
            _ => false,
        }
    }
}

/// The transport contract.
///
/// Every method takes `&self` (transports are shared across the
/// agent's tasks) and `&WireSession` (which may be `Disabled`).
/// `check_in` builds the `CheckinRequest` from the passed
/// pieces; the transport does not read the agent's identity
/// from global state.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// The transport's name, for diagnostics. Returned as a
    /// `&'static str` because every transport is a compile-time
    /// choice; there is no runtime-constructed name.
    fn name(&self) -> &'static str;

    /// `POST /beacon`. Returns the session cookie and the
    /// initial scheduling parameters.
    ///
    /// `identity` is the agent's identity struct, already
    /// populated by `gather_identity`. `agent_pubkey_pem` is
    /// the base64-encoded PEM of the agent's ECDSA public key
    /// (empty on a stager build). `identity_sig` is the
    /// base64-encoded ECDSA signature over
    /// `machine_id|hostname|username|os|identity_ts` (empty on
    /// a stager build). `identity_ts` is the Unix timestamp
    /// the signature covers (0 on a stager build).
    async fn check_in(
        &self,
        identity: &Identity,
        agent_pubkey_pem: &str,
        identity_sig: &str,
        identity_ts: i64,
        wire: &crate::crypto::wire::WireSession,
    ) -> Result<CheckinResponse, TransportError>;

    /// `GET /tasks`. Returns the queue of pending tasks and
    /// applies any `X-Beacon-*` scheduling headers to the
    /// shared state.
    async fn fetch_tasks(
        &self,
        wire: &crate::crypto::wire::WireSession,
    ) -> Result<Vec<Task>, TransportError>;

    /// `POST /results`. Uploads a task result.
    async fn post_result(
        &self,
        r: TaskResult,
        wire: &crate::crypto::wire::WireSession,
    ) -> Result<(), TransportError>;

    /// Release any held resources. Called once on agent
    /// shutdown. A transport that holds no resources (HTTP
    /// with a connection pool) is a no-op; a transport that
    /// holds a socket (TCP bind) closes it.
    async fn close(&self) -> Result<(), TransportError>;
}