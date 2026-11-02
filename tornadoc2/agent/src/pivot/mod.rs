//! Peer-to-peer pivot protocol.
//!
//! Replaces `internal/pivot/`. Four files:
//!
//! | File | Replaces |
//! |------|----------|
//! | `protocol.rs` | `protocol.go` — constants, message types, `FrameIO`, sign/verify, HKDF |
//! | `session.rs` | `session.go` — `Session`, `Role` (frame encode/decode deferred) |
//! | `client.rs` | `client.go` — `client_handshake` |
//! | `server.rs` | `server.go` — `parent_verify_and_respond` (not yet ported) |
//!
//! # Two divergences from the README that the port preserves
//!
//! See `protocol.rs`'s module doc. In short: the Go code's HKDF
//! info string is `"tornadoc2-pivot-v1"` (README says `v2`), and
//! the parent's ECDH contribution is an ephemeral, not the static
//! pivot key (README says static). The port matches the code, not
//! the README.

pub mod client;
pub mod protocol;
pub mod session;
pub mod server;

pub use protocol::{
    child_signing_payload, derive_session, parent_signing_payload,
    sign_payload, verify_signature, within_skew, AckMsg, ErrMsg,
    FrameIO, HelloMsg, PivotError, HKDF_INFO, PIVOT_VERSION,
};
pub use session::{Role, Session};

pub use client::client_handshake;