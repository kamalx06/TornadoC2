pub mod diag;
pub mod http;
pub mod dns;
pub mod smb;
pub mod doh;
pub mod quic;
pub mod websocket;

// =====================================================================
// Type re-exports (was aliases.go)
// =====================================================================

pub use crate::crypto::wire::WireSession;
pub use crate::features::shaping::ShapingSpec;
pub use crate::protocol::{
    CheckinRequest, CheckinResponse, Identity, Profile, Task,
    TaskResult,
};