//! Non-Windows stub for the SMB pivot transport.
//!
//! Replaces `transport_smb_other.go`. Construction fails with a
//! specific error; every trait method returns the same error. The
//! type exists so the crate compiles on Linux and macOS, and the
//! `agent.rs` transport-dispatch path compiles identically on
//! every platform.

use async_trait::async_trait;
use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::crypto::wire::WireSession;
use crate::features::shaping::ShapingSpec;
use crate::protocol::{
    CheckinResponse, Identity, Task, TaskResult, Transport,
    TransportError,
};

const ERR: &str = "smb transport requires a Windows target";

pub struct SmbTransport;

impl SmbTransport {
    pub fn new(
        _pipe_name: &str,
        _agent_priv: SigningKey,
        _pivot_pub: VerifyingKey,
        _identity: &Identity,
        _shaping: Option<ShapingSpec>,
    ) -> Result<Self, TransportError> {
        Err(TransportError::Other(ERR.into()))
    }
}

#[async_trait]
impl Transport for SmbTransport {
    fn name(&self) -> &'static str {
        "smb"
    }

    async fn check_in(
        &self,
        _identity: &Identity,
        _agent_pubkey_pem: &str,
        _identity_sig: &str,
        _identity_ts: i64,
        _wire: &WireSession,
    ) -> Result<CheckinResponse, TransportError> {
        Err(TransportError::Other(ERR.into()))
    }

    async fn fetch_tasks(
        &self,
        _wire: &WireSession,
    ) -> Result<Vec<Task>, TransportError> {
        Err(TransportError::Other(ERR.into()))
    }

    async fn post_result(
        &self,
        _r: TaskResult,
        _wire: &WireSession,
    ) -> Result<(), TransportError> {
        Err(TransportError::Other(ERR.into()))
    }

    async fn close(&self) -> Result<(), TransportError> {
        Ok(())
    }
}