//! Cryptographic primitives for the agent.
//!
//! `wire` is the AES-256-GCM request/response envelope keyed off
//! a P-256 ECDH exchange with the server's long-lived public key.

pub mod wire;