//! Stager support modules.
//!
//! The stager binary (`src/bin/stager.rs`) is a minimal
//! first-stage implant that fetches the full agent and executes
//! it in memory. The loader in this module is the last step —
//! everything before it (check-in, payload fetch, signature
//! verify, SHA-256 verify, decrypt) lives in `stager.rs` itself
//! so that a change to the loader does not touch the network
//! code and vice versa.

pub mod loader;