//! Agent core: construction, run loop, and dispatch.
//!
//! | File | Replaces |
//! |------|----------|
//! | `agent.rs` | `Main()`, `Agent`, `newAgent()`, `splitTransportModes()` |
//! | `run_loop.rs` | `.run()`, `.checkin()`, `.pollAndRun()`, `.sleep()`, `.rngIntn()`, `.shapeForOp()` |
//! | `dispatch.rs` | `.execute()` and every verb |
//! | `helpers.rs` | `encodeOutput`, `sanitizedEnv`, `mergeStreams`, `splitScriptArgs`, `truncate`, `mustGetwd` |
//! | `identity.rs` | `GatherIdentity`, `ParseECDSAPublicKey`, `parseECDSAPrivateKey`, `SignPayload`, `localOutboundAddr` |
//! | `tls_config.rs` | `BuildTLSConfig`, `BuildDoHTLSConfig`, `defaultProfile` |
//! | `diag.rs` | `diag`-adjacent helpers: `parse_clock`, `format_work_hours`, `inside_work_hours` |

pub mod agent;
pub mod diag;
pub mod dispatch;
pub mod helpers;
pub mod identity;
pub mod result;
pub mod run_loop;
pub mod transport_ring;
pub mod tls_config;
pub mod verify;

pub use agent::{new_agent, run_agent, split_transport_modes, Agent, AgentError, Config};