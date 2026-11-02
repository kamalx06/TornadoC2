//! WASM extension host.
//!
//! When the `wasm-host` Cargo feature is enabled, this module provides
//! a sandboxed host for WASM extensions loaded over the ECDSA-signed
//! task channel. When the feature is off, every public entry point
//! returns a clear error and the crate does not link an interpreter.
//!
//! The host ABI matches the Go tree it replaces, one for one:
//!
//! Imports (provided by the host to the guest):
//!   host_out(ptr: i32, len: i32)
//!   host_read(path_ptr: i32, path_len: i32,
//!             buf_ptr: i32, buf_cap: i32) -> i32
//!   host_env(name_ptr: i32, name_len: i32,
//!            buf_ptr: i32, buf_cap: i32) -> i32
//!   host_args(buf_ptr: i32, buf_cap: i32) -> i32
//!
//! Exports (provided by the guest to the host):
//!   run() -> i32
//!
//! The interpreter is `wasmi` — pure Rust, no JIT, no `PROT_EXEC`
//! mapping, and roughly 1 MB of binary weight rather than the 3–7 MB
//! `wasmtime` costs. The 16 MiB memory ceiling is enforced through
//! `StoreLimitsBuilder`.
//!
//! # Feature gating
//!
//! The whole module is feature-gated. `is_extension_verb()` and the
//! `WASM_HOST_ENABLED` const are always available so the dispatch
//! loop can route extension verbs (or filter them out) regardless of
//! whether the feature is on. Only the four `extension_*` functions
//! are conditional, and their stubs return the same clear error the
//! Go code would have returned if `wazero` had failed to initialise.
//!
//! # Concurrency
//!
//! The Go tree wrapped the runtime in a `sync.Mutex`. The Rust
//! version keeps the same shape — one `Mutex<ExtensionHost>` behind a
//! `OnceLock` — so calls from any thread serialise on the same lock.
//! The underlying `wasmi::Store` is `Send` when its data type is
//! `Send`, which `HostState` is (`Vec<u8>`, `Vec<String>`,
//! `StoreLimits` are all `Send`), so the mutex compiles and behaves
//! as expected.
//!
//! # Notable differences from the Go tree
//!
//! - **No unique module names.** `wazero` required a unique module
//!   name per instantiation so replacing an extension under the same
//!   logical name would not collide. `wasmi` identifies instances by
//!   `Instance` handle, not by name, so the temp-name generation the
//!   Go code did is unnecessary. Replacements drop the old handle
//!   and store the new one under the same logical key.
//!
//! - **No context cancellation.** `wasmi` does not accept a
//!   cancellation context on `TypedFunc::call`. If an extension runs
//!   forever, the call blocks until it returns. Timeouts are enforced
//!   by the task layer (the server-side task timeout), not by the
//!   extension host. This matches the practical behaviour of the Go
//!   code — `wazero` respects context cancellation only when the
//!   guest cooperates by yielding.

use crate::core::helpers::encode_output;
use crate::protocol::Result as TaskResult;
use crate::protocol::Task;

/// True when the WASM extension host was compiled into this binary.
/// The build-time feature gate is the only knob; there is no runtime
/// toggle. A caller can use this to filter extension verbs out of
/// the per-beacon catalogue when the host is absent.
pub const WASM_HOST_ENABLED: bool = cfg!(feature = "wasm-host");

/// Every verb handled by this module. The dispatch loop can route on
/// this without knowing whether the host is compiled in — the stubs
/// return a clear error if it is not.
pub fn is_extension_verb(verb: &str) -> bool {
    matches!(
        verb,
        "extension_register"
            | "extension_call"
            | "extension_list"
            | "extension_unload"
    )
}

// ---------------------------------------------------------------------
// Stub when the feature is off.

#[cfg(not(feature = "wasm-host"))]
mod imp {
    use super::*;

    const MSG: &str =
        "WASM extension host not compiled into this build; \
         rebuild with --wasm-extensions (or \"wasm_extensions\": true \
         in a JSON build config) to enable the `extension` verbs";

    pub fn extension_register(t: Task) -> TaskResult {
        TaskResult { id: t.id, error: Some(MSG.into()), ..Default::default() }
    }

    pub fn extension_call(t: Task) -> TaskResult {
        TaskResult { id: t.id, error: Some(MSG.into()), ..Default::default() }
    }

    pub fn extension_list(t: Task) -> TaskResult {
        TaskResult { id: t.id, error: Some(MSG.into()), ..Default::default() }
    }

    pub fn extension_unload(t: Task) -> TaskResult {
        TaskResult { id: t.id, error: Some(MSG.into()), ..Default::default() }
    }
}

// ---------------------------------------------------------------------
// Real implementation when the feature is on.

#[cfg(feature = "wasm-host")]
mod imp {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::{Mutex, OnceLock};

    use wasmi::{
        Caller, Engine, Extern, Instance, Linker, Module, Store,
        StoreLimits, StoreLimitsBuilder,
    };

    /// Per-store state. The host functions read `args` and append to
    /// `out`; `limits` is the `StoreLimits` the store was created
    /// with, kept alive for the lifetime of the host.
    struct HostState {
        out: Vec<u8>,
        args: Vec<String>,
        limits: StoreLimits,
    }

    impl HostState {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                args: Vec::new(),
                // 256 pages × 64 KiB/page = 16 MiB ceiling,
                // matching the Go tree's WithMemoryLimitPages(256).
                limits: StoreLimitsBuilder::new()
                    .memory_size(16 * 1024 * 1024)
                    .build(),
            }
        }
    }

    /// One host for the whole process. Holds the engine, the shared
    /// linker (so every extension sees the same imports), the single
    /// store, and the map of logical-name → instantiated module.
    struct ExtensionHost {
        engine: Engine,
        linker: Linker<HostState>,
        store: Store<HostState>,
        modules: HashMap<String, Instance>,
    }

    impl ExtensionHost {
        fn new() -> Result<Self, String> {
            let engine = Engine::default();
            let mut store = Store::new(&engine, HostState::new());
            store.limiter(|s| &mut s.limits);

            let mut linker: Linker<HostState> = Linker::new(&engine);

            linker
                .func_wrap(
                    "env",
                    "host_out",
                    |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                        if len <= 0 {
                            return;
                        }
                        let mem = match caller.get_export("memory") {
                            Some(Extern::Memory(m)) => m,
                            _ => return,
                        };
                        let start = ptr as u32 as usize;
                        let end = start + len as u32 as usize;
                        let bytes = match mem.data(&caller).get(start..end) {
                            Some(b) => b.to_vec(),
                            None => return,
                        };
                        caller.data_mut().out.extend_from_slice(&bytes);
                    },
                )
                .map_err(|e| format!("linker host_out: {e}"))?;

            linker
                .func_wrap(
                    "env",
                    "host_read",
                    |mut caller: Caller<'_, HostState>,
                     path_ptr: i32,
                     path_len: i32,
                     buf_ptr: i32,
                     buf_cap: i32|
                     -> i32 {
                        if buf_cap <= 0 {
                            return 0;
                        }
                        let mem = match caller.get_export("memory") {
                            Some(Extern::Memory(m)) => m,
                            _ => return 0,
                        };
                        let ps = path_ptr as u32 as usize;
                        let pe = ps + path_len as u32 as usize;
                        let path_bytes =
                            match mem.data(&caller).get(ps..pe) {
                                Some(b) => b.to_vec(),
                                None => return 0,
                            };
                        let path = match std::str::from_utf8(&path_bytes) {
                            Ok(s) => s,
                            Err(_) => return 0,
                        };
                        let mut file = match std::fs::File::open(path) {
                            Ok(f) => f,
                            Err(_) => return 0,
                        };
                        let mut buf = vec![0u8; buf_cap as usize];
                        let n = match file.read(&mut buf) {
                            Ok(n) => n,
                            Err(_) => return 0,
                        };
                        let bs = buf_ptr as u32 as usize;
                        if mem
                            .write(&mut caller, bs, &buf[..n])
                            .is_err()
                        {
                            return 0;
                        }
                        n as i32
                    },
                )
                .map_err(|e| format!("linker host_read: {e}"))?;

            linker
                .func_wrap(
                    "env",
                    "host_env",
                    |mut caller: Caller<'_, HostState>,
                     name_ptr: i32,
                     name_len: i32,
                     buf_ptr: i32,
                     buf_cap: i32|
                     -> i32 {
                        if buf_cap <= 0 {
                            return 0;
                        }
                        let mem = match caller.get_export("memory") {
                            Some(Extern::Memory(m)) => m,
                            _ => return 0,
                        };
                        let ns = name_ptr as u32 as usize;
                        let ne = ns + name_len as u32 as usize;
                        let name_bytes =
                            match mem.data(&caller).get(ns..ne) {
                                Some(b) => b.to_vec(),
                                None => return 0,
                            };
                        let name = match std::str::from_utf8(&name_bytes)
                        {
                            Ok(s) => s,
                            Err(_) => return 0,
                        };
                        let val = std::env::var(name).unwrap_or_default();
                        let bytes = val.as_bytes();
                        let n = bytes.len().min(buf_cap as usize);
                        let bs = buf_ptr as u32 as usize;
                        if mem
                            .write(&mut caller, bs, &bytes[..n])
                            .is_err()
                        {
                            return 0;
                        }
                        n as i32
                    },
                )
                .map_err(|e| format!("linker host_env: {e}"))?;

            linker
                .func_wrap(
                    "env",
                    "host_args",
                    |mut caller: Caller<'_, HostState>,
                     buf_ptr: i32,
                     buf_cap: i32|
                     -> i32 {
                        if buf_cap <= 0 {
                            return 0;
                        }
                        let mem = match caller.get_export("memory") {
                            Some(Extern::Memory(m)) => m,
                            _ => return 0,
                        };
                        // Arguments are exposed as a NUL-separated
                        // string, matching the Go tree.
                        let joined = caller.data().args.join("\0");
                        let bytes = joined.as_bytes();
                        let n = bytes.len().min(buf_cap as usize);
                        let bs = buf_ptr as u32 as usize;
                        if mem
                            .write(&mut caller, bs, &bytes[..n])
                            .is_err()
                        {
                            return 0;
                        }
                        n as i32
                    },
                )
                .map_err(|e| format!("linker host_args: {e}"))?;

            Ok(Self { engine, linker, store, modules: HashMap::new() })
        }

        fn register(&mut self, name: &str, wasm: &[u8]) -> Result<(), String> {
            let module = Module::new(&self.engine, wasm)
                .map_err(|e| format!("compile: {e}"))?;
            let instance = self
                .linker
                .instantiate(&mut self.store, &module)
                .map_err(|e| format!("instantiate: {e}"))?
                .start(&mut self.store)
                .map_err(|e| format!("start: {e}"))?;

            // Dropping the old handle releases it. wasmi reclaims the
            // underlying resources when the handle is gone and there
            // are no remaining references; there is no explicit
            // `Instance::drop` call to make.
            self.modules.insert(name.to_string(), instance);
            Ok(())
        }

        fn call(&mut self, name: &str, args: &[String])
            -> Result<(Vec<u8>, i32), String>
        {
            let instance = self
                .modules
                .get(name)
                .copied()
                .ok_or_else(|| format!("not loaded: {name}"))?;

            // Reset per-call state and stash the arguments before
            // entering the guest.
            {
                let state = self.store.data_mut();
                state.out.clear();
                state.args = args.to_vec();
            }

            let run = instance
                .get_typed_func::<(), i32>(&self.store, "run")
                .map_err(|_| "module does not export `run`".to_string())?;

            let exit_code = run
                .call(&mut self.store, ())
                .map_err(|e| format!("call: {e}"))?;

            let out = self.store.data_mut().out.clone();
            Ok((out, exit_code))
        }

        fn list(&self) -> Vec<String> {
            let mut names: Vec<String> =
                self.modules.keys().cloned().collect();
            names.sort();
            names
        }

        fn unload(&mut self, name: &str) -> bool {
            self.modules.remove(name).is_some()
        }
    }

    /// Process-wide host. The `Result` is cached so a failed init is
    /// reported consistently on every call — same shape as the Go
    /// tree's `extInitErr`.
    static HOST: OnceLock<Result<Mutex<ExtensionHost>, String>> =
        OnceLock::new();

    fn host() -> Result<&'static Mutex<ExtensionHost>, String> {
        match HOST.get_or_init(|| {
            ExtensionHost::new().map(Mutex::new)
        }) {
            Ok(m) => Ok(m),
            Err(e) => Err(e.clone()),
        }
    }

    fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() || name.len() > 64 {
            return Err(
                "extension name must be 1-64 characters".into(),
            );
        }
        for ch in name.chars() {
            let ok = ch == '_'
                || ch == '-'
                || ch == '.'
                || ch.is_ascii_alphanumeric();
            if !ok {
                return Err(
                    "extension name may contain only letters, \
                     digits, '_', '-', '.'"
                        .into(),
                );
            }
        }
        Ok(())
    }

    pub fn extension_register(t: Task) -> TaskResult {
        if t.args.len() < 2 {
            return TaskResult {
                id: t.id,
                error: Some(
                    "extension_register requires <name> <b64_wasm>"
                        .into(),
                ),
                ..Default::default()
            };
        }
        let name = t.args[0].clone();
        if let Err(e) = validate_name(&name) {
            return TaskResult {
                id: t.id,
                error: Some(e),
                ..Default::default()
            };
        }
        let raw = match base64_decode(&t.args[1]) {
            Ok(r) => r,
            Err(e) => {
                return TaskResult {
                    id: t.id,
                    error: Some(format!("base64: {e}")),
                    ..Default::default()
                };
            }
        };

        let m = match host() {
            Ok(m) => m,
            Err(e) => {
                return TaskResult {
                    id: t.id,
                    error: Some(format!(
                        "extension host init failed: {e}"
                    )),
                    ..Default::default()
                };
            }
        };
        let mut guard = m.lock().expect("extensions mutex poisoned");
        if let Err(e) = guard.register(&name, &raw) {
            return TaskResult {
                id: t.id,
                error: Some(e),
                ..Default::default()
            };
        }
        TaskResult {
            id: t.id,
            output: encode_output(
                format!("loaded {name}\n").as_bytes(),
            ),
            ..Default::default()
        }
    }

    pub fn extension_call(t: Task) -> TaskResult {
        if t.args.is_empty() {
            return TaskResult {
                id: t.id,
                error: Some(
                    "extension_call requires <name>".into(),
                ),
                ..Default::default()
            };
        }
        let name = t.args[0].clone();
        let args: Vec<String> = t.args[1..].to_vec();

        let m = match host() {
            Ok(m) => m,
            Err(e) => {
                return TaskResult {
                    id: t.id,
                    error: Some(format!(
                        "extension host init failed: {e}"
                    )),
                    ..Default::default()
                };
            }
        };
        let mut guard = m.lock().expect("extensions mutex poisoned");
        match guard.call(&name, &args) {
            Ok((out, exit_code)) => TaskResult {
                id: t.id,
                output: encode_output(&out),
                exit_code,
                ..Default::default()
            },
            Err(e) => TaskResult {
                id: t.id,
                error: Some(e),
                ..Default::default()
            },
        }
    }

    pub fn extension_list(t: Task) -> TaskResult {
        let m = match host() {
            Ok(m) => m,
            Err(e) => {
                return TaskResult {
                    id: t.id,
                    error: Some(format!(
                        "extension host init failed: {e}"
                    )),
                    ..Default::default()
                };
            }
        };
        let guard = m.lock().expect("extensions mutex poisoned");
        let names = guard.list();
        let body = serde_json::to_vec(&names).unwrap_or_else(|_| b"[]".to_vec());
        TaskResult {
            id: t.id,
            output: encode_output(&body),
            ..Default::default()
        }
    }

    pub fn extension_unload(t: Task) -> TaskResult {
        if t.args.is_empty() {
            return TaskResult {
                id: t.id,
                error: Some(
                    "extension_unload requires <name>".into(),
                ),
                ..Default::default()
            };
        }
        let name = t.args[0].clone();

        let m = match host() {
            Ok(m) => m,
            Err(e) => {
                return TaskResult {
                    id: t.id,
                    error: Some(format!(
                        "extension host init failed: {e}"
                    )),
                    ..Default::default()
                };
            }
        };
        let mut guard = m.lock().expect("extensions mutex poisoned");
        let removed = guard.unload(&name);
        let msg = if removed {
            format!("unloaded {name}\n")
        } else {
            format!("not loaded: {name}\n")
        };
        TaskResult {
            id: t.id,
            output: encode_output(msg.as_bytes()),
            ..Default::default()
        }
    }

    fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------
// Public re-exports. The functions are identical in both feature
// states; the stubs and the real impl share signatures.

pub use imp::{
    extension_call, extension_list, extension_register,
    extension_unload,
};