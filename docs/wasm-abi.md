# WASM extension ABI v1

Extensions are sandboxed WASM modules pushed over the signed task
channel. They are only compiled in with `--wasm-extensions`
(`wasm_host` tag).

## Compatibility

- ABI v1 is frozen. Additive host functions bump the minor version and
  are optional; a breaking change is ABI v2 and a new
  `abi_version()` value.
- A module that exports `abi_version()` must return `1`.
- Removing an ABI v1 host function requires a major release.

## Required exports

| Export | Type | Meaning |
|---|---|---|
| `run` | `() -> i32` | Entry point; `0` is success, non-zero is reported as an error. |
| `abi_version` | `() -> i32` | Optional; must return `1`. |

## Host imports

| Import | Signature | Meaning |
|---|---|---|
| `host_out` | `(ptr, len) -> i32` | Append bytes to task output; returns bytes written or a negative error. |
| `host_read` | `(ptr, len) -> i32` | Read task stdin; returns bytes read, `0` at EOF, negative on error. |
| `host_size` | `() -> i32` | Bytes available on stdin, or negative. |
| `host_env` | `(name_ptr, name_len, out_ptr, out_cap) -> i32` | Environment value length, or negative. |
| `host_args` | `(ptr, len) -> i32` | Space-joined task arguments. |
| `host_err` | `(ptr, len) -> i32` | Write to task stderr. |
| `host_time_ms` | `() -> i64` | Wall clock, milliseconds. |

Pointers refer to the caller's linear memory.

## Limits

| Limit | Value |
|---|---|
| Module size | 2 MiB |
| Linear memory | 16 MiB |
| Single host read | 8 MiB |
| Wall-clock deadline | 5 s, capped by the task timeout |

A module that exceeds the deadline is closed; an infinite loop cannot
wedge the task worker. Memory is not shared between modules.

## Minimal example

```wat
(module
  (import "env" "host_out" (func $out (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "hello")
  (func (export "abi_version") (result i32) i32.const 1)
  (func (export "run") (result i32)
    i32.const 0 i32.const 5 call $out drop
    i32.const 0))
```

```bash
wat2wasm hello.wat -o hello.wasm
extension load hello.wasm
extension call hello
```

## Rules

- Do not assume a writable filesystem; use `host_out` / `host_err`.
- Keep `run` short; return 0 and let the host collect output.
- A module may be unloaded at any time. Reload swaps the module only
  after the new one starts successfully.
