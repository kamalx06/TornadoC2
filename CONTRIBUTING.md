# Contributing to TornadoC2

**Legal Disclaimer.** TornadoC2 is a dual-use post-exploitation
framework intended for authorized security testing and research. Its
features can also be misused, and the project cannot determine the
operator's intent.

Use TornadoC2 only on systems you own or have explicit permission to
test. You are responsible for your actions and for following all
applicable laws. The maintainers do not support or authorize illegal
or unethical use.

By contributing to TornadoC2, you agree that your work is intended
for lawful and authorized security testing, research, or other
legitimate purposes. Contributions primarily intended to enable
unauthorized access or cause harm will be rejected. Dual-use
functionality by itself is not a reason for rejection, since
security research often involves capabilities that can be used for
both legitimate and malicious purposes.

---

> **Status: the agent is Rust.** The Go agent was ported to Rust
> as a ground-up rewrite — no FFI to Go, no cgo, no embedded Go
> runtime. The wire protocol, compile-time configuration model,
> ECDSA identity, and task signing are unchanged. The Rust agent
> under `agent/src/` is the only agent this tree ships; there is
> no Go tree to maintain.
>
> Agent-side contributions — new verbs, new evasions, new
> transports, new pivot transports — are open and target the Rust
> crate. See the sections below for the Rust patterns. The server
> side — handler, operator console, pivot infrastructure, audit
> chain, credential and loot stores, team chat, dead-man's switch,
> wire protocol — is unaffected by the rewrite and continues to
> receive contributions unchanged.
>
> See [README › The Rust agent](README.md#the-rust-agent) for the
> rationale, and [README › Extending TornadoC2](README.md#extending-tornadoc2)
> for the extension surfaces.

---

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Before You Start](#before-you-start)
- [Reporting Bugs](#reporting-bugs)
- [Coding Conventions](#coding-conventions)
- [What Not to Submit](#what-not-to-submit)
- [Contributing an Agent Verb](#contributing-an-agent-verb)
- [Contributing an Evasion Feature](#contributing-an-evasion-feature)
- [Contributing a Transport](#contributing-a-transport)
- [Contributing a Pivot Transport](#contributing-a-pivot-transport)
- [Contributing a WASM Extension](#contributing-a-wasm-extension)
- [Contributing a C2 Profile](#contributing-a-c2-profile)
- [Contributing a Build Config Example](#contributing-a-build-config-example)
- [Contributing an Operator-Console Feature](#contributing-an-operator-console-feature)
- [Pull Request Checklist](#pull-request-checklist)
- [Code of Conduct](#code-of-conduct)
- [Questions](#questions)

---

## Ways to Contribute

Not every contribution has to be code. The most useful
contributions, roughly in order of impact:

1. **Bug reports** with reproducible steps — see
   [Reporting Bugs](#reporting-bugs).
2. **Security reports** — do not open a public issue for security
   flaws. See [SECURITY.md](SECURITY.md).
3. **Agent contributions.** New native verbs, new evasion
   primitives, new platform support on the Rust agent. The
   pattern is the same mechanical template every existing verb
   follows — see
   [Contributing an Agent Verb](#contributing-an-agent-verb).
4. **Transport contributions.** New transports, new pivot
   transports, and improvements to the ten in-tree transports and
   the peer-to-peer pivot model. The six-file glue is described
   under [Contributing a Transport](#contributing-a-transport).
5. **WASM extensions** — new capabilities pushed to the agent at
   runtime.
6. **C2 profiles** — new HTTP fingerprints that mimic a specific
   application's traffic pattern, or improvements to the extended
   shaping/envelope schema.
7. **Operator-console features** — credential vault, loot store,
   notes, webhooks, session graph, team chat, dead-man's switch.
   These never touch the agent and are the least risky place to
   start.
8. **Build config examples** — a config that demonstrates a
   deployment shape the current examples do not cover.
9. **Fixes for existing code** that breaks on specific OS
   versions, Go toolchain versions, or Python versions.
10. **Documentation improvements** — README, extension authoring
    guide, inline docstrings, examples.
11. **Code review** on open pull requests.
12. **Testing across environments** — different Linux distros,
    Windows versions, Python versions, Go toolchain versions,
    filesystems.

If you are unsure whether something is worth contributing, open an
issue first and describe what you have in mind. It is better to
discuss the approach before you spend time writing code that may
not fit the project's direction.

---

## Before You Start

### Development environment

**Operator-side (Python):**

- Python 3.7 or later.
- OpenSSL — for TLS / mTLS certificate generation.
- Git — optional; needed for `git status` / `git log` before a
  build.
- `flask` (`pip install flask`) — HTTP listener.
- `cryptography` (`pip install cryptography`) — ECDSA signing,
  ECDH wire encryption, scrypt derivation, P-256 keypair
  generation for the pivot keypair.
- `dnslib` (`pip install dnslib`) — DNS and DoH transport.
- `aioquic` (`pip install aioquic`) — QUIC / HTTP/3 transport.
  Optional; the QUIC listener refuses to start without it and
  leaves the other transports running.
- `simple-websocket` (`pip install simple-websocket`) — WebSocket
  transport. Optional; the WebSocket listener refuses to start
  without it and leaves the other transports running.
- `pyroute2` (`pip install pyroute2`) — WireGuard transport.
  Optional; the WireGuard listener refuses to start without it.
  Requires the `wireguard` kernel module and `CAP_NET_ADMIN` on
  the Python process.

**Agent-side (Rust):**

- **Rust stable toolchain** (1.75 or later) and the target
  triples the builder cross-compiles to:
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-pc-windows-gnu`, `i686-pc-windows-gnu`. `rustup target
  add <triple>` installs each. The pins live in
  `agent/rust-toolchain.toml`.
- `cargo build` inside `agent/` resolves every dependency in
  `Cargo.toml` from the local cargo cache. The direct
  dependencies are the crate root under `agent/Cargo.toml`;
  key ones:
  - `reqwest` + `rustls` — HTTP transport
  - `quinn` — QUIC / HTTP/3 transport
  - `tokio-tungstenite` — WebSocket transport
  - `hickory-resolver` + `hickory-proto` — DNS and DoH
  - `boringtun` — WireGuard transport
  - `boring` — BoringSSL ClientHello fingerprinting
  - `aes-gcm`, `p256`, `sha2`, `hkdf` — crypto
  - `serde` + `serde_json` — wire types
  - `windows` — Windows API bindings
  - `wasmi` (default) or `wasmtime` — WASM extension host;
    pulled in only when `--features wasm-host` is enabled

  A build that does not select one of those transports still
  resolves the crate in `Cargo.lock`, because the dependency is
  unconditional in `Cargo.toml`. The `lto = "fat"` setting in
  `[profile.release]` prunes unused code from the final binary,
  so a build with `transport_mode: "http"` does not ship QUIC
  code — but the crate is still in the dependency graph.

**Optional:**

- `UPX` — binary packing (used by `paranoid`).
- `Donut` — shellcode output format, `execute-assembly`, and
  `inject: true` builds on Windows
  ([TheWover/donut](https://github.com/TheWover/donut/releases)).
- **`wasm32-unknown-unknown` target** — building WASM
  extensions that the agent loads via `--wasm-extensions`.
  `rustup target add wasm32-unknown-unknown`.
- **`install-rust-build.sh`** — one-shot bootstrap: verifies the
  Rust toolchain and target triples, builds `Bootstrap.dll`
  from `Bootstrap.cs`, warms the Cargo cache, runs `cargo fmt
  --check` and `cargo clippy`, and cross-compiles for both
  target triples. Run it after any change to `agent/Cargo.toml`.
- **`tornadoc2/shapecheck.py`** — profile validator. Ships in-tree;
  no install required beyond the Python standard library. Run
  `python3 tornadoc2/shapecheck.py` before submitting any profile
  change. See [Testing a change](#testing-a-change) below.
- `wireguard-tools` — the `wg` command, used once on the team
  server to generate the WireGuard keypair on first launch.
- **PySide6** (`pip install PySide6`) — required only for the
  `--gui` operator console. The CLI does not import it. The
  wheel bundles the Qt 6 runtime; on Linux the `xcb` and
  `wayland` platform plugins load against the host's system
  libraries (`libGL`, `libEGL`, `libxkbcommon-x11`, the
  `libxcb-*` family, `libwayland-*`). `install-deps-client.sh`
  autodetects the session and installs the matching set on
  Debian-, RHEL-, and Arch-derived systems.

  The CLI is unaffected if PySide6 is missing. A headless host
  can import PySide6 for a smoke test with
  `QT_QPA_PLATFORM=offscreen`.

### Cloning and running

```bash
git clone <repo-url>
cd <repo-dir>
pip install flask cryptography dnslib
# optional transports:
pip install aioquic simple-websocket pyroute2
# optional GUI:
pip install PySide6
python tornadoc2.py --beacon-port 8881
```

The handler prints a startup banner listing every listener it
started. If the beacon listener fails to bind, check that no other
process holds port 8881.

A transport that refuses to start because its Python package is
missing leaves the other transports running. The startup banner
names the missing package.

The operator client has two frontends. The CLI is the default:

    python beacon-client.py -c alice.cfg

The PySide6 GUI is opt-in with `--gui`:

    python beacon-client.py -c alice.cfg --gui

Both dispatch through the same `Client` methods. A change to the
CLI's dispatch table is picked up by the GUI without modification.

### Running a build

```
beacon> beacon-build
```

The wizard walks through every parameter. For scripted builds, use
`beacon-build -c <config.json>` with a config from `examples/`.

### Testing a change

Before opening a pull request:

1. **Build the agent for the platform your change touches.** A
   change to `agent/src/core/` should compile for Linux and
   Windows, both amd64 and arm64:

       cd agent
       cargo build --release --target x86_64-unknown-linux-gnu \
                              --target x86_64-pc-windows-gnu \
                              --target aarch64-unknown-linux-gnu

   A change under `#[cfg(feature = "wasm-host")]` also needs
   `--features wasm-host` on the build, so both feature states
   are exercised.
2. **Run both the wizard and the config-file build path.** A
   change to `builder.py` should be exercised through both. The
   `tornadoc2/beacon_handler.py` wizard, the
   `tornado_client/repl.py` wizard, and the
   `tornado_client/gui.py` build form are three separate entry
   points to the same builder; a change to any of them should be
   visible through all three.
3. **Start the handler and check in a beacon.** A change to the
   listener, engine, a transport, or the pivot model should be
   exercised against a live agent built from the change.
4. **Exercise the security-relevant paths.** If your change is in
   `agent/src/crypto/wire.rs`, `agent/src/core/verify.rs`, or a
   verifier, test both the accept and reject paths with valid and
   invalid signatures. Note that `verify` in the Rust agent is a
   module (`core/verify.rs`), not a class.
5. **For a C2 profile or shaping change, run `shapecheck` and
   build the agent.** `shapecheck` catches the static classes —
   path syntax, `\w` divergence, placeholder placement, encoding
   errors — in one pass:

       python3 tornadoc2/shapecheck.py profiles/c2/your-profile.json

   Then build an agent against it. The agent's
   `ValidateShapingSpec` runs at build time; a profile whose
   declared `encoding` or `placement` does not round-trip through
   the agent's shape walker fails the build. Run the build, not
   just `shapecheck`.
6. **For a directory-wide profile change, run `shapecheck` against
   the whole directory.** Cross-profile checks (`XPR001`,
   `XPR002`) fire only when the tool scans more than one profile,
   and a path collision between a new profile and an existing one
   is a load-time failure for the handler.

       python3 tornadoc2/shapecheck.py profiles/c2/

The repository has no automated test suite. A contribution that
touches a security-relevant path should include a note describing
how you verified it, ideally with the exact commands you ran.

---

## Reporting Bugs

Before opening an issue, determine whether it is a security issue
or a general bug.

**Security bugs** — do **not** open a public issue. Report privately
through the process in [SECURITY.md](SECURITY.md). Security-relevant
areas include target-to-operator injection, signature verification,
wire encryption, cookie handling, extension sandbox escape,
session-log path traversal, build-time flag injection, pivot
fingerprint spoofing, remote operator privilege escalation,
capability-check bypass, the dead-man's switch's wipe or halt
sequence, and the audit chain's tamper detection.

**General bugs** — because the agent relies on native commands and
standard-library behavior that already exists on the target, and the
listener runs on top of Flask/Werkzeug, general bugs are expected.
Examples:

- A native verb returning wrong or missing output on a specific OS
  or architecture.
- The listener failing to start on a particular Python version.
- A transport refusing to start because a Python package was
  missing, without naming the package.
- Chunked transfer stalling or failing on a large file.
- The wizard misparsing a flag or failing to compile for a supported
  target.
- Session-reaper behavior forgetting a healthy beacon too early, or
  retaining a dead one too long.
- Build script producing an agent for the wrong OS or architecture.
- A pivot child not appearing in `beacons` after the parent checks
  in.
- A `migrate` failure on a specific target OS.
- The C2 profile validation accepting a profile that fails at
  runtime — a shaping block whose `extract` path does not survive
  the agent's round-trip; a `status` code the agent does not
  expect; a `cookie_name` the listener and the transport do not
  agree on.
- A `dns_label` block that the builder did not emit into the
  agent's linker flags, or that the listener did not pick up from
  the same profile.
- A profile whose `placement.kind` is `header` or `cookie`
  behaves correctly on HTTP and QUIC but produces unparsed
  responses on WebSocket.
- GUI rendering glitches, PySide6 startup failures, or input-routing
  bugs in the Log or Chat tabs.
- Help text, completion, or UI glitches.

For these, open a regular GitHub Issue without the `security` label.
Include:

- Target OS and CPU architecture.
- Operator OS, Python version, and CPU architecture.
- Rust toolchain version (from `rustc --version` and
  `cargo --version`), plus the output of
  `rustup show active-toolchain`.
- Which transports were enabled at the handler, and which were
  built into the agent.
- Whether the beacon was built with `--verbose`.
- The exact command or wizard path you ran.
- Any error messages, logs, or agent stderr returned.
- For pivot bugs: whether the parent, child, or team server is the
  affected component, and whether the transport is SMB or TCP.
- For C2 profile bugs: the profile name, the shaping block, and
  whether the build-time validation passed. If the profile
  validated but the agent failed at runtime, include the profile
  JSON.
- For GUI bugs: the Qt platform plugin in use (`xcb`, `wayland`,
  or `offscreen`), whether the same command works through the CLI,
  and any Qt diagnostic output on the client's stderr.

**Sanitize before posting.** Logs and screenshots may contain
callback URLs, session cookies, public keys, internal IPs,
usernames, hostnames, file paths, credentials, terminal control
characters, or maliciously crafted output from compromised targets.
Remove all of that before pasting anything into a public issue.

If you are unsure whether something is a security bug or a general
bug, report it privately through the process in
[SECURITY.md](SECURITY.md). It is better to over-report than to leak
a real flaw into a public issue.

---

## Coding Conventions

The project has a consistent style. Match it.

### Python

- **`from __future__ import annotations` at the top of every file.**
  Type hints throughout.
- **Type hints on public functions and class methods.** Internal
  helpers may skip them if the signature is obvious.
- **Docstrings explain *why*, not *what*.** The code says what it
  does; the docstring says what trade-off the author chose and
  what failure mode the surrounding code is guarding against.
- **Defensive error handling with actionable messages.** Do not
  catch and drop. If a call can fail, decide the correct behaviour
  — retry, refuse, log a specific message — and say so in the code.
- **Module-level constants for tunables.** A value a future
  maintainer might want to change belongs at the top of the file,
  named, with a one-line comment about its unit or shape.
- **No global mutable state in request paths.** The listener is
  threaded; anything that survives across requests should be an
  attribute on an object with a lock or a documented ownership
  story.
- **Capabilities gate every endpoint.** A new operator-facing
  route must be registered in `ROLE_CAPABILITIES` and enforced at
  `_with_cap`, not only on the client.
- **A profile-schema addition does not need a builder change.** The
  builder serializes the merged profile dict, obfuscates it, and
  embeds it as `-X main.ProfileJSON`. The agent parses it with
  `json.Unmarshal` into its `protocol.Profile` struct. Adding a
  field to the schema means adding a Go struct field, not a new
  linker flag or a new builder branch. The `dns_label` block is
  the exception — it is emitted as dedicated linker flags because
  the DNS transport reads it before the profile is parsed.

### Rust

- **`TC2_*` environment variables for build-time values.**
  `agent/build.rs` reads each `TC2_*` var and emits a
  `pub const` into `config_generated.rs`. The builder sets the
  env var; the agent reads the const. Renaming requires a
  matching change in `beacon/builder.py` (the emitter) and
  `agent/src/config.rs` (the consumer). The `-X`-linker-flag
  pattern the Go tree used has no Rust equivalent — build.rs +
  `env!` is the equivalent.
- **`diag!` for anything that should only appear with
  `--verbose`.** Never `println!` from the agent. The macro
  expands to nothing in a non-verbose build; the visible
  toggle is `TC2_VERBOSE=true` at build time.
- **`tokio::select!` and `CancellationToken` for anything that
  dials or waits.** A cancelled task or a shutdown should abort
  the operation, not leave it running until its own timeout.
- **`Drop` for cleanup.** A `File`, `TcpStream`, or
  `JoinHandle` releases on scope exit; an explicit `close()` is
  rare. When the release has to happen before end of scope, wrap
  in a small RAII type rather than calling a `close()` method.
- **Splitting transports across files is encouraged.** HTTP,
  QUIC, WebSocket, DNS, DoH, ICMP, WireGuard, SMB, and TCP each
  have their own file under `agent/src/transport/`; a new
  transport should follow the same pattern.
- **`#[cfg(target_os = "windows")]` (or `"linux"`) for
  platform-specific modules.** The idiomatic Rust layout is
  `mod.rs` with `#[cfg(target_os = "...")] #[path = "windows.rs"]
  mod imp;` re-exported by `pub use imp::*;` — the closest 1:1
  translation of the Go build-tag layout.
- **Comments explain the invariant, not the syntax.** A comment
  on a `Drop` impl says why the resource must be released
  before end of scope; it does not say "close the file".
- **Shape specs live in `agent/src/features/shaping.rs`.** The
  `ShapeSpec` struct carries `template`, `extract`, `encoding`,
  and `placement`. `shape_wrap` / `shape_unwrap` read the payload
  bytes; the transport reads the placement. The shaping module
  itself does not know about the HTTP envelope.
- **`#![deny(unsafe_op_in_unsafe_fn)]` and `#![warn(missing_docs)]`
  at the crate root.** Adding a new public item without a doc
  comment is a warning; adding a raw pointer operation inside an
  `unsafe fn` without an inner `unsafe` block is an error. Both
  are already enabled in `agent/src/lib.rs` — do not disable them
  in a submodule.
- **`Cargo.toml` `[profile.release]` is load-bearing.** `strip =
  "symbols"`, `lto = "fat"`, `codegen-units = 1`, `panic =
  "abort"`, `opt-level = "z"` — changing any of these changes
  the shipped binary size and the memory layout a scanner sees.
  The Windows OPSEC story (no `.pdata`-reachable runtime, no
  reflection metadata) depends on them.

### Both

- **Comments on the *reason* for a non-obvious choice.** "We do
  not retry after a write succeeded, because the parent has
  already popped those tasks off the queue" is the kind of
  comment the codebase carries. Match that level of detail.
- **Failures that touch security configuration should refuse, not
  warn.** A build that would produce a plaintext agent against an
  encrypted server is a refusal, not a warning the operator may
  not read.
- **A capability with no route is a lie.** Adding a capability to
  `ROLE_CAPABILITIES` without the matching endpoint is a bug; the
  `/identify` response advertises the set to remote operators.
- **Transport-agnostic profiles.** A field added to the C2 profile
  schema must be either read by every transport that could
  plausibly consume it, or explicitly documented as
  transport-specific. The `dns_label` block is the current example
  of the latter: DNS and DoH read it; HTTP, QUIC, WebSocket,
  WireGuard, ICMP, SMB, and TCP ignore it. (WireGuard carries an
  HTTPS request inside its tunnel, so the profile's HTTP-shaped
  fields apply end to end; the `dns_label` block does not reach
  the inner request.)
- **The seven-file glue is a fixed shape.** When you add a
  transport, you add the same seven edits in the same seven
  files, in the same order, every time. If you find yourself
  diverging from the pattern, the abstraction has leaked and the
  review will ask why.

---

## What Not to Submit

Some things are deliberately out of scope. A pull request that adds
one of the following will be declined with an explanation, not
silently ignored.

**Also declined:** a new Cargo feature that is not gated the same
way `wasm-host` is. Every size-sensitive feature — anything that
pulls a dependency a lean build should not carry — belongs behind
a feature flag, off by default, and named on the `beacon-build`
command line. A contribution that adds a dependency to the
`[dependencies]` section instead of `[features]` will be sent
back. See the `wasm-host` feature for the pattern.

- **Runtime configuration files.** The agent has no config file,
  no environment variable, no command-line argument. Every
  property is baked in at build time. A feature that reads from
  disk or the environment breaks the core design.
- **Hot-reload for C2 profiles or transports on the handler.**
  Profiles are read once at startup and never again. A profile
  change would silently invalidate every agent built against the
  old shape, with no way for the beacon to know. The restart is
  cheap; the failure mode of a hot-reload is not.
- **A shell, a PTY, or an interactive live session.** The beacon
  is a pull-based implant; it does not hold a socket. Interactive
  features are not a gap to fill; they are a design boundary.
- **Persistence on the target.** The agent has no persistence
  mechanism. Adding one (scheduled task, registry run key, cron
  entry, launchd plist) is out of scope.
- **A non-Rust agent.** The agent is a single Rust binary. A
  Python or C replacement would not be considered.
- **A second WSGI server.** The handler depends on werkzeug-specific
  behaviour to read the peer certificate. gunicorn, uwsgi, and
  Hypercorn break mTLS client authentication. The built-in server
  is the only one that exposes the peer certificate the
  authentication gate requires.
- **A second protocol implementation in the GUI.** The GUI is a
  presentation layer over the same `Client` instance the CLI uses.
  A GUI that speaks its own protocol is out of scope.
- **A plugin system in the handler.** The handler is deliberately
  minimal. WASM extensions run on the agent, not the server.
- **A build that requires network access at compile time.** Every
  dependency must be resolvable from the local Cargo cache;
  `cargo build` should not fetch anything at build time.
  `install-rust-build.sh` runs `cargo fetch` once to warm the
  cache; a fresh build after that must succeed without network
  access.
- **Anything that logs more than it receives.** A change that
  writes request bodies, PEM material, or raw task args to disk
  without need is a regression in the logging discipline.
- **A change that removes a failure mode.** If a check exists
  because the failure mode is real, removing it — even to make
  tests pass, or to reduce a warning — needs a discussion first.
- **A `git update` or self-updater.** See the self-update note in
  [SECURITY.md](SECURITY.md).
- **A change that weakens the audit chain.** An "optional" audit
  entry, a "performance" bypass, or a "development mode" that
  skips chain verification will not be merged.
- **A change that weakens the dead-man's switch's fail-safe
  defaults.** A malformed config must remain "off". A cleanup
  error must remain "print and exit". The `crypto` mode's
  confirmation prompt and the remote `confirm: true` gate must
  remain in place.
- **Removal of the "honest limitations" sections in the README.**
  The project's credibility depends on them.
- **A change that makes WebSocket, QUIC, or WireGuard combinable
  with another transport in the same binary.** Each carries its
  own session state and cookie handling path; the failover ring
  is built around HTTP's headers. Mixing them is a nontrivial
  change to the failover model, not a one-line relaxation of a
  check.
- **A change that grants a capability to the `guardian` role that
  touches a beacon, a credential, or another operator.** The
  guardian role exists to hold the dead-man's switch and nothing
  else.

---

## Contributing an Agent Verb

A new native verb touches four places in the Rust tree. The
pattern is mechanical once you have seen one.

### 1. Add the implementation first

Native verbs split across `agent/src/verbs/` for
platform-agnostic utilities and the platform-specific `native/`
modules for syscall-adjacent verbs.

| Where | What goes there |
|-------|-----------------|
| `agent/src/verbs/file.rs` | Cross-platform file inspection — `cat`, `ls`, `head`, `tail`, `stat`, `strings`, `hexdump` |
| `agent/src/verbs/search.rs` | `find`, `grep` |
| `agent/src/verbs/hash.rs` | `sha1`, `sha256`, `md5`, `cksum` |
| `agent/src/verbs/text.rs` | `wc`, `nl`, `rev`, `sort`, `uniq`, `tr` |
| `agent/src/verbs/encoding.rs` | `base64`, `gzip`, `gunzip` |
| `agent/src/verbs/fs_ops.rs` | `mkdir`, `rm`, `cp`, `mv`, `chmod`, `ln`, `touch` |
| `agent/src/verbs/path.rs` | `which`, `readlink`, `realpath`, `du` |
| `agent/src/verbs/network.rs` | `curl`, `resolve`, `nc` |
| `agent/src/verbs/shell.rs` | `shell start/stop/status/exec` |
| `agent/src/native/linux/*.rs` | Linux-only syscalls — `ps`, `id`, `ifconfig`, ELF loader, hashdump |
| `agent/src/native/windows/*.rs` | Windows-only APIs — process enumeration, tokens, PE loader, BOF, .NET, lsassdump |

The current `agent/src/verbs/mod.rs` holds the dispatcher —
`is_native_extra_verb(&str) -> bool` and `native_extra_verb(&mut
Agent, Task) -> Result`. The `.execute()` match in
`agent/src/core/dispatch.rs` routes on `verb` and calls into the
dispatcher. A new utility verb is one `match` arm in
`verbs/mod.rs` plus the implementation; a new platform verb is
one `match` arm in the platform module's dispatcher.

For a cross-platform file verb in `verbs/file.rs`:

```rust
//! Cross-platform file inspection verbs.

use crate::core::helpers::encode_output;
use crate::protocol::{Result as TaskResult, Task};
use std::fs;

/// `cat <path>` — read a file and return its bytes.
///
/// Reads through `std::fs::read`, which opens with read-only
/// access and returns the whole file as a `Vec<u8>`. The
/// framework's output envelope base64-encodes the bytes, so
/// binary files round-trip. Errors are surfaced as the task's
/// `error` field, not as a swallowed empty result — the operator
/// sees the OS error string verbatim.
pub fn cat(t: &Task) -> TaskResult {
    if t.args.is_empty() {
        return TaskResult {
            id: t.id,
            error: Some("cat requires a path".into()),
            ..Default::default()
        };
    }
    match fs::read(&t.args[0]) {
        Ok(data) => TaskResult {
            id: t.id,
            output: encode_output(&data),
            ..Default::default()
        },
        Err(e) => TaskResult {
            id: t.id,
            error: Some(e.to_string()),
            ..Default::default()
        },
    }
}
```

For a Linux-only verb in `native/linux/system.rs`:

```rust
//! Linux-only system verbs.
//!
//! This module is `#[cfg(target_os = "linux")]`; the sibling
//! `windows.rs` carries the same function names on Windows, and
//! `mod.rs` re-exports whichever the target compiled.

use crate::protocol::Result as TaskResult;

/// `id` — uid, gid, and group memberships.
///
/// Reads directly from `nix::unistd::getuid` / `getgid` and the
/// supplementary-group list. There is no child process; `id(1)`
/// is not invoked.
pub fn id(_t: &Task) -> TaskResult {
    // ...
}
```

For a Windows-only verb in `native/windows/token.rs`:

```rust
//! Windows token and privilege verbs.

use crate::protocol::Result as TaskResult;

/// `whoami /priv` — list the current process token's privileges.
pub fn whoami_priv(_t: &Task) -> TaskResult {
    // ...
}
```

The convention: a `pub fn verb(t: &Task) -> TaskResult`, one
file per verb family, `#[cfg]`-gated in the module's `mod.rs`
for platform-specific modules.

For a verb that spawns a process, use
`tokio::process::Command` inside `tokio::select!` against a
`CancellationToken` derived from the task's timeout. A
`std::process::Command` with a manual kill-on-timeout is
acceptable when the verb is synchronous, but the async form is
preferred for anything long-running.

For a verb that can be called through a pivot, **do not assume
the transport is HTTP.** A pivoted child's task arrives through
the parent's transport. If the verb takes a binary arg (a COFF
blob, a shellcode), confirm the size fits the transport's
ceiling — DNS caps a logical request at roughly 47 KiB; ICMP
caps a reply at 1400 bytes. A verb whose result exceeds that on
an ICMP-only beacon drops the reply rather than truncating it.

### 2. Register the verb in the dispatcher

In `agent/src/verbs/mod.rs`:

```rust
pub fn native_extra_verb(agent: &mut Agent, t: Task) -> TaskResult {
    match t.verb.as_str() {
        // ...
        "cat" => crate::verbs::file::cat(&t),
        // ...
        other => TaskResult {
            id: t.id,
            error: Some(format!("unknown verb: {other}")),
            ..Default::default()
        },
    }
}
```

For a platform verb, the platform module's dispatcher takes the
match arm — `native::linux::dispatch(&mut agent, t)` for
`target_os = "linux"`, `native::windows::dispatch(&mut agent,
t)` for `target_os = "windows"`. The `mod.rs` re-export means
the call site in `dispatch.rs` does not need to know which
platform's implementation is linked.

### 3. Advertise it to the operator catalogue

The catalogue is served from the server's command table. Add
the entry in `beacon/constants.py`:

```python
{
    'name':        'cat',
    'args':        '<path>',
    'description': 'Read a file',
    'native':      True,
    'platforms':   None,   # or ['linux', 'windows']
    'capability':  'beacon.use',
},
```

If the verb only makes sense on one OS, set `platforms` and the
server will filter it out for the other. The client re-fetches
the catalogue on `use` for the target's OS, so tab completion
follows automatically. If the verb is only meaningful for a
capability the operator may not hold, say so in the
`capability` field — the client filters on that the same way
it filters on `platforms`.

### 4. Document it

Add a row to the README's native-verbs table under
[Operator Reference › Beacon console](README.md#beacon-console-beacon-id).
If the verb has flags, add a short subsection describing them
and at least one worked example.

### Testing

Build for both Linux and Windows and verify the verb works on
the platform it targets:

    cd agent
    cargo build --release \
        --target x86_64-unknown-linux-gnu \
        --target x86_64-pc-windows-gnu

If it takes arguments, exercise the error path for a missing or
malformed arg. If it is reachable through a pivot, verify it
also works when the child's transport is SMB or TCP.

---

# Contributing an Evasion Feature

Compile-time evasion features are set via `TC2_*` environment
variables, consumed by `agent/build.rs`, emitted as `pub const`
items in `config_generated.rs`, and read from `agent/src/config.rs`
at startup. Every evasion feature is **compile-time only** —
there is no runtime toggle, and a feature that reads from disk or
the environment at runtime breaks the core design.

Evasion features fall into two kinds, and the work starts in a
different place depending on which one you are adding.

### Where evasion code lives

| Path | What it holds |
|------|----------------|
| `agent/src/evasion/` | Runtime evasion primitives — anti-sandbox heuristics, anti-debug, anti-VM, AMSI patch, ETW patch, PPID spoof, sleep-mask, indirect syscalls. **Most new evasion work happens here.** |
| `agent/src/evasion/sleepmask/` | The sleep-mask variants. `linux.rs`, `linux_amd64.rs` (with `global_asm!`), `windows.rs`, `cronos_windows.rs`, `hwbp_windows.rs`, `native_windows.rs`, `stack_windows.rs`. A new mask is a new file here plus one arm in `sleepmask/mod.rs`'s dispatcher. |
| `agent/src/evasion/syscall.rs` | Syscall method implementations — `direct`, `indirect`. A new method is one arm in the dispatcher. |
| `agent/src/core/run_loop.rs` | The call sites. A new evasion primitive is wired in from the run loop, not from a new entry point. |
| `agent/build.rs` | The `TC2_*` env var reader. Add one `emit_bool!` / `emit_str!` per new toggle. |
| `beacon/builder.py` | The build toggle — one `BeaconBuildConfig` field plus one `env['TC2_X'] = ...` emission. |

**Changing an existing evasion primitive** — a better anti-VM
probe, a tighter AMSI patch, an updated sleep-mask pattern — is
an edit to an existing file under `agent/src/evasion/` plus, if
the toggle name changes, the corresponding builder field and
`build.rs` emitter. The multi-file linker pattern below is only
needed when adding a **new toggle**, not when improving the code
behind an existing one.

**Adding a new primitive** — a new anti-debug check, a new
sleep-mask algorithm, a new syscall method — starts with a new
file under `agent/src/evasion/`, then walks through the six
steps below to make it a build-time toggle.

### The two-file rule for evasion primitives

An evasion primitive lives in `agent/src/evasion/` and nowhere
else. Do not put evasion logic in `agent/src/core/run_loop.rs` —
the top-level loop calls into the evasion module, not the other
way around. The current `run_loop.rs` reads:

```rust
if config::ANTISANDBOX {
    if evasion::antisanbox::detected() { ... }
}
if config::ANTIDEBUG {
    if evasion::antidebug::detected() { ... }
}
if config::ANTIVM {
    if evasion::antivm::detected() { ... }
}
```

The pattern to match: `run_loop.rs` holds the *decision* to run
the check; `evasion/` holds the *implementation*. A
contribution that puts the implementation in `run_loop.rs` will
be sent back to move it.

### 1. Add the toggle to `BeaconBuildConfig`

In `beacon/builder.py`:

```python
    my_new_evasion: bool = False
```

Set a sensible default. `False` for anything that changes runtime
behaviour; the `default` OPSEC profile enables nothing.

### 2. Add the env-var emission in `_build_env_vars`

```python
    for env_key, value in (
        ...
        ('TC2_MY_NEW_EVASION', cfg.my_new_evasion),
    ):
        env[env_key] = 'true' if value else 'false'
```

### 3. Add the reader in `agent/build.rs`

```rust
    emit_bool!("TC2_MY_NEW_EVASION", "MY_NEW_EVASION");
```

`emit_bool!` emits `pub const MY_NEW_EVASION: bool = true;` or
`= false;` into `config_generated.rs` depending on the value.

### 4. Read it in `agent/src/config.rs`

```rust
pub use crate::config_generated::MY_NEW_EVASION;
```

The re-export is a one-liner; `config_generated.rs` is `include!`d
into the crate root by `lib.rs`.

### 5. Consider a named OPSEC profile

If the feature belongs in a named profile (`stealth`, `opsec`,
`paranoid`), add it to the corresponding `BeaconBuildConfig` in
`OPSEC_PROFILES` and update the profile table in the README's
[OPSEC Profiles](README.md#opsec-profiles) section.

A feature that goes into `paranoid` but not `opsec` is a
deliberate choice — `paranoid` is allowed to be slower and
larger. A feature that goes into `opsec` but not `stealth` is
also deliberate — `stealth` is the profile for engagements
where size and speed matter and only the cheapest evasions are
acceptable.

### 6. Do not silently fall back

If the feature is a mask, a patch, or an evasion, a runtime
failure must not fall through to unmasked behaviour without a
diagnostic. A `diag!` line is the minimum; a hard failure is
often correct.

For the sleep mask in particular: if the mask cannot be applied,
the agent must not sleep in plaintext — a beacon whose `.text`
is left unmasked is exactly the state a memory scanner is
looking for. Fail loudly and, if the profile is aggressive
enough, exit.

### 7. Do not add a build toggle for something the profile already carries

If the feature is a profile-level setting — a status code, a
cookie name, a response header, an encoding, a placement — it
belongs in the profile JSON, not in a new `TC2_*` env var. The
builder serializes the entire merged profile dict into
`TC2_PROFILE_JSON`, so any field the agent's
`protocol::Profile` struct declares is automatically available
at runtime. Reaching for a `TC2_*` toggle when the profile
schema would work is a regression in the design.

The one exception is a value the profile cannot carry because
it is not part of the merged dict — the `dns_label` block
reaches the DNS transport through dedicated `TC2_DNS_*` env
vars because the DNS wire format is not the profile's concern
and the transport needs the values before the profile is
parsed. Reach for a `TC2_*` env var only when the profile JSON
cannot carry the value.

---

## Contributing a Transport

A new transport is **two types plus mechanical glue in six
files.** The two types hold the design; the six files carry a
fixed template every existing transport follows.

This is the single most important contribution shape to
understand. The transport abstraction was built so that a new
transport is a contained change — the engine, the beacon
registry, the task queue, and the operator client are all
transport-agnostic and need no change. If your change touches any
of them, the abstraction has leaked and the review will say so.

### The two types

1. **Server side:** `beacon/transport/<name>.py`, subclassing the
   base transport type in `beacon/transport/base.py`. The engine
   calls three methods on it:
   - `start()` — bind and start listening. Return `True` on
     success.
   - `stop()` — release the listener and any active connections.
   - The transport-specific dispatch path. For an HTTP-shaped
     transport this returns a Flask `Response`; for a raw-socket
     transport it returns the bytes.

   The ten in-tree transports fall into four classes:

   | Class | Transports | Wire framing |
   |-------|-----------|--------------|
   | HTTP-shaped | HTTP, QUIC, WebSocket | The three JSON endpoints shared with the listener |
   | Raw-framed direct | DNS, DoH, ICMP | Each carries the same JSON body inside its own envelope |
   | Tunnelled HTTP | WireGuard | An HTTPS request carried inside a userspace WireGuard device |
   | Pivot | SMB, TCP bind, TCP reverse | The peer-to-peer pivot session |

   HTTP-shaped transports reuse the entire `BeaconListener`
   Flask app and the C2 profile's route auto-discovery. A new
   transport in that class subclasses `BeaconListener` and
   overrides `start` and `stop`; the request handlers do not
   change. The QUIC listener is the reference for this pattern.

   Raw-framed direct transports write their own wire format and
   their own dispatch. The DNS transport is the reference for
   this pattern; DoH reuses the same QNAME format inside a
   different carriage, and ICMP carries the same base64url
   envelope inside an echo request.

   Tunnelled-HTTP transports terminate a userspace tunnel and
   then carry an ordinary HTTPS request inside it. WireGuard is
   the current example: from the listener's point of view the
   request is an HTTP request like any other, and it reuses the
   entire `BeaconListener` request pipeline unchanged.

2. **Client side:** `agent/src/transport/<name>.rs`,
   implementing the `protocol::Transport` trait:

   ```rust
   #[async_trait::async_trait]
   pub trait Transport: Send + Sync {
       fn name(&self) -> &'static str;
       async fn check_in(
           &self,
           identity: &Identity,
           pubkey_pem: &str,
           identity_sig: &str,
           identity_ts: i64,
           wire: Option<&WireSession>,
       ) -> Result<CheckinResponse, TransportError>;
       async fn fetch_tasks(
           &self,
           wire: Option<&WireSession>,
       ) -> Result<Vec<Task>, TransportError>;
       async fn post_result(
           &self,
           r: Result,
           wire: Option<&WireSession>,
       ) -> Result<(), TransportError>;
       async fn close(&self);
   }
   ```

   The reference implementations are `transport/http.rs`,
   `transport/dns.rs`, `transport/doh.rs`, and
   `transport/quic.rs`. Splitting per-platform code into
   `transport/<name>_windows.rs` / `transport/<name>_linux.rs`
   is the pattern for transports that need OS-specific syscalls.

### The six files of glue

The two types above are the entire design. The six files below
connect them to the build system and the running handler. Every
one is a name-swap of the same template — there is no design work
in any of them.

| File | What is added |
|------|---------------|
| `agent/src/config.rs` | One `pub const` re-export per build-time value |
| `agent/src/bin/beacon.rs` | One `match` arm in `dispatch_transport` |
| `agent/build.rs` | One `TC2_*` env var read and `pub const` emission |
| `beacon/builder.py` | Transport validation plus one `TC2_*` env var emission per field |
| `beacon/build_manager.py` | One `cfg.X = params.get('x')` line per field |
| `beacon_handler.py` | One CLI flag per listener port plus one `start()` call |

The operator client — `tornado_client/repl.py` and
`tornado_client/gui.py` — needs no change at all. The client
talks to the server API; the transport is a server-to-agent
concern. The build wizards in those two files do need one line
per new transport (a display label and a `transport_mode` value
in the transport list), but that is a data entry, not a code
change.

### A worked example

For a hypothetical transport named `foo` with two build-time
values `foo_addr` and `foo_token`:

```rust
// agent/src/config.rs — re-export
pub use crate::config_generated::{
    FOO_ADDR, FOO_TOKEN,
};
```

```rust
// agent/build.rs — emit the consts
emit_str!("TC2_FOO_ADDR",  "FOO_ADDR");
emit_str!("TC2_FOO_TOKEN", "FOO_TOKEN");
```

```rust
// agent/src/bin/beacon.rs — transport dispatch
match mode.as_str() {
    "foo" => {
        if config::FOO_ADDR.is_empty() {
            return Err("transport=foo but FOO_ADDR is empty".into());
        }
        let t: Box<dyn Transport> = Box::new(
            crate::transport::foo::FooTransport::new(
                config::FOO_ADDR,
                config::FOO_TOKEN,
            )?,
        );
        transports.push(t);
    }
    // ...
}
```

```python
# beacon/builder.py
if 'foo' in modes:
    if not cfg.foo_addr:
        raise RuntimeError(
            "transport_mode='foo' requires foo_addr")
    env['TC2_FOO_ADDR'] = cfg.foo_addr
    if cfg.foo_token:
        env['TC2_FOO_TOKEN'] = cfg.foo_token
```

```python
# beacon/build_manager.py
cfg.foo_addr  = params.get('foo_addr') or ''
cfg.foo_token = params.get('foo_token') or ''
```

```python
# beacon_handler.py — argparse addition
parser.add_argument(
    '--foo-port', type=int, default=None,
    help='Enable the foo transport on this port.')
```

```python
# beacon_handler.py — start() addition
if self.foo_port:
    from .beacon.transport.foo import FooTransport
    self._foo_transport = FooTransport(
        self.beacon, self.host, self.foo_port, config={})
    if self._foo_transport.start():
        print(f"[BEACON] foo transport on "
              f"{self.host}:{self.foo_port}")
    else:
        self._foo_transport = None
```

That is the whole change. Nothing in `engine.py`,
`listener.py`, the beacon registry, the task queue, or the
operator client is touched.

### Handle the wire-encryption question

If your transport is **direct** (the agent speaks to the server
on its own socket, like HTTP or DNS), it supports wire
encryption the same way HTTP does. The build embeds
`TC2_SERVER_ECDH_PUBKEY` and the transport wraps request and
response bodies in the AES-GCM envelope.

If your transport is a **pivot** (traffic goes through a
parent), the parent must be able to read the child's identity
in the pivot handshake — but the child's C2 envelope is carried
opaquely, so wire encryption on the child's own C2 body is
**allowed**. See
[Contributing a Pivot Transport](#contributing-a-pivot-transport).

### Consider the C2 profile's scope

If your transport is HTTP-shaped (the same three endpoints, the
same JSON body), the C2 profile applies to it automatically:
the paths, User-Agent, extra headers, shaping block, status
codes, cookie name, and response headers all flow through
unchanged. QUIC and WebSocket are in this class.

If your transport has its own framing (DNS, DoH, ICMP), the C2
profile does **not** apply. The `dns_label` block is the only
exception — it is read by DNS and DoH because it changes the
QNAME, which is the wire format those two transports share.

WireGuard is the unusual case: it terminates a userspace tunnel
and then speaks HTTPS inside it. The profile's HTTP-shaped
fields apply end to end on the inner request, because from the
listener's point of view the request is an ordinary HTTPS
request that happens to arrive on the tunnel interface. The
`dns_label` block is not consumed by WireGuard.

### Decide whether the transport is single-only

If your transport can be combined with another in the failover
ring, decide at build time. The ring is built around the HTTP
transport's headers, so a transport that does not carry the
same `X-Beacon-*` scheduling headers cannot participate. QUIC,
WebSocket, and WireGuard are single-transport-only for this
reason. DNS, DoH, and HTTP are mutually combinable.

The builder is the only place that enforces the rule for a
transport that cannot be combined. The agent's transport
dispatcher also checks, but the error is clearer at build time
and the operator sees it before the binary is written.

### Register it in the wizards

Three separate wizard entry points reference the transport list:

- `beacon_handler.py` — the local console's `beacon-build` wizard.
- `tornado_client/repl.py` — the remote client's `_build_wizard`.
- `tornado_client/gui.py` — the PySide6 GUI's `_BuildDialog`.

Each needs one entry per new transport (a display label and a
`transport_mode` value). If the transport is platform-specific
(SMB is Windows-only, ICMP is Linux-only), the wizard's existing
`target_os` filter already handles the conditional visibility —
verify the filter picks up your entry.

### Document it

Add a section to the README under
[Transports](README.md#transports), following the shape of the
existing entries:

- What it is and how it differs from the closest existing transport.
- When to use it, and when not to.
- Requirements (packages, capabilities, platform restrictions).
- Build flags.
- Wire format, if it is not an HTTP-shaped transport.
- C2 profile applicability — whether the profile's paths and
  headers travel on this transport, whether the shaping block
  applies, and whether `--tls-profile` has any effect.
- Threat model — what it protects against and what it does not.

---

## Contributing a Pivot Transport

A new pivot transport must implement the same handshake and
frame format the three in-tree pivots (SMB, TCP bind, TCP
reverse) use. The transport that carries the frames differs; the
handshake and framing do not.

Pivot transports (SMB and TCP bind, plus the TCP reverse variant)
solve a different problem from direct transports: 
**the target has no outbound path to the team
server, but a parent beacon does.** The parent carries the child's
C2 traffic over the parent's own transport.

This is not a transparent relay. It is a **peer-to-peer handshake**
between the child and the parent:

1. The child sends a handshake containing its fingerprint, its
   identity signing public key, an ephemeral P-256 keypair, and an
   ECDSA signature over `fingerprint|epk|ts`.
2. The parent looks up the child's public key by fingerprint,
   verifying the signature (or falling back to trust-on-first-use
   on first contact).
3. The parent replies with its own ephemeral — derived from the
   engagement-wide pivot keypair — and a signature of its own.
4. Both sides derive per-direction AES-256-GCM keys via HKDF-SHA256
   with the info string `tornadoc2-pivot-v2`.
5. Every subsequent frame is an AEAD frame with a monotonic
   sequence number in the additional data. A gap or repeat is a
   fatal error.

A new pivot transport must implement the same handshake and frame
format. It differs from SMB or TCP only in the transport that
carries the frames:

- **SMB** uses a Windows named pipe over the SMB redirector.
- **TCP** uses a plain TCP socket with a pre-shared token
  presented before the handshake.
- A new pivot could use a Unix domain socket, a serial link, or a
  shared memory region — the handshake and frame format stay the
  same.

### Requirements

- **The pivot keypair is engagement-wide.** One ECDSA P-256
  keypair, generated with `beacon-build --pivot-key-gen` and passed
  to every parent and child build with `--pivot-key`. A new pivot
  transport must read the private half on the parent side and the
  public half on the child side, and the builder picks the correct
  half based on the build's role.

- **Authentication is independent of wire encryption.** The pivot
  keypair authenticates the parent to the child. The child's
  identity signing key authenticates the child to the parent.
  Neither is the server ECDH key, and neither replaces it.

- **The parent never inspects or modifies the child's C2 body.**
  The pivot session is a tunnel; the child's envelope — encrypted
  or not — travels inside it verbatim.

- **Backward compatibility is not automatic.** The pivot model
  replaced the old `relay/v1` framing with `pivot/v2`. If your
  transport introduces a new framing, bump the version string and
  refuse the old one. There is no negotiated fallback. A mixed
  `v1` / `v2` deployment does not work — the child hello is signed
  over a different payload than a `v1` parent expects, and the ack
  is signed over a payload a `v1` child cannot reconstruct.

### Files to touch

- Server side: `beacon/transport/<name>.py`, subclassing the
  pivot base class in `beacon/transport/pivot.py`.
- Client side: `agent/src/transport/<name>.rs`, implementing the
  same pivot interface `transport/smb/windows.rs` and
  `transport/tcp_bind.rs` use.
- Builder: `_build_ldflags` must refuse `--pivot-key` on a build
  whose role is neither parent nor child, and must refuse a
  parent/child combination whose keypair does not match.

The six-file glue from the direct-transport section applies
unchanged — a pivot transport still needs its config field, its
dispatch arm, its `build.rs` reader, and its handler flag.

### What works through a pivot

Everything. From the operator console's perspective, a pivoted
child is indistinguishable from a directly-connected beacon:

| Operation | Works because |
|---|---|
| File transfer (`upload`/`download`) | Chunks are tasks with base64 bodies |
| `execute-assembly` | Shellcode is base64 in the task arg |
| `bof` | COFF is base64 in the task arg |
| `extension load` | WASM module is base64 in the task arg |
| `pyexec` / `psexec` / `shexec` | Script source is base64 in the task arg |
| `socks start` | A normal task; SOCKS traffic flows through the server-side pivot listener, not the beacon-to-beacon pivot session |
| `schedule add` | Server-side; no special handling |

**Wire encryption is supported on a pivoted child.** The child's
C2 envelope is carried opaquely inside the pivot session, so a
child built with server ECDH — or with mTLS and server ECDH —
encrypts its C2 body as usual. This is the opposite of the old
transparent-relay design.

### Testing

A pivot transport cannot be tested against a single build. Test
the parent and the child together:

1. Build a parent with the new transport's relay flag and
   `--pivot-key`.
2. Build a child with the new transport and `--pivot-key`.
3. Deploy the parent first. Wait for it to appear in `beacons`.
4. Deploy the child. Verify it appears as a second beacon with a
   distinct ID and that both are operable.

Verify one large-arg verb through the pivot (`bof` or
`execute-assembly` on Windows; `pyexec --stdin` on Linux) to
confirm the framing survives the largest task the transport
supports.

---

## Contributing a WASM Extension

> **The WASM extension host is opt-in at build time.** It is a
> Cargo feature, not a runtime toggle. An agent only has the
> `extension` verbs if it was built with `--wasm-extensions`
> (or `"wasm_extensions": true` in a JSON config), which pulls
> `wasmi` (default) or `wasmtime` into the binary. The size cost
> is ~1 MB with `wasmi`, 3–7 MB with `wasmtime`. An agent built
> without the feature has no interpreter to push a module into
> and will return a clear error if the operator tries.
>
> A contribution that adds a new extension should be tested
> against an agent built with `--wasm-extensions`. See
> [README › Beacon Extensions](README.md#beacon-extensions) for
> the full posture.

Extensions run in the agent's WASM sandbox and can only call four
host functions. Everything an extension can do is defined by those
four; an extension cannot open a socket, spawn a process, or read a
file outside what `host_read` can reach.

### 1. Layout

Create a directory under `extensions/`:

```
extensions/my_extension/
  extension.json     manifest
  my_extension.wasm  compiled module
  src/               optional source
```

### 2. Manifest

```json
{
  "name":        "my_extension",
  "version":     "0.1.0",
  "description": "One sentence about what it does.",
  "binary":      "my_extension.wasm",
  "entry":       "run",
  "author":      "your handle",
  "license":     "GPL-3.0"
}
```

The name must not collide with a native verb. The
`_cmd_extension_load` path refuses to load a module whose name
matches one of the reserved verbs; the check is intentional.

### 3. WASM module

The module exports a function named `run` (or whatever `entry` names
in the manifest). It imports the four host functions from the `env`
namespace. Any other import will fail to instantiate.

```wat
(module
  (import "env" "host_out"  (func $out  (param i32 i32)))
  (import "env" "host_read" (func $read (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 16)

  (func (export "run") (result i32)
    ;; ...
    i32.const 0))
```

The module's linear memory is capped at 16 MiB by the runtime;
requesting more than that fails to instantiate.

### 4. Loading and calling

From the operator console, once the extension is in the store:

```
beacon> extension load <path/to/my_extension>
[*] Loading my_extension (…)
queued …
✓ extension load  0.32s
loaded my_extension

beacon> my_extension arg1 arg2
queued …
✓ my_extension  0.21s
<output>
```

Or via the fully-qualified form:

```
beacon> extension call my_extension arg1 arg2
```

### 5. Size and OPSEC

- Keep the compiled module under a few hundred KiB. The module
  travels base64-encoded in a task; a 500 KiB module is ~670 KiB on
  the wire.
- Do not include debug info. Build with `--release` or the
  equivalent for your toolchain.
- The module never touches disk. Do not add file writes; the host
  ABI does not expose them, so an attempt will fail to link.
- The agent binary is byte-identical with zero extensions loaded
  and with fifty — extension loading does not change the on-disk
  hash. Do not add a feature that would.

### 6. Extensions are HTTP-only in practice

A WASM module delivered over DNS is capped at roughly 47 KiB after
base64 inflation, which is smaller than any useful module. An
extension that needs to reach a DNS-only beacon does not exist in
this version. Load extensions on a direct HTTP, QUIC, or WebSocket
beacon, or on a pivoted child whose parent carries HTTP.

### 7. Do not depend on host behaviour beyond the ABI

The four host functions are the contract. Anything an extension
does must be expressible in terms of them. If your extension needs
a fifth capability (a UDP socket, a hash primitive, a random
number), that is a framework change, not an extension. Discuss it
in an issue first.

---

## Contributing a C2 Profile

A C2 profile is a JSON file under `profiles/c2/`. It controls the
HTTP fingerprint the agent presents and, for the extended schema,
the envelope metadata the listener returns.

**Where the profile applies.** The profile's HTTP-shaped fields
(paths, User-Agent, headers, shaping, status, cookie name,
response headers, stager path) apply to HTTP, QUIC, WebSocket,
and WireGuard builds, and to the parent side of a pivot. The
`dns_label` block applies to DNS and DoH builds only. ICMP does
not consume any part of the profile. SMB and TCP consume the
profile on the parent side only — the child's C2 envelope travels
opaquely inside the pivot session and the child never reads the
profile directly.

**WireGuard is HTTP-shaped.** The C2 protocol travels as a real
HTTPS request inside the tunnel: the agent dials
`https://<server-tunnel-ip>:<beacon-port>/<profile-path>` over the
userspace WireGuard device, and the team server's outer
`BeaconListener` handles it exactly as it handles a direct HTTPS
request. The profile's paths, User-Agent, extra headers, shaping
block, per-shape encoding and placement, per-role status codes,
cookie name, and response headers all travel through the tunnel
and are processed by the listener on the far side.

The one thing the profile cannot control is the **outer WireGuard
handshake**. WireGuard carries IP packets; the profile has no
field that reaches the tunnel's own framing. The message-type
bytes, the handshake initiation and response timing, the
fixed-length keys, and the outer UDP port are all set by the
WireGuard protocol and by the four `--wireguard-*` build flags,
not by the profile.

`--tls-profile` does **not** apply to the inner TLS handshake on
a WireGuard build. The inner connection uses `rustls`, not
`boring`, so the ClientHello is `rustls`'s regardless of what
the build asked for. This is a smaller gap than the WebSocket or
HTTP case: the inner TLS never crosses the public wire — a
network observer sees only the WireGuard handshake, which carries
no ClientHello at all — so the missing BoringSSL profile is
invisible to anything outside the tunnel.

### 1. Layout

The tree ships **thirty** profiles. The full list:

`amazon`, `apple-icloud`, `aws-s3`, `azure-blob`, `chrome`,
`cloudflare`, `discord`, `dns`, `dropbox`, `github`, `gitlab`,
`google-analytics`, `google-drive`, `instagram`, `jira`,
`linkedin`, `notion`, `o365`, `okta`, `onedrive`, `salesforce`,
`shopify`, `slack`, `spotify`, `stripe`, `teams`, `telegram`,
`webex`, `youtube`, `zoom`.

The `dns` profile is a special case: it declares only a
`dns_label` block and no shaping, and is intended for
`--transport dns` or `--transport doh` builds. Both the agent and
the listener must name the same profile for the verb characters
to match; the operator narrows the listener with
`--beacon-profile dns`.

A minimal profile:

```json
{
  "description":       "One sentence about the mimicked application.",
  "user_agent":        "Mozilla/5.0 (…) …",
  "linux_user_agent":  "Mozilla/5.0 (X11; Linux x86_64) …",
  "beacon_path":       "/api/v1/app/init",
  "tasks_path":        "/api/v1/app/poll",
  "results_path":      "/api/v1/app/event",
  "extra_headers":     { "X-Client-Data": "…" },
  "request_headers":   { "Origin": "https://app.example.com" }
}
```

Every field is optional except the three paths; the builder falls
back to the built-in defaults for anything missing.

**`request_headers` is a flat map.** Keys are header names,
values are header values, and every request carries all of them.
It is *not* a per-role map: the Go `protocol.Profile` struct
declares `RequestHeaders map[string]string`, and a nested object
would be silently dropped during unmarshal. The README's
extended-schema example shows the per-role shape, which is a
documentation bug on the README side — the code accepts only the
flat form.

Use `extra_headers` and `request_headers` as follows:

  * `extra_headers` — merged onto every outbound request, for
    every role. This is where the mimicked application's normal
    headers go.
  * `request_headers` — same shape, same merge behaviour.
    Historically a separate slot for headers a future schema
    might want to scope per-role; today it is a synonym for
    `extra_headers` that exists so the historical profile files
    keep working.

### Two worked examples

**A full HTTP-shaped profile that mimics an Amazon storefront.**
This is the reference for what a complete profile with shaping
looks like. Note that the three paths are distinct, the shaping
block wraps the payload in a plausible-looking response, and the
`extract` path in each block matches the field where `{{payload}}`
was substituted:

```json
{
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "linux_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

  "beacon_path":  "/gp/your-account/order-history",
  "tasks_path":   "/gp/cart/view",
  "results_path": "/gp/cart/add",

  "extra_headers": {
    "Accept": "application/json",
    "X-Requested-With": "XMLHttpRequest"
  },
  "request_headers": {},

  "cookie_name": "session-id",
  "response_headers": {
    "Server": "Server",
    "X-Amz-Cf-Id": "0000000000000000000000000000000000000000000000000000"
  },

  "shaping": {
    "checkin_response": {
      "template": {
        "orders": [
          {
            "orderId": "100-0000000-0000000",
            "orderDate": "{{ts}}",
            "summary": "{{payload}}",
            "status": "DELIVERED"
          }
        ]
      },
      "extract": "orders[0].summary"
    },
    "tasks_response": {
      "template": {
        "cart": {
          "items": [
            {
              "asin": "B000000001",
              "title": "{{payload}}",
              "qty": 1,
              "price": "9.99"
            }
          ],
          "subtotal": "9.99"
        }
      },
      "extract": "cart.items[0].title"
    },
    "results_request": {
      "template": {
        "cart": {
          "updated": {
            "asin": "B000000001",
            "note": "{{payload}}",
            "qty": 1
          }
        }
      },
      "extract": "cart.updated.note"
    }
  }
}
```

Three things this example demonstrates, and a new profile should
follow the same shape:

- **The extract path is the field the payload was written into.**
  `orders[0].summary` names the array element and the key.
  `cart.items[0].title` indexes into an object's array.
  `cart.updated.note` walks two levels of nesting. None of them
  start with a bare leading index — the walker requires a word
  character at the head of each segment.
- **The three paths are distinct and non-obvious.** `/gp/your-account/order-history`,
  `/gp/cart/view`, and `/gp/cart/add` are three separate Amazon
  endpoints an analyst would recognise. Using `/beacon`, `/tasks`,
  and `/results` here would defeat the whole purpose of the
  profile.
- **The response headers are plausible but not framework-shaped.**
  `Server: Server` looks odd but matches what Amazon's CDN
  actually returns in some configurations; `X-Amz-Cf-Id` is a
  CloudFront header an analyst would expect on an Amazon property.
  Both are the kind of header a defender looks past.

**A DNS-transport profile with only the `dns_label` block.** A
profile whose only purpose is to reshape the DNS transport's
QNAME:

```json
{
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "linux_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

  "beacon_path":  "/beacon",
  "tasks_path":   "/tasks",
  "results_path": "/results",

  "extra_headers": {},
  "request_headers": {},

  "dns_label": {
    "verb_b": "c",
    "verb_t": "p",
    "verb_r": "s",
    "payload_chunk_size": 48
  }
}
```

Two things this example demonstrates:

- **The `dns_label` block is the only field the DNS and DoH
  transports read.** The three path fields, the User-Agent, the
  header blocks — everything else in the profile above is ignored
  on a DNS or DoH build. The paths and headers are present so the
  same profile file is valid for an HTTP build against the same
  service, but the transport only consumes the `dns_label` block.
- **The verb characters are `c`/`p`/`s` instead of the defaults
  `b`/`t`/`r`.** `payload_chunk_size` is 48 instead of the default
  63. Both are chosen so the QNAME a proxy sees does not match the
  framework's historical layout.

**Both profile examples above must be started on the listener with
the same profile.** A `dns_label` block whose verbs the agent knows
but the listener does not will produce a check-in the listener
refuses to dispatch. The listener is started with
`--beacon-profile <name>`, and the agent is built with
`--c2-profile <name>`. Both read the same file.

A new profile should follow one of these two shapes. A profile that
declares both a `shaping` block and a `dns_label` block is valid —
the HTTP transports read the shaping, the DNS transports read the
`dns_label` — but the two are independent and neither affects the
other.

**`dns_label` is single-instance.** The handler scans
`profiles/c2/` at startup and reads the first `dns_label` block it
finds, in alphabetical order by filename. A second `dns_label`
block in a later-sorting profile is silently ignored, and the
verb characters the agent was built with will not match the verb
characters the listener is dispatching on. Every DNS query is
then refused with an unknown-verb error and the beacon never
checks in.

Today this is a non-issue because `dns.json` is the only in-tree
profile with a `dns_label` block, and `d` sorts before every
other profile name. It stops being a non-issue the moment any
other profile adds one.

The correct way to run a DNS-transport engagement is therefore to
name the profile explicitly on both sides:

    beacon-build linux amd64 --transport dns \
        --dns-domain c2.example.com \
        --c2-profile dns

    python tornadoc2.py --beacon-port 8881 \
        --dns-port 53 --dns-domain c2.example.com \
        --beacon-profile dns

`--beacon-profile dns` narrows the listener's scan to exactly
that file and eliminates the dependency on filename order. The
operator's checklist for a DNS build should include both flags.

### 2. Extended fields

A profile that wants the fuller envelope shape declares any of:

```json
"cookie_name": "session",
"status": {
  "beacon":  200,
  "tasks":   200,
  "results": 204,
  "error":   404
},
"response_headers": {
  "Server": "nginx",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff"
},
"shaping": {
  "checkin_response": {
    "template": { "data": { "b64": "{{payload}}" } },
    "extract":  "data.b64",
    "encoding": "base64",
    "placement": { "kind": "body" }
  },
  "tasks_response": {
    "template": { "data": { "b64": "{{payload}}" } },
    "extract":  "data.b64",
    "encoding": "base64url",
    "placement": { "kind": "header", "name": "X-Request-ID" }
  },
  "results_request": {
    "template": { "payload": "{{payload}}" },
    "extract":  "payload",
    "encoding": "hex"
  }
},
"dns_label": {
  "verb_b": "x",
  "verb_t": "y",
  "verb_r": "z",
  "payload_chunk_size": 48
},
"stager": {
  "path": "/api/v1/assets/update.bin"
}
```

Each block is independent. A profile that declares one block and
not the others behaves exactly as before the schema was extended.

### 3. Shaping block — schema rules

The `shaping` block wraps the response body in a template that looks
like a legitimate JSON blob. The template is a JSON object with
`{{payload}}`, `{{ts}}`, and `{{nonce}}` placeholders. The
`extract` field names the JSON path inside the template where the
real payload is hidden.

**Rule 1 — distinct paths per role.** `beacon_path`,
`tasks_path`, and `results_path` must be three different strings.
A profile whose three paths are identical registers one route and
shapes one role; the other two fall through to plain JSON, and an
agent that expects shaped responses fails to unwrap them.

**Rule 2 — no query strings in paths.** The listener registers
routes with Flask, which matches `request.path` with the query
string stripped. Put the discriminator in a path segment, not in a
query string.

**Rule 3 — extract paths must start with a word character.** The
walker regex is `^(\w+)(?:\[(\d+)\])?$`. `results[0]`,
`data.items[3]`, and `value` are valid. A bare leading index like
`[0].title` is rejected at build time with `bad path segment:
"[0]"`. Wrap a top-level array in an object and index into it.

**Rule 4 — `{{payload}}` must be present in every extracted field.**
The `extract` path names the field the walker reads and decodes. If
that field does not contain `{{payload}}`, the decode produces
garbage and the agent fails to parse the response.

**Rule 5 — every path must be distinct from every other path in
every other profile.** The handler scans the directory at startup
and registers each profile's three paths as Flask routes. Two
profiles that declare the same path for the same role collide;
the first one alphabetically wins and the second is refused with
a load-time error naming the collision.

A path collision is not a shaping problem — it is a routing
problem, and it stops the handler from starting at all. A
contributor testing a new profile against a running handler will
see the handler fail to boot if the new profile reuses a path the
in-tree profiles already claim.

The in-tree paths are all unique. Before submitting, run the
profile against a handler started without `--beacon-profile` and
confirm the startup banner names the new profile's three routes
without any "could not register" lines. See README.md ›
C2 Profiles › Concurrent multi-profile handlers for the full
failure mode.

### 4. Encoding and placement

Each shape may declare an `encoding` and a `placement`.

| `encoding` | Transform |
|---|---|
| `base64` (default) | Standard base64 with padding |
| `base64url` | URL-safe base64, no padding |
| `hex` | Lowercase hex, two chars per byte |
| `netbios` | Each byte as two lowercase letters a–p, one per nibble |

| `placement.kind` | Behaviour |
|---|---|
| `body` (default) | Payload is the response body |
| `header` | Payload is the value of the named response header; body becomes `{}` |
| `cookie` | Payload is the value of the named `Set-Cookie`; body becomes `{}` |

An unrecognised `encoding` falls back to `base64`. A malformed
`placement` falls through to `body`. The build refuses a shape
whose declared encoding does not round-trip through the agent's
walker.

**WebSocket ignores placement.** A WebSocket frame has no HTTP
header layer, so `placement: header` has nowhere to write. The
listener sets `TORNADO_WS` in the request environ and
`_apply_placement` leaves the payload in the body. **QUIC honours
placement** — the QUIC listener returns the Flask response verbatim.

### 5. DNS label block

`dns_label` renames the three verb characters and shrinks the
per-chunk payload length. Each verb must be a single lowercase
alphanumeric character; a collision is refused at both the agent
and the listener. `payload_chunk_size` is bounded at 63 — the DNS
label maximum — and falls through to 63 on an out-of-range value.

**The value reaches the agent through linker flags, not through
`ProfileJSON`.** The builder reads the block and emits
`-X main.DNSVerbB=…`, `-X main.DNSVerbT=…`,
`-X main.DNSVerbR=…`, and `-X main.DNSPayloadChunkSize=…`. The
Python listener reads the same block from the profile file
directly. Both sides must be started with the same profile.

### 6. Stager block

`stager.path` declares an alternate URL the stager fetches its
payload from. Empty or absent means the historical `/stage/<name>`.
The listener registers the declared path as a route that serves
the same payload; the stager appends the payload name as a
`?name=` query parameter.

### 7. Concurrent multi-profile handlers

The handler serves **every** profile under `profiles/c2/`
simultaneously. When the listener starts, it scans the directory,
parses each JSON file, and registers the profile's three declared
paths as routes on the Flask app. At runtime, an incoming request
is routed to the profile that declared its path, and the response
is shaped by that profile.

There is no "active profile" state. The path in the request *is*
the profile selector. A beacon built against `chrome` uses
`/api/v1/analytics/collect` for check-in; a beacon built against
`slack` uses `/api/client.connect`. Both reach the same listener
on the same port; each gets the response shape its own profile
declared.

**The profile set is fixed at startup.** The directory is scanned
once, when the handler boots. There is no file watcher, no
hot-reload, and no console command to reload profiles. To add,
change, or remove a profile, stop the handler, edit the directory,
and start it again.

**Path collision rule.** Two profiles cannot declare the same path
for the same role. The handler refuses a profile whose paths
collide with an already-loaded profile's paths, and the profile
fails to load with a specific error naming the collision.

### 8. Test before submitting

Load the profile against a running handler:

```
beacon> c2-profiles my_profile
```

`c2-profiles <name>` requires the `beacon.build` capability. A
viewer or guardian role will not see the command in its
catalogue; a hand-crafted request from a credential that does not
carry the capability is refused with a 403 and audited.

Then build an agent with `--c2-profile my_profile`, check it in, and
verify the wire traffic with a local proxy if you can. A profile
whose shaping block passes validation but produces responses the
agent cannot parse is the most common submission mistake.

For a `dns_label` block, build with `--transport dns`, start the
listener with `--beacon-profile <name>`, and confirm the check-in
arrives with the shaped verbs.

### 9. Do not ship a profile whose User-Agent is a lie

If the profile claims to be Chrome, the headers, paths, and shaping
should match what Chrome actually sends. A profile named `chrome`
with a Firefox UA and a `Server: nginx` header is worse than no
profile — a defender who looks twice sees the mismatch.

A profile that mimics a specific application (Slack, Teams, Google
Analytics) should be based on observed traffic from that application,
not on guesswork. If you did not capture the traffic you are
mimicking, say so in a `_doc` key and mark the profile as
approximate.

### 10. Document the profile

Add the profile to the README's
[C2 Profile Catalogue](README.md#c2-profile-catalogue) section, or
open an issue asking a maintainer to. The catalogue output is
auto-generated from the files under `profiles/c2/`, so a new
profile appears the next time the handler is restarted.

---

## Contributing a Build Config Example

The `examples/` directory holds JSON configs that demonstrate
deployment shapes the defaults do not cover. A useful example:

- Is named for the deployment it demonstrates
  (`smb-pivot-parent.json`, `dns-only.json`, `mtls-hardened.json`,
  `quic-only.json`, `websocket-only.json`,
  `wireguard-only.json`).
- Has every field present, even if it matches the default. An
  example with missing fields teaches the reader that the field is
  optional; the reader then has to consult the schema.
- Uses `_doc` keys (underscore-prefixed) for inline comments, since
  JSON has no comment syntax.
- Is referenced from the README's
  [Build Config File](README.md#build-config-file) section.

A bad example omits a required field, uses an unreal address
(`1.2.3.4` where a real deployment would use a domain), or
demonstrates a configuration the builder rejects.

If your example demonstrates a pivot deployment, include **both
halves** — the parent config and the child config — in the same
example file or as two files under a shared stem
(`smb-pivot-parent.json`, `smb-pivot-child.json`). A reader who
copies only the parent config will not have a working deployment.

**The example must include the fields the transports added by the
seven-feature extension now read.** A C2 profile is named in the
build config, not expanded inline — the extended schema lives in
the profile JSON, not the config. But a config that names a
profile should still show the profile name it works with, so the
reader can find the matching profile JSON.

If a build config declares `transport_mode: "wireguard"`, it must
also declare the four WireGuard fields
(`wireguard_server_pubkey`, `wireguard_server_addr`,
`wireguard_agent_privkey`, `wireguard_tunnel_ip`). The optional
`wireguard_inner_port` field should be present when the handler
was started with a non-default `--beacon-port`. The example config
should show all five fields, with the two that carry secrets marked
with a REPLACE_WITH placeholder.

If a build config declares a pivot (`smb` or `tcp`), it must also
declare `pivot_key_path`. The example should show the path under
`mtls_certs/`, which is the value the wizard offers by default.

---

## Contributing an Operator-Console Feature

Operator-console features never touch the agent. They are the
lowest-risk place to start, and they are governed by three rules.

### 1. Capabilities gate every endpoint

A new operator-facing feature needs a capability in
`ROLE_CAPABILITIES`. The existing feature capabilities are:

| Capability | Grants |
|-----------|--------|
| `creds.use` | Full access to the credential vault |
| `notes.use` | Full access to engagement-wide notes |
| `webhooks.manage` | Register, list, test, and remove webhook endpoints |
| `loot.use` | Full access to the loot store |
| `chat.use` | Team chat, including file sharing |
| `deadman.view` / `deadman.arm` / `deadman.halt` | Dead-man's switch control (guardian only) |

Grant a new capability to `operator` and `admin` unless there is a
specific reason to withhold it. **Never grant a capability to
`guardian` that touches a beacon, a credential, or another
operator** — the guardian role exists precisely to hold the
dead-man's switch and nothing else.

The server enforces the capability at the request handler, not
just at the client's command filter. A hand-crafted request from a
credential that does not carry the capability is refused with a 403
and audited.

### 2. Audit every mutation

Every state-changing operation writes to the hash-chained audit
log under a specific action name. The existing vocabulary is
`<feature>.<verb>` — `creds.add`, `loot.delete`, `webhooks.remove`,
`beacon.alias`, `deadman.arm`, `chat.message`, and so on.

A refused mutation is audited with `outcome=denied` on the same
action. The audit entry names the operator, the peer address, and
enough detail to distinguish the operation from a neighbouring one
— a record ID, a hash, a scope — but **never** the credential value
itself, never a password, never a raw token.

### 3. Persist safely

State files under `logs/` are loaded on startup and re-saved on
every mutation. Match the existing pattern:

- **Atomic write.** Write to `<path>.tmp`, `fsync`, rename.
- **`0600` permissions** on every state file.
- **A schema version** if the file shape may change.
- **Reject malformed state at load, do not silently drop it.**
  A corrupted `creds.json` should refuse to load with a clear
  error, not load half the vault and continue.

### 4. Route the frontend correctly

Both frontends dispatch through the same `Client._cmd_*` methods.
A new feature needs one `elif cmd ==` branch in the CLI's main
loop, and — if the feature has a UI representation — one entry in
the GUI's menu or tab structure. The GUI must not reimplement
the protocol; it calls the same `Client` method the CLI does.

### Where the files live

| Feature | State file |
|---------|------------|
| Credential vault | `logs/creds.json` |
| Engagement notes | `logs/notes.json` |
| Per-beacon notes | `logs/bnotes/<bid>.json` |
| Webhooks | `logs/webhooks.json` |
| Aliases and tags | `logs/aliases.json` |
| Loot store | `logs/lootstore/` |
| Chat | `logs/chat/` |
| Audit chain | `logs/audit/` |

A new feature should follow the same layout: one file per feature,
or one directory per feature if the feature has subordinate files.

### 5. Consider the beacon-viewer roster

If the feature is per-beacon and other operators might interact
with the same beacon, consider whether the feature should appear
in the `beacons` poll response — the `VIEWERS` column is the
current example. The roster is a heartbeat with a 30-second TTL,
keyed on `(beacon, operator)`, and is deliberately not audited.

### 6. Consider the dead-man's switch interaction

If the feature writes a state file that the switch's wipe does not
currently reach, add the path to the wipe scope. The switch's
scope check is strict — a directory named `TornadoC2` at a known
path — so a new state directory under `logs/` is picked up
automatically. A new state directory *outside* `logs/` needs an
explicit addition to the wipe list.

---

## Pull Request Checklist

Before opening a pull request:

- [ ] **The change is scoped.** One concern per pull request. A PR
      that fixes a bug and reformats the file will be sent back to
      split.
- [ ] **The commit message names what changed and why.** "Fix X
      because Y" is a message; "update file" is not.
- [ ] **The build compiles for the platforms the change touches.**
      A Rust change should build for Linux and Windows, both
      amd64 and arm64, without warnings:

          cd agent
          cargo build --release \
              --target x86_64-unknown-linux-gnu \
              --target x86_64-pc-windows-gnu \
              --target aarch64-unknown-linux-gnu

      A Python change should import cleanly on Python 3.7
      through current.
- [ ] **`cargo fmt --check` and `cargo clippy -- -D warnings` are
      clean** under `agent/` if the change touches Rust.
- [ ] **The change was exercised against a running handler.**
      Describe how in the PR body: which flags, which transport,
      which target OS.
- [ ] **Security-relevant changes include a description of the
      accept and reject paths you tested.** A change to signature
      verification, wire encryption, cookie handling, a
      capability check, the audit chain, or the dead-man's switch
      should describe what a failing case looks like.
- [ ] **The README is updated if the change affects the operator's
      behaviour.** A new verb, a new flag, a new field in the build
      config, a new C2 profile schema field — all of those appear
      in the README.
- [ ] **The change does not reduce logging.** If you removed a log
      line, the PR body explains why it was safe to remove.
- [ ] **If the change touches a security-critical path, it does
      not weaken the existing defence.** Removing a check, hiding
      a warning, or broadening a fallback needs a discussion
      first. See [SECURITY.md](SECURITY.md) for what counts as
      security-critical.
- [ ] **If the change adds a transport, the transport appears in
      the README's transport list, and the C2 profile applicability
      is documented.** Whether the profile applies, whether
      placement applies, whether `--tls-profile` applies — all
      three answers belong in the transport's section.
- [ ] **If the change adds a transport, the six-file glue
      appears in all six files.** A missing edit in
      `agent/src/config.rs` or `beacon/build_manager.py` is
      the most common omission.
- [ ] **If the change touches a C2 profile, `shapecheck` is
      clean on it.** Run
      `python3 tools/shapecheck.py profiles/c2/your-profile.json`
      and confirm zero errors. Warnings are per-profile policy
      decisions the author should have made; a PR that leaves
      warnings should say which ones it accepted and why.
- [ ] **If the change adds a C2 profile, the profile validates
      against the agent's shape walker.** Build an agent that
      embeds it and confirm the build succeeds. `shapecheck` is
      a static check; the build is the round-trip against the
      actual agent binary.
- [ ] **If the change adds a C2 profile, its paths do not collide
      with an existing profile's paths.** The handler refuses a
      colliding profile at load time; the PR should confirm the
      new profile loads cleanly alongside the in-tree ones.
- [ ] **If the change touches the WASM extension host or an
      extension**, it compiles and runs both with and without
      `--features wasm-host`. The `wasm-host` feature must never
      be on by default and must never be pulled in implicitly.
- [ ] **No secrets, no real infrastructure, no engagement data.**
      Test artifacts must not include real callback URLs, real
      team CA material, real target hostnames, or real beacon
      session cookies.

Maintainers aim to respond to every PR within seven days. A PR
that has been silent for thirty days may be closed as stale; it can
be reopened without prejudice when you have time to return to it.

---

## Code of Conduct

Be straight, be useful, and be patient. This is a security tool;
the work demands care about details and honesty about limitations.
If you find a bug, describe the failure you saw and the conditions
under which you saw it. If you propose a change, name the trade-off
you weighed. If you disagree with a decision, argue from the design
constraints rather than from personal preference.

Reports that name a real target, a real engagement, or a real
credential will be removed. Reports that mock another contributor
will be removed. Reports that describe a bug clearly and neutrally
are always welcome, even when the answer is "this is a design
decision."

---

## Questions

If you are unsure whether a change is worth the effort, or whether
a bug is security-relevant, open an issue and ask. It is better to
spend five minutes discussing an idea that does not pan out than
have you spend a day on a pull request that will be declined.