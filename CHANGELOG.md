# Changelog

## Unreleased
- Overhaul Phase 0: baseline record, frozen 18-panel no-loss inventory
  with a registry test, workspace architecture, GUI ↔ CLI parity
  matrix and locked armory repository contract.
- Overhaul Phase 1.1: HTTP/auth/task/listener/build events stream to
  the desktop Events pane; the CLI and daemon log stay quiet.
- Overhaul Phase 1.2: bridge event poller and `server` event source.
- Overhaul Phase 1.3: operator add auto-exports a verified 0600 config;
  daemon gains an instance lock, readiness pipe, rotated 0600 log,
  heartbeat, SIGHUP listener reload and atomic cleanup.
- Overhaul Phase 1.4: armory is pinned to the project repository,
  signature verification removed, safe archive reader, SHA-256
  integrity, install/remove/update and a locked-source GUI.
- Overhaul Phase 1.5: shared `build_spec` descriptor and validator
  drive the builder, server, CLI wizard and GUI; build errors are
  field-addressed.
- Overhaul Phase 2.1: pitch-black token palette, high-density defaults,
  square data grids, mono data typography and audited contrast.
- Overhaul Phase 2.2: File/View/Tabs/Help menubar, grouped panel menu,
  status cluster, workspace selector, rail removal and shell keyboard
  model.
- Overhaul Phase 2.3: four independent versioned workspace models,
  one-shot legacy migration with backup, hidden-tab persistence,
  corrupt fallback, float/detach coordination and `dragGroup` transfer.
- Overhaul Phase 2.4: side sheet, context menu, status cluster,
  progress, skeleton, sanitized markdown, copy button, state presets
  and grouped/tree data grids.

## 0.9.0
- Feature-pruned agent builds; unused transports, evasion, WASM and Jump code excluded.
- Versioned WASM ABI with limits and timeout isolation.
- Per-operator armory for BOF installation.
- Jump: psexec, winrm, wmi, scshell.
- Runtime listener management, OS-split agent trees, privilege graph.
- Assurance suite and CI.
- AES-256-GCM at-rest encryption for credentials, notes and the engagement model; backup/restore scripts.
- TOTP removed; password-HMAC lockout (5 failures / 30 s) and an 8 h session cap replace it.
- Linux persistence (systemd, cron, profile) and read-only privilege reconnaissance.
- Engagement model, timeline, findings and Markdown reporting.
- Ed25519-signed armory index and release workflow with SBOM.
- Operator handbook, detection notes, WASM ABI policy and contribution guide.
- Engagement tab in the GUI for hosts, findings, timeline and reports.

- Audit seal key + anchor persisted and verified; `audit verify`.
- Jump builds serialized with an LRU cache; scshell default service;
  engagement writes batched with caps.
- At-rest coverage extended to chat, loot, aliases, webhooks,
  listeners, scheduler; startup migration and `scripts/atrest-status.py`.
- Release workflow builds a real `Bootstrap.dll`; installer takes
  `BUILD_TAGS`; ruff in CI; armory index signing enforced.
- Windows persistence (registry/task/service), ntdll unhook, module
  stomp, fork, signed-digest self-update; WMI falls back to CIM.
- `persist` copies the binary to a durable path (`--path` overrides).

- Stomp saves original section bytes, supports `--restore`/`--force`
  and uses a tested PE helper.
- Updates require an ECDSA signature over the digest; `update publish`
  signs a staged build and the listener serves `/published/<sha>`.
- Service persistence is a real SCM service (`svc_host`) and verifies
  RUNNING.
- Audit verification is suffix-based with checkpoint offsets, holds the
  write lock, and `--full` re-walks. AAD now binds file paths; migration
  is one-shot with a marker and `atrest status|migrate`.
- Unhook can revert; builder/wizard expose unhook and stomp.

- Call-stack spoofing (`ev_stackspoof`) for thread creation and
  memory transitions, on by default for Windows, with a config switch.

- Jump psexec registers the stager as a real service (`svc_host` also
  in the stager); `persist task:system` installs an onstart SYSTEM task.
- `stomp` runs PE and BOF payloads; `fork --parent` spoofs the parent.

- Versioned model (users, shares, services, evidence with hashes),
  MITRE mapping, IOC CSV, STIX 2.1, dataset-hashed reports, bulk
  actions audited per beacon and model-projected graph.

- Export/model hardening: STIX SCO patterns and escaping, CSV formula
  neutralisation, Markdown escaping, evidence digest/loot validation,
  bulk limits and per-item errors, export filenames and 0600 writes,
  `since` model polling, schema-refusal and `.corrupt` backup for the
  engagement store, non-blocking GUI exports/report and non-churning
  engagement rendering.

- GUI phase: virtualised beacon model and views, bounded background
  runner with timeouts, multi-select bulk bar, fuzzy palette with
  recents, toasts, light/compact modes, editable keybindings, saved
  workspace and `--safe` mode, plus a 10k-row benchmark gate.

- Infrastructure: redirector generator (nginx SNI/TLS, Caddy,
  Cloudflare) and a listener health prober with states, cert expiry,
  history, webhook and client/GUI display.

- Fixed startup abort on an unreadable encrypted engagement: at-rest
  errors are now `AtRestError`, the file is quarantined, and the server
  falls back to an in-memory store. At-rest key and marker paths are
  repository-absolute with a clear warning when sealed state exists but
  the key is missing.

- Certificates carry Subject/Authority Key Identifier, and pre-AKI
  server and operator certs are reissued on start, fixing OpenSSL 3
  `Missing Authority Key Identifier` handshakes. Local-console config
  exports are signed like HTTP exports, and the client's signed
  projection now excludes the embedded signer key.

- Desktop packaging: AppImage/deb/rpm and NSIS/MSI targets, fused
  binaries, bundled Python tree, signed GitHub auto-update, icon, and
  an installer that provisions Node + Electron under /opt/tornadoc2.

- GUI cutover: Electron is the default console, PySide6 deprecated
  behind `--gui-classic` with a parity matrix. Added chat send,
  per-beacon notes and listener start/stop/probe in the shell.

- Shell 16.1: listener create/edit/delete with certificate and profile
  pickers, capability-gated controls, native dialogs, bridge
  validation for listener writes.

- Shell 16.2: build dialog with digest verification, chunked
  upload/download jobs, progress, cancel and loot capture.

- Shell 16.3: interactive shell, SOCKS proxy, BOF/assembly runners,
  credential list/reveal, notes list/clear, audit verify, AI provider
  settings, graph zoom/pan/clustering, palette-key rebinding.

- GUI removal: `gui.py`, `--gui-classic` internals, PySide6 and the Qt
  installer blocks deleted; Electron is the only GUI. Desktop tests
  replace the Qt test files; parity doc archived.

- Shell 16.5 close-out: advanced build options and config import;
  parity matrix complete, packaging refreshed.

- Fuzz targets and corpora for COFF, PE, WASM and bridge frames; COFF
  header validation is now a first-class package used by the loader.
- Node 26 LTS, Electron 45, React 19, Vite 8, Zod 4 and refreshed
  tooling; hardened fuses, custom window controls, CSP inline-style fix
  and generous IPC timeouts for long actions.

- Desktop install reliability: Electron's lazy binary download is
  driven by a postinstall guard, install scripts are explicitly
  trusted, minimatch is overridden to a patched release (audit clean),
  headless dev/preview scripts, and CSP fixes for the Vite preamble.

- Console design foundations: pitch-black token palette, tested
  AA/AAA contrast pairs, three density levels, type ramp, focus rings,
  motion budget and reusable toolbar/field/status/empty/key/split
  primitives. CI now fails on contrast regressions or stray colours.

- Console dock: persisted four-pane workspace, draggable/tabbed
  panels, edge split drops, maximize/collapse, reset, corrupt-layout
  recovery, keyboard tab moves and capability-filtered rail/palette.
  Layouts normalise on read; panel content survives tab moves. Targets
  became a table-semantics grid and the event log got filter/follow/
  copy controls.

- Shell phase: profile presets with custom tracking, labelled quick
  actions, live status metrics and clock, a branded connect gate with
  recent configs, role-aware session handoff, double-click maximize and
  detached windows on their own dock key. Disconnect now broadcasts to
  every window. A renderer error boundary and preload-race guard keep a
  blank window from being the failure mode.

- Inventory phase: derived severity and sortable columns, roster
  selection (arrows/shift/space/select-all), inline alias editing with
  F2, and an inspector rebuilt into collapsible identity/session/
  execution/payload/notes/transfer/pivot/danger sections with 30 s
  clipboard copy. Prompt inputs gained labels.

- Terminal and screen phase: task/shell transport with catalogue
  completion, per-target session transcripts, history, raw toggle,
  transcript save and local wait interrupt; screen pane with zoom/pan,
  interval capture, 32 MB 0600 binary save and inline failures.
  Workspace upgrades now backfill panels missing from older layouts.

- Typed data-grid phase: one virtualised grid primitive with
  sort/filter/raw toggle/auto-refresh; process, connection and file
  parsers with Linux/Windows fixtures and a 5000-row cap; PID-to-process
  correlation, capability-gated kill/download and file breadcrumbs with
  parent navigation. Collection is argv-based, never shell-concatenated.

- Topology phase: canvas force graph with typed edge classes, legend,
  cluster aggregation above 500 sessions with drill-down, 2k state,
  cursor-anchored zoom, pan/drag, minimap, hover cards and inspector
  selection sync. Rendering capped at 2500 nodes / 6000 links.

- Listener phase: full-width listener grid with state, TLS, cert
  expiry, health glyphs and sparklines; creation/editing in a side
  sheet; inline probe patches without reload; capability-gated
  start/stop/delete. The health endpoint now includes bind/state/TLS
  metadata and a `health` alias.

- Coordination phase: grouped chat with day rules, own-message marks
  and retry-on-failure; merged capped event ring for bridge/task/audit
  with level/source/search filters, pause and export; retained job list
  with stale detection, failure text and confirmed cancel.

- Hardening phase: lazy pane/dialog chunks with a suspension skeleton,
  enforced entry/chunk/CSS/asset/source-map budgets, vendor chunk
  splitting, CSP assertions with object/form denial, axe on gate, empty,
  populated and pane states, and a four-viewport 200 % overflow smoke.

- Taxonomy phase: six fixed panel groups with a keyboard group rail,
  curated profile sets, one-time layout migration with backup, Assets
  health badge, and Inspector execution moved into the Terminal with
  transcript subscription and command prefill.

- Armory fix: `_armory_shell` now binds every `_armory_*` helper and
  `ARMORY_BASE` by introspection, fixing the missing attribute/method
  crash; regressions cover binding, signed cache verification, bad
  signatures, fetch URL construction and catalogue listing.

- Login phase: session-launcher gate with live bridge readiness,
  drag-and-drop config validation through `webUtils.getPathForFile`,
  step rail, last-session recall, focused error recovery and a
  single-column narrow layout.

- Release verification: complete renderer/server/axe/CSP/contrast/
  budget/viewport/Go/installer matrix, AppImage build with checksum and
  fuse assertion read from the extracted image.

All earlier changes are in git history.
