# TornadoC2 desktop shell

Electron + React presentation layer. Python owns `.cfg`, mTLS, signing,
HTTP, RBAC and audit; this tree only renders and forwards typed calls
to the bridge.

Design rules, tokens, the dock model and primitive usage:
[DESIGN.md](DESIGN.md).

## Develop

Node **26 LTS** or newer, Electron 45.

```bash
npm ci                 # postinstall fetches the Electron binary once
npm run dev            # HMR; set DEVTOOLS=1 for the inspector
npm run dev:headless   # no display: Xvfb/CI
npm run typecheck
npm run audit:contrast   # WCAG pairs + stray hex
npm test
npm run build
npm run verify           # typecheck + contrast + tests
```

Electron 42+ downloads lazily; `scripts/ensure-electron.mjs`
(`postinstall`, `predev`, `prebuild`) makes a fresh clone work with
`electron-vite`. `npm run setup` forces the download if it was interrupted.
`Frame latency is negative` in the terminal is a benign Chromium
compositor message; it is unrelated to the bridge and disappears on a
real display. `npm audit` is clean; `allowScripts` in `package.json`
lists the three packages whose install scripts are trusted.

`TORNADOC2_PYTHON` picks the interpreter, `TORNADOC2_REPO` the repo root
(defaults to three levels above `app.getAppPath()`), `--config` or
`TORNADOC2_CFG` the operator config.

## Security invariants

- CSP allows inline script/`style` only for the Vite dev preamble and
  React style attributes; everything else is `'self'`.


- `sandbox`, `contextIsolation`, no Node in the renderer.
- Only `src/preload/index.ts` may touch `ipcRenderer`.
- Every renderer request is validated with zod in main (`requestSchema`).
- `app://` protocol, strict CSP, no `file://`, navigation and window
  opening denied by default.
- Packaged binaries are fused (`scripts/fuses.mjs`): no `RunAsNode`, no
  `NODE_OPTIONS`, ASAR-only, ASAR integrity.
- The bridge socket lives in `$XDG_RUNTIME_DIR/tornadoc2` (0700, socket
  0600), checks peer UID on Linux and requires a token from the READY
  line.

## Layout

```
src/main      window, protocol, bridge supervisor, IPC, security
src/preload   contextBridge allowlist
src/shared    zod schemas, protocol version
src/renderer  React app (tokens, shell, tables, palette)
scripts       fuse flipper
```

15.1 ships the shell and bridge, 15.2 the read surfaces, 15.3 the
actions, 15.4 the polish (AI pane, detached windows, palette recents,
focus traps, skip link, reduced motion, `--safe`, axe tests): task dispatch with result polling, multi-select bulk, tags and
aliases, kill/forget, jump, armory install/uninstall, evidence and
findings, exports through a main-process save dialog (0600), settings.

Mutating calls are bridge allowlist entries with zod validation in the
renderer and main; destructive ones (kill, forget, jump, bulk) sit
behind a dialog or count confirmation and land in the server audit
chain. The renderer still holds no transport state.


## Package

```bash
npm run build
npx electron-builder --linux AppImage deb rpm --publish never
```

`extraResources` bundles `tornado_client`, `tornadoc2_mcp` and
`beacon-client.py` under `resources/t2`; `scripts/afterPack.mjs` flips
the fuses; `build/` holds the icon. Windows builds use NSIS/MSI and
Authenticode through `CSC_LINK`/`CSC_KEY_PASSWORD`.

Auto-update is `electron-updater` against the GitHub releases feed,
disabled in dev and with `TORNADOC2_NO_UPDATE=1`. The renderer shows a
banner and offers restart-and-install only after a signed download.

The installer sets `chrome-sandbox` to 4755 root; a per-user launch
without that bit needs `--no-sandbox` (documented, not default).


16.3 adds the shell, SOCKS, BOF/assembly runners, creds, notes,
audit verify, AI settings, graph navigation and palette-key editor.

16.2 adds the build dialog (chunked pull, digest check, 0600 output)
and upload/download jobs with progress, cancel and loot capture.

16.1 adds listener create/edit/delete with cert/profile pickers,
capability-gated actions and Dialog/Confirm primitives (no native
`prompt`).

## Cutover

Complete. `--gui` points here, the PySide6 console is deleted, and
`--gui-classic` is an accepted alias. `docs/gui-parity.md` is the
archive of what moved; only TCP forward stays CLI-only.
