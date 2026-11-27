# Desktop design system

Pitch-black operator console. Structure is hairline, density is the
default, neon is reserved for state.

## Rules

1. **One accent per meaning.** Cyan = active/selected, green = live/ok,
   red = danger/dead, amber = warning/degraded, violet = elevated.
   Never use an accent for body copy.
2. **No raw colours in feature code.** Every colour is a token in
   `src/renderer/src/styles/tokens.css`. `npm run audit:contrast`
   fails on a stray hex.
3. **Contrast is tested, not eyeballed.** Every text/surface pair is
   asserted at WCAG AA (7:1 for body copy) in both themes.
4. **Density is a setting, not a guess.** `cozy`, `compact` (default)
   and `dense` drive `--row`, `--gap`, `--pad`, `--control-h`. Feature
   CSS reads those variables and never hard-codes a height.
5. **Focus is always visible.** 2 px `--focus` ring with 2 px offset.
   Icon-only controls need `aria-label` (`IconButton` does this).
6. **Motion is budgeted.** 90/150/220 ms on one easing curve;
   `prefers-reduced-motion` collapses it.
7. **Canvas is #0A0A0A, panes #121212, raised #1E1E1E.** Accents are
   `#00E5FF`, `#00FF00`, `#FF3B5C`, `#FFB020`, `#B18CFF`. Data grids
   and table wrappers use `--r-grid` (0).
8. **Typography is Inter for UI and JetBrains Mono for data.** Grids,
   terminals, logs and timestamps always use the mono stack.

## Primitives

`src/renderer/src/ui/` exports `Toolbar`, `ToolbarTitle`,
`ToolbarGroup`, `ToolbarSep`, `Field`, `StatusPill`, `EmptyState`,
`KeyHint`, `IconButton`, `SplitButton`, `MenuBar`, `WorkspaceSwitcher`,
`SideSheet`, `ContextMenu`, `StatusCluster`, `ProgressBar`, `Skeleton`,
`Markdown`, `CopyButton`, `EmptyPreset`, `ErrorPreset`,
`NoResultsPreset` and `DataGrid`. Compose these instead of
re-inventing headers, labels, menus or states. Contracts and
accessibility rules are in `../../docs/design/primitives.md`.

## Workspace

The console is a docking workspace (`react-resizable-panels` v4): four
default panes, draggable tabs, edge drops that split panes, header drag
that moves a whole pane, and a maximised overlay per pane.

- **Layout storage** is `t2.dock.v1`, versioned and run through
  `normalizeWorkspaceModel` on read. Unknown panels are dropped, empty
  tabsets are repaired, and corrupt JSON restores the default with a
  toast instead of a blank window.
- **Reset** lives in the status bar and command palette; it clears the
  key before restoring the default model.
- **Capabilities** filter the View menu and palette, never the saved model,
  so a loss of capability does not destroy an operator's arrangement.
- **Tab content is not remounted when moved** (`keep-mounted`), which
  matters for terminals and polling panes.
- **Tab closers live in the pane toolbar**, not inside the tab, so a
  `role="tab"` never nests an interactive button (axe
  `nested-interactive`). Delete closes the active tab.

Shortcuts: `Alt+←/→` move the active tab between panes, `Alt+1–4` move
it to a pane, `Alt+Shift+M` toggles maximise, `Delete` closes. Workspace
tabs also carry the library's keyboard selection shortcuts.

## Release gate

Phase D runs the full matrix, not a spot check: 157 renderer tests
(types, reducers, parsers, keyboard, populated axe), 133 server tests,
contrast, budget, four viewport cases at 200 %, ruff, both Go builds,
installer syntax/help, an AppImage build, checksums and a fuse read
**from inside the extracted AppImage**. `graphify update` closes it.

## Connect gate

- The gate is a session launcher, not a marketing page: a faint grid and
  horizon, a top status strip with a live bridge probe, a lockup, four
  honest readiness rows (bridge, config, transport, local state), the
  last operator session, and build/platform facts.
- The card uses a three-step rail (config → credentials → connect). The
  config can be dropped (validated `.cfg`/`.json`) or browsed; the
  selected filename and full path are shown separately.
- Drops go through preload `webUtils.getPathForFile`, the Electron 45
  replacement for `File.path`; the renderer never guesses a path.
- Bad extension, bridge offline and connect failure each have a distinct
  inline state; failures move focus to the password/config field.
- Window controls stay in the corner; the background is a drag region.
  The 860 px breakpoint collapses to a single card.

## Armory bridge

`bridge._armory_mod()` resolves the operator-local armory module.
`armory.py` owns the locked repository constant, cache, archive reader
and installs; the bridge methods never accept a URL. The pane shows the
source read-only with branch and snapshot id. Failures surface as a
clean `armory` bridge error and the pane shows them inline.

## Panel taxonomy

- Leaves are grouped once, exhaustively, in `workspace/groups.ts`:
  Session, Host, Topology, Assets, Activity, System. The registry test
  fails if a leaf is missing or appears twice.
- `View → Panels` carries one heading per group. The menu opens with
  `Alt+P`, is filterable by typing, and hides groups with no permitted
  leaf. There is no side rail.
- Every panel stays reachable through the menu, palette, command
  palette and classic layouts.
- Profiles are curated starter sets (≤ 9 tabs), not exhaustive dumps.
  They remain under `View → Classic layouts` for one release while the
  four workspaces settle.
- First run after grouping migrates once to the curated default and
  copies the previous layout to `t2.dock.v1.pre-groups`; no saved data is
  discarded silently.
- The Inspector no longer owns a task form or shell. Quick verbs and
  `Open console` prefill the Terminal; BOF/assembly output is appended to
  the same per-target transcript through a subscription, so there is one
  output surface.

## Hardening

- Every non-core pane is a lazy `React.lazy` chunk behind a `Suspense`
  skeleton; the entry chunk holds only the shell and target roster.
- `npm run budget` fails the build on an entry > 140 KB, any chunk >
  620 KB, JS > 1.25 MB, CSS > 60 KB, assets > 1.5 MB, or any source map.
  Vendor code is split into `react`, `dock`, `virtual` and `d3` chunks.
- CSP is asserted in tests: default deny, no `unsafe-eval`, `object-src`
  and `form-action` none, sources pinned to self/data. Header and meta
  are checked.
- Axe runs on the connect gate, an empty workspace, a populated
  workspace with inspector and listeners, and every pane.
- `npm run smoke:viewports` drives Chromium through 1280×720, 1440×900,
  1920×1080 and 720×450 at 200 % and fails on horizontal overflow.
- `ErrorBoundary` is the final fallback; package/fuse assertions remain
  part of the release checklist.

## Chat, events and jobs

- Chat groups consecutive messages from one operator, inserts day
  rules and marks the caller's own lines. Enter sends, Shift+Enter adds
  a newline, and a failed send restores the text with Retry/Dismiss.
  History is an object (`messages`, `topic`), not a bare array.
- Events merge bridge, task and audit producers into one 2000-entry
  ring. Level and source filters are selects; search is free text. Pause
  freezes the render, not collection. Levels carry glyphs (`■ ▲ › ·`),
  not only colour, and export writes the visible slice.
- Jobs retain every id ever seen even if a later poll drops it. Running
  jobs sort first; failures keep their error text; a 3 s tick surfaces a
  stale badge if the stream stalls; cancel is confirmed.

## Listeners

- Full-width grid: name, type, bind, TLS mode, state, health, certificate
  days, 15-probe sparkline, actions. Creation and editing use a right
  side sheet, not a modal.
- Health is text plus glyph (`● ok`, `▲ degraded`, `■ down`) and a row
  edge, so colour is never the only signal. Sparkline bars repeat the
  shape coding and carry a full `aria-label`.
- Probe runs inline and patches the row without a reload; start/stop
  optimistically flips state then refreshes. Advancing/expiring certs
  are marked in text and colour.
- The health endpoint now returns bind/state/TLS/profile metadata and a
  `health` alias alongside `state`.

## Graph

- Canvas only; d3-force runs the layout, DOM stays untouched while the
  simulation ticks.
- Edge kinds are derived from the server's shared attributes: relay,
  process parent, identity, domain, subnet. The legend is the source of
  truth for colour.
- Above 500 sessions the view collapses to subnet/domain/privilege
  clusters with aggregated links; double-click expands one cluster and
  `All clusters` returns. Rendering is capped at 2500 nodes / 6000
  links and a banner states the point at which clustering began (>2000).
- Zoom is cursor-anchored and clamped 20–400 %. Pan, node drag, hover
  cards, a live minimap and reset sit on the canvas. Selection syncs the
  inspector; dead nodes are grey, elevated nodes get a ring.
- Labels appear from 75 % zoom, or always for the hovered/selected node.
- Canvas colour values are read from CSS custom properties once per
  frame, never per node.

## Data grids

- One `DataGrid` primitive: sticky header, sortable columns with
  `aria-sort`, filter, 25 px virtual rows, raw-output toggle, refresh
  and 10 s auto-refresh. Columns are declared, never parsed ad hoc.
- Parsers are pure and total: malformed lines are dropped, output is
  capped at 5000 rows, and the raw view is always one click away.
  Fixtures cover Linux and Windows `ps`, `netstat` and `find`.
- Process kill uses `kill -9` or `taskkill /PID /F`; network correlates
  Windows PIDs against a parallel process snapshot, and Linux rows show
  `—` because the agent does not emit owning PIDs.
- Files start at `pwd`, show dirs first, navigate on double-click, carry
  clickable breadcrumbs and a parent control, and download files through
  the transfer RPC. `find -type d` / `-type f` are sent as argv, not a
  shell string.
- Collection needs `beacon.list`; kill/download actions need
  `beacon.use` and render disabled otherwise.

## Terminal and screen

- The terminal has two transports: `TASK` (one-shot verb, result polled)
  and `SHELL` (persistent prompt). The transport is a visible pill, not
  an implicit mode. `Interrupt wait` abandons local polling; the agent
  task keeps running and is labelled as such.
- Verb completion comes from the server catalogue filtered by target OS,
  with a common fallback. `Tab` completes, arrows walk the list, Enter
  runs an exact match, and `↑/↓` recall history when the menu is closed.
  The input is a `combobox` with a labelled `listbox`.
- Transcripts are per target, capped at 300 lines, and held in a module
  map mirrored to `sessionStorage`, so moving or maximising the tab never
  loses output while the window is open. Timestamps use a monospaced
  gutter; raw mode shows the untouched base64.
- Saving goes through the main-process dialog; `Ctrl+L` clears.
- Screen captures are base64 PNGs rendered as an object URL-free data
  URL, with zoom, pan, reset, interval capture and a 32 MB binary save.
  Failures land in an inline alert. Linux capture failures are expected
  and the pane says so.

## Inventory and inspector

- The target grid stays virtualised at 10k rows (unit gate asserts under
  80 mounted rows and <500 ms in jsdom). Severity is derived, never
  stored: elevated + root/system is HIGH, either alone is MED, the rest
  LOW. Colour is paired with the text label.
- Sorting is header-driven with `aria-sort`. Selection is roster-style:
  arrows move, Shift extends, Space toggles, Ctrl/Cmd+A selects all
  filtered, Escape clears, F2 or double-click edits the alias inline,
  Enter commits and Escape cancels.
- The inspector is collapsible sections — identity, session, execution,
  payloads, notes, transfer, pivot, danger — with copy buttons that
  auto-clear after 30 s. Every pre-dock action is preserved.
- `Prompt` inputs carry an `aria-label` so inline dialogs stay labelled.

## Shell

- **Menu bar** — File, View, Tabs, Help at the left. Roving focus,
  ArrowLeft/Right between menus, Enter/ArrowDown to open, Escape to
  close. `Alt+P` opens View. Panels are grouped under View.
- **Quick actions** sit right of centre: build, panels, jump, palette,
  settings, disconnect. Capability-gated ones disappear.
- **Status cluster** is on the far right: connection, config basename,
  operator, live/dead, listener health, selection, safe mode, detach,
  reset, workspace selector, UTC clock, window controls. Everything
  that used to live in the status bar moved here.
- **Workspace selector** is a controlled listbox. `Alt+W` focuses it;
  ArrowLeft/Right changes workspace; ArrowDown/Enter opens the list.
  A manual layout change marks it `custom`.
- **Connect gate** is a two-column brand/form layout with recent configs,
  version, platform and the transport invariant. Window controls sit in
  the corner.
- **Double-click the titlebar** toggles maximize unless a button or menu
  is the target. Window controls remain `no-drag`.
- **Detached windows** mount the same dock with one tabset and their own
  storage key (`t2.dock.detach.<panel>`); they reuse the main session
  and keep the full quick-action surface. The menu bar is omitted.
- Disconnect broadcasts `idle` to every window so no detached pane keeps
  a stale identity.
- A renderer fault lands in `ErrorBoundary` with reload/retry actions
  instead of a blank black window; boot waits briefly for the preload
  contract in case a detached window races registration.

## Gate

```bash
npm run audit:contrast   # token pairs + stray hex
npm run verify           # typecheck, contrast, tests (incl. dock axe)
```

CI runs both on every push. A failing pair prints its ratio and
minimum.
