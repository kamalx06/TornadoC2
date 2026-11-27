# Panel registry and no-loss checklist

This is the frozen inventory for the overhaul. Every entry stays
reachable and functional. `panel-inventory.json` is the
machine-readable copy; the workspace registry test will read it in
Phase 2 and fail if a panel disappears, becomes orphaned, or loses its
capability.

## Rules

1. No panel is renamed, merged, or deleted without a recorded decision.
2. `targets-intel` is the only alias. It renders the same component as
   `targets`, shares selection, and exists so Workspace 1 and Workspace
   4 can both show a roster.
3. Every panel keeps its capability. A loss of capability hides the
   leaf from menus and workspace defaults; it does not destroy a saved
   layout.
4. Every existing behavior below has a Phase 4 or Phase 5 owner and a
   regression test. The checklist is signed off in the release gate.
5. New panels start in the approved workspace. They are not added to
   the 18-panel legacy backup model.

## Existing 18

| Panel | Capability | Behavior that must survive |
|---|---|---|
| `targets` | `beacon.list` | Virtualized roster, severity sort, filter, roster keyboard, Shift/Ctrl selection, inline alias, bulk task/tag/kill, attach |
| `targets-intel` | `beacon.list` | Same renderer and shared selection, distinct dock id |
| `inspector` | `beacon.list` | Collapsible sections, copy buttons with 30s clear, quick verbs, BOF/assembly output into the target transcript |
| `screen` | `beacon.list` | Base64 PNG stage, zoom/pan/reset, interval capture, binary save, inline errors, Linux guidance |
| `graph` | `beacon.list` | Canvas force layout, typed edges, legend, clustering, expand, minimap, hover cards, selection sync, node cap banner |
| `terminal` | `beacon.list` | TASK/SHELL transport pill, catalogue completion, history, per-target transcript, raw toggle, save, clear, interrupt |
| `processes` | `beacon.list` | Tree/flat, declared columns, Linux/Windows kill, raw fallback, auto-refresh |
| `files` | `beacon.list` | `pwd` start, dirs first, breadcrumbs, parent, double-click, find argv, download |
| `network` | `beacon.list` | Declared columns, PID correlation, kill, raw fallback |
| `listeners` | `listener.view` | Full-width grid, health text+glyph, sparkline, TLS/cert days, start/stop/probe, side-sheet create/edit/delete |
| `armory` | `armory.view` | Locked source, installed count, index refresh, install/update/remove, per-row errors |
| `creds` | none | Masked values, reveal with clipboard clear, list |
| `settings` | none | Theme, density, connection facts, AI provider form, shortcut table |
| `events` | none | Merged ring, level/source filters, search, pause/follow, save/clear |
| `chat` | `chat.use` | Grouping, day rules, own-line marking, topic, Enter/Shift+Enter, retry/dismiss |
| `audit` | `audit.read.own` | Hash-chain reader, verify action, admin full-chain |
| `jobs` | none | Retained ids, running-first order, progress, error text, stale badge, confirmed cancel |
| `ai` | `beacon.list` | Turn log, ask, loading state, provider config link |

## Approved new panels

| Panel | Capability | Purpose |
|---|---|---|
| `extensions` | `beacon.use` | WASM extension list/load/unload/call/info |
| `operators` | `operator.list` | Roster, add, remove, role, password, export |
| `deadman` | `deadman.view` | Status, arm, warn, halt mode, shred, halt |
| `atrest` | `audit.read.all` | Coverage report and forced migration |
| `c2profiles` | `beacon.build` | Profile catalogue and raw JSON copy |
| `loot` | `loot.use` | List, get, upload, delete |
| `webhooks` | `webhooks.manage` | List, add, remove, test |
| `schedules` | `beacon.use` | Add, list, remove, output |
| `toolbox` | none | Catalogue-driven typed verbs plus command history |
| `recipes` | none | Reference recipes, copy/run through `sh` |

## Capability sources

- Existing panel caps come from `workspace/panels.ts` at baseline.
- New caps come from `tornadoc2/team/constants.py::ROLE_CAPABILITIES`.
- Server re-checks every action; the client gate is a convenience, not
  the authority.
- `operator.list` is admin/local-only. `deadman.view` is available to
  every role, while arm/halt remain separate capabilities.
