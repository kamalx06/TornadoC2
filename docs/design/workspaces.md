# Workspace architecture

Status: approved design input for Phases 2–3. No code yet.

## Goals

- Four named workspaces, each an independent dock model with its own
  storage key.
- The DESIGN layout for Workspace 1: a 2×2 operational grid.
- Every one of the 18 existing panels plus the 10 approved parity
  panels remains reachable.
- Detached OS windows and in-window floating tabsets share a drag group.
- A corrupt or partial model never blanks the console.

## Workspace registry

| Id | Label | Layout |
|---|---|---|
| `w1` | Workspace 1 — Target Operations | 2×2 split |
| `w2` | Workspace 2 — Infrastructure & Assets | single tabbed pane |
| `w3` | Workspace 3 — Comms & Telemetry | single tabbed pane |
| `w4` | Workspace 4 — Intel & Reporting | two-pane split |

`w1` is the default and the migration target for `t2.dock.v1`.

### `w1` model

```
split vertical 74/26
  split horizontal 56/44
    tabset top-left    [screen, graph]
    tabset top-right   [terminal]
  split horizontal 56/44
    tabset bottom-left [processes, files, network, extensions]
    tabset bottom-right[targets, inspector]
```

Selected tabs: `screen`, `terminal`, `processes`, `targets`.

### `w2` model

Single tab set, in order: `listeners`, `armory`, `creds`, `settings`,
`operators`, `deadman`, `atrest`, `c2profiles`.

### `w3` model

Single tab set, in order: `events`, `chat`, `audit`, `jobs`, `ai`,
`loot`, `webhooks`, `schedules`, `toolbox`, `recipes`.

### `w4` model

```
split horizontal 55/45
  tabset left  [engagement]
  tabset right [targets-intel]
```

## Storage

| Key | Meaning |
|---|---|
| `t2.workspace.v1.w1` … `.w4` | Per-workspace model, version 1 |
| `t2.workspace.v1.active` | Last active workspace id |
| `t2.dock.v1.pre-workspaces` | Verbatim backup of the old single model |
| `t2.dock.v1` | Left in place for one release; never mutated by the new shell |

Reads run through `normalizeWorkspaceModel` plus the existing repair
pass: unknown ids dropped, duplicates dropped, empty tabsets marked
`keepWhenEmpty`, missing leaves re-homed except those named in the
model's `hidden` list. A parse error restores that workspace's default
and raises a toast. If every workspace is invalid, `w1` is restored
without touching the backups.

`hidden` is recomputed on every save from the panels absent in the
model. A closed or detached tab therefore stays closed across a reload;
a model without `hidden` (legacy/profiles) still gets its missing leaves
re-homed.

Migration runs once when `t2.workspace.v1.migrated` is absent:

1. Back up `t2.dock.v1`.
2. Copy every tab from the old model into the nearest-matching `w1`
   slot; unknown placement lands in the bottom-left tab set.
3. Write the backup key before marking migration complete.
4. Never migrate into `w2`–`w4`; they always start from DESIGN defaults.

## Floating and detached panes

- **Float** creates a library floating tabset, draggable and resizable
  inside the main window.
- **Detach to window** opens the existing hardened child window with a
  single tab set and `t2.dock.detach.<panel>`.
- All workspaces and child windows use `dragGroup="t2"`.
- A main-process coordinator owns tab-id transfer: detach waits for the
  child to load, then closes the source tab; a tab that leaves a window
  is recorded hidden; a child with no tabs closes itself.
- Dropping a transferred tab back into the main workspace removes it
  from `hidden` and the child closes.
- A duplicate-id drop is rejected by the library and surfaced as a
  toast; it never overwrites the existing tab.
- `Disconnect` broadcasts `idle` to every window; detached panes keep
  the session and capability set until the operator reconnects.

## Rail removal

The 52px icon rail is removed. `View → Panels` carries the six group
headings and their leaves. The same menu opens with `Alt+P` and is
filterable. Capability-hidden groups disappear.

| Old rail/status element | New location |
|---|---|
| Group launchers | `View → Panels`, command palette, `Alt+P` |
| Assets degraded badge | Group heading badge and top health pill |
| Connection, config, live/dead, health, selection, safe mode, reset, clock | Top-right status cluster |
| Reset layout | `View`, palette, status cluster |
| Workspace profiles | `View → Classic layouts` for one release |

## Shell order

Title bar: brand → File/View/Tabs/Help → spacer → Build, Palette,
Jump, Detach, Disconnect → status cluster → window controls.

Workspace selector sits in the status cluster, immediately before the
clock. `Alt+W` focuses it.

## Keyboard

| Keys | Action |
|---|---|
| `Alt+P` | Open Panels menu |
| `Alt+W` | Focus workspace selector |
| `Alt+1–4` | Move active tab to workspace pane or workspace |
| `Alt+←/→` | Previous/next pane |
| `Alt+Shift+M` | Maximise/restore pane |
| `Alt+Shift+F` | Float active tab |
| `Delete` | Close active tab |

## Responsive behavior

- Below 1100px the shell shows only the active workspace and a compact
  selector; the status cluster scrolls horizontally rather than
  wrapping.
- Below 860px quick actions collapse into an overflow menu.
- Data grids keep 1px rows and horizontal scroll; no cards are
  introduced.

## Accessibility

- The menu bar is a real `menubar` with roving focus and Escape to
  close.
- The workspace selector is a `listbox` with `aria-activedescendant`.
- Tabsets keep the library's tab semantics; closers stay in the pane
  toolbar.
- Moving or switching a workspace announces the panel name and
  workspace through a polite live region.
- Every pane retains its axe coverage.

## Tests

Unit: model normalization, migration, backup, corrupt fallback,
duplicate ids, workspace switching, detached transfer, rail removal
mapping.

Integration: 18-panel presence in all menus, every panel openable,
capability hide/show, `Alt+P` and `Alt+W`, detach round-trip.

Visual: four viewports at 200%, no horizontal overflow, waterfall-free
first paint.
