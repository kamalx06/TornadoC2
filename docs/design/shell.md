# Shell and menu contract

Status: Phase 2.2.

## Structure

```
titlebar
  brand
  File  View  Tabs  Help         (menubar; main window only)
  spacer
  build  panels  jump  palette  settings  disconnect
  connection · config · operator · live/dead · listener health
  selection · safe · detach · reset
  workspace selector · UTC clock · window controls
```

No side rail. Panel groups live under `View → Panels`, one heading per
group. The quick `Panels` menu remains as a second launcher.

## Menus

- **File** — Build, Export IOCs/STIX/report, Disconnect, Quit.
- **View** — grouped panels, workspaces, classic layouts, reset,
  density, theme.
- **Tabs** — Close, move left/right, maximise, detach.
- **Help** — shortcuts, copy diagnostics, about.

Checkitems use `role="menuitemcheckbox"` semantics (`aria-checked`).
Separators are `role="separator"`; group labels are presentation
headings.

## Keyboard

- `Alt+P` opens View and focuses its first item.
- ArrowLeft/ArrowRight move between top-level menus (opening the next
  menu if one is open).
- ArrowUp/ArrowDown/Home/End move inside the open menu.
- Enter or Space activates. Escape closes and returns focus to the
  trigger. Tab closes.
- `Alt+W` focuses the workspace selector. ArrowLeft/Right changes
  workspace; ArrowDown/Enter opens the list.
- Clicking outside closes the menu.

## Bounds

- Status cluster caps at 55vw with hidden overflow; below 1120px the
  config and operator text drop, then stats and pills below 980px.
- Menubar stays left of the quick actions and never wraps.
- The titlebar is the drag region; controls and menus set
  `-webkit-app-region: no-drag`.
- Double-click maximize ignores button and menubar targets.

## Preservation

Every old footer metric appears in the status cluster, including reset
and the clock. Detached windows still omit main-window navigation and
keep quick actions.
