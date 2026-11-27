# UI primitives

Status: Phase 2.4. All live in `src/renderer/src/ui/` and are exported
from `ui/index.ts`. Every colour comes from tokens.

| Primitive | Contract |
|---|---|
| `MenuBar` | Desktop menubar, roving focus, Escape restore, checkitems |
| `WorkspaceSwitcher` | Controlled listbox, `Alt+W`, edge clamp |
| `SideSheet` | Right dialog sheet, focus trap, dirty-close confirm, Escape, scroll lock |
| `ContextMenu` | Portal menu, viewport clamp, outside/Escape close, arrows |
| `StatusCluster` | Status strip container with `role=status` |
| `ProgressBar` | Determinate/indeterminate, `aria-valuenow`/`text` |
| `Skeleton` | Busy lines with `role=status` and `aria-busy` |
| `Markdown` | marked + DOMPurify, fixed tag/attr allowlist, links `_blank` + `noreferrer` |
| `CopyButton` | Clipboard with 30 s clear and copied announcement |
| `EmptyPreset` / `ErrorPreset` / `NoResultsPreset` | State panels; error supports retry |
| `DataGrid` | Virtual rows, grouped columns with visibility menu, tree mode (`aria-level`, twisty) |

## Rules

- SideSheet and Dialog restore the previously focused element and trap
  Tab. Dirty SideSheets require confirmation.
- Context menus and listboxes clamp to the viewport.
- Markdown is the only `dangerouslySetInnerHTML` surface. Scripts,
  event handlers and non-allowlisted attributes are removed.
- Grouped columns can be hidden together; at least the menu remains so
  the user can restore them.
- Tree rows expose depth as `aria-level` and expansion state.
- Empty and error states replace the grid body; error retry calls the
  grid refresh.
- All primitives are covered by axe and keyboard tests.
