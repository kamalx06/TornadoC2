# GUI ↔ CLI feature parity

Status: Phase 0 skeleton. The full machine-readable manifest and CI
check land in Phase 5. Until then this table is the review artefact.

Legend: **both** = exists in each interface; **cli** = CLI only;
**gui** = GUI only; **partial** = exists but narrower; **N/A** =
inherently interface-specific.

Rules:

1. Every catalogue entry and bridge method has a row.
2. A `cli` row is not complete until the GUI has a first-class path.
3. A `gui` row is not complete until the CLI has an equivalent.
4. `partial` rows name the missing part.
5. N/A rows still need a documented reason.
6. CI fails if an entry or method is unmapped.

## Main menu

| Surface | CLI | GUI | Missing / target | Phase |
|---|---|---|---|---|
| Connect / disconnect | cli | both | GUI gate; CLI args | N/A |
| Beacons / targets | both | both | roster vs list | complete |
| Use / attach target | cli | gui | selected target; CLI `use` | complete |
| Detach target | cli | gui | GUI context | N/A |
| Info / caps | cli | partial | GUI shows identity/inspector; add caps in Settings | 5 |
| At-rest status/migrate | cli | gui (new `atrest`) | panel | 5 |
| Audit read/verify/chat/checkpoint | both | partial | add checkpoint action, chat filter | 5 |
| Chat | both | both | | complete |
| Loot list/get/upload/delete | cli | partial (list) | `loot` panel with get/upload/delete | 5 |
| History | cli | gui | Toolbox → History sub-tab | 5 |
| Jobs list/cancel | both | both | | complete |
| Build | partial | partial | CLI full flags; GUI dynamic builder | 4, 6 |
| C2 profiles | cli | gui (new `c2profiles`) | panel with raw JSON copy | 5 |
| Listeners list/start/stop/probe/create/edit/delete | both | partial | side-sheet advanced types, health watch | 4 |
| Armory list/install/uninstall/update | both | partial | remove, update, locked source UI | 4 |
| BOF store add/remove/list, run | cli | partial (run) | Armory/BOF store management | 5 |
| Deadman status/arm/reset/disable/warn/halt/shred | cli | gui (new `deadman`) | panel + status pill | 5 |
| Halt teamserver | cli | gui | File menu with confirm | 5 |
| Clear | cli | both | pane actions | complete |
| Help | cli | partial | Help menu, shortcuts | 2 |
| Recipes | cli | gui (new `recipes`) | panel with copy/run | 5 |
| AI | both | both | multi-turn chat redesign | 4 |
| Exit | cli | gui | window close | N/A |
| Operators list/add/remove/set-role/passwd/export | cli | gui (new `operators`) | panel | 5 |
| Killall filters | cli | partial | bulk dialog filters | 5 |
| Notes per beacon / global / search | both | partial (per beacon) | global notes in Toolbox | 5 |
| Webhooks list/add/remove/test | cli | gui (new `webhooks`) | panel | 5 |
| Creds list/get/add/search/validate/delete | cli | partial (list/reveal) | panel forms/actions | 5 |
| Schedules add/list/remove/output | cli | gui (new `schedules`) | panel | 5 |
| Extensions list/info/load/unload/call | cli | gui (new `extensions`) | Workspace 1 tab | 5 |
| SOCKS start/stop/status | both | partial | status pill and stop | 5 |
| Multiplayer toggle | cli | gui | API + Settings/admin | 5 |
| Update publish | cli | gui | Build → Publish | 5 |

## Beacon verbs

| Surface | CLI | GUI | Missing / target | Phase |
|---|---|---|---|---|
| File verbs (`ls`, `cat`, `find`, `grep`, `head`, `tail`, `stat`, `strings`, `hexdump`, hashes, `du`, `wc`, `nl`, `rev`, `sort`, `uniq`, `tr`, `base64`, `which`) | cli | partial (files grid, terminal) | Toolbox typed forms and JSON table modes | 5 |
| Host verbs (`ps`, `netstat`, `ifconfig`, `arp`, `route`, `users`, `groups`, `av-list`, `id`, `env`, `pwd`, `whoami`, `hostname`, `uname`, `df`, `uptime`, `date`, `getpid`, `getppid`) | cli | partial (processes/network) | Toolbox forms; table flags | 5 |
| File mutation (`mkdir`, `rm`, `cp`, `mv`, `chmod`, `ln`, `touch`, `gzip`, `gunzip`) | cli | partial (terminal) | Toolbox forms | 5 |
| `exec`, `sh`, `curl`, `resolve`, `nc` | cli | partial (terminal) | Toolbox forms | 5 |
| `upload`, `download` | both | both | | complete |
| Tokens (`make_token`, `runas`, `rev2self`, `steal_token`) | cli | partial (terminal) | Inspector quick verbs | 5 |
| `migrate`, `execmem`, `pyexec`, `psexec`, `shexec` | cli | partial (terminal) | Toolbox forms | 5 |
| `hashdump`, `lsassdump`, `enablepriv` | cli | partial (terminal) | Toolbox forms | 5 |
| `privesc`, `persist`, `spawnto` | cli | partial (terminal) | Toolbox forms | 5 |
| `sleep`, `workhours`, `kill`, `exit` | both | both | | complete |
| `bof`, `execute-assembly` | both | both | | complete |
| `screenshot` | cli | both | GUI viewer is richer | 5 |
| `info`, `graph modes`, `forget`, `tasks`, `wait`, `schedule` | cli | partial | Toolbox/graph query | 5 |
| `extension` | cli | gui (new) | panel | 5 |
| `export`, `socks`, `detach` | both | both | | complete |

## GUI-only work for the CLI

| Surface | Target CLI form | Phase |
|---|---|---|
| Screen viewer | `screen capture [path]`, `screen watch` | 5 |
| Process/file/network structured grids | `ps --table|--json`, `ls --table`, `netstat --table` | 5 |
| Target severity sort/filter | `targets --sort severity --filter <q>` | 5 |
| Merged events ring | `events tail [--level] [--source] [--follow]` | 5 |
| Listener health sparkline | `listeners health [--watch]` | 5 |
| Layout save/load | `layout save|load|reset` | 5 |
| Inspector copy actions | `info --copy` | 5 |
| Armory update/remove | `armory update <name>`, `armory installed` | 5 |
| Markdown AI output | terminal-native, no change needed | N/A |
| Detached windows / palette / theme / density | inherently GUI | N/A |
| AI multi-turn history | `ai` keeps one-shot, transcript flag optional | N/A |

## Manifest shape (Phase 5)

```ts
type ParityRow = {
  id: string            // catalogue name or bridge method
  cli: 'full' | 'partial' | 'none' | 'na'
  gui: 'full' | 'partial' | 'none' | 'na'
  target: string
  phase: 4 | 5 | 6
  test: string
}
```

The manifest is the single review input. Progress is counted from it;
a row cannot be closed by prose alone.
