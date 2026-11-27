# GUI parity and cutover

The cutover is complete: `--gui` runs the Electron shell and the
PySide6 console (`gui.py`) is deleted. `--gui-classic` is accepted as a
no-op alias. The matrix stays as the record of what moved.

Every row is **green**: shipped and tested. No surface is CLI-only
any more.

| Surface | Electron | Notes |
|---|---|---|
| Connect / disconnect, password | green | branded gate, recent configs, session reuse, no PEM in renderer |
| Dockable, resizable, tabbed workspace | green | persisted + normalised model, drag/edge split, maximize, reset, keyboard moves, axe |
| Target table, filter, palette | green | virtualised 10k gate, severity sort, roster keyboard, inline alias, table semantics |
| Target inspector: task + result | green | sectioned, copy actions, base64 result decoding |
| Task quick actions (whoami, pwd, ls, info) | green | |
| Alias, tag, note, forget, kill | green | confirm on forget |
| Multi-select bulk task/tag/kill | green | per-beacon audit |
| Listeners list, health, cert days | green | server prober data |
| Listener start/stop, probe | green | inline probe patches the row; 15-probe sparkline |
| Listener create/edit, cert/profile pickers, delete | green | side sheet, capability-gated |
| Engagement hosts/users/shares/services/evidence/findings | green | virtualised |
| Evidence add (hash or loot digest), finding add | green | |
| Timeline, MITRE footer | green | |
| Graph | green | canvas force layout, typed edges/legend, cluster expand, minimap, hover/selection sync, 2k state |
| Audit reader + verify | green | full chain re-walk, admin |
| Chat read + send | green | grouped/day rules, recoverable send, rate limit server-side |
| Armory install/uninstall/update | green | digest + format checks |
| Jump (psexec/winrm/wmi/scshell) | green | confirm dialog, cleanup default |
| Exports IOC/STIX/report to 0600 files | green | main-process save dialog |
| Notes add/list/clear per beacon | green | |
| Build dialog | green | 16.5; advanced drawer (mTLS, WireGuard, pivot, C2 profile, TCP relay) plus config import |
| Upload/download + jobs with progress and cancel | green | retained list, stale badge, confirmed cancel; loot on download |
| Interactive shell, SOCKS proxy | green | dual task/shell terminal with catalogue completion, history and transcripts; TCP forward is a build option |
| Screen capture | green | base64 PNG, zoom/pan, interval, 0600 binary save, inline errors |
| Process / connection / file grids | green | Linux+Windows fixtures, raw fallback, PID correlation, kill/download, breadcrumbs |
| BOF run, execute-assembly, creds list/reveal | green | clipboard auto-clear on reveal |
| AI one-shot console + settings | green | provider/key editor writes `ai.json` 0600 |
| Capability gating of every action | green | from `caps`; server re-checks |
| Settings: theme, density, palette key | green | dark/light, cozy/compact/dense; only the palette key is rebindable |
| AI provider settings | green | key stays masked, `ai.json` 0600 |
| Native `prompt`/`confirm` | green | Dialog/Confirm primitives |
| Detached windows, safe mode, axe tests | green | detached dock reuses the session and its own layout key; gate/empty/populated/pane axe matrix |
| Bundle budget, CSP, viewport gate | green | lazy chunks, 140 KB entry budget, four viewports at 200 %, CSP assertions |
| Profiles, quick actions, live status, window controls | green | 4 exhaustive presets, custom marker, labelled actions | |

## Cutover rules

1. `--gui` is Electron; `--gui-classic` is aliased to it.
2. The shell and CLI share the same `Client` through the bridge; a
   protocol change lands once.
3. No feature lands in a second frontend; the matrix has no red rows.
4. `gui.py`, PySide6 and the Qt installer blocks are removed;
   `install-deps-client.sh` installs Node and Electron only.
