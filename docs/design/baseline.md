# Phase 0 baseline

Captured before any workspace or backend change. This is the reference
point for the overhaul; a regression against it blocks the next phase.

- Date: 2026-11-28
- Commit: `4401dd1` (`main`)
- Dirty tree at capture: `DESIGN.md` (new, untracked)
- Python: 3.15.2 in `/tmp/opencode/t2venv` (temporary baseline venv)
- Node: 26.13.1 / npm 11.20.0
- Go: 1.27.4 linux/amd64
- Rust: not required for this tree

| Check | Command | Result |
|---|---|---|
| Ruff | `ruff check tornadoc2 client/tornado_client client/tornadoc2_mcp tests_py scripts` | pass, 0 findings |
| Server tests | `python -m unittest discover -s tests_py` | pass, 133 tests |
| Renderer verify | `npm run verify` (typecheck, contrast, vitest) | pass, 29 files / 157 tests |
| Bundle budget | `npm run budget` | pass, entry 104.6 KB, JS 1096.6 KB, CSS 51.3 KB |
| Viewport smoke | `npm run smoke:viewports` | pass, 4/4 viewports, no overflow |
| Go linux build | `GOOS=linux GOARCH=amd64 go build -tags t_http ./linux` | pass |
| Go windows build | `GOOS=windows GOARCH=amd64 go build -tags 't_http jump_psexec jump_winrm jump_wmi jump_scshell wasm_host' ./windows` | pass |

Notes:

- `go build ./linux` needs `-o`; the package directory is also named
  `linux` and the default output would collide with it.
- The viewport smoke run reports `bridge lost` because no operator
  config is supplied. The gate still renders and all overflow/form
  assertions pass, which is what the gate covers.
- Available baseline counts: 18 registered panels, 4 profiles, 69
  bridge methods, 133 server tests, 157 renderer tests.

Do not update this file as phases land. Add a dated release-gate file
instead.
