# Changelog

## 0.9.0
- Feature-pruned agent builds; unused transports, evasion, WASM and Jump code excluded.
- Versioned WASM ABI with limits and timeout isolation.
- Per-operator armory for BOF installation.
- Jump: psexec, winrm, wmi, scshell.
- Runtime listener management, OS-split agent trees, privilege graph.
- Assurance suite and CI.
- AES-256-GCM at-rest encryption for credentials, notes and the engagement model; backup/restore scripts.
- TOTP removed; password-HMAC lockout (5 failures / 30 s) and an 8 h session cap replace it.
- Linux persistence (systemd, cron, profile) and read-only privilege reconnaissance.
- Engagement model, timeline, findings and Markdown reporting.
- Ed25519-signed armory index and release workflow with SBOM.
- Operator handbook, detection notes, WASM ABI policy and contribution guide.
- Engagement tab in the GUI for hosts, findings, timeline and reports.

- Audit seal key + anchor persisted and verified; `audit verify`.
- Jump builds serialized with an LRU cache; scshell default service;
  engagement writes batched with caps.
- At-rest coverage extended to chat, loot, aliases, webhooks,
  listeners, scheduler; startup migration and `scripts/atrest-status.py`.
- Release workflow builds a real `Bootstrap.dll`; installer takes
  `BUILD_TAGS`; ruff in CI; armory index signing enforced.
- Windows persistence (registry/task/service), ntdll unhook, module
  stomp, fork, signed-digest self-update; WMI falls back to CIM.
- `persist` copies the binary to a durable path (`--path` overrides).

- Stomp saves original section bytes, supports `--restore`/`--force`
  and uses a tested PE helper.
- Updates require an ECDSA signature over the digest; `update publish`
  signs a staged build and the listener serves `/published/<sha>`.
- Service persistence is a real SCM service (`svc_host`) and verifies
  RUNNING.
- Audit verification is suffix-based with checkpoint offsets, holds the
  write lock, and `--full` re-walks. AAD now binds file paths; migration
  is one-shot with a marker and `atrest status|migrate`.
- Unhook can revert; builder/wizard expose unhook and stomp.

- Call-stack spoofing (`ev_stackspoof`) for thread creation and
  memory transitions, on by default for Windows, with a config switch.

- Jump psexec registers the stager as a real service (`svc_host` also
  in the stager); `persist task:system` installs an onstart SYSTEM task.
- `stomp` runs PE and BOF payloads; `fork --parent` spoofs the parent.

- Versioned model (users, shares, services, evidence with hashes),
  MITRE mapping, IOC CSV, STIX 2.1, dataset-hashed reports, bulk
  actions audited per beacon and model-projected graph.

- Export/model hardening: STIX SCO patterns and escaping, CSV formula
  neutralisation, Markdown escaping, evidence digest/loot validation,
  bulk limits and per-item errors, export filenames and 0600 writes,
  `since` model polling, schema-refusal and `.corrupt` backup for the
  engagement store, non-blocking GUI exports/report and non-churning
  engagement rendering.

- GUI phase: virtualised beacon model and views, bounded background
  runner with timeouts, multi-select bulk bar, fuzzy palette with
  recents, toasts, light/compact modes, editable keybindings, saved
  workspace and `--safe` mode, plus a 10k-row benchmark gate.

- Infrastructure: redirector generator (nginx SNI/TLS, Caddy,
  Cloudflare) and a listener health prober with states, cert expiry,
  history, webhook and client/GUI display.

All earlier changes are in git history.
