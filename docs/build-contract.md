# Build specification contract

Status: Phase 1.5. The descriptor and rules are implemented in
`tornadoc2/beacon/build_spec.py`.

## One source of truth

The following consume `build_spec` directly:

- `BeaconBuilder.build()` validates before touching the toolchain.
- `BuildManager._validate_transport()` validates before spending a
  build slot or rate token.
- `BeaconHandler._load_build_config()` validates the merged remote
  config before path checks.
- The CLI wizard takes its transport list from the descriptor and
  validates the finished payload.
- The GUI Agent Builder fetches the descriptor and validation from the
  bridge.

No transport or cross-field rule may exist only in a caller.

## Descriptor

`build.options` / Python `descriptor()` returns:

```json
{
  "version": 1,
  "oses": ["linux", "windows"],
  "arches": ["amd64", "arm64", "386"],
  "formats": {"linux": ["elf", "shellcode", "stager"],
               "windows": ["exe", "dll", "shellcode", "stager"]},
  "transports": [
    {"id": "http", "label": "HTTP", "platforms": ["linux", "windows"],
     "exclusive": false, "fields": ["url", "tls_profile", "c2_profile"],
     "description": "..."}
  ],
  "relay_fields": ["smb_relay_pipe", "tcp_relay_target", "..."],
  "fields": [{"name": "url", "type": "url", "required": true}],
  "tls_profiles": ["go", "chrome", "firefox", "safari"],
  "sleep_masks": ["", "none", "rc4", "aes-ctr", "cronos", "hwbp"],
  "syscall_methods": ["direct", "indirect"],
  "inject_methods": ["default", "apc", "..."],
  "jump_methods": ["psexec", "winrm", "wmi", "scshell"],
  "persistence": ["systemd", "cron", "profile", "registry", "..."],
  "evasion": ["antisanbox", "..."],
  "defaults": {"target_os": "linux", "output_format": "elf", "...": "..."}
}
```

The UI must hide transports whose `platforms` exclude the selected OS
and show only the selected transport's `fields`. `relay_fields` are
parent-side and hidden for `smb`/`tcp`/`tcprev` children.

## Validation

`build.validate` takes `{config}` and returns
`{ok: bool, errors: [{field, message}]}`. It is pure and performs no
network or filesystem access.

The server build route returns the same `fields` array on a rejected
config, so the form can attach errors to inputs. A rejected build
never consumes a build slot.

Rules include, in addition to types and enums:

- `smb`/`tcp`/`tcprev`/`websocket`/`quic`/`wireguard` are exclusive.
- `smb` is Windows-only and requires a pipe; UNC requires `\pipe\`.
- `tcp`/`tcprev` tokens are exactly 64 hex characters.
- Pivot children and parent relay fields require `pivot_key_path`.
- A child cannot also carry parent relay fields.
- `icmp` is Linux-only and requires a dotted-quad address.
- `dns`/`doh` require a zone; DoH requires an `https://` resolver.
- WireGuard requires keys, an address with port and a tunnel IP.
- Stagers require HTTP, `https://`, `stage_name`, no mTLS, no WASM,
  no self-injection.
- `cronos`/`hwbp` require Windows amd64; `indirect` requires Windows;
  `apc` requires Windows, `inject=true` and a compatible format.
- `inject` is limited to exe/shellcode on Windows and elf on Linux.
- Formats must match the OS.
- Remote C2 profiles are names, never paths.

## Field error shape

```json
{"field": "tcp_bind_token",
 "message": "tcp_bind_token must be 64 hex chars"}
```

An empty `field` is a form-level error. Messages are plain text; the
renderer escapes them.

## Compatibility

`normalize()` fills defaults and joins `transport_mode` before
validation, so a partial config is judged on the same shape the
builder receives. Adding a transport means one descriptor entry, one
field mapping and one rule block in `build_spec.py`; the wizard and
GUI pick it up without edits.
