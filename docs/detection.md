# Detection notes

Per-feature telemetry, so builds can be chosen for a target's
monitoring rather than by habit. "Default" means the behaviour with no
extra flag; every feature is off unless its tag is compiled.

## Agent

| Feature | Default | Telemetry |
|---|---|---|
| Transport http | on | TLS SNI/URI, periodic POST cadence, JA3/JA4 if uTLS is off |
| Transport dns | off | High-volume `TXT` queries, long labels |
| Transport quic | off | UDP/443, QUIC initial packets |
| Transport wireguard | off | UDP 51820, handshake noise, no SNI |
| Transport icmp | off | ICMP echo payload size/entropy |
| Sleep mask | off | Unbacked/private RW regions during sleep |
| AMSI patch | on (Windows) | `amsi.dll` `AmsiScanBuffer` prologue differs from disk |
| ETW patch | on (Windows) | `ntdll!EtwEventWrite` prologue differs |
| Anti-VM / anti-sandbox | off | Early exits, disk/CPU queries, `GetSystemFirmwareTable` |
| PPID spoof | off | Parent PID in `CreateProcess` does not match the parent image |
| Syscall direct/indirect | off | Call stacks without `ntdll` frames |
| WASM host | off | Pages of `RW` memory from `wazero`, no `PROT_EXEC` |
| BOF | off | `VirtualAlloc` + `CreateThread` inside the beacon |
| Jump psexec | on if tagged | Service creation, `ADMIN$` SMB write, 7045 events |
| Jump scshell | on if tagged | `ChangeServiceConfig` on an existing service, no new service |
| Jump wmi | on if tagged | `wmic.exe` / `Win32_Process.Create`, `WmiPrvSE` child |
| Jump winrm | on if tagged | WinRM 5985/5986, `wsmprovhost.exe` child |
| Persist systemd | Linux | `~/.config/systemd/user/*.service`, `systemctl --user enable` |
| Persist cron | Linux | `@reboot` line in the user crontab |
| Persist profile | Linux | Appended `~/.profile` line |
| Persist registry | Windows | `HKCU\...\Run` value `Tornado_*` |
| Persist task | Windows | `schtasks` at logon, `\Tornado\*`; `task:system` at start as SYSTEM |
| Persist service | Windows | `sc create Tornado_*`, 7045 event |
| Stack spoof (`ev_stackspoof`) | on (Windows) | Return addresses in the Go image, `kernel32`/`ntdll`-shaped chain; ~1.5 KB size delta (linker noise) |
| Unhook (`ev_unhook`) | off | `ntdll` `.text` matches disk; hooks on ntdll vanish |
| Stomp (`ev_stomp`) | off | No new private RX region; payload inside a signed module range; `--restore` reverts |
| Fork | off | Two processes of the same image, second with no console; `--parent` also spoofs PPID |
| Update | off | `.new`/`.old` files beside the binary, new PID with same path, ECDSA-verified |

## Server

| Feature | Default | Telemetry |
|---|---|---|
| mTLS + password HMAC | on | Certificate CN + `X-Operator-*` headers |
| HMAC lockout | on | `auth.lockout` audit entry after 5 failures |
| Listener health | on | Server-side TLS handshakes + `/health` every 60 s |
| At-rest encryption | on | `T2ENC1` header and high-entropy `logs/*.json` |
| Audit chain | on | Append-only hash chain; checkpoints preserve order |
| Armory | opt-in | pinned GitHub/codeload fetches, `client/.tornadoc2/armory` writes |

## Gaps

- No call-stack spoofing yet; direct syscalls alone are visible in
  ETW call stacks on recent Windows.
- `stomp` overwrites a loaded module's `.text` in place; a module
  integrity check on that module will flag it.
- WMI runs `wmic` first and falls back to PowerShell CIM; both are
  visible in process creation.
- Jump writes the payload under `ADMIN$` / `%TEMP%` with a predictable
  prefix; rename before copying if the target watches those paths.
- Linux persistence is user-level only; root methods (system unit,
  `ld.so.preload`) are not implemented.
- The armory has no signature. Trust rests on TLS, the pinned host
  and per-payload SHA-256. A compromised upstream account can replace
  the catalogue; compare the displayed snapshot id if that matters.
