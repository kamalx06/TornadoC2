"""Team server operator registry.

Holds the team CA, the server certificate, and the operators.json
database. Every method that mutates state takes the internal lock;
the file is small and reads are cheap, so list/get re-read from disk
each time rather than caching.

Layout under TEAM_CA_DIR (default: team_ca/):

    ca.pem             team CA certificate
    ca.key             team CA private key — 0600
    server.pem         listener server cert, signed by CA
    server.key         listener server key — 0600
    operators.json     registry — 0600
    operators/
        <name>.crt     client cert for operator <name>
        <name>.key     client key for operator <name> — 0600

The listener presents server.pem. Clients present their per-operator
cert and verify the server against ca.pem.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time

from . import constants

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


_OPERATOR_NAME_RE = re.compile(
    r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')

_RESERVED_OPERATOR_NAMES = frozenset({
    'room',    # /history @room means "the broadcast room"
    'off',     # /dm off leaves DM mode
    'exit',    # /dm exit leaves DM mode
    'leave',   # /dm leave leaves DM mode
    'none',    # /dm none leaves DM mode
    'system',  # day and system lines render under this name
})


class OperatorRegistry:

    SCRYPT_N = 1 << 17      # 131072 — 128 MiB per derivation
    SCRYPT_R = 8
    SCRYPT_P = 1

    LEGACY_PBKDF2_ITERS = 200_000

    @staticmethod
    def _derive_key(password: str, salt: bytes,
                    algo: str = 'scrypt',
                    params: dict = None) -> bytes:
                    
        import hashlib as _hl

        if algo == 'scrypt':
            p = dict(params or {
                'n': OperatorRegistry.SCRYPT_N,
                'r': OperatorRegistry.SCRYPT_R,
                'p': OperatorRegistry.SCRYPT_P,
            })
            maxmem = 128 * p['n'] * p['r'] * 2
            return _hl.scrypt(
                password.encode('utf-8'),
                salt=salt,
                n=p['n'], r=p['r'], p=p['p'],
                maxmem=maxmem, dklen=32,
            )

        if algo == 'pbkdf2-sha256':
            iters = int((params or {}).get(
                'iters', OperatorRegistry.LEGACY_PBKDF2_ITERS))
            return _hl.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                iters,
                dklen=32,
            )

        raise ValueError(
            f'unknown password derivation algorithm: {algo!r}')

    def __init__(self, base_dir: str = None):
        self.base_dir = base_dir or constants.TEAM_CA_DIR
        self.ca_dir = self.base_dir
        self.ca_cert = os.path.join(self.base_dir, 'ca.pem')
        self.ca_key = os.path.join(self.base_dir, 'ca.key')
        self.server_cert = os.path.join(self.base_dir, 'server.pem')
        self.server_key = os.path.join(self.base_dir, 'server.key')
        self.operators_file = os.path.join(
            self.base_dir, 'operators.json')
        self.operators_dir = os.path.join(
            self.base_dir, 'operators')
        self._lock = threading.Lock()
        self._name_locks: dict = {}
        self._name_locks_guard = threading.Lock()
        self._ca_pubkey = None
        self._ca_pubkey_lock = threading.Lock()
        os.makedirs(self.base_dir, exist_ok=True)

    def _name_lock(self, name: str) -> threading.Lock:
        with self._name_locks_guard:
            lock = self._name_locks.get(name)
            if lock is None:
                lock = threading.Lock()
                self._name_locks[name] = lock
            return lock

    # ------------------------------------------------------------------
    # Per-operator layout

    @staticmethod
    def _safe_name(name: str) -> str:
        """Map an operator name to a filesystem-safe directory name.
        Anything outside [A-Za-z0-9._-] becomes an underscore."""
        cleaned = ''.join(
            c if c.isalnum() or c in '-_.' else '_' for c in name)
        return cleaned or 'unknown'

    def operator_dir(self, name: str, create: bool = True) -> str:
        """Return the per-operator directory. Creates it on first
        use with 0700 permissions. Set create=False to just compute
        the path for a lookup."""
        path = os.path.join(self.operators_dir, self._safe_name(name))
        if create:
            os.makedirs(path, exist_ok=True)
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass
        return path

    def paths_for(self, name: str) -> dict:
        """Return the on-disk paths for one operator. Does not create
        the directory; call operator_dir(name) first if you intend
        to write files."""
        op_dir = os.path.join(self.operators_dir, self._safe_name(name))
        return {
            'dir':  op_dir,
            'cert': os.path.join(op_dir, 'client.crt'),
            'key':  os.path.join(op_dir, 'client.key'),
            'ca':   self.ca_cert,
        }

    # ------------------------------------------------------------------
    # Openssl helper

    def _openssl(self, cmd, label):
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise RuntimeError(
                'openssl not found on PATH — team server requires it '
                'for CA and certificate generation')
        if r.returncode != 0:
            raise RuntimeError(
                f'{label} failed: '
                + (r.stderr or r.stdout or '').strip())

    def ca_fingerprint(self) -> str:
        """SHA-256 of the loaded CA, for startup diagnostics.

        Printed by the operator listener at start so an operator can
        compare the running server's CA against the ca_pem inside a
        client config without having to inspect files on disk. A
        mismatch here is the root cause of TLSV1_ALERT_UNKNOWN_CA."""
        import ssl as _ssl
        import hashlib as _hashlib
        try:
            with open(self.ca_cert, 'rb') as fh:
                pem = fh.read().decode('utf-8')
            der = _ssl.PEM_cert_to_DER_cert(pem)
        except Exception:
            return '?'
        return _hashlib.sha256(der).hexdigest()

    # ------------------------------------------------------------------
    # CA bootstrap

    def ensure_ca(self) -> None:
        """Generate the team CA if it is not already present.

        The CA is the trust anchor for every operator cert and for
        the server cert the listener presents. Its private key never
        leaves this directory.
        """
        if os.path.isfile(self.ca_cert) and os.path.isfile(self.ca_key):
            return
        self._openssl([
            'openssl', 'req', '-x509',
            '-newkey', 'rsa:4096', '-sha256', '-nodes',
            '-days', '3650',
            '-keyout', self.ca_key,
            '-out', self.ca_cert,
            '-subj', '/CN=TornadoTeamCA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-addext', 'subjectKeyIdentifier=hash',
        ], 'team CA generation')
        try:
            os.chmod(self.ca_key, 0o600)
        except OSError:
            pass

    def ensure_server_cert(self) -> None:
        """Generate a server cert signed by the team CA if missing.

        The listener presents this cert to clients. It is distinct
        from the CA so the CA private key is never used for anything
        except signing.
        """
        if (os.path.isfile(self.server_cert)
                and os.path.isfile(self.server_key)):
            return
        self.ensure_ca()
        csr = os.path.join(self.ca_dir, 'server.csr')
        ext = os.path.join(self.ca_dir, 'server.ext')
        with open(ext, 'w', encoding='utf-8') as fh:
            fh.write(
                'basicConstraints=critical,CA:FALSE\n'
                'keyUsage=critical,digitalSignature,keyEncipherment\n'
                'extendedKeyUsage=serverAuth\n'
                'subjectAltName=DNS:localhost,IP:127.0.0.1\n'
            )
        try:
            self._openssl([
                'openssl', 'req', '-newkey', 'rsa:2048',
                '-sha256', '-nodes',
                '-keyout', self.server_key, '-out', csr,
                '-subj', '/CN=tornado-team-server',
            ], 'server CSR')
            self._openssl([
                'openssl', 'x509', '-req', '-in', csr,
                '-CA', self.ca_cert, '-CAkey', self.ca_key,
                '-CAcreateserial', '-out', self.server_cert,
                '-days', '365', '-sha256',
                '-extfile', ext,
            ], 'server cert sign')
        finally:
            for p in (csr, ext):
                try:
                    os.remove(p)
                except OSError:
                    pass
        try:
            os.chmod(self.server_key, 0o600)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Cert verification

    def verify_cert(self, der: bytes):
        """Verify a client certificate against the team CA and return
        the CN, or None on any failure.

        Called by the operator listener for every request. Returns
        None for: unparseable DER, signature mismatch, expired or
        not-yet-valid cert, missing CA, or missing crypto library.
        Never raises.
        """
        if not _CRYPTO_OK or not der:
            return None
        try:
            with self._ca_pubkey_lock:
                if self._ca_pubkey is None:
                    with open(self.ca_cert, 'rb') as fh:
                        _ca = x509.load_pem_x509_certificate(
                            fh.read())
                    self._ca_pubkey = _ca.public_key()
            ca_pub = self._ca_pubkey
            leaf = x509.load_der_x509_certificate(der)

            from cryptography.hazmat.primitives.asymmetric \
                import rsa as _rsa, ec as _ec
            if isinstance(ca_pub, _rsa.RSAPublicKey):
                ca_pub.verify(
                    leaf.signature,
                    leaf.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    leaf.signature_hash_algorithm,
                )
            elif isinstance(ca_pub, _ec.EllipticCurvePublicKey):
                ca_pub.verify(
                    leaf.signature,
                    leaf.tbs_certificate_bytes,
                    _ec.ECDSA(leaf.signature_hash_algorithm),
                )
            else:
                return None

            try:
                nb = leaf.not_valid_before_utc.timestamp()
                na = leaf.not_valid_after_utc.timestamp()
            except AttributeError:
                nb = leaf.not_valid_before.timestamp()
                na = leaf.not_valid_after.timestamp()
            now = time.time()
            if now < nb or now > na:
                return None
            try:
                eku = leaf.extensions.get_extension_for_class(
                    x509.ExtendedKeyUsage).value
                if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH \
                        not in eku:
                    return None
            except x509.ExtensionNotFound:
                pass

            cns = leaf.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)
            if len(cns) != 1:
                return None
            return cns[0].value
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Registry file

    def _load(self) -> dict:
        try:
            with open(self.operators_file, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                import sys as _sys
                print(f"[REGISTRY] {self.operators_file} is not a "
                      f"JSON object (got {type(data).__name__}); "
                      f"treating as empty", file=_sys.stderr,
                      flush=True)
                return {}
            return data
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            import sys as _sys
            print(f"[REGISTRY] failed to load "
                  f"{self.operators_file}: "
                  f"{type(exc).__name__}: {exc}",
                  file=_sys.stderr, flush=True)
            return {}

    def _save(self, data: dict) -> None:
        tmp = self.operators_file + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.operators_file)
        try:
            os.chmod(self.operators_file, 0o600)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Operator CRUD

    def list(self):
        """Return every registered operator as a list of dicts.
        Each dict carries at least `name`, `role`, `revoked`."""
        with self._lock:
            data = self._load()
        return [dict(v, name=k) for k, v in sorted(data.items())]

    def get(self, name):
        """Return one operator as a dict, or None if unknown."""
        with self._lock:
            data = self._load()
        entry = data.get(name)
        if entry is None:
            return None
        return dict(entry, name=name)

    def add(self, name, role: str = 'operator',
            password: str = '') -> None:
        """Register a new operator and mint a cert/key pair.

        Writes the cert and key under team_ca/operators/. The local
        operator copies them to the client machine out of band — no
        HTTP endpoint exposes them.

        If `password` is non-empty, an scrypt derivation (128 MiB
        working set, per-operator random salt) is stored as
        `auth_hash` on the operator record, together with
        `auth_algo`, `auth_params`, and `auth_salt` so a client can
        reproduce the same key. Every operator request must then
        carry an HMAC over (ts || nonce || path) keyed by the same
        derivation; the client prompts for the password once per
        session. Leaving the password blank keeps the operator
        cert-only, which is the default and the correct choice for
        automated workflows.
        """
        if role == 'local':
            raise ValueError('local role is not mintable')
        if role not in ('viewer', 'guardian', 'operator', 'admin'):
            raise ValueError(f'invalid role: {role}')
        if not isinstance(name, str) or not _OPERATOR_NAME_RE.match(name):
            raise ValueError(
                f'invalid operator name: {name!r} — must be 1–64 '
                f'characters, start with a letter or digit, and '
                f'contain only A–Z a–z 0–9 . _ -')
        if name in _RESERVED_OPERATOR_NAMES:
            raise ValueError(
                f'{name!r} is a reserved name — it collides with '
                f'a client-side chat command')

        auth_hash = ''
        auth_algo = ''
        auth_params = {}
        auth_salt = ''
        if password:
            auth_algo = 'scrypt'
            auth_params = {
                'n': self.SCRYPT_N,
                'r': self.SCRYPT_R,
                'p': self.SCRYPT_P,
            }
            auth_salt_bytes = os.urandom(16)
            auth_salt = auth_salt_bytes.hex()
            dk = self._derive_key(
                password, auth_salt_bytes,
                auth_algo, auth_params)
            auth_hash = dk.hex()

        with self._name_lock(name):
            with self._lock:
                data = self._load()
                if name in data:
                    raise ValueError(f'{name} already exists')
                if len(data) >= constants.MAX_OPERATORS:
                    raise ValueError(
                        f'operator limit reached '
                        f'({constants.MAX_OPERATORS})')

            self._mint_cert(name)

            with self._lock:
                data = self._load()
                if len(data) >= constants.MAX_OPERATORS:
                    import shutil
                    shutil.rmtree(
                        self.operator_dir(name, create=False),
                        ignore_errors=True)
                    raise ValueError(
                        f'operator limit reached '
                        f'({constants.MAX_OPERATORS})')
                entry = {
                    'role': role,
                    'revoked': False,
                    'added': time.time(),
                }
                if auth_hash:
                    entry['auth_hash'] = auth_hash
                    entry['auth_algo'] = auth_algo
                    entry['auth_params'] = auth_params
                    entry['auth_salt'] = auth_salt
                data[name] = entry
                self._save(data)

    def verify_auth(self, name, path, ts, nonce, mac) -> bool:
        """Return True if the HMAC over (ts || nonce || path) with the
        operator's stored auth key matches `mac`.

        Returns True when the operator has no auth_hash on record —
        the cert-only path stays backwards compatible. Returns False
        when the operator has a hash but the request does not carry a
        valid HMAC, or carries one outside the +/- 300 s window.
        """
        with self._lock:
            data = self._load()
        entry = data.get(name)
        if not entry:
            return False
        stored = entry.get('auth_hash')
        if not stored:
            return True

        import hashlib as _hashlib
        import hmac as _hmac

        try:
            ts_int = int(ts)
        except (TypeError, ValueError):
            return False
        if abs(time.time() - ts_int) > 300:
            return False

        key = bytes.fromhex(stored)
        msg = f"{ts}\x1f{nonce}\x1f{path}".encode('utf-8')
        expected = _hmac.new(
            key, msg, _hashlib.sha256).hexdigest()
        try:
            return _hmac.compare_digest(expected, mac)
        except Exception:
            return False

    def set_password(self, name, password: str) -> None:
        """Reset an operator's password. Empty string clears the
        second factor entirely — the operator reverts to cert-only.

        Changing the password also migrates the derivation to the
        current default (scrypt). An operator whose config still
        carries the legacy PBKDF2 params will fail the HMAC check
        on their next connection until their config is re-exported;
        the admin who ran `operator passwd` gets a prompt saying so.
        """
        with self._lock:
            data = self._load()
            if name not in data:
                raise ValueError(f'{name} not found')

            if password:
                auth_algo = 'scrypt'
                auth_params = {
                    'n': self.SCRYPT_N,
                    'r': self.SCRYPT_R,
                    'p': self.SCRYPT_P,
                }
                auth_salt_bytes = os.urandom(16)
                dk = self._derive_key(
                    password, auth_salt_bytes,
                    auth_algo, auth_params)
                data[name]['auth_hash'] = dk.hex()
                data[name]['auth_algo'] = auth_algo
                data[name]['auth_params'] = auth_params
                data[name]['auth_salt'] = auth_salt_bytes.hex()
            else:
                data[name].pop('auth_hash', None)
                data[name].pop('auth_algo', None)
                data[name].pop('auth_params', None)
                data[name].pop('auth_salt', None)

            self._save(data)


    def remove(self, name) -> None:
        """Drop an operator from the registry and delete their
        per-operator directory (cert, key, config). Admin entries
        are refused here as a second line of defence — the local
        console already checks this before calling."""
        with self._lock:
            data = self._load()
            if name not in data:
                raise ValueError(f'{name} not found')
            if data[name].get('role') == 'admin':
                raise ValueError(
                    'refusing to remove admin — demote first')
            data.pop(name)
            self._save(data)

        op_dir = os.path.join(self.operators_dir, self._safe_name(name))
        if os.path.isdir(op_dir):
            import shutil
            try:
                shutil.rmtree(op_dir)
            except OSError:
                pass

    def set_role(self, name, role) -> None:
        if role == 'local':
            raise ValueError('local role is not assignable')
        if role not in ('viewer', 'guardian', 'operator', 'admin'):
            raise ValueError(f'invalid role: {role}')
        with self._lock:
            data = self._load()
            if name not in data:
                raise ValueError(f'{name} not found')
            data[name]['role'] = role
            self._save(data)

    # ------------------------------------------------------------------
    # Cert minting

    def _mint_cert(self, name) -> None:
        """Mint the client cert and key for `name`, storing them in
        the operator's own subdirectory. Called by add()."""
        op_dir = self.operator_dir(name)
        paths = self.paths_for(name)
        crt = paths['cert']
        key = paths['key']
        csr = os.path.join(op_dir, 'client.csr')
        ext = os.path.join(op_dir, 'client.ext')
        cnf = os.path.join(op_dir, 'client.cnf')
        with open(ext, 'w', encoding='utf-8') as fh:
            fh.write(
                'basicConstraints=critical,CA:FALSE\n'
                'keyUsage=critical,digitalSignature,keyEncipherment\n'
                'extendedKeyUsage=clientAuth\n'
            )
        with open(cnf, 'w', encoding='utf-8') as fh:
            fh.write(
                '[req]\n'
                'prompt = no\n'
                'distinguished_name = dn\n'
                'utf8 = yes\n'
                '[dn]\n'
                f'CN = {name}\n'
            )
        self.ensure_ca()
        try:
            self._openssl([
                'openssl', 'req', '-newkey', 'rsa:2048',
                '-sha256', '-nodes',
                '-keyout', key, '-out', csr,
                '-config', cnf,
            ], f'{name} CSR')
            self._openssl([
                'openssl', 'x509', '-req', '-in', csr,
                '-CA', self.ca_cert, '-CAkey', self.ca_key,
                '-CAcreateserial', '-out', crt,
                '-days', '365', '-sha256',
                '-extfile', ext,
            ], f'{name} cert sign')
        finally:
            for p in (csr, ext, cnf):
                try:
                    os.remove(p)
                except OSError:
                    pass
        try:
            os.chmod(key, 0o600)
        except OSError:
            pass