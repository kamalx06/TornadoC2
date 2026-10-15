"""mTLS HTTP transport. Stages PEM material in tempfiles because the
standard library's SSL context wants file paths, not PEM strings."""

import http.client
import hashlib as _hashlib
import hmac as _hmac
import json
import os
import secrets as _secrets
import ssl
import tempfile
import time as _time
import urllib.error
import urllib.request


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that verifies the peer certificate
    fingerprint after the TLS handshake.

    urllib does not surface the peer certificate to the caller,
    so we subclass the connection and check it here. If the
    config carried a server_cert_sha256, a connection whose
    peer cert does not hash to that value is closed before the
    request is sent; the exception propagates up through
    urllib as an SSLError.
    """

    def __init__(self, *args, expected_fp=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._expected_fp = expected_fp

    def connect(self):
        super().connect()
        if not self._expected_fp:
            return
        der = self.sock.getpeercert(binary_form=True)
        if not der:
            try:
                self.close()
            except Exception:
                pass
            raise ssl.SSLError(
                'server presented no certificate')
        got = _hashlib.sha256(der).hexdigest()
        if got != self._expected_fp:
            try:
                self.close()
            except Exception:
                pass
            raise ssl.SSLError(
                f'server certificate fingerprint mismatch: '
                f'expected {self._expected_fp[:16]}..., '
                f'got {got[:16]}...')


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler that wires expected_fp into the connection
    class. urllib instantiates the class itself; the expected
    fingerprint is captured in a closure so it does not have
    to travel through do_open's argument list.
    """

    def __init__(self, context=None, expected_fp=None):
        super().__init__(context=context)
        self._expected_fp = expected_fp

    def https_open(self, req):
        expected = self._expected_fp
        ctx = self._context

        def conn_factory(*args, **kwargs):
            kwargs.setdefault('context', ctx)
            return _PinnedHTTPSConnection(
                *args, expected_fp=expected, **kwargs)

        return self.do_open(conn_factory, req)


class Transport:

    def __init__(self, cfg):
        self.cfg = cfg
        self.base = (f"https://{cfg['server_host']}:"
                     f"{cfg['server_port']}")
        self._ca = self._stage(cfg['ca_pem'])
        self._cert = self._stage(cfg['client_cert'])
        self._key = self._stage(cfg['client_key'])
        self._server_fp = (cfg.get('server_cert_sha256') or '').lower()
        self._auth_key = None
        self._auth_prompted = False
        self._verify_config_signature(cfg)

        try:
            ctx = ssl.create_default_context(cafile=self._ca)
        except Exception:
            self.close()
            raise
        ctx.check_hostname = False
        ctx.load_cert_chain(self._cert, self._key)
        if self._server_fp:
            self._opener = urllib.request.build_opener(
                _PinnedHTTPSHandler(
                    context=ctx,
                    expected_fp=self._server_fp))
        else:
            import sys as _sys
            print("  (config has no server certificate pin — "
                  "re-export on the server to enable pinning)",
                  file=_sys.stderr)
            self._opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx))

    @staticmethod
    def _stage(pem: str) -> str:
        fd, path = tempfile.mkstemp(prefix='tc_', suffix='.pem')
        with os.fdopen(fd, 'w') as fh:
            fh.write(pem)
        os.chmod(path, 0o600)
        return path

    def _verify_config_signature(self, cfg: dict) -> None:
        """Verify the config's detached signature against its
        embedded signer public key, then pin the signer's
        fingerprint so a swapped signer is refused on the next
        load.

        Trust model is SSH-style TOFU: on first use, the signer
        fingerprint is printed and pinned; on subsequent loads,
        a mismatch is a hard refusal. An operator who has been
        told the fingerprint out of band compares the printed
        value once and never again.

        A config with no signature (an export from before the
        feature) prints a warning and continues; refusing would
        break every deployment on upgrade day. A config with a
        signature that fails to verify is refused.
        """
        sig_b64 = cfg.get('config_signature_b64') or ''
        pub_pem = cfg.get('config_signer_pubkey_pem') or ''
        if not sig_b64 or not pub_pem:
            import sys as _sys
            print("  (config has no signature — legacy export; "
                  "re-export on the server to enable verification)",
                  file=_sys.stderr)
            return

        try:
            from cryptography.hazmat.primitives import hashes as _h
            from cryptography.hazmat.primitives.asymmetric \
                import ec as _ec
            from cryptography.hazmat.primitives import serialization \
                as _ser
            import base64 as _b64
            import json as _json
        except ImportError as exc:
            raise RuntimeError(
                f'this config is signed, but the `cryptography` '
                f'package is not installed so the signature '
                f'cannot be verified. Install with '
                f'`pip install cryptography` and retry. '
                f'({exc})')

        try:
            pub = _ser.load_pem_public_key(pub_pem.encode('utf-8'))
        except Exception as exc:
            raise RuntimeError(
                f'config signer public key is unreadable: {exc}')
        if not isinstance(pub, _ec.EllipticCurvePublicKey):
            raise RuntimeError(
                'config signer key is not an ECDSA public key')

        signed = {k: v for k, v in cfg.items()
                  if k != 'config_signature_b64'}
        canonical = _json.dumps(
            signed, sort_keys=True,
            separators=(',', ':')).encode('utf-8')
        try:
            sig = _b64.b64decode(sig_b64, validate=True)
        except Exception as exc:
            raise RuntimeError(
                f'config signature is not valid base64: {exc}')
        try:
            pub.verify(sig, canonical, _ec.ECDSA(_h.SHA256()))
        except Exception as exc:
            raise RuntimeError(
                f'config signature verification FAILED: {exc}. '
                f'The file was modified in transit, or it was '
                f'not minted by the team server you trust. '
                f'Refusing to load it.')

        fp = _hashlib.sha256(pub_pem.encode('utf-8')).hexdigest()
        pin_dir = os.path.expanduser('~/.tornadoc2')
        os.makedirs(pin_dir, exist_ok=True)
        try:
            os.chmod(pin_dir, 0o700)
        except OSError:
            pass
        op_name = cfg.get('name') or 'default'
        server = cfg.get('server_host') or '?'
        server_tag = _hashlib.sha256(
            server.encode('utf-8')).hexdigest()[:8]
        new_pin_path = os.path.join(
            pin_dir, f'{op_name}.{server_tag}.signer-pin')
        legacy_pin_path = os.path.join(
            pin_dir, f'{op_name}.signer-pin')

        if (not os.path.isfile(new_pin_path)
                and os.path.isfile(legacy_pin_path)):
            try:
                with open(legacy_pin_path, 'r',
                          encoding='utf-8') as fh:
                    prior = fh.read().strip()
                with open(new_pin_path, 'w',
                          encoding='utf-8') as fh:
                    fh.write(prior)
                os.chmod(new_pin_path, 0o600)
                os.remove(legacy_pin_path)
            except OSError:
                pass

        pin_path = new_pin_path
        if os.path.isfile(pin_path):
            with open(pin_path, 'r', encoding='utf-8') as fh:
                pinned = fh.read().strip()
            if pinned != fp:
                raise RuntimeError(
                    f"the config's signer has changed for this "
                    f"operator. Pinned: {pinned[:16]}...; "
                    f"current: {fp[:16]}....  If the team server "
                    f"legitimately rotated its handler signing key "
                    f"(and the operator has confirmed this out of "
                    f"band), delete {pin_path!r} and retry. "
                    f"Otherwise this config was not minted by the "
                    f"server you trust.")
        else:
            import sys as _sys
            print(f"  config signer fingerprint: {fp[:32]}...",
                  file=_sys.stderr)
            print(f"  (pinned to {pin_path})", file=_sys.stderr)
            with open(pin_path, 'w', encoding='utf-8') as fh:
                fh.write(fp)
            try:
                os.chmod(pin_path, 0o600)
            except OSError:
                pass

    def _ensure_auth_key(self) -> None:
        """Prompt for the operator password.

        Called lazily — not from post() directly, but from the
        retry path when the server has answered with 401 and
        `auth_error: password_required`. That means the prompt only
        fires when the server has explicitly told us it wants a
        password; a 503 (multiplayer off), a connection refused, or
        a 404 (version mismatch) surfaces before we ever ask the
        operator for anything.
        """
        if self._auth_key is not None:
            return
        if not self.cfg.get('password_required'):
            return

        import getpass
        try:
            pw = getpass.getpass(
                f"operator password for "
                f"{self.cfg.get('name', '?')}: ")
        except (EOFError, KeyboardInterrupt):
            raise RuntimeError(
                'operator password required but no input '
                'available')
        if not pw:
            raise RuntimeError('empty password')

        algo = self.cfg.get('auth_algo') or 'pbkdf2-sha256'
        params = self.cfg.get('auth_params') or {}

        salt_hex = (self.cfg.get('auth_salt') or '').strip()
        if salt_hex:
            try:
                salt_bytes = bytes.fromhex(salt_hex)
            except ValueError as exc:
                raise RuntimeError(
                    f'config auth_salt is not valid hex: {exc}')
            if len(salt_bytes) != 16:
                raise RuntimeError(
                    f'config auth_salt is {len(salt_bytes)} bytes; '
                    f'expected 16. Re-export the config on the '
                    f'server.')
        else:
            salt_bytes = self.cfg['name'].encode('utf-8')

        if algo == 'scrypt':
            p = params or {'n': 1 << 17, 'r': 8, 'p': 1}
            maxmem = 128 * p['n'] * p['r'] * 2
            try:
                self._auth_key = _hashlib.scrypt(
                    pw.encode('utf-8'),
                    salt=salt_bytes,
                    n=p['n'], r=p['r'], p=p['p'],
                    maxmem=maxmem, dklen=32,
                )
            except (ValueError, AttributeError) as exc:
                raise RuntimeError(
                    f'could not derive key with scrypt '
                    f'(params n={p["n"]} r={p["r"]} '
                    f'p={p["p"]}): {exc}. Your Python '
                    f'needs OpenSSL 1.1.0+ for scrypt.')
        elif algo == 'pbkdf2-sha256':
            iters = int(params.get('iters', 200_000))
            self._auth_key = _hashlib.pbkdf2_hmac(
                'sha256',
                pw.encode('utf-8'),
                salt_bytes,
                iters,
                dklen=32,
            )
        else:
            raise RuntimeError(
                f'unsupported auth algorithm in config: '
                f'{algo!r}. Re-export the config on a '
                f'current team server.')

    def post(self, path: str, payload: dict,
             timeout: float = 180.0) -> dict:
        return self._post_with_auth_retry(
            path, payload, timeout, allow_prompt=True)

    def _post_with_auth_retry(self, path, payload, timeout,
                              allow_prompt):
        """Send one request. If the server answers 401 with
        `auth_error: password_required` and `allow_prompt` is True,
        prompt for the password, derive the key, and retry once.

        The single-retry guard prevents an infinite loop if the
        password is wrong: the second request carries the HMAC, the
        server answers 401 with `auth_error: password_invalid`, and
        that error is surfaced to the caller unchanged. """
        headers = {'Content-Type': 'application/json'}
        if self._auth_key is not None:
            ts = str(int(_time.time()))
            nonce = _secrets.token_hex(16)
            msg = f"{ts}\x1f{nonce}\x1f{path}".encode('utf-8')
            mac = _hmac.new(
                self._auth_key, msg, _hashlib.sha256).hexdigest()
            headers['X-Operator-Ts'] = ts
            headers['X-Operator-Nonce'] = nonce
            headers['X-Operator-Mac'] = mac
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode(),
            headers=headers,
            method='POST')
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            try:
                data = json.loads(body)
                msg = data.get('error') or body or str(e.reason)
                code = data.get('auth_error')
                if code:
                    msg = f"[{code}] {msg}"
            except Exception:
                code = None
                msg = body.strip() or str(e.reason)

            if (e.code == 401
                    and code == 'password_required'
                    and allow_prompt
                    and self.cfg.get('password_required')):
                self._ensure_auth_key()
                return self._post_with_auth_retry(
                    path, payload, timeout, allow_prompt=False)

            if (e.code == 401
                    and code == 'session_expired'
                    and allow_prompt):
                self._auth_key = None
                self._auth_prompted = False
                return self._post_with_auth_retry(
                    path, payload, timeout, allow_prompt=True)

            raise RuntimeError(f"HTTP {e.code}: {msg}")
        except urllib.error.URLError as e:
            reason = getattr(e, 'reason', e)
            raise RuntimeError(f"connect: {reason}")

        try:
            return json.loads(raw)
        except ValueError as exc:
            snippet = raw[:200].decode('utf-8', errors='replace')
            raise RuntimeError(
                f"server returned non-JSON on {path}: {exc}; "
                f"body starts with {snippet!r}")

    def close(self):
        for p in (self._ca, self._cert, self._key):
            try:
                os.remove(p)
            except OSError:
                pass