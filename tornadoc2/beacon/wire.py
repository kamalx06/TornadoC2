"""Wire encryption.

The agent and the server share a P-256 ECDH key derived from the
agent's ephemeral keypair and the server's long-lived keypair. From
that shared secret a 32-byte AES-256-GCM key is derived and used to
encrypt every subsequent request and response body.

The wire format is a JSON envelope:

    request from agent:
        {"enc": "v1", "epk": "<b64>", "iv": "<b64>", "ct": "<b64>"}

    response from server:
        {"enc": "v1", "iv": "<b64>", "ct": "<b64>"}

The `epk` field carries the agent's ephemeral public key so the
server can derive the same shared secret. When the request is a
POST with a body, it is present in the envelope. On a GET-shaped
poll (HTTP /tasks, DNS /tasks) the request has no body, so the
epk travels out of band — the X-ECDH-Pubkey header on HTTP, a
QNAME chunk on DNS — and the response is still encrypted because
the server derives the same shared secret from it. The server's
response carries no key material because the agent already has
the shared secret.

Plaintext bodies are still accepted — an agent built without
`ServerECDHPubkey` embedded sends raw JSON and the server processes
it exactly as before. Encryption is opt-in per build.
"""

import base64
import hashlib
import json
import os
import secrets

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization
    _CRYPTO = True
except ImportError:
    _CRYPTO = False


WIRE_VERSION = "v1"
_INFO = b"tornadoc2-wire-v1"


class ServerECDH:
    """Long-lived P-256 keypair. The public half is embedded in every
    agent at build time; the private half never leaves the server.
    Rotating this key requires rebuilding all agents — same tradeoff
    as `.keys/handler_signing.key`."""

    def __init__(self, key_path):
        self.key_path = key_path
        self.private = self._load_or_generate()
        raw = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        self.public_b64 = base64.b64encode(raw).decode('ascii')

    def _load_or_generate(self):
        if os.path.isfile(self.key_path):
            try:
                with open(self.key_path, 'rb') as fh:
                    return serialization.load_pem_private_key(
                        fh.read(), password=None)
            except Exception as exc:
                raise RuntimeError(
                    f"server ECDH key at {self.key_path!r} exists "
                    f"but cannot be loaded: {exc}. Move it aside "
                    f"and restart to generate a new key, or "
                    f"restore it from backup. Regenerating here "
                    f"would permanently invalidate every agent "
                    f"built against the old public half."
                ) from exc
        priv = ec.generate_private_key(ec.SECP256R1())
        try:
            os.makedirs(
                os.path.dirname(self.key_path) or '.', exist_ok=True)
            with open(self.key_path, 'wb') as fh:
                fh.write(priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return priv

    def derive_shared(self, peer_pub_bytes):
        """Return the 32-byte ECDH shared secret."""
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_pub_bytes)
        return self.private.exchange(ec.ECDH(), peer)


def _key_from_shared(shared):
    """SHA-256(shared || info) — a 32-byte AES-256 key. Not HKDF;
    we control both sides and only need a hash-extract step."""
    return hashlib.sha256(shared + _INFO).digest()


def decrypt(shared, envelope):
    """Decrypt an envelope to plaintext bytes. Raises on failure."""
    if not _CRYPTO:
        raise RuntimeError('cryptography not installed')
    iv = base64.b64decode(envelope['iv'])
    ct = base64.b64decode(envelope['ct'])
    aes = AESGCM(_key_from_shared(shared))
    return aes.decrypt(iv, ct, None)


def encrypt(shared, plaintext):
    """Wrap plaintext bytes in a response envelope."""
    if not _CRYPTO:
        raise RuntimeError('cryptography not installed')
    iv = secrets.token_bytes(12)
    aes = AESGCM(_key_from_shared(shared))
    ct = aes.encrypt(iv, plaintext, None)
    return {
        'enc': WIRE_VERSION,
        'iv':  base64.b64encode(iv).decode('ascii'),
        'ct':  base64.b64encode(ct).decode('ascii'),
    }


def is_envelope(payload):
    return (
        isinstance(payload, dict)
        and payload.get('enc') == WIRE_VERSION
        and 'iv' in payload
        and 'ct' in payload
    )