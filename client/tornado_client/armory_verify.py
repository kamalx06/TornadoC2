"""Ed25519 verification for the armory index.

The armory repository ships ``index.json`` plus a detached
``index.json.sig`` (base64 Ed25519 over the exact index bytes).
Trusted public keys are compiled into the client, so a compromised
GitHub account or a mirror cannot silently serve different BOFs.

``TORNADOC2_ARMORY_KEYS`` overrides the embedded set with a
comma-separated list of base64 32-byte public keys, for operators
running a private fork.
"""

from __future__ import annotations

import base64
import os

# Base64 Ed25519 public keys trusted for the default index. Rotate by
# signing the new index with the new key and replacing this tuple.
# Set TORNADOC2_ARMORY_KEYS to replace the set for a private fork, or
# to "off" to accept an unsigned index (warning printed).

#Note: This key and key in deploy directory is currently put for testing purposes it is not the real public key for armory repository, 
# when armory repository created the public key will be updated by author for operators to be installing the armory repository easily
ARMORY_KEYS = (
    'WdhDH4f1RUQNXDf0hBlLbX80rxYPdlZN2OlN5BM9iZE=',
)


def trusted_keys() -> list[bytes]:
    env = os.environ.get('TORNADOC2_ARMORY_KEYS', '').strip()
    if env.lower() in ('off', 'none'):
        return []
    raw = env.split(',') if env else list(ARMORY_KEYS)
    out = []
    for item in raw:
        item = item.strip()
        if not item:
            continue
        try:
            key = base64.b64decode(item, validate=True)
        except Exception:
            continue
        if len(key) == 32:
            out.append(key)
    return out


def verify(body: bytes, signature_b64: str, keys=None) -> bool:
    """True only when a trusted key validates the signature."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    try:
        sig = base64.b64decode(signature_b64.strip(), validate=True)
    except Exception:
        return False
    if len(sig) != 64:
        return False
    for key in (trusted_keys() if keys is None else keys):
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(sig, body)
            return True
        except InvalidSignature:
            continue
        except Exception:
            continue
    return False
