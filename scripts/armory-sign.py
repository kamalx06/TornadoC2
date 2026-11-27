#!/usr/bin/env python3
"""Sign an armory index with a detached Ed25519 signature.

Usage:
    keygen  scripts/armory-sign.py keygen armory.key armory.pub
    sign    scripts/armory-sign.py sign armory.key index.json

The private key is a raw 32-byte file (mode 0600). The public key is
printed as base64; paste it into ARMORY_KEYS in
client/tornado_client/armory_verify.py. The signature is written to
``<index>.sig`` as base64 over the exact index bytes.
"""
import base64
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)


def keygen(priv_path, pub_path):
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes_raw()
    with open(priv_path, 'wb') as fh:
        fh.write(raw)
    os.chmod(priv_path, 0o600)
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    b64 = base64.b64encode(pub).decode()
    with open(pub_path, 'w', encoding='ascii') as fh:
        fh.write(b64 + '\n')
    print(b64)


def sign(priv_path, index_path):
    key = Ed25519PrivateKey.from_private_bytes(
        open(priv_path, 'rb').read())
    body = open(index_path, 'rb').read()
    sig = base64.b64encode(key.sign(body))
    with open(index_path + '.sig', 'wb') as fh:
        fh.write(sig)
    print(index_path + '.sig')


def main(argv):
    if len(argv) == 4 and argv[1] == 'keygen':
        keygen(argv[2], argv[3])
    elif len(argv) == 4 and argv[1] == 'sign':
        sign(argv[2], argv[3])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
