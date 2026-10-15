"""ECDSA signing for beacon task dispatch.

The server holds one keypair per handler run (`handler.signer`). Every
task is signed before dispatch; the agent embeds the public key at
build time and refuses to execute anything whose signature fails.

The same key signs the agent's own bootstrap metadata (identity), so a
man-in-the-middle that substitutes a beacon cannot redirect tasks.
"""

from __future__ import annotations

import base64
import json
from typing import Optional


class TaskSigner:
    """Wraps the handler's ECDSA signer for the beacon wire format."""

    def __init__(self, handler_signer):
        self.signer = handler_signer
        if self.signer is not None:
            self.public_pem = getattr(
                self.signer, 'public_pem', '') or ''
        else:
            self.public_pem = ''

    @property
    def enabled(self) -> bool:
        return self.signer is not None

    def sign_task(self, task_wire: dict) -> str:
        """Return base64 signature over the canonical task JSON."""
        if not self.enabled:
            return ''
        payload = json.dumps(task_wire, sort_keys=True,
                             separators=(',', ':'),
                             ensure_ascii=False).encode('utf-8')
        sig = self.signer.sign(payload)
        return base64.b64encode(sig).decode('ascii')

    def verify_payload(self, payload: bytes, signature_b64: str) -> bool:
        """Used by tests; agents verify with their embedded pubkey."""
        if not self.enabled:
            return True
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            sig = base64.b64decode(signature_b64)
            verifier = getattr(self.signer, 'verify', None)
            if verifier is not None:
                return bool(verifier(payload, sig))
            priv = getattr(self.signer, 'private', None)
            if priv is None:
                return False
            priv.public_key().verify(
                sig, payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False