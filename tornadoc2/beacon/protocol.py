"""Wire protocol for the beacon subsystem.

Three endpoints, two message types. Every field that can contain binary
data is base64-encoded so the whole payload is JSON-safe.

    POST /beacon    check-in       → {id, sleep, jitter, kill_deadline}
    GET  /tasks     poll           → [{id, verb, args, timeout}, ...]
    POST /results   result upload  → 204

Future protocol versions add fields without changing existing ones.
The agent advertises its protocol revision as the `proto` field in
the check-in identity; the server echoes its own in the /beacon
response. There is currently no header-based negotiation.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field
from typing import List, Optional


def new_task_id() -> str:
    """Return an opaque task identifier."""
    return secrets.token_hex(8)


@dataclass
class Task:
    """A unit of work dispatched to a beacon."""
    id:       str
    verb:     str
    args:     List[str] = field(default_factory=list)
    timeout:  int = 60
    signature: str = ''      # base64 ECDSA over the unsigned body

    def unsigned(self) -> dict:
        """The canonical bytes the signature covers."""
        return {
            'id':      self.id,
            'verb':    self.verb,
            'args':    list(self.args),
            'timeout': self.timeout,
        }

    def to_wire(self) -> dict:
        body = self.unsigned()
        body['signature'] = self.signature
        return body

    @classmethod
    def from_wire(cls, payload: dict) -> 'Task':
        return cls(
            id=payload['id'],
            verb=payload['verb'],
            args=list(payload.get('args', [])),
            timeout=int(payload.get('timeout', 60)),
            signature=payload.get('signature', ''),
        )


@dataclass
class Result:
    """A beacon's response to a Task."""
    id:        str
    output:    bytes = b''
    error:     Optional[str] = None
    exit_code: int = 0
    signature: str = ''

    def signable(self) -> bytes:
        """Canonical bytes the signature covers. Must match the Go
        agent's Result.signable() exactly: same fields, sorted keys,
        no whitespace."""
        body = {
            'id':        self.id,
            'output':    base64.b64encode(self.output).decode('ascii'),
            'error':     self.error or '',
            'exit_code': self.exit_code,
        }

        return json.dumps(body, sort_keys=True,
                          separators=(',', ':'),
                          ensure_ascii=False).encode('utf-8')

    def to_wire(self) -> dict:
        return {
            'id':        self.id,
            'output':    base64.b64encode(self.output).decode('ascii'),
            'error':     self.error or '',
            'exit_code': self.exit_code,
            'signature': self.signature,
        }

    @classmethod
    def from_wire(cls, payload: dict) -> 'Result':
        raw = payload.get('output', '')
        try:
            data = base64.b64decode(raw) if raw else b''
        except Exception:
            data = b''
        return cls(
            id=payload['id'],
            output=data,
            error=payload.get('error'),
            exit_code=int(payload.get('exit_code', 0)),
            signature=payload.get('signature', ''),
        )