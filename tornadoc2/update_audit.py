"""Structured update audit logging."""

import os
import re

try:
    from .constants import LOGS_DIR
except (ImportError, AttributeError):
    LOGS_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'logs',
    )

AUDIT_LOG_FILE = os.path.join(LOGS_DIR, 'updater.log')

_SECRET_PATTERNS = (
    re.compile(
        r'(?i)(password|passwd|token|secret|api[_-]?key'
        r'|credential|session)\s*[=:]\s*\S+'
    ),
    re.compile(r'(?i)(-----BEGIN [A-Z ]+ PRIVATE KEY-----)'),
)


def _sanitize_value(value):
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub('[REDACTED]', text)
    return text


class UpdateAuditLogger:
    """Append-only audit trail for update operations."""

    def __init__(self, log_path=None):
        self.log_path = log_path or AUDIT_LOG_FILE

    def _write(self, event, fields=None):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        parts = [event]
        for key, value in (fields or {}).items():
            if value is None or value == '':
                continue
            parts.append(f'{key}={_sanitize_value(value)}')
        line = ' '.join(parts)
        with open(self.log_path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def log(self, event, **fields):
        self._write(event, fields)