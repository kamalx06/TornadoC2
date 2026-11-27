#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="${1:-logs/backups/backup-$stamp.tar.gz}"
mkdir -p "$(dirname "$out")"
tar -czf "$out" \
  logs/audit logs/chat logs/lootstore logs/creds.json logs/notes.json \
  logs/engagement.json logs/at_rest.key listeners.json team_ca .keys \
  mtls_certs tls_certs \
  2>/dev/null || true
chmod 600 "$out"
sha256sum "$out" > "$out.sha256"
echo "$out"
