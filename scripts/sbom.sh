#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../tornadoc2/agent"
out="${1:-sbom.txt}"
{
  echo "format: tornadoc2-sbom/1"
  echo "version: $(cat ../../VERSION)"
  echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "[go]"
  go list -m all
} > "$out"
echo "$out"
