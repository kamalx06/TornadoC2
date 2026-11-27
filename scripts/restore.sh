#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
arc="${1:?usage: restore.sh <backup.tar.gz>}"
sha256sum -c "$arc.sha256"
tar -tzf "$arc" >/dev/null
tar -xzf "$arc" -C .
echo "restored $arc"
