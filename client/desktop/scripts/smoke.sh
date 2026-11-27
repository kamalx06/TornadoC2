#!/usr/bin/env bash
# Launch the shell headless for a few seconds and fail on a crash.
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp)"
set +e
timeout 15 xvfb-run -a npx electron out/main/index.js --no-sandbox \
  >"$out" 2>&1
code=$?
set -e
if grep -qiE "segmentation|fatal error|failed to load" "$out"; then
  cat "$out"; exit 1
fi
# 124 = timeout, which is a healthy still-running window.
if [[ $code -ne 0 && $code -ne 124 ]]; then
  cat "$out"; exit 1
fi
echo "smoke ok"
