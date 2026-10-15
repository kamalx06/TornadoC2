#!/usr/bin/env bash
# Entry point for the TornadoC2 container.
#
# Forwards every argument to `python3 tornadoc2.py`. Prints a warning
# when a capability the handler will need is missing, so the operator
# sees the problem on the first startup line rather than three
# transports into a debug session.

set -euo pipefail

cd /opt/TornadoC2

if [ "${TORNADO_CHECK_CAPS:-1}" = "1" ] && command -v capsh >/dev/null 2>&1; then
    if ! capsh --has-p=cap_net_raw >/dev/null 2>&1; then
        echo "[entrypoint] warning: CAP_NET_RAW not granted — the ICMP transport will refuse to start" >&2
        echo "[entrypoint]   fix: docker run --cap-add=NET_RAW ..." >&2
    fi
    if ! capsh --has-p=cap_net_admin >/dev/null 2>&1; then
        echo "[entrypoint] warning: CAP_NET_ADMIN not granted — the WireGuard transport will refuse to start" >&2
        echo "[entrypoint]   fix: docker run --cap-add=NET_ADMIN ..." >&2
    fi
fi

exec python3 tornadoc2.py "$@"
