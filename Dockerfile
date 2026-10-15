# syntax=docker/dockerfile:1.6

FROM python:3.13-slim-trixie

# ---------------------------------------------------------------------------
# Build-time knobs. Set to 0 to trim the image when a capability is not
# needed by the engagement.
#
#   INSTALL_UPX       UPX packing for the `paranoid` OPSEC profile
#   INSTALL_MINGW     MinGW-w64 for output_format=dll builds
#   INSTALL_DONUT     When 1, installs the `donut-shellcode` Python
#                     binding (which carries its own `donut` binary)
#                     if no vendored copy is present at
#                     beacon/bin/donut. Required for --format
#                     shellcode builds and for inject: true on a
#                     Windows build
#   INSTALL_RUST      Adds rustup + wasm32-unknown-unknown for building
#                     WASM extensions. Off by default — the extensions
#                     that ship in-tree are pre-built
#   BOOTSTRAP_GO      Run install-go-build.sh at build time to warm the
#                     module cache. Requires network at build time
# ---------------------------------------------------------------------------
ARG GO_VERSION=1.24.4
ARG INSTALL_UPX=1
ARG INSTALL_MINGW=1
ARG INSTALL_DONUT=0
ARG INSTALL_RUST=0
ARG BOOTSTRAP_GO=1
ARG TARGETARCH=amd64

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOFLAGS=-mod=mod \
    GOPATH=/go \
    PATH=/go/bin:/usr/local/go/bin:$PATH

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        openssl \
        libssl-dev \
        libffi-dev \
        build-essential \
        pkg-config \
        libcap2-bin \
        wireguard-tools \
        iproute2 \
        procps \
        netcat-openbsd \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Optional: UPX (paranoid OPSEC profile).
RUN if [ "$INSTALL_UPX" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends upx-ucl \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# Optional: MinGW cross-compilers (output_format=dll).
RUN if [ "$INSTALL_MINGW" = "1" ] && [ "$TARGETARCH" = "amd64" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            gcc-mingw-w64-x86-64 \
            gcc-mingw-w64-i686 \
        && rm -rf /var/lib/apt/lists/*; \
    elif [ "$INSTALL_MINGW" = "1" ]; then \
        echo "[build] INSTALL_MINGW=1 requested on TARGETARCH=${TARGETARCH}"; \
        echo "[build]   MinGW is amd64-host only; skipping."; \
        echo "[build]   output_format=dll builds will not work inside"; \
        echo "[build]   this architecture's image. Use the amd64 image"; \
        echo "[build]   for DLL builds, or cross-compile from outside."; \
    fi

# Optional: Rust + wasm32-unknown-unknown (building WASM extensions)
RUN if [ "$INSTALL_RUST" = "1" ]; then \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --default-toolchain stable; \
        /root/.cargo/bin/rustup target add wasm32-unknown-unknown; \
    fi

# ---------------------------------------------------------------------------
# Go toolchain
# ---------------------------------------------------------------------------
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) goarch=amd64 ;; \
      arm64) goarch=arm64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" \
        -o /tmp/go.tar.gz; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz; \
    go version

# ---------------------------------------------------------------------------
# Python dependencies
# ---------------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        python3-flask \
        python3-cryptography \
        python3-dnslib \
        python3-aioquic \
        python3-simple-websocket \
        python3-pyroute2; \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Go tools
# ---------------------------------------------------------------------------
RUN CGO_ENABLED=0 go install mvdan.cc/garble@v0.17.0

# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------
WORKDIR /opt/TornadoC2
COPY . .

RUN if [ "$BOOTSTRAP_GO" = "1" ] && [ -x ./install-go-build.sh ]; then \
        ./install-go-build.sh || echo "[build] bootstrap-go skipped (non-fatal)"; \
    fi

RUN if [ "$INSTALL_DONUT" = "1" ]; then \
        if [ -x beacon/bin/donut ]; then \
            echo "[build] donut: vendored binary at beacon/bin/donut"; \
        else \
            pip install --no-cache-dir \
                --break-system-packages donut-shellcode; \
        fi; \
    elif [ -x beacon/bin/donut ]; then \
        echo "[build] donut: vendored binary at beacon/bin/donut"; \
    else \
        echo "[build] donut: not installed (INSTALL_DONUT=0, no vendored binary)"; \
    fi

RUN mkdir -p \
        tls_certs \
        mtls_certs \
        team_ca \
        .keys/server \
        .keys/agent \
        logs/audit \
        logs/chat \
        logs/lootstore \
        logs/bnotes \
        bofs \
        beacon_output \
        payloads \
        profiles/c2 \
    && chmod 0700 .keys .keys/server .keys/agent bofs

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
COPY docker/entrypoint.sh /usr/local/bin/tornado-entrypoint
RUN chmod 0755 /usr/local/bin/tornado-entrypoint

# Beacon HTTP, SOCKS pivot, client tunnel, WebSocket, operator API,
# DNS (UDP + TCP), QUIC, WireGuard.
EXPOSE 8881 8882 8883 8884 12341 53/udp 53/tcp 8885/udp 51820/udp

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/tornado-entrypoint"]
CMD ["--beacon-port", "8881"]
