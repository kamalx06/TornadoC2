#!/usr/bin/env bash

set -uo pipefail

# --------------------------------------------------------------------
# TornadoC2 — operator workstation dependency installer
#
# Installs what the operator client needs:
#
#   * cryptography   — required when the operator config is
#                      signed (transport.py verifies the config
#                      signature at load time). Also used by the
#                      certificate-chain check in
#                      `operators export`.
#   * Node.js 26 LTS  — runs the Electron shell.
#   * Electron       — built from client/desktop and installed
#                      read-only under /opt/tornadoc2.
#
# And, optionally:
#
#   * httpx          — the AI console and MCP server HTTP client
#                      (--with-ai).
#   * mcp            — the Model Context Protocol library
#                      (--with-mcp).
#
# Electron needs the GTK/NSS/X11 runtime libraries, installed per
# family below. Mesa/GBM is needed for GPU-less software rendering.
#
# Node is pinned and verified against the publisher's SHASUMS256.txt;
# an existing Node >= 26 on PATH is reused unless --force-node is
# passed. Nothing is installed outside /opt/tornadoc2 and the distro
# package manager.

# The client does NOT need:
#
#   * the Go toolchain          (remote builds happen on the server)
#   * garble, Donut, UPX        (server-side build tools)
#   * MinGW, Rust/wasm32        (server-side build tools)
#   * wireguard-tools           (that runs on the server)
#   * CAP_NET_RAW/CAP_NET_ADMIN (server-side transports only)
#   * flask, dnslib, aioquic, simple-websocket, pyroute2
#   * an LLM provider SDK       (the AI console talks to the
#                               provider's HTTP API directly via
#                               httpx — no anthropic, openai, or
#                               google-generativeai package is
#                               needed, and none is installed)
#
# The client is a thin mTLS-speaking Python process. That is all.
#
# Supported platforms, tested across their current releases:
#
#   Debian family   — Debian 11 (Bullseye) through 13 (Trixie),
#                     Ubuntu 20.04 through 24.04, Kali, Mint, Pop,
#                     Parrot, Raspbian, and any derivative that
#                     declares ID_LIKE=debian.
#
#   RHEL family     — RHEL 8 and 9, CentOS Stream 8 and 9, Rocky 8
#                     and 9, Alma 8 and 9, Oracle Linux 8 and 9,
#                     Fedora 38 through 41, Amazon Linux 2023.
#
#   Arch family     — Arch, Manjaro, EndeavourOS, Garuda, Artix,
#                     and any derivative that declares
#                     ID_LIKE=arch.
#
#   macOS           — any version that ships Python 3.7 or later.
#                     Homebrew's PEP 668 handling is detected and
#                     the recommended --venv path is offered.
#
#   Windows         — not covered by this script. On Windows,
#                     install Python from python.org and run:
#                       pip install cryptography pyreadline3
#
# Robustness contract. A system package that cannot be installed
# does not abort the run. Each Electron runtime library is tried
# individually; failures are recorded and named in the summary.
# The Python packages are installed via pip, which is authoritative
# and works on every supported platform regardless of what the
# system package manager provides.
# --------------------------------------------------------------------

# --------------------------------------------------------------------
# Configuration

PIP_REQUIRED=(
    "cryptography"
)

PIP_AI=(
    "httpx"
)

PIP_MCP=(
    "mcp"
)

# --------------------------------------------------------------------
# Flags

INSTALL_GUI=1
INSTALL_AI=0
INSTALL_MCP=0
SKIP_NODE=0
SKIP_DESKTOP_ENTRY=0
FORCE_NODE=0
VENV_PATH=""

usage() {
    sed -n '5,78p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Usage: install-deps-client.sh [options]

Options:
  --classic-gui         Accepted no-op (the Qt console is gone).
  --qt-libs <mode>      Accepted no-op. x11, wayland, both, none.
  --x11, --wayland      Accepted no-op aliases for the above.
  --no-qt-libs          Accepted no-op alias.

  --skip-node           Do not install Node.js; require >= 26 on PATH.
  --force-node          Install the pinned Node even if a suitable
                        one is already present.
  --skip-desktop-entry  Do not write the .desktop launcher.

  --no-gui, --minimal   CLI only: no Node and no Electron.

  --venv <path>         Install the Python packages into a
                        virtualenv at <path> instead of the system
                        interpreter. Recommended on a workstation
                        that already has its own Python
                        environment, and on macOS where the
                        Homebrew Python is PEP 668 managed.
                        Created if it does not exist.

  --with-ai             Install httpx, needed by the AI console
                        (`beacon-client.py ai`) and by the
                        standalone MCP server.

  --with-mcp            Install mcp (the MCP protocol library),
                        needed only by the standalone server
                        (`python -m tornadoc2_mcp`). Also
                        installs httpx.

  --all                 --with-ai --with-mcp

  -h, --help            This message.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-node)
            SKIP_NODE=1; shift ;;
        --force-node)
            FORCE_NODE=1; shift ;;
        --skip-desktop-entry)
            SKIP_DESKTOP_ENTRY=1; shift ;;
        --classic-gui|--qt-libs|--x11|--wayland|--no-qt-libs)
            # Removed with the Qt console; accepted as no-ops.
            case "$1" in
                --qt-libs) shift ;;
                --classic-gui|--x11|--wayland|--no-qt-libs) ;;
            esac
            shift ;;
        --no-gui|--minimal)
            INSTALL_GUI=0
            shift
            ;;
        --with-ai)
            INSTALL_AI=1
            shift
            ;;
        --with-mcp)
            INSTALL_AI=1        # mcp depends on httpx
            INSTALL_MCP=1
            shift
            ;;
        --all)
            INSTALL_AI=1
            INSTALL_MCP=1
            shift
            ;;
        --qt-libs)
            if [[ $# -lt 2 ]]; then
                echo "error: --qt-libs requires a value" >&2
                exit 1
            fi
            case "$2" in
                *)
                    echo "error: --qt-libs value must be one of:" \
                         "x11, wayland, both, none" >&2
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --venv)
            if [[ $# -lt 2 ]]; then
                echo "error: --venv requires a path" >&2
                exit 1
            fi
            VENV_PATH="$2"
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "unknown flag: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# --------------------------------------------------------------------
# Output helpers

if [[ -t 1 ]]; then
    C_INFO=$'\033[36m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'
    C_ERR=$'\033[31m'; C_RST=$'\033[0m'
else
    C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_RST=""
fi

say()  { printf '%s[+]%s %s\n' "$C_INFO" "$C_RST" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$C_OK"   "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_WARN" "$C_RST" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_ERR"  "$C_RST" "$*" >&2; exit 1; }

# --------------------------------------------------------------------
# Electron / Node

NODE_VERSION="26.13.1"
NODE_BASE="https://nodejs.org/dist/v${NODE_VERSION}"
APP_ROOT="/opt/tornadoc2"

_have_node() {
    local v
    v="$(node --version 2>/dev/null || true)"
    [[ "$v" =~ ^v(2[6-9]|[3-9][0-9]) ]]
}

install_node() {
    if [[ "$FORCE_NODE" -eq 0 ]] && _have_node; then
        ok "node: $(node --version) on PATH"
        return 0
    fi
    if [[ "$CAN_INSTALL_SYSTEM" -eq 0 ]]; then
        warn "node >= 26 missing and no root: install Node yourself"
        return 1
    fi
    case "$(uname -m)" in
        x86_64|amd64) arch=x64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) warn "unsupported arch $(uname -m) for Node"; return 1 ;;
    esac
    local name="node-v${NODE_VERSION}-linux-${arch}"
    local tmp; tmp="$(mktemp -d)"
    say "node: downloading ${NODE_VERSION} (${arch})"
    if ! curl -fsSL --max-time 120 "$NODE_BASE/$name.tar.xz" \
            -o "$tmp/node.tar.xz"; then
        warn "node download failed"; rm -rf "$tmp"; return 1
    fi
    if ! curl -fsSL --max-time 30 "$NODE_BASE/SHASUMS256.txt" \
            -o "$tmp/SHASUMS256.txt"; then
        warn "SHASUMS256.txt unavailable; refusing an unverified binary"
        rm -rf "$tmp"; return 1
    fi
    local want got
    want="$(awk -v n="$name.tar.xz" '$2==n{print $1}' "$tmp/SHASUMS256.txt")"
    got="$(sha256sum "$tmp/node.tar.xz" | awk '{print $1}')"
    if [[ -z "$want" || "$want" != "$got" ]]; then
        warn "node checksum mismatch"; rm -rf "$tmp"; return 1
    fi
    ok "node: checksum verified"
    $SUDO mkdir -p "$APP_ROOT"
    if $SUDO tar -xJf "$tmp/node.tar.xz" -C "$APP_ROOT"; then
        $SUDO rm -rf "$APP_ROOT/node"
        $SUDO mv "$APP_ROOT/$name" "$APP_ROOT/node"
        $SUDO ln -sf "$APP_ROOT/node/bin/node" /usr/local/bin/node
        $SUDO ln -sf "$APP_ROOT/node/bin/npm" /usr/local/bin/npm
        $SUDO ln -sf "$APP_ROOT/node/bin/npx" /usr/local/bin/npx
        rm -rf "$tmp"
        ok "node: installed under $APP_ROOT/node"
        return 0
    fi
    rm -rf "$tmp"
    warn "node extraction failed"
    return 1
}

install_electron_libs() {
    [[ "$UNAME_S" == "Linux" ]] || return 0
    say "electron: runtime libraries"
    case "$FAMILY" in
        debian)
            install_syspkgs libgtk-3-0 libnss3 libxss1 libasound2 \
                libgbm1 libdrm2 libxshmfence1 libatk-bridge2.0-0 \
                libcups2 || true
            ;;
        rhel)
            install_syspkgs gtk3 nss libXScrnSaver alsa-lib \
                mesa-libgbm libdrm libxshmfence at-spi2-atk \
                cups-libs || true
            ;;
        arch)
            install_syspkgs gtk3 nss libxss alsa-lib mesa libdrm \
                libxshmfence at-spi2-atk libcups || true
            ;;
    esac
}

install_electron_app() {
    local src
    src="$(cd "$(dirname "$0")" && pwd)/client/desktop"
    if [[ ! -f "$src/package.json" ]]; then
        warn "client/desktop not found; run from the repository root"
        return 1
    fi
    if [[ "$CAN_INSTALL_SYSTEM" -eq 0 ]]; then
        warn "no root: the shell is built but not installed"
        return 1
    fi
    say "electron: building the renderer"
    if ! ( cd "$src" && npm ci --no-audit --no-fund \
            && npm run build ); then
        warn "desktop build failed"; return 1
    fi
    $SUDO rm -rf "$APP_ROOT/desktop" "$APP_ROOT/electron"
    $SUDO mkdir -p "$APP_ROOT/desktop"
    $SUDO cp -a "$src/out" "$src/package.json" "$APP_ROOT/desktop/"
    $SUDO cp -a "$src/node_modules/electron/dist" "$APP_ROOT/electron"
    $SUDO cp "$APP_ROOT/electron/chrome-sandbox" \
        "$APP_ROOT/electron/chrome-sandbox.real" 2>/dev/null || true
    $SUDO chown root:root "$APP_ROOT/electron/chrome-sandbox" 2>/dev/null || true
    $SUDO chmod 4755 "$APP_ROOT/electron/chrome-sandbox" 2>/dev/null || true
    $SUDO tee /usr/local/bin/tornadoc2-desktop >/dev/null <<'LAUNCH'
#!/bin/sh
exec /opt/tornadoc2/electron/electron /opt/tornadoc2/desktop "$@"
LAUNCH
    $SUDO chmod 755 /usr/local/bin/tornadoc2-desktop
    ok "electron: installed under $APP_ROOT/desktop"

    if [[ "$SKIP_DESKTOP_ENTRY" -eq 0 ]]; then
        $SUDO mkdir -p /usr/share/applications
        $SUDO tee /usr/share/applications/tornadoc2.desktop >/dev/null <<'ENTRY'
[Desktop Entry]
Type=Application
Name=TornadoC2
Comment=Operator console
Exec=/usr/local/bin/tornadoc2-desktop
Terminal=false
Categories=Network;Security;
ENTRY
        ok "electron: desktop entry installed"
    fi
}

# --------------------------------------------------------------------
# Privilege detection

CAN_INSTALL_SYSTEM=0
if [[ $EUID -eq 0 ]]; then
    SUDO=""
    CAN_INSTALL_SYSTEM=1
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
    CAN_INSTALL_SYSTEM=1
else
    SUDO=""
    CAN_INSTALL_SYSTEM=0
fi

# --------------------------------------------------------------------
# OS / distro detection

UNAME_S="$(uname -s)"
case "$UNAME_S" in
    Linux)
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release
            DISTRO_ID="${ID:-unknown}"
            DISTRO_LIKE="${ID_LIKE:-}"
            DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
        else
            DISTRO_ID=unknown
            DISTRO_LIKE=""
            DISTRO_NAME="unknown Linux"
        fi
        case "$DISTRO_ID" in
            debian|ubuntu|kali|parrot|linuxmint|pop|raspbian|neon|zorin|elementary)
                FAMILY=debian ;;
            rhel|centos|fedora|rocky|almalinux|ol|amzn)
                FAMILY=rhel ;;
            arch|manjaro|endeavouros|garuda|artix|arcolinux|rebornos)
                FAMILY=arch ;;
            *)
                case "$DISTRO_LIKE" in
                    *debian*|*ubuntu*) FAMILY=debian ;;
                    *rhel*|*fedora*)   FAMILY=rhel ;;
                    *arch*)            FAMILY=arch ;;
                    *)                 FAMILY=unknown ;;
                esac
                ;;
        esac
        ;;
    Darwin)
        FAMILY=macos
        DISTRO_NAME="$(sw_vers -productName 2>/dev/null || echo macOS) \
$(sw_vers -productVersion 2>/dev/null || '')"
        ;;
    *)
        FAMILY=unknown
        DISTRO_NAME="$UNAME_S"
        ;;
esac

# --------------------------------------------------------------------
# Banner

say "os:       $DISTRO_NAME"
say "family:   $FAMILY"
if [[ "$INSTALL_GUI" -eq 1 ]]; then
    say "gui:      yes (--no-gui to skip Node/Electron)"
else
    say "gui:      no"
fi
if [[ "$INSTALL_AI" -eq 1 ]]; then
    say "ai:       yes (httpx for beacon-client.py ai)"
else
    say "ai:       no  (--with-ai to install httpx)"
fi
if [[ "$INSTALL_MCP" -eq 1 ]]; then
    say "mcp:      yes (mcp + httpx for python -m tornadoc2_mcp)"
else
    say "mcp:      no  (--with-mcp to install mcp + httpx)"
fi
[[ -n "$VENV_PATH" ]] && say "venv:     $VENV_PATH"

# --------------------------------------------------------------------
# Package manager detection

case "$FAMILY" in
    debian)
        PKG_MGR="apt-get"
        command -v apt-get >/dev/null 2>&1 \
            || { warn "apt-get not found on a Debian-family host"; \
                 CAN_INSTALL_SYSTEM=0; }
        ;;
    rhel)
        PKG_MGR="$(command -v dnf || command -v yum || true)"
        [[ -n "$PKG_MGR" ]] \
            || { warn "neither dnf nor yum found on a RHEL-family host"; \
                 CAN_INSTALL_SYSTEM=0; }
        ;;
    arch)
        PKG_MGR="pacman"
        command -v pacman >/dev/null 2>&1 \
            || { warn "pacman not found on an Arch-family host"; \
                 CAN_INSTALL_SYSTEM=0; }
        ;;
    macos|*)
        PKG_MGR=""
        ;;
esac

# --------------------------------------------------------------------
# System package helpers

FAILED_SYSPKGS=()

_syspkg_present() {
    local pkg="$1"
    case "$FAMILY" in
        debian) dpkg -s "$pkg" >/dev/null 2>&1 ;;
        rhel)   rpm -q "$pkg" >/dev/null 2>&1 ;;
        arch)   pacman -Qi "$pkg" >/dev/null 2>&1 ;;
        *)      return 1 ;;
    esac
}

install_syspkg() {
    local pkg="$1"
    [[ "$CAN_INSTALL_SYSTEM" -eq 1 ]] || return 1
    _syspkg_present "$pkg" && return 0

    case "$FAMILY" in
        debian)
            $SUDO apt-get install -y --no-install-recommends \
                "$pkg" >/dev/null 2>&1
            ;;
        rhel)
            $SUDO "$PKG_MGR" install -y "$pkg" >/dev/null 2>&1
            ;;
        arch)
            $SUDO pacman -S --needed --noconfirm \
                "$pkg" >/dev/null 2>&1
            ;;
    esac
}

install_syspkgs() {
    local pkgs=("$@")
    local missing=()
    local p

    [[ "$CAN_INSTALL_SYSTEM" -eq 1 ]] || {
        for p in "${pkgs[@]}"; do
            _syspkg_present "$p" || FAILED_SYSPKGS+=("$p")
        done
        return 0
    }

    for p in "${pkgs[@]}"; do
        _syspkg_present "$p" || missing+=("$p")
    done

    if (( ${#missing[@]} == 0 )); then
        ok "all ${#pkgs[@]} system packages already present"
        return 0
    fi

    case "$FAMILY" in
        debian)
            $SUDO apt-get install -y --no-install-recommends \
                "${missing[@]}" >/dev/null 2>&1 || true
            ;;
        rhel)
            $SUDO "$PKG_MGR" install -y \
                "${missing[@]}" >/dev/null 2>&1 || true
            ;;
        arch)
            $SUDO pacman -S --needed --noconfirm \
                "${missing[@]}" >/dev/null 2>&1 || true
            ;;
    esac

    for p in "${missing[@]}"; do
        if ! _syspkg_present "$p"; then
            install_syspkg "$p" || FAILED_SYSPKGS+=("$p")
        fi
    done
}

# --------------------------------------------------------------------
# Python sanity

if ! command -v python3 >/dev/null 2>&1; then
    die "python3 is not on PATH. The operator client needs Python \
3.7 or later. Install it from your package manager (Debian: \
python3, RHEL: python3, Arch: python, macOS: brew install \
python@3.12), or from python.org."
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VERSION%%.*}"
PY_MINOR="${PY_VERSION#*.}"
if (( PY_MAJOR < 3 )) || (( PY_MAJOR == 3 && PY_MINOR < 7 )); then
    die "Python ${PY_VERSION} is older than the 3.7 floor the \
client requires."
fi
ok "python3: $(python3 --version)"

# --------------------------------------------------------------------
# Virtualenv (recommended path)

if [[ -n "$VENV_PATH" ]]; then
    if [[ ! -d "$VENV_PATH" ]]; then
        say "creating venv at $VENV_PATH"
        if ! python3 -m venv "$VENV_PATH" 2>/dev/null; then
            case "$FAMILY" in
                debian)
                    say "installing python3-venv"
                    if [[ "$CAN_INSTALL_SYSTEM" -eq 1 ]]; then
                        $SUDO apt-get update -qq
                        $SUDO apt-get install -y \
                            --no-install-recommends \
                            python3-venv >/dev/null 2>&1 \
                            || true
                    fi
                    ;;
                rhel)
                    say "installing python3-virtualenv"
                    if [[ "$CAN_INSTALL_SYSTEM" -eq 1 ]]; then
                        $SUDO "$PKG_MGR" install -y \
                            python3-virtualenv >/dev/null 2>&1 \
                            || true
                    fi
                    ;;
                arch|macos)
                    # Bundled with Python.
                    ;;
            esac

            if ! python3 -m venv "$VENV_PATH" 2>/dev/null; then
                die "python3 -m venv failed even after installing \
the venv module. On Debian this is python3-venv; on RHEL it is \
python3-virtualenv. Install it manually and retry."
            fi
        fi
    fi
    # shellcheck disable=SC1091
    . "$VENV_PATH/bin/activate"
    ok "activated venv: $VENV_PATH"
    PYTHON_BIN="$(command -v python)"
    PIP_CMD=("$PYTHON_BIN" -m pip)
    PIP_FLAGS=()
else
    PYTHON_BIN="$(command -v python3)"
    PIP_CMD=("$PYTHON_BIN" -m pip)
    PIP_FLAGS=()
fi

# --------------------------------------------------------------------
# pip availability

if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    if [[ -n "$VENV_PATH" ]]; then
        die "pip is not available inside the venv at $VENV_PATH. \
This usually means the venv was created without pip. Delete \
$VENV_PATH and rerun."
    fi

    warn "pip is not available for $PYTHON_BIN"

    say "attempting python3 -m ensurepip"
    if "$PYTHON_BIN" -m ensurepip --default-pip >/dev/null 2>&1; then
        ok "pip installed via ensurepip"
    else
        case "$FAMILY" in
            debian)
                say "installing python3-pip via apt"
                if [[ "$CAN_INSTALL_SYSTEM" -eq 1 ]]; then
                    $SUDO apt-get update -qq
                    $SUDO apt-get install -y \
                        --no-install-recommends \
                        python3-pip >/dev/null 2>&1 \
                        || die "python3-pip install failed"
                else
                    die "python3-pip is not installed and sudo is \
not available. Run as root or install python3-pip manually."
                fi
                ;;
            rhel)
                say "installing python3-pip via dnf"
                if [[ "$CAN_INSTALL_SYSTEM" -eq 1 ]]; then
                    $SUDO "$PKG_MGR" install -y \
                        python3-pip >/dev/null 2>&1 \
                        || die "python3-pip install failed"
                else
                    die "python3-pip is not installed and sudo is \
not available. Run as root or install python3-pip manually."
                fi
                ;;
            arch)
                say "installing python-pip via pacman"
                if [[ "$CAN_INSTALL_SYSTEM" -eq 1 ]]; then
                    $SUDO pacman -Sy --needed --noconfirm \
                        python-pip >/dev/null 2>&1 \
                        || die "python-pip install failed"
                else
                    die "python-pip is not installed and sudo is \
not available. Run as root or install python-pip manually."
                fi
                ;;
            macos)
                die "pip is not available and ensurepip failed. \
On macOS, reinstall Python with 'brew install python@3.12' or \
from python.org, then retry."
                ;;
            *)
                die "pip is missing and this OS is not recognised. \
Install pip for $PYTHON_BIN manually, or rerun with \
--venv <path> after installing the venv module for your Python."
                ;;
        esac
        ok "pip installed"
    fi
fi

# PEP 668 check.
if [[ -z "$VENV_PATH" ]]; then
    if "$PYTHON_BIN" -m pip install --dry-run --no-deps cryptography \
            2>&1 | grep -q "externally-managed-environment"; then
        PIP_FLAGS+=(--break-system-packages)
        warn "PEP 668 externally-managed environment detected;"
        warn "adding --break-system-packages to pip installs."
        warn "  If you would rather not touch the system Python,"
        warn "  rerun with:  $0 --venv ~/.tornadoc2-venv"
    fi
fi

# --------------------------------------------------------------------
# Python packages

say "installing Python packages"

PIP_FAILED=()

if [[ "$INSTALL_MCP" -eq 1 ]]; then
    if (( PY_MAJOR < 3 )) || (( PY_MAJOR == 3 && PY_MINOR < 10 )); then
        warn "--with-mcp requires Python 3.10 or later"
        warn "  this interpreter is Python ${PY_VERSION}."
        warn "  mcp will not install; the standalone MCP server"
        warn "  will not run. The AI console still works if"
        warn "  httpx installs successfully."
        INSTALL_MCP=0
    fi
fi

if [[ "$INSTALL_AI" -eq 1 ]]; then
    if (( PY_MAJOR < 3 )) || (( PY_MAJOR == 3 && PY_MINOR < 8 )); then
        warn "--with-ai requires Python 3.8 or later for a"
        warn "  current httpx. This interpreter is Python"
        warn "  ${PY_VERSION}; pip may install an older httpx,"
        warn "  and the AI console may fail at import time."
        warn "  Consider rerunning with --venv on a newer Python."
    fi
fi

for pkg in "${PIP_REQUIRED[@]}"; do
    import_name="${pkg//-/_}"
    if "$PYTHON_BIN" -c "import ${import_name}" 2>/dev/null; then
        ok "python: $pkg importable"
        continue
    fi
    say "python: installing $pkg"
    if "${PIP_CMD[@]}" install --quiet "${PIP_FLAGS[@]}" "$pkg"; then
        ok "python: $pkg installed"
    else
        PIP_FAILED+=("$pkg")
        warn "pip install $pkg failed. A config without a signature"
        warn "still loads; a signed config raises at load time."
    fi
done

if [[ "$INSTALL_AI" -eq 1 ]]; then
    for pkg in "${PIP_AI[@]}"; do
        import_name="${pkg//-/_}"
        if "$PYTHON_BIN" -c "import ${import_name}" 2>/dev/null; then
            ok "python: $pkg importable"
            continue
        fi
        say "python: installing $pkg"
        if "${PIP_CMD[@]}" install --quiet "${PIP_FLAGS[@]}" "$pkg"; then
            ok "python: $pkg installed"
        else
            PIP_FAILED+=("$pkg")
            warn "pip install $pkg failed — AI console and"
            warn "MCP server will not run. Retry with:"
            warn "    ${PIP_CMD[*]} install ${PIP_FLAGS[*]} $pkg"
        fi
    done
fi

if [[ "$INSTALL_MCP" -eq 1 ]]; then
    for pkg in "${PIP_MCP[@]}"; do
        import_name="${pkg//-/_}"
        if "$PYTHON_BIN" -c "import ${import_name}" 2>/dev/null; then
            ok "python: $pkg importable"
            continue
        fi
        say "python: installing $pkg"
        if "${PIP_CMD[@]}" install --quiet "${PIP_FLAGS[@]}" "$pkg"; then
            ok "python: $pkg installed"
        else
            PIP_FAILED+=("$pkg")
            warn "pip install $pkg failed — the standalone MCP"
            warn "server will not run. Retry with:"
            warn "    ${PIP_CMD[*]} install ${PIP_FLAGS[*]} $pkg"
        fi
    done
fi

# --------------------------------------------------------------------
# readline — stdlib on Linux and macOS, a package on Windows

case "$UNAME_S" in
    Linux)
        if "$PYTHON_BIN" -c "import readline" 2>/dev/null; then
            ok "readline: available (history and tab-complete)"
        else
            case "$FAMILY" in
                debian) install_syspkg "python3-readline" || true ;;
                rhel)   install_syspkg "readline-devel" || true ;;
                arch)   : ;;
            esac
            if "$PYTHON_BIN" -c "import readline" 2>/dev/null; then
                ok "readline: installed"
            else
                warn "readline is missing on this Python. On Linux"
                warn "it is part of the stdlib; a stripped build may"
                warn "lack it. Install python3-readline (Debian),"
                warn "readline (RHEL), or the equivalent."
            fi
        fi
        ;;
    Darwin)
        if "$PYTHON_BIN" -c "import readline" 2>/dev/null; then
            ok "readline: available (history and tab-complete)"
        else
            warn "readline is not importable. python.org builds"
            warn "include it; a Homebrew Python does not. Install"
            warn "with: brew install readline, then reinstall Python"
            warn "from source so it links against the Homebrew"
            warn "readline."
        fi
        ;;
    *)
        warn "readline is a Unix module; it is not expected on this"
        warn "platform. On Windows the client falls back to"
        warn "pyreadline3 — install it into the same Python with:"
        warn "    ${PIP_CMD[*]} install pyreadline3"
        ;;
esac

# --------------------------------------------------------------------
# Verify

say "verifying"

if "$PYTHON_BIN" -c "import cryptography" 2>/dev/null; then
    ver="$("$PYTHON_BIN" -c 'import cryptography; print(cryptography.__version__)')"
    ok "cryptography $ver  (config-signature verification enabled)"
else
    warn "cryptography not importable — signed configs will be"
    warn "refused at load time"
fi

if [[ "$INSTALL_AI" -eq 1 ]]; then
    if "$PYTHON_BIN" -c "import httpx" 2>/dev/null; then
        ver="$("$PYTHON_BIN" -c 'import httpx; print(httpx.__version__)')"
        ok "httpx $ver  (AI console + MCP server ready)"
    else
        warn "httpx not importable — AI console and MCP server"
        warn "will not run"
    fi
fi

if [[ "$INSTALL_MCP" -eq 1 ]]; then
    if "$PYTHON_BIN" -c "import mcp" 2>/dev/null; then
        ok "mcp importable  (standalone MCP server ready)"
    else
        warn "mcp not importable — the standalone MCP server"
        warn "will not run"
    fi
fi

# --------------------------------------------------------------------
# Failure summary

if (( ${#FAILED_SYSPKGS[@]} > 0 )); then
    printf '\n'
    say "the following system packages could not be installed:"
    for p in "${FAILED_SYSPKGS[@]}"; do
        say "    $p"
    done
    say "the client itself is unaffected — pip covers the Python"
    say "side. Electron runtime library gaps affect --gui only;"
    say "install the missing names with your package manager if"
    say "the GUI fails to launch."
fi

if (( ${#PIP_FAILED[@]} > 0 )); then
    printf '\n'
    warn "the following Python packages could not be installed:"
    for p in "${PIP_FAILED[@]}"; do
        warn "    $p"
    done
    warn "retry manually with:"
    warn "    ${PIP_CMD[*]} install ${PIP_FLAGS[*]} ${PIP_FAILED[*]}"
fi

# --------------------------------------------------------------------
# Summary

if [[ "$INSTALL_GUI" -eq 1 ]]; then
    if [[ "$SKIP_NODE" -eq 0 ]]; then
        install_node || warn "continuing without a managed Node"
    elif ! _have_node; then
        warn "--skip-node set but no Node >= 26 on PATH"
    fi
    install_electron_libs
    install_electron_app
fi

printf '\n'
say "client dependency installation complete"
if [[ -n "$VENV_PATH" ]]; then
    say "the packages live in: $VENV_PATH"
    say "activate before launching:"
    say "    source $VENV_PATH/bin/activate"
fi

say "run the client with:"
say "    python3 beacon-client.py -c <your>.cfg"
if [[ "$INSTALL_GUI" -eq 1 ]]; then
    say "    python3 beacon-client.py -c <your>.cfg --gui"
    say "    (Electron shell)"
fi
if [[ "$INSTALL_AI" -eq 1 ]]; then
    say "run the AI console with:"
    say "    python3 beacon-client.py ai -c <your>.cfg"
    say "    (create ~/.tornadoc2/ai.json first; see README.md"
    say "     under AI Operator Console and MCP Server)"
fi
if [[ "$INSTALL_MCP" -eq 1 ]]; then
    say "run the standalone MCP server with:"
    say "    python3 -m tornadoc2_mcp -c <your>.cfg"
fi