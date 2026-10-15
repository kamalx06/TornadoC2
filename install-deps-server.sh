#!/usr/bin/env bash

set -uo pipefail

# --------------------------------------------------------------------
# TornadoC2 — team server dependency installer
#
# Installs everything the handler (tornadoc2.py) needs to run and
# to compile agents:
#
#   * Python 3.7+ and the handler's Python dependencies
#     (flask, cryptography, dnslib, aioquic, simple-websocket,
#     pyroute2)
#   * The Go 1.24 toolchain and garble
#   * wireguard-tools and the WireGuard kernel module
#   * libcap2-bin (for the setcap grants the ICMP and WireGuard
#     transports need)
#   * openssl, libssl-dev, libffi-dev, build-essential
#
# Always installed:
#
#   * mono-devel / mono   — the C# compiler (mcs) for the .NET
#                           bootstrap DLL that the Windows agent
#                           embeds via //go:embed. Without mcs (or
#                           csc on a Windows host) the Windows
#                           agent cannot be built; the Linux agent
#                           is unaffected. The compiler is required
#                           because Bootstrap.dll is generated from
#                           source at build time, not checked in.
#
# Optional, installed unless --minimal:
#
#   * upx-ucl             — for the paranoid OPSEC profile
#   * gcc-mingw-w64       — for output_format=dll builds
#   * rustup + wasm32     — for building WASM extensions
#   * donut-shellcode     — for --format shellcode and inject:true
#
# NOT for the operator workstation. Use install-deps-client.sh
# there; the client needs none of the above.
#
# Supported families, tested across their current releases:
#
#   Debian family   — Debian 11 (Bullseye) through 13 (Trixie),
#                     Ubuntu 20.04 through 24.04, Kali, Mint, Pop,
#                     Parrot, Raspbian, and any derivative that
#                     declares ID_LIKE=debian.
#
#   RHEL family     — RHEL 8 and 9, CentOS Stream 8 and 9, Rocky 8
#                     and 9, Alma 8 and 9, Oracle Linux 8 and 9,
#                     Fedora 38 through 41, Amazon Linux 2023.
#                     EPEL is used where available; on Amazon Linux
#                     and any host without EPEL, missing packages
#                     fall through to pip.
#
#   Arch family     — Arch, Manjaro, EndeavourOS, Garuda, Artix,
#                     and any derivative that declares
#                     ID_LIKE=arch. python-dnslib and python-aioquic
#                     live in the AUR, not the official repos; those
#                     two always come from pip on this family.
#
# Any other distribution is refused with a message naming the
# family it should have declared.
#
# Robustness contract. A system package that cannot be installed
# does not abort the run. Each is tried individually, failures are
# recorded, and the summary at the end names them. Every Python
# package is verified by importing it; a package that cannot be
# imported is installed via pip. This gives a working handler on a
# minimal host even when the distribution's archive is out of
# date, missing a package, or has a different name for it.
# --------------------------------------------------------------------

# --------------------------------------------------------------------
# Configuration

# Python packages the handler imports. Each is verified by import
# and installed via pip if the system package manager cannot
# provide it.
PIP_REQUIRED=(
    "flask"
    "cryptography"
    "dnslib"
    "aioquic"
    "simple-websocket"
    "pyroute2"
)

# Optional Python packages. Skipped under --minimal.
PIP_PACKAGES_OPTIONAL=(
    "donut-shellcode"
)

# Go modules installed into $GOPATH/bin.
GO_INSTALL_TOOLS=(
    "mvdan.cc/garble@v0.17.0"
)

# --------------------------------------------------------------------
# Flags

MINIMAL=0

usage() {
    sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Usage: $(basename "$0") [options]

Options:
  --minimal          Skip UPX, MinGW, Rust/wasm32, and Donut.
                     Installs only what the handler needs to run
                     and to compile a plain ELF or PE agent.
  -h, --help         This message.
EOF
}

for arg in "$@"; do
    case "$arg" in
        --minimal) MINIMAL=1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown flag: $arg" >&2; exit 1 ;;
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

need_root() {
    if [[ $EUID -ne 0 ]]; then
        SUDO="sudo"
    else
        SUDO=""
    fi
}

# --------------------------------------------------------------------
# Distro detection

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
    DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
    DISTRO_VERSION="${VERSION_ID:-}"
else
    die "/etc/os-release not found — cannot identify distribution"
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
            *)                 die "unsupported distribution: $DISTRO_ID ($DISTRO_LIKE)" ;;
        esac
        ;;
esac

say "distro:   $DISTRO_NAME"
say "family:   $FAMILY"
[[ -n "$DISTRO_VERSION" ]] && say "version:  $DISTRO_VERSION"
need_root
say "sudo:     ${SUDO:-<none, running as root>}"

# --------------------------------------------------------------------
# Package manager

case "$FAMILY" in
    debian)
        PKG_MGR="apt-get"
        command -v apt-get >/dev/null 2>&1 \
            || die "apt-get not found on a Debian-family host"
        ;;
    rhel)
        PKG_MGR="$(command -v dnf || command -v yum || true)"
        [[ -n "$PKG_MGR" ]] \
            || die "neither dnf nor yum found on a RHEL-family host"
        ;;
    arch)
        PKG_MGR="pacman"
        command -v pacman >/dev/null 2>&1 \
            || die "pacman not found on an Arch-family host"
        ;;
esac

say "pkg mgr:  $PKG_MGR"

# --------------------------------------------------------------------
# EPEL handling for the RHEL family.
#
# EPEL provides several packages the framework wants on RHEL 8/9:
# upx, wireguard-tools (on RHEL 8 only), python3-dnslib, mingw64-gcc,
# and (on RHEL 8) python3-flask. On Fedora the packages are in the
# main repos and EPEL is not needed. Amazon Linux 2023 does not
# carry EPEL at all; the fallback to pip covers the gap.

if [[ "$FAMILY" == "rhel" ]]; then
    case "$DISTRO_ID" in
        rhel|centos|rocky|almalinux|ol)
            if ! rpm -q epel-release >/dev/null 2>&1; then
                say "installing EPEL release package"
                if ! $SUDO "$PKG_MGR" install -y epel-release \
                        >/dev/null 2>&1; then
                    warn "epel-release could not be installed — some"
                    warn "optional packages will be missing. The Python"
                    warn "fallback below will cover anything the handler"
                    warn "actually needs."
                else
                    ok "EPEL enabled"
                fi
            else
                ok "EPEL already enabled"
            fi
            ;;
        fedora)
            # Fedora carries everything in the main repos. EPEL is
            # optional and only adds extras; skip it.
            ;;
        amzn)
            warn "Amazon Linux: EPEL is not available. Some optional"
            warn "packages (upx, wireguard-tools, python3-dnslib) may be"
            warn "missing from the repositories. The Python fallback"
            warn "handles the Python ones; the rest are optional."
            ;;
    esac
fi

# --------------------------------------------------------------------
# System package installation helpers
#
# Each package is tried individually. A failure is recorded and the
# install continues — a single missing package must not sink the
# whole run.

FAILED_SYSPKGS=()

_syspkg_present() {
    local pkg="$1"
    case "$FAMILY" in
        debian) dpkg -s "$pkg" >/dev/null 2>&1 ;;
        rhel)   rpm -q "$pkg" >/dev/null 2>&1 ;;
        arch)   pacman -Qi "$pkg" >/dev/null 2>&1 ;;
    esac
}

install_syspkg() {
    local pkg="$1"

    if _syspkg_present "$pkg"; then
        return 0
    fi

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

# Bulk installer: tries the whole list in one transaction first, which
# is much faster when everything is available, then verifies each
# package and retries the missing ones individually.
install_syspkgs() {
    local pkgs=("$@")
    local missing=()

    # Quick verification: which of these are already present?
    for p in "${pkgs[@]}"; do
        _syspkg_present "$p" || missing+=("$p")
    done

    if (( ${#missing[@]} == 0 )); then
        ok "all ${#pkgs[@]} system packages already present"
        return 0
    fi

    # Bulk attempt. The `|| true` is deliberate — a single missing
    # package must not abort the transaction's other installs.
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

    # Per-package verification and retry.
    for p in "${missing[@]}"; do
        if ! _syspkg_present "$p"; then
            install_syspkg "$p" || FAILED_SYSPKGS+=("$p")
        fi
    done
}

# --------------------------------------------------------------------
# Refresh the package cache.
#
# A stale cache is the most common reason a package "cannot be
# installed" when it is in fact available. Refresh once before the
# bulk install, not per-package.

say "refreshing package cache"
case "$FAMILY" in
    debian) $SUDO apt-get update -qq >/dev/null 2>&1 || true ;;
    rhel)   $SUDO "$PKG_MGR" makecache -q >/dev/null 2>&1 || true ;;
    arch)   $SUDO pacman -Sy --noconfirm >/dev/null 2>&1 || true ;;
esac

# --------------------------------------------------------------------
# System package lists, per family.
#
# Package names differ across families in ways that are not
# algorithmic — Python bindings are `python3-foo` on Debian and RHEL
# but `python-foo` on Arch; MinGW is `gcc-mingw-w64-x86-64` on
# Debian, `mingw64-gcc` on RHEL, `mingw-w64-gcc` on Arch. Listing
# them per family is more legible than trying to derive them.

case "$FAMILY" in
    debian)
        SYSTEM_PKGS=(
            # Python interpreter and build tooling
            python3 python3-pip python3-venv python3-dev
            # Python bindings the handler uses; anything missing
            # falls through to pip below
            python3-flask python3-cryptography python3-dnslib
            # TLS and native build tooling
            openssl libssl-dev libffi-dev build-essential
            # Base utilities
            git curl ca-certificates
            # Go toolchain
            golang-go
            # WireGuard support
            wireguard-tools
            # Capability helper for ICMP and WireGuard
            libcap2-bin
            # C# compiler for the .NET bootstrap DLL (Bootstrap.dll)
            # that the Windows agent embeds. Without mcs the Windows
            # target is skipped by install-go-build.sh.
            mono-devel
            # Optional (skipped under --minimal, harmless otherwise)
            upx-ucl
            gcc-mingw-w64-x86-64
            libnotify-bin
        )

        # Transport-specific Python bindings are Trixie-only in the
        # archive. On older releases they go through pip. Add them
        # to the apt list only when the release carries them, so we
        # avoid a pointless per-package retry.
        if [[ "$DISTRO_ID" == "debian" && "$DISTRO_VERSION" == "13" ]]; then
            SYSTEM_PKGS+=(
                python3-aioquic
                python3-simple-websocket
                python3-pyroute2
            )
        elif [[ "$DISTRO_ID" == "ubuntu" \
                && "${DISTRO_VERSION%%.*}" -ge 24 ]] 2>/dev/null; then
            # Ubuntu 24.04 (Noble) ships python3-aioquic and
            # python3-pyroute2 in universe. simple-websocket may or
            # may not be present; the fallback covers it either way.
            SYSTEM_PKGS+=(
                python3-aioquic
                python3-pyroute2
            )
        fi
        ;;

    rhel)
        SYSTEM_PKGS=(
            # Python interpreter and build tooling
            python3 python3-pip python3-devel
            # Python bindings; the fallback covers anything missing
            python3-flask python3-cryptography python3-dnslib
            # TLS and native build tooling
            openssl openssl-devel libffi-devel
            gcc gcc-c++ make
            # Base utilities
            git curl ca-certificates
            # Go toolchain
            golang
            # WireGuard support
            wireguard-tools
            # Capability helper
            libcap
            # C# compiler for the .NET bootstrap DLL. mono-devel is
            # in EPEL on RHEL 8/9 and in the main repos on Fedora.
            # Amazon Linux 2023 does not carry it; the build script
            # warns and skips the Windows target there.
            mono-devel
            # Optional
            upx
            mingw64-gcc
            libnotify
        )

        # Python transport bindings are essentially never in the
        # RHEL-family main repos or EPEL. The pip fallback installs
        # them; adding them to the system list would just produce a
        # recorded failure for no reason.
        ;;

    arch)
        SYSTEM_PKGS=(
            # Python interpreter and build tooling
            python python-pip
            # Python bindings; python-dnslib is AUR-only, so it will
            # fail here and fall through to pip. python-flask,
            # python-cryptography, and python-pyroute2 are in the
            # official repos on a current install.
            python-flask python-cryptography python-dnslib
            # TLS and native build tooling
            openssl libffi base-devel
            # Base utilities
            git curl ca-certificates
            # Go toolchain
            go
            # WireGuard support
            wireguard-tools
            # Capability helper
            libcap
            # C# compiler for the .NET bootstrap DLL.
            mono
            # Optional
            upx
            mingw-w64-gcc
            libnotify
        )
        ;;
esac

say "installing system packages (${#SYSTEM_PKGS[@]} packages)"
install_syspkgs "${SYSTEM_PKGS[@]}"

# --------------------------------------------------------------------
# Python version floor

if ! command -v python3 >/dev/null 2>&1; then
    die "python3 is not on PATH — the system-package install should \
have added it. Check 'which python3' and your shell's PATH."
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VERSION%%.*}"
PY_MINOR="${PY_VERSION#*.}"
if (( PY_MAJOR < 3 )) || (( PY_MAJOR == 3 && PY_MINOR < 7 )); then
    die "Python ${PY_VERSION} is older than the 3.7 floor the handler \
requires."
fi
ok "python3: $(python3 --version)"

# --------------------------------------------------------------------
# Python packages
#
# Every package in PIP_REQUIRED is verified by importing it. If the
# import fails, the package is installed via pip. This is the
# authoritative check — the system package install above is
# best-effort.

say "checking Python packages"

# Detect a PEP 668 externally-managed environment. Debian 12+,
# Ubuntu 23.04+, Fedora 38+, and Homebrew Python mark the system
# interpreter this way.
PIP_FLAGS=()
if python3 -m pip install --dry-run --no-deps flask 2>&1 \
        | grep -q "externally-managed-environment"; then
    PIP_FLAGS+=(--break-system-packages)
fi

# Map pip package name → Python import name where they differ.
declare -A IMPORT_NAMES=(
    [flask]=flask
    [cryptography]=cryptography
    [dnslib]=dnslib
    [aioquic]=aioquic
    [simple-websocket]=simple_websocket
    [pyroute2]=pyroute2
)

PIP_FAILED=()
for pkg in "${PIP_REQUIRED[@]}"; do
    import_name="${IMPORT_NAMES[$pkg]:-${pkg//-/_}}"
    if python3 -c "import ${import_name}" 2>/dev/null; then
        ok "python: $pkg importable"
        continue
    fi
    say "python: installing $pkg via pip"
    if python3 -m pip install --quiet "${PIP_FLAGS[@]}" "$pkg"; then
        ok "python: $pkg installed via pip"
    else
        PIP_FAILED+=("$pkg")
        warn "pip install $pkg failed — the transport that depends on"
        warn "it will refuse to start. Install it manually to enable."
    fi
done

if [[ $MINIMAL -eq 0 ]]; then
    for pkg in "${PIP_PACKAGES_OPTIONAL[@]}"; do
        python3 -c "import ${pkg//-/_}" 2>/dev/null && continue
        say "python: installing optional $pkg"
        python3 -m pip install --quiet "${PIP_FLAGS[@]}" "$pkg" || \
            warn "optional pip install $pkg failed"
    done
fi

# --------------------------------------------------------------------
# Go toolchain

if ! command -v go >/dev/null 2>&1; then
    die "go is not on PATH — the system-package install should have \
added it. On a host where golang-go or golang is not packaged, install \
the official tarball from https://go.dev/dl/ and re-run this script."
fi

GO_VERSION_ACTUAL="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
ok "go: $(go version)"

# The agent's go.mod declares `go 1.24`. Reject anything older so the
# failure is legible here rather than three minutes into a build.
GO_MAJOR="${GO_VERSION_ACTUAL%%.*}"
GO_REST="${GO_VERSION_ACTUAL#*.}"
GO_MINOR="${GO_REST%%.*}"
if [[ -n "$GO_MAJOR" && -n "$GO_MINOR" ]]; then
    if (( GO_MAJOR < 1 )) || (( GO_MAJOR == 1 && GO_MINOR < 24 )); then
        die "Go ${GO_VERSION_ACTUAL} is older than the 1.24 the agent \
requires. Debian 13, Ubuntu 24.04, RHEL 9, Fedora 40, and Arch ship \
Go 1.24+. An older release needs the official tarball from \
https://go.dev/dl/"
    fi
fi

# --------------------------------------------------------------------
# C# compiler for the bootstrap DLL
#
# install-go-build.sh generates native/Bootstrap.dll from
# native/Bootstrap.cs before the Windows agent build. The Go
# loader //go:embed's the DLL, so if the file is missing the
# Windows target is skipped. mcs (Mono C# compiler) is the Linux
# path; csc is the Windows path.

say "checking C# compiler"
if command -v mcs >/dev/null 2>&1; then
    ok "mcs: $(command -v mcs)"
elif command -v csc >/dev/null 2>&1; then
    ok "csc: $(command -v csc)"
else
    warn "no C# compiler found (mcs or csc)"
    warn "install mono-devel (Debian/RHEL) or mono (Arch), or"
    warn "build Bootstrap.dll on a Windows host and check it in"
    warn "next to Bootstrap.cs"
    warn ""
    warn "the Linux agent will build; the Windows target will be"
    warn "skipped by install-go-build.sh until the DLL exists"
fi

GOBIN="$(go env GOPATH)/bin"
case ":$PATH:" in
    *":$GOBIN:"*) ;;
    *) export PATH="$PATH:$GOBIN"
       warn "added $GOBIN to PATH for this run — add it to your shell profile too" ;;
esac

# --------------------------------------------------------------------
# garble

say "installing garble"
if command -v garble >/dev/null 2>&1; then
    ok "garble already installed: $(command -v garble)"
else
    for tool in "${GO_INSTALL_TOOLS[@]}"; do
        if go install "$tool"; then
            ok "installed $tool"
        else
            warn "go install $tool failed — only the opsec and paranoid"
            warn "profiles need it"
        fi
    done
fi

# --------------------------------------------------------------------
# UPX (binary packing, only used by the paranoid profile)

if [[ $MINIMAL -eq 0 ]]; then
    if command -v upx >/dev/null 2>&1; then
        ok "upx: $(command -v upx)"
    else
        warn "upx not found — the paranoid OPSEC profile will skip packing"
    fi
fi

# --------------------------------------------------------------------
# Donut (shellcode generator; needed by --format shellcode and inject)

if [[ $MINIMAL -eq 0 ]]; then
    say "checking Donut"
    if command -v donut >/dev/null 2>&1 \
            || [[ -x beacon/bin/donut ]]; then
        ok "donut already present"
    elif python3 -c "import donut" 2>/dev/null; then
        ok "donut via Python bindings (donut-shellcode)"
    else
        warn "donut not installed. Install one of:"
        warn "    pip install donut-shellcode      (Python bindings)"
        warn "    or build from https://github.com/TheWover/donut"
        warn "    and drop the binary at beacon/bin/donut"
        warn "shellcode output and inject:true will fail without it."
    fi
fi

# --------------------------------------------------------------------
# Rust + wasm32 (only needed if you build WASM extensions)

if [[ $MINIMAL -eq 0 ]]; then
    say "checking Rust + wasm32 for WASM extensions"
    if command -v rustup >/dev/null 2>&1; then
        rustup target add wasm32-unknown-unknown 2>/dev/null || true
        ok "rustup present; wasm32-unknown-unknown target ensured"
    else
        warn "rustup not present. WASM extensions cannot be built."
        warn "    install via:  curl --proto '=https' --tlsv1.2 \\"
        warn "                  -sSf https://sh.rustup.rs | sh"
        warn "then:         rustup target add wasm32-unknown-unknown"
    fi
fi

# --------------------------------------------------------------------
# Kernel WireGuard module
#
# WireGuard has been mainline since kernel 5.6. On a current
# distribution the module is already present. The only failure modes
# are a container that does not share the host kernel's module set,
# or a custom kernel built without CONFIG_WIREGUARD.

say "checking WireGuard kernel module"
if modinfo wireguard >/dev/null 2>&1; then
    ok "wireguard kernel module is available"
else
    warn "wireguard kernel module not found. Load it with:"
    warn "    modprobe wireguard"
    warn "or add it to /etc/modules-load.d/ for a persistent load at boot."
    warn "The WireGuard transport refuses to start without it."
    warn "A missing module usually means a stripped kernel or a"
    warn "container namespace that does not expose the host's modules."
fi

# --------------------------------------------------------------------
# Linux capabilities for the ICMP and WireGuard transports

PYTHON_BIN="$(command -v python3 || true)"
say "checking transports that need elevated network capabilities"

if [[ -z "$PYTHON_BIN" ]]; then
    warn "python3 is not on PATH; skipping the capability check"
elif command -v setcap >/dev/null 2>&1; then
    if getcap "$PYTHON_BIN" 2>/dev/null | grep -q "cap_net_raw"; then
        ok "CAP_NET_RAW already set on $PYTHON_BIN"
    else
        warn "CAP_NET_RAW not set — the ICMP transport will refuse to start."
        warn "    grant with:  sudo setcap cap_net_raw+ep $PYTHON_BIN"
    fi
    if getcap "$PYTHON_BIN" 2>/dev/null | grep -q "cap_net_admin"; then
        ok "CAP_NET_ADMIN already set on $PYTHON_BIN"
    else
        warn "CAP_NET_ADMIN not set — the WireGuard transport will refuse to start."
        warn "    grant with:  sudo setcap cap_net_admin+ep $PYTHON_BIN"
    fi
else
    warn "setcap not found (libcap2-bin on Debian, libcap on RHEL,"
    warn "libcap on Arch). Install it and run:"
    warn "    sudo setcap cap_net_raw+ep $PYTHON_BIN"
    warn "    sudo setcap cap_net_admin+ep $PYTHON_BIN"
fi

# --------------------------------------------------------------------
# Failure summary

if (( ${#FAILED_SYSPKGS[@]} > 0 )); then
    printf '\n'
    say "the following system packages could not be installed:"
    for p in "${FAILED_SYSPKGS[@]}"; do
        say "    $p"
    done
    say "the pip fallback above covered any missing Python bindings;"
    say "any remaining gaps are optional features and will be named"
    say "by the handler at startup if the engagement needs them."
fi

if (( ${#PIP_FAILED[@]} > 0 )); then
    printf '\n'
    warn "the following Python packages could not be installed:"
    for p in "${PIP_FAILED[@]}"; do
        warn "    $p"
    done
    warn "the handler will refuse to start. Install them manually:"
    warn "    python3 -m pip install ${PIP_FLAGS[*]} ${PIP_FAILED[*]}"
fi

# --------------------------------------------------------------------
# Summary

printf '\n'
say "server dependency installation complete"
say "next steps:"
say "  1.  ./install-go-build.sh       (repair go.mod, resolve modules, build)"
say "  2.  python3 tornadoc2.py --beacon-port 8881"