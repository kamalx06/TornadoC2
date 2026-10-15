#!/usr/bin/env bash

set -uo pipefail

# --------------------------------------------------------------------
# TornadoC2 — operator workstation dependency installer
#
# Installs the Python packages the operator client needs:
#
#   * cryptography   — required when the operator config is
#                      signed (transport.py verifies the config
#                      signature at load time). Also used by the
#                      certificate-chain check in
#                      `operators export`.
#   * PySide6        — the GUI (`beacon-client.py --gui`). The
#                      CLI does not import PySide6.
#
# And, on Linux, the Qt runtime libraries the PySide6 xcb and
# wayland platform plugins load against. PySide6's wheel bundles
# Qt itself but not the host's glibc, X11, Wayland, and OpenGL
# dependencies.
#
# The X11 and Wayland runtime sets are selected independently:
#
#   --qt-libs x11       only the xcb platform plugin's deps
#   --qt-libs wayland   only the wayland platform plugin's deps
#   --qt-libs both      both
#   --qt-libs none      neither (the GUI will not launch)
#
# The default is autodetected from the current session: a host
# with WAYLAND_DISPLAY set installs only Wayland; a host with
# only DISPLAY set installs only X11; a host with neither (a
# headless install, or an SSH session with no forwarding yet)
# installs both, on the assumption that the operator may connect
# a display later.
#
# The client does NOT need:
#
#   * the Go toolchain          (remote builds happen on the server)
#   * garble, Donut, UPX        (server-side build tools)
#   * MinGW, Rust/wasm32        (server-side build tools)
#   * wireguard-tools           (that runs on the server)
#   * CAP_NET_RAW/CAP_NET_ADMIN (server-side transports only)
#   * flask, dnslib, aioquic, simple-websocket, pyroute2
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
#                       pip install cryptography PySide6 pyreadline3
#
# Robustness contract. A system package that cannot be installed
# does not abort the run. Each Qt runtime library is tried
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

PIP_GUI=(
    "PySide6"
)

# --------------------------------------------------------------------
# Flags

INSTALL_GUI=1
VENV_PATH=""

# Qt runtime library selection. Empty until autodetected or set by
# flag. One of: x11, wayland, both, none.
QT_LIBS=""

usage() {
    sed -n '2,80p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Usage: $(basename "$0") [options]

Options:
  --qt-libs <mode>      Which Qt runtime libraries to install.
                        One of:
                          x11       only the xcb plugin's deps
                          wayland   only the wayland plugin's deps
                          both      both sets
                          none      neither (the GUI will not
                                    launch; the CLI still works)
                        Default: autodetected from the current
                        session. WAYLAND_DISPLAY set → wayland;
                        only DISPLAY set → x11; neither → both.

  --x11                 Shorthand for --qt-libs x11
  --wayland             Shorthand for --qt-libs wayland
  --no-qt-libs          Shorthand for --qt-libs none

  --no-gui, --minimal   Skip PySide6 and the Qt runtime libraries
                        entirely. Equivalent to --qt-libs none
                        plus not installing PySide6. Installs
                        only what the CLI needs.

  --venv <path>         Install the Python packages into a
                        virtualenv at <path> instead of the system
                        interpreter. Recommended on a workstation
                        that already has its own Python
                        environment, and on macOS where the
                        Homebrew Python is PEP 668 managed.
                        Created if it does not exist.

  -h, --help            This message.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-gui|--minimal)
            INSTALL_GUI=0
            QT_LIBS="none"
            shift
            ;;
        --qt-libs)
            if [[ $# -lt 2 ]]; then
                echo "error: --qt-libs requires a value" >&2
                exit 1
            fi
            case "$2" in
                x11|wayland|both|none) QT_LIBS="$2" ;;
                *)
                    echo "error: --qt-libs value must be one of:" \
                         "x11, wayland, both, none" >&2
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --x11)      QT_LIBS="x11"; shift ;;
        --wayland)  QT_LIBS="wayland"; shift ;;
        --no-qt-libs) QT_LIBS="none"; shift ;;
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
# Autodetect the Qt library selection when the operator did not
# specify one. See the header for the logic.

if [[ -z "$QT_LIBS" ]]; then
    if [[ "$INSTALL_GUI" -eq 0 ]]; then
        QT_LIBS="none"
    elif [[ "$UNAME_S" != "Linux" ]]; then
        # macOS and Windows ship the Qt runtime with the wheel.
        QT_LIBS="none"
    elif [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        QT_LIBS="wayland"
    elif [[ -n "${DISPLAY:-}" ]]; then
        QT_LIBS="x11"
    else
        # Neither set. A headless server, or an SSH session with
        # no X forwarding yet. Install both so the GUI works
        # whichever display the operator connects.
        QT_LIBS="both"
    fi
fi

# --------------------------------------------------------------------
# Banner

say "os:       $DISTRO_NAME"
say "family:   $FAMILY"
if [[ "$INSTALL_GUI" -eq 1 ]]; then
    say "gui:      yes (--no-gui to skip PySide6)"
else
    say "gui:      no"
fi
[[ -n "$VENV_PATH" ]] && say "venv:     $VENV_PATH"

# Explain the Qt libs choice, and where it came from.
if [[ "$INSTALL_GUI" -eq 1 && "$UNAME_S" == "Linux" ]]; then
    case "$QT_LIBS" in
        x11)     detail="x11 only" ;;
        wayland) detail="wayland only" ;;
        both)    detail="x11 + wayland" ;;
        none)    detail="none" ;;
    esac
    # Was it explicit or autodetected?
    explicit=0
    for a in "$@"; do
        case "$a" in
            --qt-libs|--x11|--wayland|--no-qt-libs)
                explicit=1; break ;;
        esac
    done
    if (( explicit )); then
        say "qt libs:  $detail (from flag)"
    else
        case "$QT_LIBS" in
            wayland) source="WAYLAND_DISPLAY is set" ;;
            x11)     source="DISPLAY is set, WAYLAND_DISPLAY is not" ;;
            both)    source="neither WAYLAND_DISPLAY nor DISPLAY is set" ;;
            *)       source="gui disabled" ;;
        esac
        say "qt libs:  $detail (autodetected: $source)"
    fi
    if [[ "$QT_LIBS" == "both" ]]; then
        say "          pass --x11 or --wayland to install one set only"
    fi
fi

if [[ "$CAN_INSTALL_SYSTEM" -eq 0 ]]; then
    warn "no sudo and not running as root — system package installs"
    warn "will be skipped. pip will handle the Python packages; Qt"
    warn "runtime libraries will not be installed by this script."
    warn "If the GUI fails to launch, install them manually with"
    warn "your package manager or rerun with sudo."
fi

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
# Qt runtime libraries on Linux
#
# Two independent sets, selected by $QT_LIBS. Each is per-family
# because package names differ across families; each is installed
# with the per-package retry so one missing name does not abort
# the transaction for the rest.

if [[ "$INSTALL_GUI" -eq 1 && "$UNAME_S" == "Linux" \
        && "$QT_LIBS" != "none" ]]; then

    QT_LIBS_TO_INSTALL=()

    if [[ "$QT_LIBS" == "x11" || "$QT_LIBS" == "both" ]]; then
        say "installing Qt X11 runtime libraries"
        case "$FAMILY" in
            debian)
                QT_LIBS_TO_INSTALL+=(
                    libgl1
                    libegl1
                    libxkbcommon-x11-0
                    libxcb-cursor0
                    libxcb-icccm4
                    libxcb-image0
                    libxcb-keysyms1
                    libxcb-randr0
                    libxcb-render-util0
                    libxcb-shape0
                    libxcb-xinerama0
                    libdbus-1-3
                    libfontconfig1
                )
                ;;
            rhel)
                QT_LIBS_TO_INSTALL+=(
                    mesa-libGL
                    mesa-libEGL
                    libxkbcommon-x11
                    xcb-util-cursor
                    xcb-util-wm
                    xcb-util-image
                    xcb-util-keysyms
                    xcb-util-renderutil
                    libXrandr
                    libXinerama
                    dbus-libs
                    fontconfig
                )
                ;;
            arch)
                QT_LIBS_TO_INSTALL+=(
                    mesa
                    libxkbcommon-x11
                    xcb-util-cursor
                    xcb-util-wm
                    xcb-util-image
                    xcb-util-keysyms
                    xcb-util-renderutil
                    libxrandr
                    libxinerama
                    dbus
                    fontconfig
                )
                ;;
            *)
                warn "unrecognised Linux family ($FAMILY); skipping"
                warn "X11 Qt runtime libraries. If the GUI fails to"
                warn "launch, install libGL, libEGL,"
                warn "libxkbcommon-x11, and the libxcb-* family with"
                warn "your package manager."
                ;;
        esac
    fi

    if [[ "$QT_LIBS" == "wayland" || "$QT_LIBS" == "both" ]]; then
        say "installing Qt Wayland runtime libraries"
        case "$FAMILY" in
            debian)
                QT_LIBS_TO_INSTALL+=(
                    libwayland-client0
                    libwayland-cursor0
                    libwayland-egl1
                    libxkbcommon0
                    libgl1
                    libegl1
                    libdbus-1-3
                    libfontconfig1
                    qt6-wayland
                )
                ;;
            rhel)
                QT_LIBS_TO_INSTALL+=(
                    wayland
                    libxkbcommon
                    mesa-libGL
                    mesa-libEGL
                    dbus-libs
                    fontconfig
                    qt6-qtwayland
                )
                ;;
            arch)
                QT_LIBS_TO_INSTALL+=(
                    wayland
                    libxkbcommon
                    mesa
                    dbus
                    fontconfig
                    qt6-wayland
                )
                ;;
            *)
                warn "unrecognised Linux family ($FAMILY); skipping"
                warn "Wayland Qt runtime libraries. If the GUI fails"
                warn "to launch under Wayland, install"
                warn "libwayland-client, libxkbcommon, libGL, and the"
                warn "Qt6 wayland platform plugin with your package"
                warn "manager."
                ;;
        esac
    fi

    if (( ${#QT_LIBS_TO_INSTALL[@]} > 0 )); then
        # Deduplicate — the two lists overlap on the GL / dbus /
        # fontconfig packages, and installing a package twice is
        # harmless but noisy.
        declare -A _seen=()
        QT_UNIQUE=()
        for p in "${QT_LIBS_TO_INSTALL[@]}"; do
            [[ -n "${_seen[$p]:-}" ]] && continue
            _seen[$p]=1
            QT_UNIQUE+=("$p")
        done
        unset _seen

        install_syspkgs "${QT_UNIQUE[@]}"

        if (( ${#FAILED_SYSPKGS[@]} > 0 )); then
            warn "some Qt runtime libraries could not be installed;"
            warn "the GUI may fall back to QT_QPA_PLATFORM=offscreen"
            warn "or fail to launch. See the summary at the end."
        else
            ok "Qt runtime libraries installed"
        fi
    fi
fi

# --------------------------------------------------------------------
# Python packages

say "installing Python packages"

PIP_FAILED=()

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

if [[ "$INSTALL_GUI" -eq 1 ]]; then
    if "$PYTHON_BIN" -c "import PySide6" 2>/dev/null; then
        ok "python: PySide6 importable"
    else
        say "python: installing PySide6 (this may take a minute)"
        if "${PIP_CMD[@]}" install --quiet "${PIP_FLAGS[@]}" PySide6; then
            ok "python: PySide6 installed"
        else
            PIP_FAILED+=("PySide6")
            warn "pip install PySide6 failed — the CLI still works;"
            warn "--gui will not launch. Retry with:"
            warn "    ${PIP_CMD[*]} install ${PIP_FLAGS[*]} PySide6"
        fi
    fi
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

if [[ "$INSTALL_GUI" -eq 1 ]]; then
    if "$PYTHON_BIN" -c "import PySide6" 2>/dev/null; then
        ver="$("$PYTHON_BIN" -c 'import PySide6; print(PySide6.__version__)')"
        ok "PySide6 $ver  (--gui available)"
    else
        warn "PySide6 not importable — --gui will not launch"
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
    say "side. Qt runtime library gaps affect --gui only; install"
    say "the missing names with your package manager if the GUI"
    say "fails to launch."
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

printf '\n'
say "client dependency installation complete"
if [[ -n "$VENV_PATH" ]]; then
    say "the packages live in: $VENV_PATH"
    say "activate before launching:"
    say "    source $VENV_PATH/bin/activate"
fi

if [[ "$INSTALL_GUI" -eq 1 && "$UNAME_S" == "Linux" ]]; then
    say "Qt runtime libraries selected: $QT_LIBS"
    if [[ "$QT_LIBS" == "x11" ]]; then
        say "  the GUI will use the xcb platform plugin (X11)"
        say "  on a Wayland session it will fall back through XWayland"
    elif [[ "$QT_LIBS" == "wayland" ]]; then
        say "  the GUI will use the wayland platform plugin"
        say "  on a pure X11 session launch the client with:"
        say "      QT_QPA_PLATFORM=xcb python3 beacon-client.py ..."
    elif [[ "$QT_LIBS" == "both" ]]; then
        say "  both plugin sets installed; the GUI auto-selects"
    elif [[ "$QT_LIBS" == "none" ]]; then
        say "  neither plugin set installed; --gui will not launch"
    fi
fi

say "run the client with:"
say "    python3 beacon-client.py -c <your>.cfg"
if [[ "$INSTALL_GUI" -eq 1 ]]; then
    say "    python3 beacon-client.py -c <your>.cfg --gui"
fi