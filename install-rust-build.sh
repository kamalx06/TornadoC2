#!/usr/bin/env bash

set -euo pipefail

# --------------------------------------------------------------------
# Configuration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_NAME="beacon"

# Entry points that produce a binary. The first field is the [[bin]]
# name in Cargo.toml; the second is the filename stem in the output
# directory. A .exe suffix is appended for Windows targets.
MAIN_BINS=(
    "beacon:beacon"
    "stager:stager"
)

# Cross-compilation triples. One line per target the agent must
# produce.
BUILD_TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu"
    # Add the others when the engagement needs them:
    # "aarch64-unknown-linux-gnu"
    # "i686-pc-windows-gnu"
    # "aarch64-pc-windows-msvc"
)

# Directory the compiled binaries land in, relative to the crate root.
OUT_DIR_NAME="beacon_output"

# --------------------------------------------------------------------
# Output helpers

if [[ -t 1 ]]; then
    C_INFO=$'\033[36m'
    C_WARN=$'\033[33m'
    C_ERR=$'\033[31m'
    C_RST=$'\033[0m'
else
    C_INFO=""; C_WARN=""; C_ERR=""; C_RST=""
fi

say()  { printf '%s[fix]%s %s\n'  "$C_INFO" "$C_RST" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_WARN" "$C_RST" "$*" >&2; }
die()  { printf '%s[err]%s %s\n'  "$C_ERR"  "$C_RST" "$*" >&2; exit 1; }

# --------------------------------------------------------------------
# Locate the crate directory

if [[ $# -gt 0 ]]; then
    TARGET="$1"
else
    TARGET="$SCRIPT_DIR/tornadoc2/agent"
fi

[[ -d "$TARGET" ]] || die "target directory not found: $TARGET"
cd "$TARGET"
[[ -f Cargo.toml ]] || die "no Cargo.toml in $TARGET"

say "target: $TARGET"

# --------------------------------------------------------------------
# Verify the Rust toolchain

command -v cargo >/dev/null 2>&1 || \
    die "cargo not found on PATH — install rustup: https://rustup.rs"
command -v rustc >/dev/null 2>&1 || \
    die "rustc not found on PATH — install rustup: https://rustup.rs"

say "cargo:      $(cargo --version)"
say "rustc:      $(rustc --version)"
say "rustup home: ${RUSTUP_HOME:-$HOME/.rustup}"
say "cargo home:  ${CARGO_HOME:-$HOME/.cargo}"

# --------------------------------------------------------------------
# Ensure the cross-compilation targets are installed

for triple in "${BUILD_TARGETS[@]}"; do
    if rustup target list --installed 2>/dev/null | grep -qx "$triple"; then
        say "target present: $triple"
    else
        say "adding target: $triple"
        rustup target add "$triple" || \
            die "could not add target $triple — install it manually \
with: rustup target add $triple"
    fi
done

# --------------------------------------------------------------------
# Build the .NET bootstrap DLL
#
# The Rust loader include_bytes!s Bootstrap.dll, and include_bytes!
# refuses to build if the file does not exist. Compile it from
# Bootstrap.cs whenever the source is newer than the DLL, or when
# the DLL is missing entirely.
#
# mcs (Mono C# compiler) is used on Linux. On Windows, csc from
# the .NET Framework directory is used. If neither is available,
# the script warns and skips the Windows target rather than
# failing the whole build.

BOOTSTRAP_CS="native/Bootstrap.cs"
BOOTSTRAP_DLL="native/Bootstrap.dll"

if [[ -f "$BOOTSTRAP_CS" ]]; then
    NEED_BUILD=0
    if [[ ! -f "$BOOTSTRAP_DLL" ]]; then
        NEED_BUILD=1
        say "Bootstrap.dll missing — will build from $BOOTSTRAP_CS"
    elif [[ "$BOOTSTRAP_CS" -nt "$BOOTSTRAP_DLL" ]]; then
        NEED_BUILD=1
        say "Bootstrap.cs is newer than Bootstrap.dll — rebuilding"
    fi

    if [[ $NEED_BUILD -eq 1 ]]; then
        if command -v mcs >/dev/null 2>&1; then
            say "building $BOOTSTRAP_DLL with mcs"
            if mcs -target:library -out:"$BOOTSTRAP_DLL" "$BOOTSTRAP_CS"; then
                say "  OK ($(stat -c %s "$BOOTSTRAP_DLL") bytes)"
            else
                die "mcs failed — fix Bootstrap.cs and rerun"
            fi
        elif command -v csc >/dev/null 2>&1; then
            say "building $BOOTSTRAP_DLL with csc"
            if csc /target:library /out:"$BOOTSTRAP_DLL" "$BOOTSTRAP_CS"; then
                say "  OK"
            else
                die "csc failed — fix Bootstrap.cs and rerun"
            fi
        else
            warn "no C# compiler found (mcs or csc)"
            warn "install mono-mcs on Linux or build Bootstrap.dll"
            warn "on a Windows host and check it in next to Bootstrap.cs"
            warn ""
            warn "the Windows agent build will fail without it"
            warn "the Linux agent build is unaffected"
            SKIP_WINDOWS=1
        fi
    else
        say "Bootstrap.dll is up to date"
    fi
fi

# --------------------------------------------------------------------
# Warm the Cargo cache and run the linters once

say "running cargo fetch (this warms the dependency cache)"
cargo fetch || die "cargo fetch failed — check network access to crates.io"

say "running cargo fmt --check"
cargo fmt --check || {
    warn "cargo fmt reports differences. Run 'cargo fmt' to fix."
    warn "The build is not blocked."
}

say "running cargo clippy"
if ! cargo clippy --all-targets -- -D warnings 2>&1 | tail -n 20; then
    warn "cargo clippy reports issues. Build may still succeed."
fi

# --------------------------------------------------------------------
# Build every configured target

OUT_DIR="$(pwd)/$OUT_DIR_NAME"
mkdir -p "$OUT_DIR"

SKIP_WINDOWS="${SKIP_WINDOWS:-0}"

FAILED=0
for triple in "${BUILD_TARGETS[@]}"; do
    # Determine the platform from the triple. Anything with "windows"
    # in it produces .exe files and honors SKIP_WINDOWS.
    if [[ "$triple" == *windows* && "$SKIP_WINDOWS" == "1" ]]; then
        warn "skipping $triple — Bootstrap.dll not built"
        continue
    fi

    say "building $triple"

    for entry in "${MAIN_BINS[@]}"; do
        bin="${entry%%:*}"
        stem="${entry##*:}"

        if ! cargo build --release --target "$triple" --bin "$bin"; then
            warn "  build failed for $bin ($triple) — see above"
            FAILED=1
            continue
        fi

        # Determine the artifact filename. Cargo writes to
        # target/<triple>/release/<bin>[.exe].
        suffix=""
        [[ "$triple" == *windows* ]] && suffix=".exe"

        src="$(pwd)/target/$triple/release/${bin}${suffix}"
        if [[ ! -f "$src" ]]; then
            warn "  artifact not found at $src — cargo reported success"
            warn "  but the expected file is missing. Check the target"
            warn "  directory structure and the [[bin]] name in Cargo.toml."
            FAILED=1
            continue
        fi

        # Output name: <stem>_<platform>_<arch>[.exe]
        # e.g. beacon_linux_amd64, beacon_windows_amd64.exe
        case "$triple" in
            x86_64-unknown-linux-gnu)   os=linux;   arch=amd64 ;;
            aarch64-unknown-linux-gnu)  os=linux;   arch=arm64 ;;
            x86_64-pc-windows-gnu)      os=windows; arch=amd64 ;;
            i686-pc-windows-gnu)        os=windows; arch=386   ;;
            x86_64-pc-windows-msvc)     os=windows; arch=amd64 ;;
            aarch64-pc-windows-msvc)    os=windows; arch=arm64 ;;
            *)                          os=unknown; arch=unknown ;;
        esac

        out="$OUT_DIR/${stem}_${os}_${arch}${suffix}"
        cp -f "$src" "$out"
        size=$(stat -c %s "$out" 2>/dev/null || stat -f %z "$out")
        say "  OK  $(basename "$out")  (${size} bytes)"
    done
done

# --------------------------------------------------------------------
# Summary

printf '\n'
if [[ $FAILED -eq 0 ]]; then
    say "all builds passed"
else
    warn "one or more builds failed"
fi

say "done"