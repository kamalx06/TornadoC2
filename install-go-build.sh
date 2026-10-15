#!/usr/bin/env bash

set -euo pipefail

# --------------------------------------------------------------------
# Configuration

MODULE_NAME="tornadoc2/agent"
GO_VERSION="1.24"

GARBLE_VERSION="v0.17.0"

# Entry points that produce a binary. One line per main package.
# The first field is the directory under the agent module root;
# the second is the output filename stem. A .exe suffix is
# appended for windows targets.
MAIN_PKGS=(
    "stageless:beacon"
    "stager:stager"
)

# Directory the compiled binaries land in, relative to the agent
# module root. Created if it does not exist.
OUT_DIR_NAME="beacon_output"

DIRECT_DEPS=(
    "github.com/miekg/dns v1.1.62"
    "github.com/refraction-networking/utls v1.6.7"
    "github.com/tetratelabs/wazero v1.8.2"
    "github.com/quic-go/quic-go v0.48.2"
    "github.com/coder/websocket v1.8.12"
    "github.com/chrj/wgnet v0.1.0"
)

BUILD_TARGETS=(
    "linux/amd64"
    "windows/amd64"
)

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
# Locate the agent directory

if [[ $# -gt 0 ]]; then
    TARGET="$1"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    TARGET="$SCRIPT_DIR/tornadoc2/agent"
fi

[[ -d "$TARGET" ]] || die "target directory not found: $TARGET"
cd "$TARGET"
[[ -f go.mod ]] || die "no go.mod in $TARGET"

say "target: $TARGET"

# --------------------------------------------------------------------
# Verify the Go toolchain

command -v go >/dev/null 2>&1 || \
    die "go not found on PATH — install the Go toolchain first"

GO_VERSION_INSTALLED="$(go env GOVERSION)"          # e.g. go1.24.3
GOPATH_BIN="$(go env GOPATH)/bin"

say "go:         $GO_VERSION_INSTALLED"
say "GOPATH/bin: $GOPATH_BIN"
say "GOMODCACHE: $(go env GOMODCACHE)"

# --------------------------------------------------------------------
# PATH: make sure $GOPATH/bin is available so any tool we install
# below is immediately usable, and any tool already installed is
# visible to `command -v` further down.
case ":$PATH:" in
    *":$GOPATH_BIN:"*) ;;
    *) PATH="$PATH:$GOPATH_BIN"
       export PATH
       say "added $GOPATH_BIN to PATH for this run" ;;
esac

# --------------------------------------------------------------------
# Install garble

say "installing garble $GARBLE_VERSION"

if command -v garble >/dev/null 2>&1; then
    HAVE="$(garble version 2>&1 | head -n1 || true)"
    say "  garble on PATH: $HAVE"
else
    say "  no garble on PATH; installing"
fi

if ! go install "mvdan.cc/garble@${GARBLE_VERSION}" ; then
    warn "go install garble@${GARBLE_VERSION} failed"
    warn ""
    warn "The most common cause is that garble's go.mod requires a"
    warn "newer Go toolchain than the one installed. Check with:"
    warn "    go install mvdan.cc/garble@${GARBLE_VERSION}"
    warn "and read the error. If it says 'requires go >= X.Y.Z',"
    warn "either install Go X.Y.Z or downgrade GARBLE_VERSION."
    warn ""
    warn "garble is optional: only the 'opsec' and 'paranoid'"
    warn "OPSEC profiles use it. Continuing without it."
else
    # Verify the binary actually landed on PATH.
    if command -v garble >/dev/null 2>&1; then
        say "  installed: $(command -v garble)"
        say "  version:   $(garble version 2>&1 | head -n1 || true)"
    else
        warn "go install succeeded but garble is not on PATH"
        warn "add this to your shell profile and restart:"
        warn "    export PATH=\"\$PATH:$GOPATH_BIN\""
    fi
fi

# --------------------------------------------------------------------
# Build the .NET bootstrap DLL
#
# The Go loader //go:embed's Bootstrap.dll, and //go:embed refuses
# to build if the file does not exist. Compile it from Bootstrap.cs
# whenever the source is newer than the DLL, or when the DLL is
# missing entirely.
#
# mcs (Mono C# compiler) is used on Linux. On Windows, csc from the
# .NET Framework directory is used. If neither is available, the
# script warns and skips the Windows target rather than failing the
# whole build.

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
# Back up the current go.mod / go.sum

STAMP="$(date +%Y%m%d_%H%M%S)"

if [[ -f go.mod ]]; then
    cp -p go.mod "go.mod.bak.$STAMP"
    say "backed up go.mod → go.mod.bak.$STAMP"
fi
if [[ -f go.sum ]]; then
    cp -p go.sum "go.sum.bak.$STAMP"
    say "backed up go.sum → go.sum.bak.$STAMP"
fi

# --------------------------------------------------------------------
# Rewrite go.mod

say "rewriting go.mod (module=$MODULE_NAME, go=$GO_VERSION)"

{
    printf 'module %s\n' "$MODULE_NAME"
    printf '\n'
    printf 'go %s\n' "$GO_VERSION"
    printf '\n'
    printf 'require (\n'
    for dep in "${DIRECT_DEPS[@]}"; do
        printf '    %s\n' "$dep"
    done
    printf ')\n'
} > go.mod

# --------------------------------------------------------------------
# Report local packages

for subdir in evasion stager extensions; do
    if [[ -d "$subdir" ]]; then
        count=$(find "$subdir" -type f -name '*.go' | wc -l)
        say "local package: $subdir/ ($count .go file(s))"
    fi
done

# --------------------------------------------------------------------
# Resolve the dependency graph

say "running go mod tidy (this fetches the full dependency graph)"
go mod tidy

# --------------------------------------------------------------------
# Format every .go file

say "normalizing formatting (gofmt -w)"
mapfile -d '' GO_FILES < <(find . -type f -name '*.go' \
    -not -path './vendor/*' -not -path './.git/*' -print0)

if [[ ${#GO_FILES[@]} -eq 0 ]]; then
    warn "no .go files found under $TARGET"
else
    say "  ${#GO_FILES[@]} file(s)"
    gofmt -w "${GO_FILES[@]}"
fi

# --------------------------------------------------------------------
# Static analysis

say "running go vet"
if ! go vet ./... ; then
    warn "go vet reported issues (see above). Build may still succeed."
fi

# --------------------------------------------------------------------
# Build every configured target

OUT_DIR="$(pwd)/$OUT_DIR_NAME"
mkdir -p "$OUT_DIR"

SKIP_WINDOWS="${SKIP_WINDOWS:-0}"

FAILED=0
for target in "${BUILD_TARGETS[@]}"; do
    goos="${target%%/*}"
    goarch="${target##*/}"

    if [[ "$goos" == "windows" && "$SKIP_WINDOWS" == "1" ]]; then
        warn "skipping $goos/$goarch — Bootstrap.dll not built"
        continue
    fi

    say "building $goos/$goarch"

    for entry in "${MAIN_PKGS[@]}"; do
        src="${entry%%:*}"
        stem="${entry##*:}"

        if [[ ! -d "$src" ]]; then
            warn "  $src/ not found — skipping $stem"
            continue
        fi

        out="$OUT_DIR/${stem}_${goos}_${goarch}"
        [[ "$goos" == "windows" ]] && out+=".exe"

        if CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
                go build -trimpath -o "$out" "./$src" ; then
            size=$(stat -c %s "$out" 2>/dev/null || stat -f %z "$out")
            say "  OK  $(basename "$out")  (${size} bytes)"
        else
            warn "  build failed for $src ($goos/$goarch) — see above"
            FAILED=1
        fi
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