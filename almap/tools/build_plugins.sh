#!/usr/bin/env bash
# tools/build_plugins.sh - build the AlScript C plugins.
#
# Compiles plugins/<name>.c into <out>/<name>.so with
#   gcc -std=c99 -Wall -Wextra -shared -fPIC
# and keeps going after a failure: every failing plugin is listed
# ("FAILED: <name>") and the exit status is 1 if any failed.
#
# Usage:
#   bash tools/build_plugins.sh [--out DIR] [--werror] [--clean] [NAME...]
#     --out DIR   write the .so files to DIR (default: the plugins dir)
#     --werror    add -Werror
#     --clean     first delete every <out>/*.so that has no matching .c
#     NAME...     build only these plugins (default: all *.c)
# Environment:
#   PLUGINS_DIR   directory holding the .c files (default: plugins)
#                 (a relative --out or PLUGINS_DIR is relative to the caller's directory)
#   JOBS          parallel compiles (default: number of CPUs)
#
# A plugin that includes <openssl/...> is linked with -lssl -lcrypto.
#
# Authorized use only. See README.md.

set -uo pipefail

CALLER_PWD="$PWD"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

# Relative --out / PLUGINS_DIR are relative to the caller's directory;
# the default source dir "plugins" is relative to the repository root.
abspath() {
    case "$1" in
        /*) printf '%s' "$1" ;;
        *) printf '%s/%s' "$CALLER_PWD" "$1" ;;
    esac
}
SRC_DIR="plugins"
[ -n "${PLUGINS_DIR:-}" ] && SRC_DIR="$(abspath "$PLUGINS_DIR")"
OUT_DIR=""
WERROR=0
CLEAN=0
ONE=""
names=()

while [ $# -gt 0 ]; do
    case "$1" in
        --out)
            [ $# -ge 2 ] || { echo "[build_plugins] error: --out needs a directory" >&2; exit 2; }
            OUT_DIR="$(abspath "$2")"; shift 2 ;;
        --werror) WERROR=1; shift ;;
        --clean) CLEAN=1; shift ;;
        --one)
            # internal: build one plugin for the parallel driver. Only here
            # are the BP_* hand-off variables read, so a stray BP_* in the
            # caller's environment cannot change a normal run.
            ONE="$2"; OUT_DIR="${BP_OUT:-}"; WERROR="${BP_WERROR:-0}"; shift 2 ;;
        -h|--help)
            sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        -*)
            echo "[build_plugins] error: unknown option $1" >&2; exit 2 ;;
        *) names+=("$1"); shift ;;
    esac
done
OUT_DIR="${OUT_DIR:-$SRC_DIR}"

build_one() {
    local base="$1"
    local src="$SRC_DIR/$base.c"
    local out="$OUT_DIR/$base.so"
    local flags=(-std=c99 -Wall -Wextra -shared -fPIC)
    local libs=()

    if [ ! -f "$src" ]; then
        echo "[build_plugins] FAILED: $base (no $src)" >&2
        [ -n "${BP_FAILED:-}" ] && echo "$base" >>"$BP_FAILED"
        return 1
    fi
    [ "$WERROR" -eq 1 ] && flags+=(-Werror)
    if grep -q '#include <openssl/' "$src"; then
        libs=(-lssl -lcrypto)
    fi
    if gcc "${flags[@]}" -o "$out" "$src" "${libs[@]}"; then
        return 0
    fi
    rm -f "$out"
    echo "[build_plugins] FAILED: $base" >&2
    [ -n "${BP_FAILED:-}" ] && echo "$base" >>"$BP_FAILED"
    return 1
}

if [ -n "$ONE" ]; then
    build_one "$ONE"
    exit $?
fi

if ! command -v gcc >/dev/null 2>&1; then
    echo "[build_plugins] error: gcc not found in PATH" >&2
    exit 1
fi

mkdir -p "$OUT_DIR" || exit 1

if [ "$CLEAN" -eq 1 ]; then
    shopt -s nullglob
    for so in "$OUT_DIR"/*.so; do
        base="$(basename "$so" .so)"
        if [ ! -f "$SRC_DIR/$base.c" ]; then
            echo "[build_plugins] removing stale $so (no $SRC_DIR/$base.c)" >&2
            rm -f "$so"
        fi
    done
    shopt -u nullglob
fi

if [ ${#names[@]} -eq 0 ]; then
    shopt -s nullglob
    for src in "$SRC_DIR"/*.c; do
        names+=("$(basename "$src" .c)")
    done
    shopt -u nullglob
    if [ ${#names[@]} -eq 0 ]; then
        echo "[build_plugins] error: no $SRC_DIR/*.c found" >&2
        exit 1
    fi
fi

total=${#names[@]}
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

export PLUGINS_DIR="$SRC_DIR" BP_OUT="$OUT_DIR" BP_WERROR="$WERROR"
BP_FAILED="$(mktemp)"
export BP_FAILED
trap 'rm -f "$BP_FAILED"' EXIT

printf '%s\0' "${names[@]}" | xargs -0 -n1 -P "$JOBS" bash "$0" --one
xrc=$?

failed=$(wc -l <"$BP_FAILED")
if [ "$xrc" -ne 0 ] && [ "$failed" -eq 0 ]; then
    # A worker died (signal, OOM, could not start) without reporting a plugin.
    echo "[build_plugins] error: a build worker died without reporting (xargs exit $xrc); some plugins were not built" >&2
    exit 1
fi
ok=$((total - failed))
echo "[build_plugins] done: $ok built, $failed failed" >&2
[ "$failed" -eq 0 ]
