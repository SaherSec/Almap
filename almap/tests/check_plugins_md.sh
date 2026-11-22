#!/usr/bin/env bash
# tests/check_plugins_md.sh - docs/PLUGINS.md generator.
# (1) On a small temp manifest the generator prints the four separate
#     counts and the total, a per-family table and a per-check table,
#     and --check notices a stale file.
# (2) The word "verified" never appears without its qualifier, so the
#     four counts can never be read as one number.
# (3) docs/PLUGINS.md in the repository is up to date.
# Exit: 0 = pass, 1 = fail.
set -u

cd "$(dirname "$0")/.." || exit 1
GEN=tools/gen_plugins_md.py
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

fails=0
check() { # label status
    if [ "$2" -eq 0 ]; then echo "ok   $1"; else echo "FAIL: $1" >&2; fails=$((fails + 1)); fi
}

printf 'name\tfamily\ttier\tstatus\tevidence\n' >"$TMPD/m.tsv"
{
    printf 'alpha\tdb\tvuln\tlab\tlab/db\n'
    printf 'beta\tdb\tinfo\tlab\tlab/db\n'
    printf 'gamma\thttp\tdetect\tcaptured\tfixtures/gamma\n'
    printf 'delta\tiot\tdetect\tderived\tfixtures/delta\n'
    printf 'epsilon\tiot\texperimental\texperimental\t-\n'
    printf 'zeta\tiot\texperimental\texperimental\t-\n'
} >>"$TMPD/m.tsv"

python3 -I "$GEN" --manifest "$TMPD/m.tsv" --out "$TMPD/out.md" >/dev/null 2>&1
check "generator runs on a temp manifest" $?

grep -qx 'Verified (lab): 2' "$TMPD/out.md";                 check "count: Verified (lab): 2" $?
grep -qx 'Verified (captured fixture): 1' "$TMPD/out.md";    check "count: Verified (captured fixture): 1" $?
grep -qx 'Detected (derived fixture): 1' "$TMPD/out.md";     check "count: Detected (derived fixture): 1" $?
grep -qx 'Experimental: 2' "$TMPD/out.md";                   check "count: Experimental: 2" $?
grep -qx 'Total checks: 6' "$TMPD/out.md";                   check "count: Total checks: 6" $?
grep -qE '^\| db \| 2 \| 0 \| 0 \| 0 \| 2 \|$' "$TMPD/out.md";   check "family table row for db" $?
grep -qE '^\| iot \| 0 \| 0 \| 1 \| 2 \| 3 \|$' "$TMPD/out.md";  check "family table row for iot" $?
grep -qE '^\| gamma \| http \| detect \| captured \| fixtures/gamma \|$' "$TMPD/out.md"; check "per-check table row" $?

python3 -I "$GEN" --manifest "$TMPD/m.tsv" --out "$TMPD/out.md" --check >/dev/null 2>&1
check "--check passes on a fresh file" $?
echo "stale" >>"$TMPD/out.md"
python3 -I "$GEN" --manifest "$TMPD/m.tsv" --out "$TMPD/out.md" --check >/dev/null 2>&1
[ $? -eq 1 ]; check "--check fails on a stale file" $?
python3 -I "$GEN" --manifest "$TMPD/m.tsv" --out "$TMPD/missing.md" --check >/dev/null 2>&1
[ $? -eq 1 ]; check "--check fails on a missing file" $?

printf 'name\tfamily\ttier\tstatus\tevidence\nbad\tdb\tinfo\tweird\t-\n' >"$TMPD/bad.tsv"
python3 -I "$GEN" --manifest "$TMPD/bad.tsv" --out "$TMPD/bad.md" >/dev/null 2>&1
[ $? -eq 2 ]; check "an unknown status is an error (exit 2)" $?

# no bare "verified", in the temp output and in the real file
bare() { grep -i 'verified' "$1" | grep -viE 'verified \((lab|captured fixture)\)' ; }
[ -z "$(bare "$TMPD/out.md")" ];            check "temp output: no unqualified 'verified'" $?
python3 -I "$GEN" --check >/dev/null 2>&1;  check "docs/PLUGINS.md is up to date" $?
[ -z "$(bare ../docs/PLUGINS.md)" ];        check "docs/PLUGINS.md: no unqualified 'verified'" $?

echo "plugins.md check: $fails failed"
[ "$fails" -eq 0 ]
