#!/usr/bin/env bash
# tests/check_verified_selftest.sh - tools/check_verified.py.
# A check counts as verified (lab / captured fixture / derived fixture) only
# if CI ran every one of its lab cases and every case passed. The tool reads
# the per-family runner output (PASS/FAIL lines) from a results directory.
# Exit: 0 = pass, 1 = fail.
set -u

cd "$(dirname "$0")/.." || exit 1
TOOL=tools/check_verified.py
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

fails=0
check() { if [ "$2" -eq 0 ]; then echo "ok   $1"; else echo "FAIL: $1" >&2; fails=$((fails + 1)); fi; }

T=$'\t'
setup() { # DIR - a manifest, lab cases and a complete set of passing results
    local d=$1
    mkdir -p "$d/plugins" "$d/lab/db" "$d/lab/web" "$d/results"
    {
        echo "name${T}family${T}tier${T}status${T}evidence"
        echo "alpha${T}db${T}vuln${T}lab${T}lab/db"
        echo "beta${T}web${T}detect${T}captured${T}fixtures/beta"
        echo "gamma${T}web${T}detect${T}derived${T}fixtures/gamma"
        echo "delta${T}db${T}experimental${T}experimental${T}-"
    } >"$d/plugins/MANIFEST.tsv"
    {
        echo "alpha${T}vuln${T}3306${T}match:^alpha: VULNERABLE"
        echo "alpha${T}patched${T}3307${T}match:^alpha: NOT VULNERABLE"
    } >"$d/lab/db/cases.tsv"
    {
        echo "beta${T}fixture${T}19090${T}fixture:pos-1:match:DETECTED"
        echo "beta${T}fixture${T}19090${T}fixture:neg-1:match:NOT DETECTED"
        echo "gamma${T}fixture${T}19090${T}fixture:pos-1:match:DETECTED"
    } >"$d/lab/web/cases.tsv"
    {
        echo "PASS alpha vuln 3306"
        echo "PASS alpha patched 3307"
        echo "lab db: 2/2 passed"
    } >"$d/results/db.log"
    {
        echo "PASS beta fixture 19090"
        echo "PASS beta fixture 19090"
        echo "PASS gamma fixture 19090"
        echo "lab web: 3/3 passed"
    } >"$d/results/web.log"
}

run() { python3 -I "$TOOL" --manifest "$1/plugins/MANIFEST.tsv" --lab "$1/lab" "$1/results" 2>&1; }

setup "$TMPD/ok"
run "$TMPD/ok" >"$TMPD/ok.out"; rc=$?
[ "$rc" -eq 0 ]; check "every case ran and passed: exit 0" $?
grep -q 'Verified (lab): 1' "$TMPD/ok.out" && grep -q 'Verified (captured fixture): 1' "$TMPD/ok.out" && grep -q 'Detected (derived fixture): 1' "$TMPD/ok.out"
check "prints the confirmed counts per bucket" $?

setup "$TMPD/missing"; sed -i '/patched/d' "$TMPD/missing/results/db.log"
OUT=$(run "$TMPD/missing"); rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -q 'alpha: expected 2 passing case(s), CI ran 1'
check "a case that did not run: exit 1 and the check is named" $?

setup "$TMPD/failed"; sed -i 's/^PASS alpha vuln/FAIL alpha vuln/' "$TMPD/failed/results/db.log"
OUT=$(run "$TMPD/failed"); rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -q 'alpha: 1 case(s) FAILED'
check "a failing case: exit 1 and the check is named" $?

setup "$TMPD/nofam"; rm "$TMPD/nofam/results/web.log"
OUT=$(run "$TMPD/nofam"); rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -q 'beta: expected 2 passing case(s), CI ran 0' && echo "$OUT" | grep -q 'gamma: expected 1 passing case(s), CI ran 0'
check "a whole family that did not run: every check in it is named" $?

setup "$TMPD/nocases"; sed -i '/^alpha/d' "$TMPD/nocases/lab/db/cases.tsv"
OUT=$(run "$TMPD/nocases"); rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -q 'alpha: no lab case'
check "status lab with no case in cases.tsv: exit 1" $?

setup "$TMPD/exp"; : >"$TMPD/exp/results/db.log"; sed -i '/alpha/d' "$TMPD/exp/lab/db/cases.tsv"; sed -i 's/^alpha\tdb\tvuln\tlab\tlab\/db/alpha\tdb\texperimental\texperimental\t-/' "$TMPD/exp/plugins/MANIFEST.tsv"
OUT=$(run "$TMPD/exp"); rc=$?
[ "$rc" -eq 0 ]
check "experimental checks need no results" $?

OUT=$(python3 -I "$TOOL" --manifest "$TMPD/ok/plugins/MANIFEST.tsv" --lab "$TMPD/ok/lab" "$TMPD/does-not-exist" 2>&1); rc=$?
[ "$rc" -eq 2 ]
check "a missing results directory is an error (exit 2), not a pass" $?

echo "check_verified self-test: $fails failed"
[ "$fails" -eq 0 ]
