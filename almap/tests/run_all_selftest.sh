#!/usr/bin/env bash
# tests/run_all_selftest.sh - tests/run_all.sh and the skip convention.
#
#  * a test that exits 77 is reported SKIP, 0 PASS, anything else FAIL;
#  * --no-skips turns every SKIP into a failure that names the test;
#  * the raw-socket integration tests exit 77 (not 0) when they cannot get
#    raw sockets, so a green run can never hide them;
#  * inside a user+network namespace (what CI uses without sudo) the same
#    raw-socket test really runs and passes.
# Exit: 0 = pass, 1 = fail, 77 = the namespace part could not run.
set -u

cd "$(dirname "$0")/.." || exit 1
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

fails=0
check() { # label status
    if [ "$2" -eq 0 ]; then echo "ok   $1"; else echo "FAIL: $1" >&2; fails=$((fails + 1)); fi
}

# ---- 1. exit-code handling with fake tests ------------------------------
mkdir -p "$TMPD/t"
printf '#!/usr/bin/env bash\nexit 0\n'  >"$TMPD/t/integration_ok.sh"
printf '#!/usr/bin/env bash\necho "skipping: no raw sockets"\nexit 77\n' >"$TMPD/t/integration_skip.sh"
printf '#!/usr/bin/env bash\necho "boom"\nexit 1\n' >"$TMPD/t/integration_fail.sh"

run() { TESTS_DIR="$TMPD/t" bash tests/run_all.sh "$@" 2>&1; }

OUT=$(run --only integration_ok); rc=$?
[ "$rc" -eq 0 ] && echo "$OUT" | grep -q '^PASS integration_ok.sh'
check "a passing test: PASS, exit 0" $?

OUT=$(run --only integration_skip); rc=$?
[ "$rc" -eq 0 ] && echo "$OUT" | grep -q '^SKIP integration_skip.sh' && echo "$OUT" | grep -q '1 skipped'
check "a skipping test: SKIP is visible, exit 0 without --no-skips" $?

OUT=$(run --no-skips --only integration_skip); rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -q 'SKIP is a failure here: integration_skip.sh'
check "--no-skips: a skip fails the run and names the test" $?

OUT=$(run --only integration_fail); rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -q '^FAIL integration_fail.sh' && echo "$OUT" | grep -q 'boom'
check "a failing test: FAIL with its output, exit 1" $?

OUT=$(run --only 'integration_(ok|skip|fail)'); rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -qE '1 passed, 1 failed, 1 skipped'
check "the summary counts passed, failed and skipped" $?

# ---- 2. the real raw-socket tests exit 77 without raw sockets ------------
if python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP).close()' 2>/dev/null; then
    echo "note: this process has raw sockets; the 'normal user' checks are skipped"
else
    for t in integration_syn integration_os integration_osdb integration_udp integration_workers_syn; do
        bash "tests/$t.sh" >"$TMPD/$t.log" 2>&1
        [ $? -eq 77 ]
        check "$t.sh exits 77 (not 0) without raw sockets" $?
    done
    OUT=$(bash tests/run_all.sh --no-skips --only integration_syn 2>&1); rc=$?
    [ "$rc" -eq 1 ] && echo "$OUT" | grep -q 'SKIP is a failure here: integration_syn.sh'
    check "run_all --no-skips as a normal user fails and names integration_syn.sh" $?
fi

# ---- 3. in a user+net namespace the raw-socket test really runs -----------
if unshare -Urn true 2>/dev/null && command -v ip >/dev/null 2>&1; then
    OUT=$(unshare -Urn bash -c 'ip link set lo up; bash tests/run_all.sh --no-skips --only integration_syn' 2>&1); rc=$?
    [ "$rc" -eq 0 ] && echo "$OUT" | grep -q '^PASS integration_syn.sh'
    check "in a namespace: integration_syn.sh PASSes with --no-skips" $?
else
    echo "note: unshare -Urn or ip unavailable; the namespace check is skipped"
fi

echo "run_all self-test: $fails failed"
[ "$fails" -eq 0 ]
