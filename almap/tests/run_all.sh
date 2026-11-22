#!/usr/bin/env bash
# tests/run_all.sh [--no-skips] [--only REGEX] - run every test and report.
#
# Runs, in this order: the repository hygiene check, the plugin build with
# -Werror, the C core warning check, the C unit tests, the Goose unit tests,
# the plugin lint and its self-tests, the generated-docs check and every
# tests/integration_*.sh. (The podman lab has its own job: tests/lab/run.sh.)
#
# Exit status of a test: 0 = PASS, 77 = SKIP, anything else = FAIL.
# A skip is visible ("SKIP <name>" and the summary) and does not fail a local
# run. With --no-skips (what CI uses) every SKIP is a failure that names the
# test, so a test that could not run can never hide in a green result.
#
#   --no-skips   treat SKIP as failure
#   --only RE    run only the tests whose name matches the extended regex RE
#
# Environment: TESTS_DIR (default tests) is where integration_*.sh live;
# GOOSE_HOME may point at a Goose release directory (goose + stdlib).
set -u

cd "$(dirname "$0")/.." || exit 1
TESTS_DIR=${TESTS_DIR:-tests}
NO_SKIPS=0
ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-skips) NO_SKIPS=1; shift ;;
        --only) ONLY=${2:-}; shift 2 ;;
        -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "usage: $0 [--no-skips] [--only REGEX]" >&2; exit 2 ;;
    esac
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/logs" "$WORK/obj" "$WORK/plugins"

# Goose: use PATH, else GOOSE_HOME, else the usual download location.
setup_goose() {
    command -v goose >/dev/null 2>&1 && [ -n "${GOOSE_STDLIB:-}" ] && return 0
    if ! command -v goose >/dev/null 2>&1; then
        for d in "${GOOSE_HOME:-}" "$HOME/Downloads/goose-v2026.3-linux-x64"; do
            if [ -n "$d" ] && [ -x "$d/goose" ]; then
                PATH="$d:$PATH"
                break
            fi
        done
    fi
    command -v goose >/dev/null 2>&1 || { echo "goose not found (put it on PATH or set GOOSE_HOME)"; return 1; }
    if [ -z "${GOOSE_STDLIB:-}" ]; then
        GOOSE_STDLIB="$(dirname "$(command -v goose)")/stdlib"
    fi
    export GOOSE_STDLIB PATH
}

names=()
cmds=()
add() { names+=("$1"); cmds+=("$2"); }

add hygiene          "bash tests/check_repo_hygiene.sh"
add plugins-build    "bash tools/build_plugins.sh --werror --clean --out '$WORK/plugins'"
add c-core-warnings  "for f in c/*.c; do gcc -std=c99 -Wall -Wextra -Werror -pthread -c \$f -o '$WORK/obj/'\$(basename \$f .c).o || exit 1; done"
add unit-c-http      "gcc -std=c99 -Wall -Wextra -Werror -I c tests/test_http.c c/http.c -o '$WORK/test_http' && '$WORK/test_http'"
add unit-c-drain     "gcc -std=c99 -Wall -Wextra -Werror -I c tests/test_drain.c -o '$WORK/test_drain' && '$WORK/test_drain'"
add unit-goose       "setup_goose && goose build tests/test_almap.goose --cc gcc -o '$WORK/test_almap' && '$WORK/test_almap'"
add lint-selftest    "bash tests/lint_plugins_selftest.sh"
add lint-plugins     "bash tests/lint_plugins.sh"
add downgrade-selftest "bash tests/downgrade_plugins_selftest.sh"
add plugins-md       "bash tests/check_plugins_md.sh"
add run-all-selftest "bash tests/run_all_selftest.sh"
add check-verified-selftest "bash tests/check_verified_selftest.sh"
add build-almap      "setup_goose && goose build almap.goose --cc gcc -o almap"
for t in "$TESTS_DIR"/integration_*.sh; do
    [ -f "$t" ] || continue
    add "$(basename "$t")" "setup_goose >/dev/null 2>&1; bash '$t'"
done

export -f setup_goose 2>/dev/null || true

pass=0; fail=0; skip=0
skipped=()
for i in "${!names[@]}"; do
    name=${names[$i]}
    if [ -n "$ONLY" ] && ! printf '%s' "$name" | grep -Eq "$ONLY"; then
        continue
    fi
    log=$WORK/logs/$name.log
    start=$(date +%s)
    # shellcheck disable=SC2016
    timeout 900 bash -c "$(declare -f setup_goose); ${cmds[$i]}" >"$log" 2>&1
    rc=$?
    secs=$(( $(date +%s) - start ))
    case $rc in
        0)  echo "PASS $name (${secs}s)"; pass=$((pass + 1)) ;;
        77) echo "SKIP $name (${secs}s)"; skip=$((skip + 1)); skipped+=("$name") ;;
        *)  echo "FAIL $name (exit $rc, ${secs}s)"; fail=$((fail + 1))
            tail -n 40 "$log" | sed 's/^/     | /' ;;
    esac
done

echo "$pass passed, $fail failed, $skip skipped"
if [ "$skip" -gt 0 ] && [ "$NO_SKIPS" -eq 1 ]; then
    for n in "${skipped[@]}"; do
        echo "SKIP is a failure here: $n"
    done
    fail=$((fail + skip))
fi
[ "$fail" -eq 0 ]
