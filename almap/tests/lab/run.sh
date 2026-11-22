#!/usr/bin/env bash
# tests/lab/run.sh FAMILY [CHECK...] - run a family's lab cases.
#
# Pulls every image of the family by digest (failure: "LAB: cannot pull
# <image>", exit 1), starts the family's pod(s) with podman kube play,
# waits for the published ports, builds each plugin from its .c, runs it
# with ./almap against the target (live containers, or a fixture replayed
# by mock_server.py), compares the plugin output with the case's
# expectation, prints "PASS|FAIL <check> <role> <port>", tears the pods
# down and exits 1 if anything failed.
#
# Environment: LAB_DIR (default tests/lab), FIXTURES_DIR (default
# tests/fixtures), ALMAP_BIN (default ./almap), PLUGINS_DIR (default plugins).
# Only pods named almaplab-* are ever touched. Everything stays on 127.0.0.1.
set -u

cd "$(dirname "$0")/../.." || exit 1
LAB_DIR=${LAB_DIR:-tests/lab}
FIXTURES_DIR=${FIXTURES_DIR:-tests/fixtures}
ALMAP_BIN=${ALMAP_BIN:-./almap}
export PLUGINS_DIR=${PLUGINS_DIR:-plugins}

if [ $# -lt 1 ]; then
    echo "usage: $0 FAMILY [CHECK...]" >&2
    exit 2
fi
family=$1; shift
wanted=("$@")
dir=$LAB_DIR/$family

LAB_TMP=$(mktemp -d)
POD_UP=""
# shellcheck source=tests/lab/lib.sh
. tests/lab/lib.sh

cleanup() {
    [ -n "$POD_UP" ] && lab_down "$POD_UP"
    rm -rf "$LAB_TMP"
}
trap cleanup EXIT

die() { echo "LAB: $*"; exit 1; }

command -v podman >/dev/null 2>&1 || die "podman not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
[ -x "$ALMAP_BIN" ] || die "$ALMAP_BIN not built"
[ -f "$dir/cases.tsv" ] || die "no $dir/cases.tsv"

# which cases are selected, and do any need live containers?
cases=()
live=0
while IFS= read -r line; do
    check=${line%%$'\t'*}
    if [ ${#wanted[@]} -gt 0 ]; then
        keep=0
        for w in "${wanted[@]}"; do [ "$w" = "$check" ] && keep=1; done
        [ "$keep" -eq 1 ] || continue
    fi
    cases+=("$line")
    expect=$(printf '%s' "$line" | awk -F'\t' '{print $4}')
    case $expect in fixture:*) ;; *) live=1 ;; esac
done < <(lab_rows "$dir/cases.tsv")
[ ${#cases[@]} -gt 0 ] || die "no cases selected in $dir/cases.tsv"

if [ -f "$dir/images.tsv" ]; then
    lab_pull_images "$dir/images.tsv" || exit 1
fi

if [ "$live" -eq 1 ]; then
    [ -f "$dir/pod.yaml" ] || die "no $dir/pod.yaml for the live cases"
    POD_UP=$dir/pod.yaml
    lab_up "$dir/pod.yaml" || die "podman kube play failed: $(tr '\n' ' ' <"$LAB_TMP/up.log" | cut -c1-300)"
    if [ -f "$dir/ports.tsv" ]; then
        while IFS=$'\t' read -r _ _ hostport; do
            lab_wait_port "$hostport" 60 || die "port $hostport did not open in time"
        done < <(lab_rows "$dir/ports.tsv")
    fi
fi

failed=0
total=0
for line in "${cases[@]}"; do
    IFS=$'\t' read -r check role portspec expect <<<"$line"
    total=$((total + 1))
    lab_run_case "$check" "$role" "$portspec" "$expect" || failed=$((failed + 1))
done

echo "lab $family: $((total - failed))/$total passed"
[ "$failed" -eq 0 ]
