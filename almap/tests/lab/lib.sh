#!/usr/bin/env bash
# tests/lab/lib.sh - helpers for tests/lab/run.sh (sourced, not run).
#
# Lab rules (see docs/plans/2026-11-22-almap-fix-design.md):
#  * every image is pinned by digest and pulled before the pods start;
#  * pods are named almaplab-<family> and are the only thing the lab ever
#    starts, replaces or removes;
#  * ports are published on 127.0.0.1 only (hostIP in pod.yaml). Host port
#    blocks: control 19000-19099, fixtures 19090-19099; each family gets
#    its own hundred above that.
#
# Files per family (tests/lab/<family>/):
#   images.tsv  role<TAB>image@sha256:...<TAB>origin_url<TAB>represents
#   pod.yaml    podman kube play file (optional for fixture-only families)
#   ports.tsv   role<TAB>containerPort<TAB>hostPort (the ports to wait for)
#   cases.tsv   check<TAB>role<TAB>port<TAB>expect
#     expect: match:ERE | nomatch:ERE | fixture:CASE:match:ERE |
#             fixture:CASE:nomatch:ERE   (ERE is a Python regular expression)
#             oracle:KIND   (the output must equal what an independent client
#                            reports: <family>/oracle/compare.sh PLUGIN HOST PORT KIND)
#     port:   N for TCP, udp:N for a UDP scan
#   A fixture CASE is tests/fixtures/<check>/<CASE>.bin and may have an
#   optional <CASE>.mock file with lines proto=tcp|udp, send_first=1,
#   after_bytes=K for tests/lab/mock_server.py.

# lab_rows FILE - the non-comment, non-empty lines of FILE
lab_rows() {
    grep -vE '^[[:space:]]*(#|$)' "$1"
}

# lab_pull_images IMAGES_TSV - pull every image by digest; print
# "LAB: cannot pull <image>" for each failure and return 1 if any failed.
lab_pull_images() {
    local role image rest rc=0
    while IFS=$'\t' read -r role image rest; do
        if ! podman pull -q "$image" >/dev/null 2>&1; then
            echo "LAB: cannot pull $image"
            rc=1
        fi
    done < <(lab_rows "$1")
    return $rc
}

# lab_up POD_YAML / lab_down POD_YAML - only the pods named in the file
lab_up() {
    podman kube play --replace --quiet "$1" >"$LAB_TMP/up.log" 2>&1
}
lab_down() {
    podman kube down "$1" >/dev/null 2>&1
}

# lab_wait_port PORT [SECONDS] - wait until 127.0.0.1:PORT is really serving.
# A TCP connect is not enough: a rootless port forwarder accepts before the
# container's service listens and then closes the connection. The port counts
# as ready when the connection stays open (a service waiting for a request)
# or delivers data (a banner), not when the peer closes straight away.
lab_wait_port() {
    python3 -I - "$1" "${2:-60}" <<'PY'
import socket, sys, time
port, limit = int(sys.argv[1]), float(sys.argv[2])
end = time.time() + limit
while time.time() < end:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=1)
    except OSError:
        time.sleep(0.3)
        continue
    s.settimeout(0.5)
    try:
        ready = s.recv(1) != b""      # data: a banner; b"": closed at once
    except socket.timeout:
        ready = True                  # held open, waiting for a request
    except OSError:
        ready = False
    s.close()
    if ready:
        sys.exit(0)
    time.sleep(0.3)
sys.exit(1)
PY
}

# lab_build_plugin CHECK - build plugins/CHECK.c into $LAB_TMP/so; print the .so path
lab_build_plugin() {
    local so="$LAB_TMP/so/$1.so"
    if [ ! -f "$so" ]; then
        bash tools/build_plugins.sh --out "$LAB_TMP/so" "$1" >"$LAB_TMP/build-$1.log" 2>&1 || return 1
    fi
    printf '%s' "$so"
}

# lab_eval JSON_FILE MODE REGEX PORT - judge the scan output. Prints the reason
# on failure and returns 1. nomatch never passes without plugin output, so a
# dead or silent target cannot look like a clean result.
lab_eval() {
    python3 -I - "$@" <<'PY'
import json, re, sys
path, mode, rx, port = sys.argv[1:5]
try:
    data = json.load(open(path))
except ValueError as exc:
    print("scan output is not JSON (%s): %s" % (exc, open(path).read()[:120].strip()))
    sys.exit(1)
outs = [r.get("script_out", "") for r in data
        if r.get("port") == int(port) and r.get("state") == "open"]
outs = [o for o in outs if o]
if not outs:
    print("no plugin output (port %s not open, or the plugin printed nothing)" % port)
    sys.exit(1)
hit = any(re.search(rx, o, re.M) for o in outs)
if (mode == "match") != hit:
    print("%s '%s' but output was: %s" % ("expected match for" if mode == "match" else "expected no match for", rx, " | ".join(outs)[:200]))
    sys.exit(1)
sys.exit(0)
PY
}

# lab_run_case CHECK ROLE PORTSPEC EXPECT - run one case; print PASS/FAIL
lab_run_case() {
    local check=$1 role=$2 portspec=$3 expect=$4
    local scan=connect port=$portspec mode rx fcase="" so json reason mock_pid="" opts proto send_first after
    case $portspec in udp:*) scan=udp; port=${portspec#udp:} ;; esac

    if ! so=$(lab_build_plugin "$check"); then
        echo "FAIL $check $role $port: plugin build failed (see $LAB_TMP/build-$check.log)"
        return 1
    fi

    case $expect in
        fixture:*)
            local rest=${expect#fixture:}
            fcase=${rest%%:*}; rest=${rest#*:}
            mode=${rest%%:*}; rx=${rest#*:}
            local bin=$FIXTURES_DIR/$check/$fcase.bin
            if [ ! -f "$bin" ]; then
                echo "FAIL $check $role $port: fixture $bin not found"
                return 1
            fi
            proto=tcp; send_first=""; after=""
            if [ -f "$FIXTURES_DIR/$check/$fcase.mock" ]; then
                while IFS='=' read -r k v; do
                    case $k in
                        proto) proto=$v ;;
                        send_first) [ "$v" = 1 ] && send_first=--send-first ;;
                        after_bytes) after="--after-bytes $v" ;;
                    esac
                done <"$FIXTURES_DIR/$check/$fcase.mock"
            fi
            [ "$proto" = udp ] && scan=udp
            # shellcheck disable=SC2086
            python3 -I tests/lab/mock_server.py --proto "$proto" --port "$port" --fixture "$bin" $send_first $after >"$LAB_TMP/mock-$port.out" 2>&1 &
            mock_pid=$!
            local i
            for i in $(seq 1 50); do
                grep -q '^ready' "$LAB_TMP/mock-$port.out" 2>/dev/null && break
                sleep 0.1
            done
            ;;
        oracle:*)
            # the plugin's output must equal what an independent client reports
            # (tests/lab/<family>/oracle/compare.sh PLUGIN HOST PORT KIND)
            local okind=${expect#oracle:} ocmp
            if ocmp=$(bash "$dir/oracle/compare.sh" "$so" 127.0.0.1 "$port" "$okind" 2>&1); then
                echo "PASS $check $role $port"
                return 0
            fi
            echo "FAIL $check $role $port: oracle $okind disagrees: $(printf '%s' "$ocmp" | tr '\n' ' ' | cut -c1-300)"
            return 1
            ;;
        match:*) mode=match; rx=${expect#match:} ;;
        nomatch:*) mode=nomatch; rx=${expect#nomatch:} ;;
        *) echo "FAIL $check $role $port: bad expect '$expect'"; return 1 ;;
    esac

    json=$LAB_TMP/scan-$check-$port.json
    "$ALMAP_BIN" -t 127.0.0.1 -p "$port" --scan "$scan" --script "$so" --json --timeout 3000 >"$json" 2>"$LAB_TMP/scan-$check-$port.err"
    local rc=1
    if reason=$(lab_eval "$json" "$mode" "$rx" "$port"); then rc=0; fi
    [ -n "$mock_pid" ] && { kill "$mock_pid" 2>/dev/null; wait "$mock_pid" 2>/dev/null; }

    if [ "$rc" -eq 0 ]; then
        echo "PASS $check $role $port"
    else
        echo "FAIL $check $role $port: $reason"
    fi
    return $rc
}
