#!/usr/bin/env bash
# tests/lab/selftest.sh - the lab runner and the fixture replay server.
#
#  * mock_server.py replays a fixture over TCP (request first, banner
#    first) and UDP, byte for byte;
#  * run.sh control starts the pinned control targets in podman, checks
#    plugin output against cases.tsv (live containers and a captured
#    fixture), and tears everything down;
#  * a wrong digest fails loudly with "LAB: cannot pull";
#  * a wrong expectation fails, and a nomatch case cannot pass on a dead
#    port;
#  * only almaplab-* pods are ever touched (other containers survive).
#
# Needs rootless podman and network access to the image registry.
# Exit: 0 = pass, 1 = fail.
set -u

cd "$(dirname "$0")/../.." || exit 1
LAB=tests/lab
TMPD=$(mktemp -d)
MOCK_PID=""
cleanup() {
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
    rm -rf "$TMPD"
}
trap cleanup EXIT

fails=0
check() { # label status
    if [ "$2" -eq 0 ]; then echo "ok   $1"; else echo "FAIL: $1" >&2; fails=$((fails + 1)); fi
}

# ---- 1. mock_server.py -------------------------------------------------
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi' >"$TMPD/http.bin"
printf 'SSH-2.0-LabBanner_1.0\r\n' >"$TMPD/banner.bin"
printf '\x00\x01\x02udp-reply' >"$TMPD/udp.bin"

start_mock() { # args...  (waits for the 'ready' line)
    python3 -I "$LAB/mock_server.py" "$@" >"$TMPD/mock.out" 2>&1 &
    MOCK_PID=$!
    for _ in $(seq 1 50); do
        grep -q '^ready' "$TMPD/mock.out" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}
stop_mock() { [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; MOCK_PID=""; }

start_mock --proto tcp --port 19091 --fixture "$TMPD/http.bin"
check "mock tcp: starts and prints ready" $?
python3 -I - <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", 19091), timeout=3)
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
data = b""
while True:
    c = s.recv(4096)
    if not c:
        break
    data += c
sys.exit(0 if data == b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi" else 1)
PY
check "mock tcp: replays the fixture after the request head" $?
stop_mock

start_mock --proto tcp --port 19092 --fixture "$TMPD/banner.bin" --send-first
python3 -I - <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", 19092), timeout=3)
data = s.recv(100)            # no request sent: the server speaks first
sys.exit(0 if data == b"SSH-2.0-LabBanner_1.0\r\n" else 1)
PY
check "mock tcp --send-first: banner arrives without a request" $?
stop_mock

start_mock --proto udp --port 19093 --fixture "$TMPD/udp.bin"
python3 -I - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b"ping", ("127.0.0.1", 19093))
data, _ = s.recvfrom(4096)
sys.exit(0 if data == b"\x00\x01\x02udp-reply" else 1)
PY
check "mock udp: replays the fixture for a datagram" $?
stop_mock

# ---- 2. the control family --------------------------------------------
others_before=$(podman ps -a --format '{{.Names}}' | grep -v '^almaplab-' | sort)

OUT=$(bash "$LAB/run.sh" control 2>&1)
rc=$?
echo "$OUT" | sed 's/^/     | /' | tail -12
check "run.sh control exits 0" $rc
echo "$OUT" | grep -q '^PASS http_title control'
check "live nginx: http_title reports the page" $?
echo "$OUT" | grep -q '^PASS ssh_version control'
check "live OpenSSH: ssh_version reports the banner" $?
echo "$OUT" | grep -q '^PASS http_title fixture'
check "captured fixture replayed through the mock server" $?
[ -z "$(podman ps -a --format '{{.Names}}' | grep '^almaplab-')" ]
check "no almaplab-* containers left after the run" $?

# ---- 3. failure modes ---------------------------------------------------
BAD=$TMPD/baddigest
mkdir -p "$BAD"
cp -r "$LAB/control" "$BAD/control"
sed -i -E 's#(docker.io/library/nginx@sha256:)[0-9a-f]{64}#\10000000000000000000000000000000000000000000000000000000000000000#' "$BAD/control/images.tsv"
OUT=$(LAB_DIR="$BAD" bash "$LAB/run.sh" control 2>&1)
rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -q '^LAB: cannot pull docker.io/library/nginx@sha256:0000'
check "an unpullable digest fails with 'LAB: cannot pull <image>'" $?

BADX=$TMPD/badexpect
mkdir -p "$BADX"
cp -r "$LAB/control" "$BADX/control"
sed -i 's/match:Welcome to nginx/match:THIS TEXT IS NOT PRESENT/' "$BADX/control/cases.tsv"
OUT=$(LAB_DIR="$BADX" bash "$LAB/run.sh" control http_title 2>&1)
rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -q '^FAIL http_title control'
check "a wrong expectation fails the run" $?

DEAD=$TMPD/deadport
mkdir -p "$DEAD/control"
cp "$LAB/control/images.tsv" "$LAB/control/pod.yaml" "$LAB/control/ports.tsv" "$DEAD/control/"
printf 'http_title\tcontrol\t19001\tnomatch:VULNERABLE\nhttp_title\tcontrol\t19987\tnomatch:VULNERABLE\n' >"$DEAD/control/cases.tsv"
OUT=$(LAB_DIR="$DEAD" bash "$LAB/run.sh" control 2>&1)
rc=$?
[ "$rc" -eq 1 ] && echo "$OUT" | grep -q '^PASS http_title control' && echo "$OUT" | grep -q '^FAIL http_title control .*19987'
check "nomatch passes on a live port and cannot pass on a dead one" $?

# ---- 4. other containers are untouched ----------------------------------
others_after=$(podman ps -a --format '{{.Names}}' | grep -v '^almaplab-' | sort)
[ "$others_before" = "$others_after" ]
check "containers that are not almaplab-* were not touched" $?

echo "lab self-test: $fails failed"
[ "$fails" -eq 0 ]
