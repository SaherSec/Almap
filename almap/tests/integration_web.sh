#!/usr/bin/env bash
# tests/integration_web.sh - Web UI test.
# Loopback only: starts the ALmap Web UI, checks GET /api/status
# (health), GET / (HTML contains ALmap Web UI), and POST /api/scan
# (connect scan of a python listener through the JSON API, plus a
# 400 on an invalid request and a 404 on an unknown path).
# Security checks: default bind is 127.0.0.1; every /api/ call needs
# the startup token (401 without / with a wrong one); a foreign Host or
# Origin is refused (403); "script" accepts only a plugin name inside
# plugins/ - absolute paths, "..", unknown names and a symlink that
# escapes plugins/ are refused, and a constructor-bearing .so outside
# plugins/ is never loaded; --web-bind 0.0.0.0 warns, a bad address
# exits 2.
# Use only on networks you own or have permission to scan; this test
# only uses loopback.
set -u

cd "$(dirname "$0")/.." || exit 1

WEB_PORT=18081
SCAN_PORT=18082
HOST=127.0.0.1

if [ ! -x ./almap ]; then
    echo "building ./almap ..." >&2
    goose build almap.goose --cc gcc || exit 1
fi
if [ ! -x ./almap ]; then
    echo "error: ./almap not found after build" >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "error: need curl for the Web UI test" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: need python3 for the listener" >&2
    exit 1
fi

WEB_PID=""
LISTENER_PID=""
WEB2_PID=""
HANG_PID=""
EXTRA_PIDS=()
TMPD=$(mktemp -d)
LINK=plugins/zz-integration-web-escape.so
cleanup() {
    rm -f "$LINK"
    rm -rf "$TMPD"
    for p in "${EXTRA_PIDS[@]:-}"; do
        [ -n "$p" ] && { kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; }
    done
    if [ -n "$HANG_PID" ]; then
        kill "$HANG_PID" 2>/dev/null || true
        wait "$HANG_PID" 2>/dev/null || true
    fi
    if [ -n "$WEB2_PID" ]; then
        kill "$WEB2_PID" 2>/dev/null || true
        wait "$WEB2_PID" 2>/dev/null || true
    fi
    if [ -n "$WEB_PID" ]; then
        kill "$WEB_PID" 2>/dev/null || true
        wait "$WEB_PID" 2>/dev/null || true
        WEB_PID=""
    fi
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

echo "starting python3 listener on $HOST:$SCAN_PORT" >&2
python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(128)
s.settimeout(30)
end = time.time() + 30
while time.time() < end:
    try:
        c, _ = s.accept()
        c.close()
    except socket.timeout:
        break
s.close()
' "$SCAN_PORT" >/dev/null 2>&1 &
LISTENER_PID=$!

# A valid plugin for the name-resolution check.
if [ ! -f plugins/sample_banner.so ]; then
    gcc -std=c99 -Wall -Wextra -shared -fPIC -o plugins/sample_banner.so plugins/sample_banner.c || fail "cannot build plugins/sample_banner.so"
fi
# A .so whose constructor runs on dlopen; it must never be loaded.
MARKER="$TMPD/constructor-ran"
cat >"$TMPD/evil.c" <<EOC
#include <stdio.h>
__attribute__((constructor)) static void ran(void) {
    FILE *f = fopen("$MARKER", "w");
    if (f) { fputs("x", f); fclose(f); }
}
int almap_script_run(void *ctx) { (void)ctx; return 0; }
EOC
gcc -shared -fPIC -o "$TMPD/evil.so" "$TMPD/evil.c" || fail "cannot build test .so"
ln -sf "$TMPD/evil.so" "$LINK"

echo "starting ./almap --web on $HOST:$WEB_PORT" >&2
./almap --web --web-port "$WEB_PORT" >/tmp/integration_web.log 2>&1 &
WEB_PID=$!
sleep 2

grep -q "listening on 127.0.0.1:$WEB_PORT" /tmp/integration_web.log || fail "default bind is not 127.0.0.1: $(cat /tmp/integration_web.log)"
if command -v ss >/dev/null 2>&1; then
    ss -ltn | grep -q "127.0.0.1:$WEB_PORT " || fail "socket not bound to 127.0.0.1"
fi
TOKEN=$(sed -n 's/^API token: \([0-9a-f]\{32\}\).*/\1/p' /tmp/integration_web.log)
[ -n "$TOKEN" ] || fail "no API token printed at startup"
grep -q "#token=$TOKEN" /tmp/integration_web.log || fail "startup URL lacks #token="
AUTH="Authorization: Bearer $TOKEN"
echo "bind 127.0.0.1 + token OK" >&2

JSON="Content-Type: application/json"
code() { curl -s -o /tmp/web_sec.out -w "%{http_code}" "$@" 2>/dev/null; }
SCAN_URL="http://$HOST:$WEB_PORT/api/scan"
scan_body() { echo "{\"targets\":\"$HOST\",\"ports\":\"$SCAN_PORT\",\"scan_type\":\"connect\",\"timeout\":1000${1:-}}"; }

# Token: required on every API route.
[ "$(code "http://$HOST:$WEB_PORT/api/status")" = "401" ] || fail "status without token not 401"
[ "$(code -X POST "$SCAN_URL" -d "$(scan_body)")" = "401" ] || fail "scan without token not 401"
[ "$(code -H "Authorization: Bearer 00000000000000000000000000000000" "http://$HOST:$WEB_PORT/api/status")" = "401" ] || fail "wrong token not 401"
echo "token required -> 401 OK" >&2

# Host / Origin.
[ "$(code -H "$AUTH" -H "Host: evil.example:$WEB_PORT" "http://$HOST:$WEB_PORT/api/status")" = "403" ] || fail "foreign Host not 403"
[ "$(code -H "Host: evil.example:$WEB_PORT" "http://$HOST:$WEB_PORT/")" = "403" ] || fail "foreign Host on / not 403"
[ "$(code -H "$AUTH" -H "Origin: http://evil.example" -X POST "$SCAN_URL" -H "Content-Type: text/plain" -d "$(scan_body)")" = "403" ] || fail "cross-origin scan not 403"
[ "$(code -H "$AUTH" -H "Origin: http://$HOST:$WEB_PORT" "http://$HOST:$WEB_PORT/api/status")" = "200" ] || fail "same-origin request refused"
[ "$(code -H "$AUTH" -H "Host: localhost:$WEB_PORT" "http://$HOST:$WEB_PORT/api/status")" = "200" ] || fail "Host localhost refused"
echo "Host/Origin checks OK" >&2

# Request size and Content-Type.
BIG=$(python3 -c 'print("{\"targets\":\"" + "a"*9000 + "\"}")')
[ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d "$BIG")" = "413" ] || fail "9000-byte body not 413"
grep -q '"error":"request too large"' /tmp/web_sec.out || fail "413 body: $(cat /tmp/web_sec.out)"
[ "$(code -H "$AUTH" -H "$JSON" -H "Content-Length: 99999999999999999999999" -X POST "$SCAN_URL" -d "{}")" = "400" ] || fail "huge Content-Length not 400"
grep -q '"error":"bad request"' /tmp/web_sec.out || fail "400 body: $(cat /tmp/web_sec.out)"
[ "$(code -H "$AUTH" -H "Content-Type: text/plain" -X POST "$SCAN_URL" -d "$(scan_body)")" = "415" ] || fail "text/plain scan not 415"
grep -q '{"error":"Content-Type must be application/json"}' /tmp/web_sec.out || fail "415 body: $(cat /tmp/web_sec.out)"
[ "$(code -H "$AUTH" -X POST "$SCAN_URL" -d "$(scan_body)")" = "415" ] || fail "form-encoded scan not 415"
[ "$(code -H "$AUTH" -H "Content-Type: Application/JSON; charset=utf-8" -X POST "$SCAN_URL" -d '{"ports":"80"}')" = "400" ] || fail "JSON with charset param refused as non-JSON"
echo "request size / Content-Type checks OK" >&2

# Security response headers on every reply: HTML, API 200, 401, 404, 415,
# 413 (C-side early reply) and a scan result (C-framed 200).
hdr_check() { # NAME FILE
    local h
    for h in "X-Content-Type-Options: nosniff" "X-Frame-Options: DENY" \
             "Content-Security-Policy: frame-ancestors 'none'" "Cache-Control: no-store"; do
        grep -qiF "$h" "$2" || fail "$1: missing header '$h': $(head -c 400 "$2")"
    done
}
curl -sD "$TMPD/h_index" -o /dev/null "http://$HOST:$WEB_PORT/"
hdr_check "GET /" "$TMPD/h_index"
curl -sD "$TMPD/h_status" -o /dev/null -H "$AUTH" "http://$HOST:$WEB_PORT/api/status"
hdr_check "GET /api/status" "$TMPD/h_status"
curl -sD "$TMPD/h_401" -o /dev/null "http://$HOST:$WEB_PORT/api/status"
head -1 "$TMPD/h_401" | grep -q 401 || fail "expected 401 for the header check"
hdr_check "401" "$TMPD/h_401"
curl -sD "$TMPD/h_404" -o /dev/null -H "$AUTH" "http://$HOST:$WEB_PORT/nope"
head -1 "$TMPD/h_404" | grep -q 404 || fail "expected 404 for the header check"
hdr_check "404" "$TMPD/h_404"
curl -sD "$TMPD/h_415" -o /dev/null -H "$AUTH" -H "Content-Type: text/plain" -X POST "$SCAN_URL" -d '{}'
head -1 "$TMPD/h_415" | grep -q 415 || fail "expected 415 for the header check"
hdr_check "415" "$TMPD/h_415"
curl -sD "$TMPD/h_413" -o /dev/null -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d "$BIG"
head -1 "$TMPD/h_413" | grep -q 413 || fail "expected 413 for the header check"
hdr_check "413" "$TMPD/h_413"
curl -sD "$TMPD/h_scan" -o /dev/null -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d "$(scan_body)"
head -1 "$TMPD/h_scan" | grep -q 200 || fail "expected 200 for the scan header check: $(cat "$TMPD/h_scan")"
hdr_check "scan 200" "$TMPD/h_scan"
echo "security response headers OK" >&2

# A string value with an escape the parser does not decode is a 400 (it
# used to be ignored, e.g. the scan ran without the plugin).
[ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d '{"targets":"127.0.0.1","ports":"80","script":"a\"b"}')" = "400" ] || fail "script with an escape not 400"
grep -q '{"error":"invalid string escape in field script"}' /tmp/web_sec.out || fail "escape 400 body: $(cat /tmp/web_sec.out)"
[ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d '{"targets":"127.0.0.1\u0000","ports":"80"}')" = "400" ] || fail "targets with \\u0000 not 400"
grep -q '{"error":"invalid string escape in field targets"}' /tmp/web_sec.out || fail "escape 400 body: $(cat /tmp/web_sec.out)"
[ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d '{"targets":"127.0.0.1","ports":"80\n"}')" = "400" ] || fail "ports with \\n not 400"
echo "JSON string escapes -> 400 OK" >&2

# Slow clients must not block the server.
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
status_ms() {
    local t0 t1
    t0=$(now_ms)
    [ "$(code -H "$AUTH" --max-time 8 "http://$HOST:$WEB_PORT/api/status")" = "200" ] || return 1
    t1=$(now_ms)
    echo $((t1 - t0))
}
# holder N SECONDS: open N idle connections, hold them, then exit.
idle_holder() {
    python3 -c '
import socket, sys, time
socks = []
for _ in range(int(sys.argv[1])):
    s = socket.create_connection(("127.0.0.1", int(sys.argv[2])))
    socks.append(s)
print("ready", flush=True)
time.sleep(float(sys.argv[3]))
' "$1" "$WEB_PORT" "$2"
}
coproc IDLE10 { idle_holder 10 6; }
read -r _ <&"${IDLE10[0]}"
ELAPSED=$(status_ms) || fail "/api/status failed behind 10 idle connections"
[ "$ELAPSED" -lt 500 ] || fail "status took ${ELAPSED}ms behind 10 idle connections (want < 500)"
echo "10 idle connections: status in ${ELAPSED}ms OK" >&2
kill "$IDLE10_PID" 2>/dev/null; wait "$IDLE10_PID" 2>/dev/null

# Trickle: one header byte every 300 ms must be closed within 2.5 s.
TRICKLE=$(python3 -c '
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.settimeout(0.05)
t0 = time.time()
data = b"GET /api/status HTTP/1.1\r\nX-Slow: " + b"a" * 200
i = 0
closed = None
while time.time() - t0 < 6:
    try:
        s.send(data[i:i+1]); i += 1
    except OSError:
        closed = time.time() - t0; break
    try:
        if s.recv(64) == b"":
            closed = time.time() - t0; break
    except socket.timeout:
        pass
    except OSError:
        closed = time.time() - t0; break
    time.sleep(0.25)
print("%d" % (closed * 1000) if closed is not None else "never")
' "$WEB_PORT")
[ "$TRICKLE" != "never" ] || fail "trickle client was never closed"
[ "$TRICKLE" -lt 2500 ] || fail "trickle client closed after ${TRICKLE}ms (want < 2500)"
echo "trickle client closed after ${TRICKLE}ms OK" >&2

# Short body: Content-Length 100, 10 bytes sent, then stall -> closed
# by the server without a reply, and the server still answers.
SHORT=$(python3 -c '
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n0123456789")
s.settimeout(4)
t0 = time.time()
try:
    d = s.recv(4096)
except socket.timeout:
    print("never"); sys.exit(0)
except OSError:
    d = b""
print("reply" if d else "%d" % ((time.time() - t0) * 1000))
' "$WEB_PORT")
[ "$SHORT" != "never" ] || fail "short-body client was never closed"
[ "$SHORT" != "reply" ] || fail "short-body client got a reply"
[ "$SHORT" -lt 2600 ] || fail "short-body client closed after ${SHORT}ms (want < 2600)"
[ "$(code -H "$AUTH" "http://$HOST:$WEB_PORT/api/status")" = "200" ] || fail "status after short-body client failed"
echo "short body dropped after ${SHORT}ms OK" >&2

# 40 idle connections (over the pending limit): status still answers.
coproc IDLE40 { idle_holder 40 5; }
read -r _ <&"${IDLE40[0]}"
# While the flood fills every pending slot new connections are refused
# (by design); once the per-request deadline has expired the idle
# connections are dropped and the server answers again.
sleep 3
ELAPSED=$(status_ms) || fail "/api/status failed after 40 idle connections"
echo "40 idle connections: status answered in ${ELAPSED}ms after the deadline OK" >&2
kill "$IDLE40_PID" 2>/dev/null; wait "$IDLE40_PID" 2>/dev/null
[ "$(code -H "$AUTH" "http://$HOST:$WEB_PORT/api/status")" = "200" ] || fail "status after idle flood failed"

# Script: plugin names only.
for bad in "$TMPD/evil.so" "../plugins/sample_banner" "plugins/sample_banner.so" "a..b" ".hidden"; do
    [ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d "$(scan_body ",\"script\":\"$bad\"")")" = "400" ] || fail "script '$bad' not refused"
    grep -q "plugin name" /tmp/web_sec.out || fail "script '$bad' error message: $(cat /tmp/web_sec.out)"
done
[ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d "$(scan_body ",\"script\":\"no_such_plugin\"")")" = "400" ] || fail "unknown plugin not 400"
grep -q "unknown plugin" /tmp/web_sec.out || fail "unknown plugin message: $(cat /tmp/web_sec.out)"
[ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d "$(scan_body ",\"script\":\"zz-integration-web-escape\"")")" = "400" ] || fail "symlink escaping plugins/ not refused"
[ ! -e "$MARKER" ] || fail "a .so outside plugins/ was loaded (constructor ran)"
[ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d "$(scan_body ",\"script\":\"sample_banner\"")")" = "200" ] || fail "valid plugin name refused: $(cat /tmp/web_sec.out)"
echo "script name-only checks OK" >&2

# Health check: the server must respond on the requested port.
STATUS=$(curl -s -o /tmp/web_status.out -w "%{http_code}" -H "$AUTH" "http://$HOST:$WEB_PORT/api/status" 2>/dev/null) || fail "curl /api/status failed"
[ "$STATUS" = "200" ] || fail "expected 200 on /api/status, got $STATUS"
grep -q '"status":"ok"' /tmp/web_status.out || fail "/api/status missing status ok"
grep -q '"version":"5.1.0"' /tmp/web_status.out || fail "/api/status missing version 5.1.0"
echo "GET /api/status OK" >&2

# Index page: HTML shell with the scan form and terminal output.
INDEX=$(curl -s -o /tmp/web_index.out -w "%{http_code}" "http://$HOST:$WEB_PORT/" 2>/dev/null) || fail "curl / failed"
[ "$INDEX" = "200" ] || fail "expected 200 on /, got $INDEX"
grep -q "ALmap Web UI" /tmp/web_index.out || fail "/ missing ALmap Web UI"
grep -q "/api/scan" /tmp/web_index.out || fail "/ missing /api/scan JS"
grep -q "Authorization" /tmp/web_index.out || fail "/ JS does not send the token"
echo "GET / OK" >&2

# Scan: POST JSON connect scan against the listener, expect open.
SCAN_CODE=$(curl -s -o /tmp/web_scan.out -w "%{http_code}" -X POST "http://$HOST:$WEB_PORT/api/scan" -H "$AUTH" -H "Content-Type: application/json" -d "{\"targets\":\"$HOST\",\"ports\":\"$SCAN_PORT\",\"scan_type\":\"connect\",\"timeout\":1000}" 2>/dev/null) || fail "curl /api/scan failed"
[ "$SCAN_CODE" = "200" ] || fail "expected 200 on /api/scan, got $SCAN_CODE: $(cat /tmp/web_scan.out)"
grep -q "\"ip\":\"$HOST\"" /tmp/web_scan.out || fail "/api/scan missing ip"
grep -q '"state":"open"' /tmp/web_scan.out || fail "/api/scan missing open state"
echo "POST /api/scan connect OK" >&2

# Invalid scan: missing targets must be 400 with an error field.
BAD_CODE=$(curl -s -o /tmp/web_bad.out -w "%{http_code}" -X POST "http://$HOST:$WEB_PORT/api/scan" -H "$AUTH" -H "Content-Type: application/json" -d '{"ports":"80"}' 2>/dev/null) || fail "curl bad scan failed"
[ "$BAD_CODE" = "400" ] || fail "expected 400 on invalid scan, got $BAD_CODE"
grep -q '"error"' /tmp/web_bad.out || fail "invalid scan missing error field"
echo "POST /api/scan invalid -> 400 OK" >&2

# Unknown path must be 404.
NOTFOUND=$(curl -s -o /tmp/web_404.out -w "%{http_code}" "http://$HOST:$WEB_PORT/does-not-exist" 2>/dev/null) || fail "curl 404 failed"
[ "$NOTFOUND" = "404" ] || fail "expected 404 on unknown path, got $NOTFOUND"
echo "GET unknown -> 404 OK" >&2

# --web-bind: all interfaces must warn; a bad address must exit 2.
WEB2_PORT=$((WEB_PORT + 10))
./almap --web --web-port "$WEB2_PORT" --web-bind 0.0.0.0 >/tmp/integration_web2.log 2>&1 &
WEB2_PID=$!
sleep 1
grep -q "listening on 0.0.0.0:$WEB2_PORT" /tmp/integration_web2.log || fail "--web-bind 0.0.0.0 not honoured: $(cat /tmp/integration_web2.log)"
grep -q "^warning:" /tmp/integration_web2.log || fail "--web-bind 0.0.0.0 printed no warning"
./almap --web --web-bind 10.0.0.300 >/dev/null 2>&1
[ $? -eq 2 ] || fail "invalid --web-bind did not exit 2"
./almap --web-bind 127.0.0.1 >/dev/null 2>&1
[ $? -eq 2 ] || fail "--web-bind without --web did not exit 2"
echo "--web-bind OK" >&2

# ---------------------------------------------------------------------
# Scan lifecycle: full output, caps, one at a time, kill semantics.
# ---------------------------------------------------------------------
HANG_PORT=18083
CAP_PORT=18101
LIM_PORT=18102
PORTS2000="1-2000"

# start_web PORT [VAR=value ...]: start a server, set LAST_PID/LAST_TOKEN.
start_web() {
    local port=$1 log i
    shift
    log="$TMPD/web$port.log"
    env "$@" ./almap --web --web-port "$port" >"$log" 2>&1 &
    LAST_PID=$!
    EXTRA_PIDS+=("$LAST_PID")
    for i in $(seq 1 50); do
        grep -q '^API token' "$log" 2>/dev/null && break
        sleep 0.1
    done
    LAST_TOKEN=$(sed -n 's/^API token: \([0-9a-f]\{32\}\).*/\1/p' "$log")
    [ -n "$LAST_TOKEN" ] || fail "server on $port did not start: $(cat "$log")"
}
stop_web() { kill "$LAST_PID" 2>/dev/null; wait "$LAST_PID" 2>/dev/null; }
# post PORT TOKEN OUTFILE BODY: print the HTTP status.
post() {
    curl -s -o "$3" -w "%{http_code}" -X POST "http://$HOST:$1/api/scan" \
        -H "Authorization: Bearer $2" -H "Content-Type: application/json" -d "$4" 2>/dev/null
}
json_ok() { python3 -c 'import json,sys; json.load(sys.stdin)' <"$1" 2>/dev/null; }
json_has() { python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if d.get(sys.argv[2]) == json.loads(sys.argv[3]) else 1)' "$1" "$2" "$3" 2>/dev/null; }
kids() { pgrep -P "$1" 2>/dev/null | wc -l; }
body_ports() { echo "{\"targets\":\"$HOST\",\"ports\":\"$1\",\"scan_type\":\"connect\",\"timeout\":1000}"; }
HANG_BODY="{\"targets\":\"$HOST\",\"ports\":\"$HANG_PORT\",\"scan_type\":\"connect\",\"timeout\":5000,\"retries\":0}"

# A listener whose accept queue is already full: connect() to it hangs
# (SYN dropped) until the scan's --timeout. Deterministic, offline.
python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(0)
fill = []
for _ in range(3):
    c = socket.socket()
    c.setblocking(False)
    try:
        c.connect(("127.0.0.1", int(sys.argv[1])))
    except BlockingIOError:
        pass
    fill.append(c)
time.sleep(120)
' "$HANG_PORT" >/dev/null 2>&1 &
HANG_PID=$!
sleep 0.5
python3 -c '
import socket, sys
s = socket.socket(); s.settimeout(1)
try:
    s.connect(("127.0.0.1", int(sys.argv[1]))); sys.exit(1)
except socket.timeout:
    sys.exit(0)' "$HANG_PORT" || fail "blackhole listener on $HANG_PORT does not hang connects"

# 1. 2000 ports: far more than the old 32 KiB cap, still valid JSON.
C=$(post "$WEB_PORT" "$TOKEN" "$TMPD/big.out" "$(body_ports "$PORTS2000")")
[ "$C" = "200" ] || fail "2000-port scan: expected 200, got $C: $(head -c 200 "$TMPD/big.out")"
json_ok "$TMPD/big.out" || fail "2000-port scan body is not valid JSON ($(wc -c <"$TMPD/big.out") bytes)"
[ "$(wc -c <"$TMPD/big.out")" -gt 40000 ] || fail "2000-port scan body unexpectedly small"
echo "2000-port scan: 200, valid JSON, $(wc -c <"$TMPD/big.out") bytes OK" >&2

# 2. Over the output cap: 500 {"truncated":true}, never a partial body.
start_web "$CAP_PORT" ALMAP_WEB_OUT_CAP=4096
C=$(post "$CAP_PORT" "$LAST_TOKEN" "$TMPD/cap.out" "$(body_ports "$PORTS2000")")
[ "$C" = "500" ] || fail "over-cap scan: expected 500, got $C"
json_ok "$TMPD/cap.out" || fail "over-cap body is not valid JSON: $(head -c 200 "$TMPD/cap.out")"
json_has "$TMPD/cap.out" truncated true || fail "over-cap body lacks truncated:true: $(cat "$TMPD/cap.out")"
grep -q 'scan output exceeded 4096 bytes' "$TMPD/cap.out" || fail "over-cap message: $(cat "$TMPD/cap.out")"
[ "$(kids "$LAST_PID")" = "0" ] || fail "child left after over-cap scan"
echo "over-cap scan -> 500 truncated OK" >&2
stop_web

# 3. Exact boundary, calibrated from a real measured output length L:
# cap == L is fine (200), cap == L-1 is over (500 truncated).
BODY20=$(body_ports "1-20")
L=$(./almap -t "$HOST" -p 1-20 --scan connect --timeout 1000 --retries 3 --json 2>&1 | wc -c)
L2=$(./almap -t "$HOST" -p 1-20 --scan connect --timeout 1000 --retries 3 --json 2>&1 | wc -c)
[ "$L" = "$L2" ] && [ "$L" -gt 100 ] && [ "$L" -le 4096 ] || fail "cannot calibrate output length ($L / $L2)"
start_web "$CAP_PORT" "ALMAP_WEB_OUT_CAP=$L"
C=$(post "$CAP_PORT" "$LAST_TOKEN" "$TMPD/at.out" "$BODY20")
[ "$C" = "200" ] || fail "output == cap ($L): expected 200, got $C: $(head -c 200 "$TMPD/at.out")"
json_ok "$TMPD/at.out" || fail "at-cap body is not valid JSON"
[ "$(wc -c <"$TMPD/at.out")" = "$L" ] || fail "at-cap body is $(wc -c <"$TMPD/at.out") bytes, want $L"
stop_web
start_web "$CAP_PORT" "ALMAP_WEB_OUT_CAP=$((L - 1))"
C=$(post "$CAP_PORT" "$LAST_TOKEN" "$TMPD/at.out" "$BODY20")
[ "$C" = "500" ] || fail "output == cap+1: expected 500, got $C"
json_has "$TMPD/at.out" truncated true || fail "cap+1 body lacks truncated:true: $(cat "$TMPD/at.out")"
stop_web
echo "cap boundary ($L bytes: ok at cap, over at cap-1) OK" >&2

# 4. A slow scan does not block the server; a second scan gets 409.
curl -s -o "$TMPD/slow.out" -w "%{http_code}" -X POST "$SCAN_URL" -H "$AUTH" -H "$JSON" -d "$HANG_BODY" >"$TMPD/slow.code" 2>/dev/null &
SLOW_CURL=$!
sleep 1
[ "$(code -H "$AUTH" "http://$HOST:$WEB_PORT/api/status")" = "200" ] || fail "status during scan failed"
grep -q '"scan_running":true' /tmp/web_sec.out || fail "status during scan lacks scan_running:true: $(cat /tmp/web_sec.out)"
ELAPSED=$(status_ms) || fail "status during scan failed"
[ "$ELAPSED" -lt 500 ] || fail "status took ${ELAPSED}ms during a scan (want < 500)"
[ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d "$(scan_body)")" = "409" ] || fail "second scan not 409"
grep -q '{"error":"a scan is already running"}' /tmp/web_sec.out || fail "409 body: $(cat /tmp/web_sec.out)"
# The child gets /dev/null as stdin and none of our sockets.
CHILD=$(pgrep -P "$WEB_PID" | head -1)
[ -n "$CHILD" ] || fail "no scan child found while scanning"
[ "$(readlink "/proc/$CHILD/fd/0")" = "/dev/null" ] || fail "scan child stdin is not /dev/null"
LINO=$(awk -v h="$(printf '%04X' "$WEB_PORT")" '$2 ~ ":"h"$" && $4 == "0A" {print $10}' /proc/net/tcp | head -1)
[ -n "$LINO" ] || fail "cannot find the listener inode"
if ls -l "/proc/$CHILD/fd" 2>/dev/null | grep -q "socket:\[$LINO\]"; then fail "scan child inherited the listening socket"; fi
wait "$SLOW_CURL"
[ "$(cat "$TMPD/slow.code")" = "200" ] || fail "slow scan: expected 200, got $(cat "$TMPD/slow.code")"
json_ok "$TMPD/slow.out" || fail "slow scan body is not valid JSON"
sleep 0.2
[ "$(code -H "$AUTH" "http://$HOST:$WEB_PORT/api/status")" = "200" ] || fail "status after scan failed"
grep -q '"scan_running":false' /tmp/web_sec.out || fail "status after scan lacks scan_running:false: $(cat /tmp/web_sec.out)"
echo "slow scan: status served, second scan 409, child fds clean OK" >&2

# 5. Wall-clock limit: 504 and no child left behind.
start_web "$LIM_PORT" ALMAP_WEB_SCAN_LIMIT_S=1
T0=$(now_ms)
C=$(post "$LIM_PORT" "$LAST_TOKEN" "$TMPD/lim.out" "$HANG_BODY")
T1=$(now_ms)
[ "$C" = "504" ] || fail "wall-clock limit: expected 504, got $C: $(cat "$TMPD/lim.out")"
json_ok "$TMPD/lim.out" || fail "504 body is not valid JSON"
grep -q 'scan exceeded 1 s wall-clock limit' "$TMPD/lim.out" || fail "504 body: $(cat "$TMPD/lim.out")"
[ $((T1 - T0)) -lt 4000 ] || fail "504 after $((T1 - T0)) ms (want ~1000)"
[ "$(kids "$LAST_PID")" = "0" ] || fail "scan child remains after the wall-clock kill"
C=$(post "$LIM_PORT" "$LAST_TOKEN" "$TMPD/lim2.out" "$(body_ports "$SCAN_PORT")")
[ "$C" = "200" ] || fail "scan after a timeout: expected 200, got $C"
echo "wall-clock limit -> 504, child reaped, next scan OK" >&2
stop_web

# 6. Requester disconnects: the child is gone within 1 s, next scan runs.
raw_scan() { # PORT BODY TOKEN HOLD_SECONDS EXTRA_BYTES(0/1)
python3 -c '
import socket, sys, time
b = sys.argv[2].encode()
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1:" + sys.argv[1].encode() + b"\r\nAuthorization: Bearer " + sys.argv[3].encode() +
          b"\r\nContent-Type: application/json\r\nContent-Length: " + str(len(b)).encode() + b"\r\n\r\n" + b)
hold = float(sys.argv[4])
time.sleep(hold)
if sys.argv[5] == "1":
    s.sendall(b"GARBAGE" * 20)
    s.settimeout(15)
    data = b""
    while True:
        d = s.recv(65536)
        if not d: break
        data += d
    print(data.split(b" ", 2)[1].decode())
else:
    s.close()
' "$@"
}
raw_scan "$WEB_PORT" "$HANG_BODY" "$TOKEN" 1 0 &
DISC=$!
sleep 0.6
[ "$(kids "$WEB_PID")" -ge 1 ] || fail "no scan child while the client is connected"
wait "$DISC"
GONE=0
for i in $(seq 1 20); do
    if [ "$(kids "$WEB_PID")" = "0" ]; then GONE=1; break; fi
    sleep 0.05
done
[ "$GONE" = 1 ] || fail "scan child still running 1 s after the client disconnected"
[ "$(code -H "$AUTH" -H "$JSON" -X POST "$SCAN_URL" -d "$(scan_body)")" = "200" ] || fail "scan after a disconnect not accepted: $(cat /tmp/web_sec.out)"
echo "client disconnect kills the child; next scan OK" >&2

# 6b. Extra bytes from the requester are not a hang-up.
raw_scan "$WEB_PORT" "$HANG_BODY" "$TOKEN" 0.5 1 >"$TMPD/extra.code"
[ "$(cat "$TMPD/extra.code")" = "200" ] || fail "extra request bytes aborted the scan (got '$(cat "$TMPD/extra.code")')"
echo "extra request bytes do not kill the scan OK" >&2
[ "$(kids "$WEB_PID")" = "0" ] || fail "child left after the suite"

# 7. Early 413 replies must never stall the event loop (unauthenticated
# clients that send a 413-triggering head and then go silent).
bad_holder() { # PORT COUNT HOLD_SECONDS TOKEN: prints "ready <status ms>"
python3 -c '
import socket, sys, time
port = int(sys.argv[1])
socks = []
for _ in range(int(sys.argv[2])):
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(b"POST /x HTTP/1.1\r\nHost: 127.0.0.1:" + sys.argv[1].encode() + b"\r\nContent-Length: 8192\r\n\r\n")
    socks.append(s)
# A status request queued right behind the bad ones.
t0 = time.time()
c = socket.create_connection(("127.0.0.1", port))
c.settimeout(8)
c.sendall(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:" + sys.argv[1].encode() + b"\r\nAuthorization: Bearer " + sys.argv[4].encode() + b"\r\n\r\n")
d = b""
while b"scan_running" not in d:
    x = c.recv(4096)
    if not x: break
    d += x
print("ready %d" % ((time.time() - t0) * 1000), flush=True)
time.sleep(float(sys.argv[3]))
' "$@"
}
coproc BAD20 { bad_holder "$WEB_PORT" 20 4 "$TOKEN"; }
read -r _ ELAPSED <&"${BAD20[0]}"
[ "${ELAPSED:-9999}" -lt 500 ] || fail "status took ${ELAPSED}ms behind 20 silent 413 clients (want < 500)"
kill "$BAD20_PID" 2>/dev/null; wait "$BAD20_PID" 2>/dev/null
echo "20 silent 413 clients: status in ${ELAPSED}ms OK" >&2

# 7b. ...and they do not delay the wall-clock kill of a running scan.
start_web "$LIM_PORT" ALMAP_WEB_SCAN_LIMIT_S=1
LIMTOK=$LAST_TOKEN
LIMPID=$LAST_PID
( post "$LIM_PORT" "$LIMTOK" "$TMPD/lim3.out" "$HANG_BODY" >"$TMPD/lim3.code"; now_ms >"$TMPD/lim3.end" ) &
LIM3=$!
T0=$(now_ms)
sleep 0.5
coproc BADL { bad_holder "$LIM_PORT" 20 3 "$LIMTOK"; }
read -r _ <&"${BADL[0]}"
wait "$LIM3"
T1=$(cat "$TMPD/lim3.end")
kill "$BADL_PID" 2>/dev/null; wait "$BADL_PID" 2>/dev/null
[ "$(cat "$TMPD/lim3.code")" = "504" ] || fail "scan under 413 load: expected 504, got $(cat "$TMPD/lim3.code")"
[ $((T1 - T0)) -lt 1700 ] || fail "504 came after $((T1 - T0)) ms under 413 load (want ~1000)"
[ "$(kids "$LIMPID")" = "0" ] || fail "child left after 504 under load"
echo "504 under 413 load after $((T1 - T0)) ms OK" >&2
stop_web

# 8. A scan child must not outlive a killed server.
alive() { [ -r "/proc/$1/stat" ] && ! sed 's/^.*) //' "/proc/$1/stat" | grep -q '^Z'; }
start_web "$LIM_PORT"
DPID=$LAST_PID
curl -s -o /dev/null -X POST "http://$HOST:$LIM_PORT/api/scan" -H "Authorization: Bearer $LAST_TOKEN" -H "$JSON" -d "$HANG_BODY" --max-time 8 &
DCURL=$!
sleep 1
DCHILD=$(pgrep -P "$DPID" | head -1)
[ -n "$DCHILD" ] || fail "no scan child to orphan"
kill -9 "$DPID"; wait "$DPID" 2>/dev/null
GONE=0
for i in $(seq 1 20); do
    if ! alive "$DCHILD"; then GONE=1; break; fi
    sleep 0.05
done
kill "$DCURL" 2>/dev/null; wait "$DCURL" 2>/dev/null
[ "$GONE" = 1 ] || { kill -9 "$DCHILD" 2>/dev/null; fail "scan child survived a kill -9 of the server"; }
echo "server killed: scan child gone within 1 s OK" >&2

# 9. A client that floods bytes after a 413-triggering head must not hold
# the event loop (drain is bounded per call and by its deadline).
flooder() { # PORT SECONDS: prints ms until the server's close is seen
python3 -c '
import socket, sys, time
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port))
s.settimeout(3)
s.sendall(b"POST /x HTTP/1.1\r\nHost: 127.0.0.1:" + sys.argv[1].encode() + b"\r\nContent-Length: 8192\r\n\r\n")
blob = b"A" * 65536
# Several senders share the socket so the flood outruns the server.
import os
kids = []
for _ in range(3):
    pid = os.fork()
    if pid == 0:
        end = time.time() + float(sys.argv[2])
        try:
            while time.time() < end:
                s.sendall(blob)
        except OSError:
            pass
        os._exit(0)
    kids.append(pid)
t0 = time.time()
closed = "never"
while time.time() - t0 < float(sys.argv[2]):
    try:
        s.sendall(blob)
    except OSError:
        closed = "%d" % ((time.time() - t0) * 1000)
        break
print(closed)
' "$@"
}
flood_round() { # NFLOODERS
    local n=$1 i pids=() ms
    for i in $(seq 1 "$n"); do
        flooder "$WEB_PORT" 1.5 >"$TMPD/flood$i.out" &
        pids+=($!)
    done
    sleep 0.1
    ms=$(status_ms) || fail "/api/status failed during a ${n}-flooder drain"
    [ "$ms" -lt 500 ] || fail "status took ${ms}ms with $n flooding 413 clients (want < 500)"
    wait "${pids[@]}"
    for i in $(seq 1 "$n"); do
        local c
        c=$(cat "$TMPD/flood$i.out")
        [ "$c" != "never" ] && [ "$c" -lt 1000 ] || fail "flooder $i not closed by the server within 1 s (got '$c')"
    done
    echo "$n flooding 413 client(s): status in ${ms}ms, closed by server OK" >&2
}
flood_round 1
flood_round 4

# A trickle reader must not stall the server: every response send has a
# total wall-clock budget (ALMAP_WEB_SEND_BASE_MS + 1 s per MiB), so a
# client that reads 1 byte every 200 ms is cut off, and other requests
# are served while it is being served.
SLOW_PORT=18103
start_web "$SLOW_PORT" ALMAP_WEB_SEND_BASE_MS=1500 ALMAP_WEB_OUT_CAP=33554432
SLOW_PID=$LAST_PID
SLOW_TOKEN=$LAST_TOKEN
python3 -c '
import socket, sys, time, urllib.request
port, tok = int(sys.argv[1]), sys.argv[2]
body = b"{\"targets\":\"127.0.0.1\",\"ports\":\"1-40000\",\"scan_type\":\"connect\",\"timeout\":1000}"
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
s.connect(("127.0.0.1", port))
s.sendall(b"POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % (port, tok.encode(), len(body)) + body)
# wait (reading nothing) until the scan result is being sent: the server
# only writes once the scan is finished, so wait for the first bytes.
s.settimeout(120)
first = s.recv(1)
if not first:
    print("nodata"); sys.exit(0)
t0 = time.time()
got = 1
status_at = None
closed = "never"
s.settimeout(5)
while time.time() - t0 < 9:
    if status_at is None and time.time() - t0 > 0.5:
        r = urllib.request.Request("http://127.0.0.1:%d/api/status" % port, headers={"Authorization": "Bearer " + tok})
        try:
            urllib.request.urlopen(r, timeout=7).read()
            status_at = int((time.time() - t0) * 1000)
        except Exception:
            status_at = 99999
    try:
        d = s.recv(1)
    except socket.timeout:
        d = b"x"
    except OSError:
        closed = "%d" % ((time.time() - t0) * 1000); break
    if not d:
        closed = "%d" % ((time.time() - t0) * 1000); break
    got += 1
    time.sleep(0.2)
print(closed, status_at, got)
' "$SLOW_PORT" "$SLOW_TOKEN" >"$TMPD/slow_reader.out" 2>&1
read -r SR_CLOSED SR_STATUS SR_GOT <"$TMPD/slow_reader.out"
[ "$SR_STATUS" != "nodata" ] || fail "slow reader: no response: $(cat "$TMPD/slow_reader.out")"
# The server must give up on the trickle reader after its total budget
# (1.5 s + 1 s per MiB of a ~2.5 MiB result, about 4 s) and then answer.
# (The reader itself only sees EOF after it has read the queued bytes,
# so the server-side effect is observed through /api/status.)
[ "$SR_STATUS" -lt 5000 ] || fail "status (asked 0.5 s into the trickle read) answered only at ${SR_STATUS}ms (want < 5000: send budget is about 4 s)"
stop_web
echo "slow reader: server gave up, status answered at ${SR_STATUS}ms OK" >&2
echo "scan lifecycle OK" >&2

echo "ok: web ui / status / scan / errors / bind / token / host+origin / plugin names" >&2
exit 0
