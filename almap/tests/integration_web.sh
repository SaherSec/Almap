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
TMPD=$(mktemp -d)
LINK=plugins/zz-integration-web-escape.so
cleanup() {
    rm -f "$LINK"
    rm -rf "$TMPD"
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
grep -q '"version":"5.0.0"' /tmp/web_status.out || fail "/api/status missing version 5.0.0"
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

echo "ok: web ui / status / scan / errors / bind / token / host+origin / plugin names" >&2
exit 0
