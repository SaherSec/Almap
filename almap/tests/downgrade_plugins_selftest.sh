#!/usr/bin/env bash
# tests/downgrade_plugins_selftest.sh - tools/downgrade_plugins.py on a
# small temp tree: verdict words in printed text are replaced, the INFO
# prefix is added once, matcher literals are left alone, the generated
# manifest passes the tier lint, and a second run changes nothing.
# Exit: 0 = pass, 1 = fail.
set -u

cd "$(dirname "$0")/.." || exit 1
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
P=$TMPD/plugins
mkdir -p "$P" "$TMPD/fixtures" "$TMPD/lab"

fails=0
check() { # label condition-exit-status
    if [ "$2" -eq 0 ]; then echo "ok   $1"; else echo "FAIL: $1" >&2; fails=$((fails + 1)); fi
}

cat >"$P/ftp-bounce-2.c" <<'EOF'
#include "arsenal_util.h"
int almap_script_run(AlScriptContext *ctx) {
    ar_out(ctx, "VULNERABLE: FTP PORT bounce accepted");
    ar_out(ctx, "not vulnerable: FTP PORT bounce (code %d)", 5);
    ar_out(ctx, "ftp-bounce-2: detected (HTTP %d)", 200);
    ar_out(ctx, "Consul: not detected");
    ar_append(ctx, "; DETECTED");
    return 0;
}
EOF
cat >"$P/http-shellshock.c" <<'EOF'
#include "arsenal_util.h"
int almap_script_run(AlScriptContext *ctx) {
    if (strstr(resp, "VULNERABLE")) { ar_out(ctx, "marker seen"); }
    ar_http_request(ctx, "Referer: () { :; }; echo VULNERABLE\r\n");
    return 0;
}
EOF
cat >"$P/http_title.c" <<'EOF'
#include "arsenal_util.h"
int almap_script_run(AlScriptContext *ctx) {
    snprintf(ctx->output_buf, (size_t)ctx->output_max, "title=\"%s\"", t);
    return 0;
}
EOF
printf '#include "alscript.h"\n' >"$P/arsenal_util.h"

python3 -I tools/downgrade_plugins.py --plugins "$P" >"$TMPD/run1.log" 2>&1
check "downgrade runs" $?

grep -q '"ftp-bounce-2: INFO matches probe for: FTP PORT bounce accepted"' "$P/ftp-bounce-2.c"
check "VULNERABLE becomes 'matches probe for' behind the INFO prefix" $?
grep -q '"ftp-bounce-2: INFO probe did not match: FTP PORT bounce (code %d)"' "$P/ftp-bounce-2.c"
check "'not vulnerable' becomes 'probe did not match'" $?
grep -q '"ftp-bounce-2: INFO probe matched (HTTP %d)"' "$P/ftp-bounce-2.c"
check "an existing '<name>: ' prefix gets INFO inserted once" $?
grep -q '"ftp-bounce-2: INFO Consul: probe did not match"' "$P/ftp-bounce-2.c"
check "other text is kept after the prefix" $?
grep -q '"; probe matched"' "$P/ftp-bounce-2.c"
check "ar_append text loses the verdict word without a prefix" $?
grep -q 'strstr(resp, "VULNERABLE")' "$P/http-shellshock.c" && grep -q 'echo VULNERABLE' "$P/http-shellshock.c"
check "matcher and payload literals are untouched" $?
grep -q '"title=\\"%s\\""' "$P/http_title.c"
check "raw-fact output_buf writers get no prefix" $?
[ "$(grep -c '' "$P/MANIFEST.tsv")" -eq 4 ]
check "manifest has a header and three rows" $?
grep -q '^ftp-bounce-2	services	experimental	experimental	-$' "$P/MANIFEST.tsv"
check "manifest row is experimental with a family" $?

python3 -I tools/lint_plugins.py --plugins "$P" --fixtures "$TMPD/fixtures" --lab "$TMPD/lab" >"$TMPD/lint.log" 2>&1
check "the generated tree passes the lint" $?

cp -r "$P" "$TMPD/after1"
python3 -I tools/downgrade_plugins.py --plugins "$P" >"$TMPD/run2.log" 2>&1
diff -r "$TMPD/after1" "$P" >/dev/null
check "a second run changes nothing (idempotent)" $?

echo "downgrade self-test: $fails failed"
[ "$fails" -eq 0 ]
