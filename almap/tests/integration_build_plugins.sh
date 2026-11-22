#!/usr/bin/env bash
# tests/integration_build_plugins.sh - tools/build_plugins.sh behaviour.
# (a) a full build succeeds and builds every plugins/*.c,
# (b) one broken plugin is reported but does not stop the others,
# (c) --clean removes .so files that have no .c,
# (d) the whole tree builds warning-free (-Werror),
# (e) naming a plugin builds only that one,
# (f) a worker dying without a report still fails the build,
# (g) an unknown plugin name is a failure,
# (h) BP_* in the caller's environment are ignored,
# (i) a relative --out is relative to the caller's directory.
# No network, no root, no listeners.
# Exit: 0 = pass, 1 = fail.
set -u

cd "$(dirname "$0")/.." || exit 1

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# (a) full build into a scratch directory
want=$(ls plugins/*.c | wc -l)
bash tools/build_plugins.sh --out "$TMPD/out" >"$TMPD/a.log" 2>&1
rc=$?
[ "$rc" -eq 0 ] || { tail -5 "$TMPD/a.log" >&2; fail "(a) full build exited $rc, want 0"; }
got=$(ls "$TMPD"/out/*.so 2>/dev/null | wc -l)
[ "$got" -eq "$want" ] || fail "(a) built $got .so files, want $want"
echo "ok (a): full build, $got plugins"

# (b) one broken plugin must not stop the rest
mkdir -p "$TMPD/root/plugins" "$TMPD/root/c"
cp plugins/*.h "$TMPD/root/plugins/"
cp c/*.h "$TMPD/root/c/"
for p in http_title ssh_version redis_info mongodb_info; do
    cp "plugins/$p.c" "$TMPD/root/plugins/"
done
printf 'this is not C;\n' >"$TMPD/root/plugins/zz_broken.c"
PLUGINS_DIR="$TMPD/root/plugins" bash tools/build_plugins.sh --out "$TMPD/b" >"$TMPD/b.log" 2>&1
rc=$?
[ "$rc" -eq 1 ] || fail "(b) broken plugin: exit $rc, want 1"
grep -q 'FAILED: zz_broken' "$TMPD/b.log" || fail "(b) output does not name 'FAILED: zz_broken'"
for p in http_title ssh_version redis_info mongodb_info; do
    [ -f "$TMPD/b/$p.so" ] || fail "(b) $p.so was not built after the failure"
done
[ ! -f "$TMPD/b/zz_broken.so" ] || fail "(b) zz_broken.so exists"
grep -q 'done: 4 built, 1 failed' "$TMPD/b.log" || fail "(b) summary line is not 'done: 4 built, 1 failed'"
echo "ok (b): failure reported, others built"

# (c) --clean removes .so files with no matching .c
mkdir -p "$TMPD/c"
: >"$TMPD/c/stale.so"
bash tools/build_plugins.sh --clean --out "$TMPD/c" http_title >"$TMPD/c.log" 2>&1 \
    || fail "(c) --clean build failed"
[ ! -e "$TMPD/c/stale.so" ] || fail "(c) stale.so was not removed"
[ -f "$TMPD/c/http_title.so" ] || fail "(c) http_title.so missing"
echo "ok (c): --clean removed stale.so"

# (d) the whole tree builds warning-free under -Werror
bash tools/build_plugins.sh --werror --out "$TMPD/w" >"$TMPD/d.log" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
    grep -c 'warning:\|error:' "$TMPD/d.log" >&2
    grep 'FAILED' "$TMPD/d.log" | head -5 >&2
    fail "(d) --werror build exited $rc, want 0"
fi
echo "ok (d): warning-free under -Werror"

# (e) a named plugin builds only that plugin
n=$(ls "$TMPD"/c/*.so | wc -l)
[ "$n" -eq 1 ] || fail "(e) named build produced $n .so files, want 1"
echo "ok (e): named build"

# (f) a worker that dies without reporting must still fail the build
REAL_GCC=$(command -v gcc)
mkdir -p "$TMPD/fakebin" "$TMPD/rootf/plugins" "$TMPD/rootf/c"
cat >"$TMPD/fakebin/gcc" <<FAKE
#!/usr/bin/env bash
case "\$*" in *zz_kill.c*) kill -9 "\$PPID" ;; esac
exec $REAL_GCC "\$@"
FAKE
chmod +x "$TMPD/fakebin/gcc"
cp plugins/*.h "$TMPD/rootf/plugins/"; cp c/*.h "$TMPD/rootf/c/"
cp plugins/http_title.c "$TMPD/rootf/plugins/"
cp plugins/http_title.c "$TMPD/rootf/plugins/zz_kill.c"
PATH="$TMPD/fakebin:$PATH" PLUGINS_DIR="$TMPD/rootf/plugins" \
    bash tools/build_plugins.sh --out "$TMPD/f" >"$TMPD/f.log" 2>&1
rc=$?
[ "$rc" -eq 1 ] || fail "(f) worker killed silently: exit $rc, want 1"
grep -q 'worker' "$TMPD/f.log" || fail "(f) output does not mention the failed worker"
echo "ok (f): silent worker death fails the build"

# (h) a stray BP_WERROR in the caller's environment must not enable -Werror
mkdir -p "$TMPD/rooth/plugins" "$TMPD/rooth/c"
cp plugins/*.h "$TMPD/rooth/plugins/"; cp c/*.h "$TMPD/rooth/c/"
cp plugins/http_title.c "$TMPD/rooth/plugins/zz_warn.c"
echo 'static int zz_unused_variable;' >>"$TMPD/rooth/plugins/zz_warn.c"
BP_WERROR=1 PLUGINS_DIR="$TMPD/rooth/plugins" \
    bash tools/build_plugins.sh --out "$TMPD/h" >"$TMPD/h.log" 2>&1 \
    || fail "(h) BP_WERROR in the environment changed the build"
echo "ok (h): BP_* from the caller's environment are ignored"

# (i) a relative --out is relative to the caller's directory
HERE=$PWD
(cd "$TMPD" && bash "$HERE/tools/build_plugins.sh" --out rel_out http_title >"$TMPD/i.log" 2>&1) \
    || fail "(i) relative --out build failed"
[ -f "$TMPD/rel_out/http_title.so" ] || fail "(i) rel_out/http_title.so not in the caller's directory"
echo "ok (i): relative --out"

# (g) an unknown name is a failure
bash tools/build_plugins.sh --out "$TMPD/g" no_such_plugin >"$TMPD/g.log" 2>&1
rc=$?
[ "$rc" -eq 1 ] || fail "(g) unknown plugin: exit $rc, want 1"
grep -q 'FAILED: no_such_plugin' "$TMPD/g.log" || fail "(g) output does not name 'FAILED: no_such_plugin'"
echo "ok (g): unknown name fails"

echo "integration test PASSED: build_plugins"
exit 0
