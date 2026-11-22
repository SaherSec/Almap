#!/usr/bin/env bash
# tests/check_release_selftest.sh - tools/build_release.sh packages what the
# release promises: the binary, gcc-built plugins (not their sources), the
# plugin manifest and status page, the top-level README, CHANGELOG and
# LICENSE, the service database and a checksum that verifies. Nothing is
# written into the repository (the dist directory is a temp directory).
# Exit: 0 = pass, 1 = fail.
set -u

cd "$(dirname "$0")/.." || exit 1
if ! command -v goose >/dev/null 2>&1; then
    echo "SKIP: goose not found on PATH (the release build needs it)"
    exit 77
fi
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

fails=0
check() { if [ "$2" -eq 0 ]; then echo "ok   $1"; else echo "FAIL: $1" >&2; fails=$((fails + 1)); fi; }

DIST_DIR="$TMPD/dist" bash tools/build_release.sh --osdb /dev/null >"$TMPD/build.log" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
    # /dev/null is not a usable OS DB; retry with the generated fallback
    DIST_DIR="$TMPD/dist" bash tools/build_release.sh >"$TMPD/build.log" 2>&1
    rc=$?
fi
[ "$rc" -eq 0 ]; check "build_release.sh succeeds" $?
[ "$rc" -eq 0 ] || tail -8 "$TMPD/build.log" | sed 's/^/     | /' >&2

ARCH=$TMPD/dist/almap-5.1.0-linux-x86_64.tar.gz
[ -s "$ARCH" ]; check "the archive is named for version 5.1.0" $?
(cd "$TMPD/dist" && sha256sum -c almap-5.1.0-linux-x86_64.tar.gz.sha256 >/dev/null 2>&1)
check "the sha256 file verifies the archive" $?

tar tzf "$ARCH" >"$TMPD/list.txt" 2>/dev/null
P=almap-5.1.0-linux-x86_64
for f in almap VERSION signatures.db README.md CHANGELOG.md LICENSE PLUGINS.md plugins/MANIFEST.tsv plugins/ssl-heartbleed.so plugins/http_title.so; do
    grep -qx "$P/$f" "$TMPD/list.txt"
    check "the archive contains $f" $?
done
! grep -qE '\.(c|h|rs)$' "$TMPD/list.txt"
check "the archive carries no plugin sources" $?
[ "$(grep -cE '/plugins/[^/]+\.so$' "$TMPD/list.txt")" -eq "$(ls plugins/*.c | wc -l)" ]
check "one gcc-built .so per plugin source" $?

mkdir -p "$TMPD/x" && tar xzf "$ARCH" -C "$TMPD/x" 2>/dev/null
grep -q '^Total checks: ' "$TMPD/x/$P/PLUGINS.md" && grep -q 'v5.1.0' "$TMPD/x/$P/README.md"
check "the packaged README and PLUGINS.md are the real ones" $?
[ -z "$(cd "$(git rev-parse --show-toplevel)" && git status --short -- almap/dist | head -1)" ]
check "nothing from the build is tracked by git" $?

echo "release self-test: $fails failed"
[ "$fails" -eq 0 ]
