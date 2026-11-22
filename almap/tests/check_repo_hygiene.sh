#!/usr/bin/env bash
# tests/check_repo_hygiene.sh - repository hygiene checks.
# Fails if build products are tracked by git, or if the ignore rules for
# local copies and build products are missing.
# Exit: 0 = pass, 1 = fail.
set -u

cd "$(dirname "$0")/.." || exit 1
ROOT=$(git rev-parse --show-toplevel) || exit 1
cd "$ROOT" || exit 1

fails=0
fail() {
    echo "FAIL: $1" >&2
    fails=$((fails + 1))
}

# 1. No tracked build products.
tracked=$(git ls-files | grep -E '\.so$|\.o$|^almap/almap$|^almap/dist/' || true)
if [ -n "$tracked" ]; then
    n=$(printf '%s\n' "$tracked" | wc -l)
    fail "$n tracked build products, for example: $(printf '%s\n' "$tracked" | head -3 | tr '\n' ' ')"
fi

# 2. Ignore rules.
for p in \
    almap-claude/x \
    almap-opencode/x \
    almap-opencode-rust/x \
    ALMAP_REVIEW.md \
    .superpowers/x \
    almap/plugins/foo.so \
    almap/c/x.o \
    almap/almap \
    almap/dist/x.tar.gz; do
    if ! git check-ignore -q "$p"; then
        fail "not ignored: $p"
    fi
done

# 3. The Rust plugin port is gone (C is the only plugin source). While the
#    directory still exists every .rs must be accounted for: it has a C twin
#    (same name, or with '-' written as '_') or is listed in
#    docs/plans/plugin-renames.tsv.
if [ -d almap/rust_plugins ]; then
    for f in almap/rust_plugins/*.rs; do
        n=$(basename "$f" .rs)
        u=${n//-/_}
        if [ ! -f "almap/plugins/$n.c" ] && [ ! -f "almap/plugins/$u.c" ] &&
           ! grep -q "^$n$(printf '\t')" docs/plans/plugin-renames.tsv; then
            fail "rust_plugins/$n.rs has no C twin and is not in plugin-renames.tsv"
        fi
    done
    fail "almap/rust_plugins still exists (C sources are the only plugin source)"
fi

if [ "$fails" -ne 0 ]; then
    echo "hygiene: $fails check(s) failed" >&2
    exit 1
fi
echo "hygiene: ok"
exit 0
