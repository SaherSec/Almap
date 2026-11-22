#!/usr/bin/env bash
# tests/lint_plugins_selftest.sh - self-tests for tools/lint_plugins.py.
# Builds small plugin/fixture/lab trees in a temp dir, each violating one
# rule, and checks that the lint fails and names that rule (and that a
# clean tree and the allowed edge cases pass).
# Exit: 0 = pass, 1 = fail.
set -u

cd "$(dirname "$0")/.." || exit 1
LINT=tools/lint_plugins.py
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

fails=0
n=0

# plugin DIR NAME 'C statements' - write plugins/NAME.c
plugin() {
    printf '#include "arsenal_util.h"\nint almap_script_run(AlScriptContext *ctx) {\n%s\n    return 0;\n}\n' "$3" >"$1/plugins/$2.c"
}

# source FILE KIND URL - write a fixture .SOURCE
source_file() {
    {
        echo "kind: $2"
        echo "url: https://example.invalid/$3"
        echo "retrieved: 2026-11-22"
        echo "shows: a response used by the self-test"
        echo "basis: self-test data"
        [ "$2" = derived ] && echo "template_commit: 0123456789abcdef0123456789abcdef01234567"
    } >"$1"
}

# base DIR - a clean tree that passes the lint.
base() {
    local d=$1
    mkdir -p "$d/plugins" "$d/fixtures/c_det" "$d/fixtures/d_der" "$d/lab/db"
    plugin "$d" a_exp '    ar_out(ctx, "a_exp: INFO hello");'
    plugin "$d" b_vuln '    ar_out(ctx, "b_vuln: VULNERABLE");
    ar_out(ctx, "b_vuln: NOT VULNERABLE");'
    plugin "$d" c_det '    ar_out(ctx, "c_det: DETECTED");
    ar_out(ctx, "c_det: NOT DETECTED");'
    plugin "$d" d_der '    ar_out(ctx, "d_der: DETECTED");'
    plugin "$d" e_info '    ar_out(ctx, "e_info: version 1.2");'
    printf 'name\tfamily\ttier\tstatus\tevidence\n' >"$d/plugins/MANIFEST.tsv"
    {
        printf 'a_exp\thttp\texperimental\texperimental\t-\n'
        printf 'b_vuln\tdb\tvuln\tlab\tlab/db\n'
        printf 'c_det\thttp\tdetect\tcaptured\tfixtures/c_det\n'
        printf 'd_der\tiot\tdetect\tderived\tfixtures/d_der\n'
        printf 'e_info\tdb\tinfo\tlab\tlab/db\n'
    } >>"$d/plugins/MANIFEST.tsv"
    printf 'b_vuln\tvuln\t3306\tmatch:^b_vuln: VULNERABLE\nb_vuln\tpatched\t3307\tmatch:^b_vuln: NOT VULNERABLE\ne_info\tservice\t3308\tmatch:version 1\\.2\n' >"$d/lab/db/cases.tsv"
    : >"$d/fixtures/c_det/pos-1.bin"; source_file "$d/fixtures/c_det/pos-1.SOURCE" captured c1
    : >"$d/fixtures/c_det/neg-1.bin"; source_file "$d/fixtures/c_det/neg-1.SOURCE" captured c2
    : >"$d/fixtures/d_der/pos-1.bin"; source_file "$d/fixtures/d_der/pos-1.SOURCE" derived d1
    : >"$d/fixtures/d_der/neg-1.bin"; source_file "$d/fixtures/d_der/neg-1.SOURCE" captured d2
}

run_lint() {
    python3 -I "$LINT" --plugins "$1/plugins" --fixtures "$1/fixtures" --lab "$1/lab" 2>&1
}

expect_ok() { # label dir
    n=$((n + 1))
    local out rc
    out=$(run_lint "$2"); rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "FAIL: $1: lint exited $rc, want 0" >&2; echo "$out" | head -5 >&2; fails=$((fails + 1))
    else
        echo "ok   $1"
    fi
}

expect_fail() { # label dir name rule
    n=$((n + 1))
    local out rc
    out=$(run_lint "$2"); rc=$?
    if [ "$rc" -ne 1 ]; then
        echo "FAIL: $1: lint exited $rc, want 1" >&2; fails=$((fails + 1))
    elif ! printf '%s\n' "$out" | grep -qE "^LINT: $3: $4\b"; then
        echo "FAIL: $1: no 'LINT: $3: $4' line; got:" >&2; echo "$out" | head -5 >&2; fails=$((fails + 1))
    else
        echo "ok   $1"
    fi
}

mk() { rm -rf "$TMPD/$1"; base "$TMPD/$1"; echo "$TMPD/$1"; }

d=$(mk clean);                    expect_ok "clean tree passes" "$d"

# rule 1: manifest rows and sources match
d=$(mk r1a); plugin "$d" extra '    ar_out(ctx, "extra: INFO x");'
expect_fail "rule1: .c without a manifest row" "$d" extra rule1
d=$(mk r1b); printf 'ghost\thttp\texperimental\texperimental\t-\n' >>"$d/plugins/MANIFEST.tsv"
expect_fail "rule1: manifest row without a .c" "$d" ghost rule1
d=$(mk r1c); printf 'a_exp\thttp\texperimental\texperimental\t-\n' >>"$d/plugins/MANIFEST.tsv"
expect_fail "rule1: duplicate manifest row" "$d" a_exp rule1
d=$(mk r1d); sed -i 's/^a_exp\thttp\texperimental/a_exp\thttp\tbogus/' "$d/plugins/MANIFEST.tsv"
expect_fail "rule1: invalid tier value" "$d" a_exp rule1
d=$(mk r1e); sed -i 's/^a_exp\thttp/a_exp\tnofamily/' "$d/plugins/MANIFEST.tsv"
expect_fail "rule1: invalid family value" "$d" a_exp rule1

# rule 2: verdict words by tier, INFO prefix for experimental
d=$(mk r2a); sed -i 's/^b_vuln\tdb\tvuln\tlab/b_vuln\tdb\tdetect\tlab/' "$d/plugins/MANIFEST.tsv"
expect_fail "rule2: VULNERABLE in a detect plugin" "$d" b_vuln rule2
d=$(mk r2b); plugin "$d" a_exp '    ar_out(ctx, "a_exp: DETECTED");'
expect_fail "rule2: DETECTED in an experimental plugin" "$d" a_exp rule2
d=$(mk r2c); plugin "$d" a_exp '    ar_out(ctx, "a_exp: INFO detected (HTTP %d)", 200);'
expect_fail "rule2: lower-case 'detected (HTTP 200)' flagged" "$d" a_exp rule2
d=$(mk r2d); plugin "$d" a_exp '    ar_out(ctx, "a_exp: INFO vulnerable?");'
expect_fail "rule2: 'vulnerable?' flagged" "$d" a_exp rule2
d=$(mk r2e); plugin "$d" a_exp '    ar_out(ctx, "a_exp: hello");'
expect_fail "rule2: experimental line without the INFO prefix" "$d" a_exp rule2
d=$(mk r2f); plugin "$d" a_exp '    /* VULNERABLE in a comment */ // DETECTED too
    ar_out(ctx, "a_exp: INFO hello");'
expect_ok "rule2: verdict words in comments are ignored" "$d"
d=$(mk r2g); plugin "$d" a_exp '    if (strstr(resp, "VULNERABLE")) { ar_out(ctx, "a_exp: INFO marker seen"); }'
expect_ok "rule2: a matcher literal is not output" "$d"
d=$(mk r2h); plugin "$d" a_exp '    const char *w = "NOT DETECTED";
    ar_out(ctx, "a_exp: INFO %s", w);'
expect_fail "rule2: a verdict word hidden in an initialiser" "$d" a_exp rule2
d=$(mk r2i); printf 'static const char *w = "VULNERABLE";\n' >"$d/plugins/shared.h"
expect_fail "rule2: verdict word in a shared header" "$d" shared.h rule2
d=$(mk r2j); plugin "$d" a_exp '    ar_out(ctx, fmt_from_elsewhere);'
expect_fail "rule2: ar_out format that is not a literal (experimental)" "$d" a_exp rule2
d=$(mk r2k); plugin "$d" a_exp '    snprintf(ctx->output_buf, (size_t)ctx->output_max, "title=\"%s\"", "VULNERABLE");'
expect_fail "rule2: verdict word written straight to output_buf" "$d" a_exp rule2
d=$(mk r2l); plugin "$d" a_exp '    snprintf(ctx->output_buf, (size_t)ctx->output_max, "title=\"%s\"", t);'
expect_ok "rule2: raw facts written to output_buf need no prefix" "$d"

# rule 3: vuln needs lab; experimental tier and status go together
d=$(mk r3a); sed -i 's/^b_vuln\tdb\tvuln\tlab\tlab\/db/b_vuln\tdb\tvuln\tcaptured\tfixtures\/c_det/' "$d/plugins/MANIFEST.tsv"
expect_fail "rule3: vuln must have status lab" "$d" b_vuln rule3
d=$(mk r3b); sed -i 's/^a_exp\thttp\texperimental\texperimental/a_exp\thttp\texperimental\tlab/' "$d/plugins/MANIFEST.tsv"
expect_fail "rule3b: experimental tier with status lab" "$d" a_exp rule3b

# rule 4: evidence must exist
d=$(mk r4a); rm "$d/lab/db/cases.tsv"
expect_fail "rule4: status lab without a lab case" "$d" b_vuln rule4
d=$(mk r4b); rm "$d/fixtures/c_det/neg-1.bin" "$d/fixtures/c_det/neg-1.SOURCE"
expect_fail "rule4: captured without a negative fixture" "$d" c_det rule4
d=$(mk r4c); rm -r "$d/fixtures/d_der"
expect_fail "rule4: derived without fixtures" "$d" d_der rule4

# rule 5: every fixture has a complete .SOURCE
d=$(mk r5a); rm "$d/fixtures/c_det/pos-1.SOURCE"
expect_fail "rule5: .bin without .SOURCE" "$d" 'c_det/pos-1' rule5
d=$(mk r5b); sed -i '/^basis:/d' "$d/fixtures/c_det/pos-1.SOURCE"
expect_fail "rule5: .SOURCE missing a key" "$d" 'c_det/pos-1' rule5
d=$(mk r5c); sed -i '/^template_commit:/d' "$d/fixtures/d_der/pos-1.SOURCE"
expect_fail "rule5: derived .SOURCE without template_commit" "$d" 'd_der/pos-1' rule5
d=$(mk r5d); sed -i 's/^retrieved:.*/retrieved: yesterday/' "$d/fixtures/c_det/pos-1.SOURCE"
expect_fail "rule5: bad retrieved date" "$d" 'c_det/pos-1' rule5
d=$(mk r5e); sed -i 's/^kind:.*/kind: invented/' "$d/fixtures/c_det/pos-1.SOURCE"
expect_fail "rule5: kind must be captured or derived" "$d" 'c_det/pos-1' rule5

# rule 6: captured needs all-captured fixtures
d=$(mk r6); source_file "$d/fixtures/c_det/neg-1.SOURCE" derived c9
expect_fail "rule6: captured check with a derived fixture" "$d" c_det rule6

# rule 7: derived only for detect
d=$(mk r7); sed -i 's/^d_der\tiot\tdetect/d_der\tiot\tinfo/' "$d/plugins/MANIFEST.tsv"
expect_fail "rule7: derived status needs tier detect" "$d" d_der rule7

echo "lint self-test: $n checks, $fails failed"
[ "$fails" -eq 0 ]
