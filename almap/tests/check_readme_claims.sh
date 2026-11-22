#!/usr/bin/env bash
# tests/check_readme_claims.sh - the documentation says what is true.
#  * the version is 5.1.0 everywhere it appears;
#  * the README repeats the four plugin counts of docs/PLUGINS.md exactly,
#    and carries none of the old claims (623 plugins, "about 100 full
#    protocol checks", "Nmap killer", unmeasured speed claims);
#  * the number of shipped service-signature rules it states is the real one;
#  * the stale pieces of the GUIDE, AGENTS.md and almap/README.md are gone;
#  * the CHANGELOG has a 5.1.0 section that lists every renamed or merged
#    plugin of docs/plans/plugin-renames.tsv.
# Needs ./almap (the first line of --help is checked).
# Exit: 0 = pass, 1 = fail.
set -u

cd "$(dirname "$0")/.." || exit 1
ROOT=$(cd .. && pwd)
fails=0
check() { if [ "$2" -eq 0 ]; then echo "ok   $1"; else echo "FAIL: $1" >&2; fails=$((fails + 1)); fi; }

# ---- version -------------------------------------------------------------
[ "$(tr -d '[:space:]' <VERSION)" = "5.1.0" ];                       check "VERSION is 5.1.0" $?
grep -q 'return "5.1.0";' modules/webui.goose;                        check "the Web UI reports 5.1.0" $?
grep -q '"version":"5.1.0"' tests/integration_web.sh;                 check "integration_web.sh expects 5.1.0" $?
grep -q 'v5.1.0' "$ROOT/README.md";                                   check "README badge says v5.1.0" $?
if [ -x ./almap ]; then
    ./almap --help 2>&1 | head -1 | grep -q 'ALmap v5.1.0'
    check "the first line of ./almap --help says v5.1.0" $?
else
    echo "note: ./almap not built, --help check skipped"
fi

# ---- plugin counts -----------------------------------------------------------
for key in 'Verified (lab)' 'Verified (captured fixture)' 'Detected (derived fixture)' 'Experimental' 'Total checks'; do
    line=$(grep -m1 "^$key: " "$ROOT/docs/PLUGINS.md")
    [ -n "$line" ] && grep -qxF "$line" "$ROOT/README.md"
    check "README repeats '$line'" $?
done
! grep -qE '623|about 100|~100|[Nn]map [Kk]iller|[Ff]astest|faster than|exceeds Nmap' "$ROOT/README.md"
check "README has none of the old claims (623, ~100, killer, fastest)" $?
grep -q '^## Known limits' "$ROOT/README.md" && grep -qi 'no benchmark' "$ROOT/README.md"
check "README has a Known limits section and says there are no benchmarks" $?

# ---- the shipped service signature count ---------------------------------------
real=$(grep -cvE '^[[:space:]]*(#|$)' signatures.db)
grep -qE "signatures\.db\` has $real rules" "$ROOT/README.md"
check "README states the real signatures.db rule count ($real)" $?

# ---- stale docs ---------------------------------------------------------------
! grep -qE 'v4\.0|V4\.0|4\.0\.0|5-script|Killer|exceeds Nmap' "$ROOT/docs/GUIDE.md"
check "GUIDE has no v4.0, 5-script or 'Killer' leftovers" $?
grep -q '5\.1\.0' "$ROOT/docs/GUIDE.md";                              check "GUIDE mentions 5.1.0" $?
! grep -qE 'V4\.0|v4\.0|4\.0\.0' AGENTS.md;                           check "AGENTS.md is not stuck at 4.0.0" $?
! grep -qF '\n' README.md;                                            check "almap/README.md has no literal \\n" $?

# ---- changelog ----------------------------------------------------------------
grep -q '^## 5\.1\.0' "$ROOT/CHANGELOG.md";                           check "CHANGELOG has a 5.1.0 section" $?
missing=0
while IFS=$'\t' read -r old rest; do
    case $old in ''|'#'*) continue ;; esac
    grep -qF "$old" "$ROOT/CHANGELOG.md" || { echo "  not in CHANGELOG: $old" >&2; missing=$((missing + 1)); }
done <"$ROOT/docs/plans/plugin-renames.tsv"
[ "$missing" -eq 0 ];                                                 check "every renamed or merged plugin is in the CHANGELOG" $?

echo "readme claims: $fails failed"
[ "$fails" -eq 0 ]
