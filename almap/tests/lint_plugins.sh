#!/usr/bin/env bash
# tests/lint_plugins.sh - run the plugin tier lint on the real tree
# (plugins/MANIFEST.tsv, tests/fixtures, tests/lab).
# Exit: 0 = clean, 1 = violations (printed as "LINT: <name>: <rule>: ...").
cd "$(dirname "$0")/.." || exit 1
exec python3 -I tools/lint_plugins.py "$@"
