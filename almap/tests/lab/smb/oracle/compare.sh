#!/usr/bin/env bash
# compare.sh PLUGIN_SO HOST PORT KIND - run a plugin and the matching oracle and
# diff them (KIND: protocols | signing). Exit 0 only when they agree exactly.
set -eu
so=$1; host=$2; port=$3; kind=$4
here=$(cd "$(dirname "$0")" && pwd)
raw=$("${ALMAP_BIN:-$here/../../../../almap}" -t "$host" -p "$port" --scan connect --script "$so" --json --timeout 3000 2>/dev/null || true)
got=$(printf '%s' "$raw" | python3 -I -c '
import json,sys
d=json.load(sys.stdin)
for r in d:
    if r.get("script_out"):
        print(r["script_out"]); break')
case $kind in
  protocols) want=$("$here/protocols_oracle.sh" "$host" "$port") ;;
  signing)   want=$(python3 -I "$here/signing_oracle.py" "$host" "$port") ;;
  *) echo "unknown oracle kind $kind"; exit 1 ;;
esac
if [ -z "$want" ] || [ -z "$got" ]; then echo "DIFFER $kind $host:$port (empty output: plugin=${#got} bytes, oracle=${#want} bytes)"; exit 1; fi
if [ "$got" = "$want" ]; then echo "AGREE $kind $host:$port"; else echo "DIFFER $kind $host:$port"; diff <(printf '%s\n' "$got") <(printf '%s\n' "$want") | cut -c1-300; exit 1; fi
