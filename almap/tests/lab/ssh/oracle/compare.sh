#!/usr/bin/env bash
# compare.sh PLUGIN_SO HOST PORT KIND - run a plugin and the matching oracle and
# diff them (KIND: algos | hostkeys). Exit 0 only when they agree exactly.
set -eu
so=$1; host=$2; port=$3; kind=$4
here=$(cd "$(dirname "$0")" && pwd)
raw=$("${ALMAP_BIN:-$here/../../../../almap}" -t "$host" -p "$port" --scan connect --script "$so" --json --timeout 3000 2>/dev/null || true)
got=$(printf '%s' "$raw" | python3 -I -c '
import json,sys
d=json.load(sys.stdin)
def find(o):
    if isinstance(o,dict):
        for k,v in o.items():
            if k=="script_out": return v
            r=find(v)
            if r is not None: return r
    if isinstance(o,list):
        for v in o:
            r=find(v)
            if r is not None: return r
print(find(d) or "")')
case $kind in
  algos)    want=$("$here/algos_oracle.sh" "$host" "$port") ;;
  hostkeys) want=$("$here/hostkeys_oracle.sh" "$host" "$port"); got=${got#ssh-hostkey: } ;;
esac
if [ -z "$want" ] || [ -z "$got" ]; then echo "DIFFER $kind $host:$port (empty output: plugin=${#got} bytes, oracle=${#want} bytes)"; exit 1; fi
if [ "$got" = "$want" ]; then echo "AGREE $kind $host:$port"; else echo "DIFFER $kind $host:$port"; diff <(printf '%s\n' "$got") <(printf '%s\n' "$want") | cut -c1-300; exit 1; fi
