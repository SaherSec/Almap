#!/usr/bin/env bash
# algos_oracle.sh HOST PORT - the server's KEXINIT name-lists as the OpenSSH
# client reports them (ssh -vv, "peer server KEXINIT proposal"), printed as
# "name: list" (a c2s/s2c pair that is identical is printed once as enc/mac/comp) joined with "; " (the plugin output is one line) in the order and with the names the ssh2-enum-algos plugin uses.
# Independent of the plugin. The connection is never authenticated.
set -eu
host=$1; port=$2
ssh -vv -o BatchMode=yes -o PreferredAuthentications=none -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p "$port" "$host" true 2>&1 |
awk '
  /peer server KEXINIT proposal/ {on=1}
  on && /debug2: KEX algorithms:/     {sub(/^.*KEX algorithms: /,"");      v["kex"]=$0}
  on && /debug2: host key algorithms:/{sub(/^.*host key algorithms: /,""); v["hostkey"]=$0}
  on && /debug2: ciphers ctos:/       {sub(/^.*ciphers ctos: /,"");        v["enc-c2s"]=$0}
  on && /debug2: ciphers stoc:/       {sub(/^.*ciphers stoc: /,"");        v["enc-s2c"]=$0}
  on && /debug2: MACs ctos:/          {sub(/^.*MACs ctos: /,"");           v["mac-c2s"]=$0}
  on && /debug2: MACs stoc:/          {sub(/^.*MACs stoc: /,"");           v["mac-s2c"]=$0}
  on && /debug2: compression ctos:/   {sub(/^.*compression ctos: /,"");    v["comp-c2s"]=$0}
  on && /debug2: compression stoc:/   {sub(/^.*compression stoc: /,"");    v["comp-s2c"]=$0}
  /debug2: languages/                 {on=0}
  END {
    print "kex: " v["kex"]; print "hostkey: " v["hostkey"]
    n = split("enc mac comp", g, " ")
    for (i = 1; i <= n; i++) {
      if (v[g[i] "-c2s"] == v[g[i] "-s2c"]) print g[i] ": " v[g[i] "-c2s"]
      else { print g[i] "-c2s: " v[g[i] "-c2s"]; print g[i] "-s2c: " v[g[i] "-s2c"] }
    }
  }
' | tr -d '\r' | paste -sd'|' | sed 's/|/; /g'
