#!/usr/bin/env bash
# hostkeys_oracle.sh HOST PORT - the host keys of an SSH server as OpenSSH's own
# tools see them: "<type> <bits> SHA256:<fp>" per key, same format as the
# ssh-hostkey plugin. Independent of the plugin (ssh-keyscan + ssh-keygen).
set -eu
host=$1; port=$2
for t in ed25519 ecdsa rsa; do
    ssh-keyscan -T 5 -p "$port" -t "$t" "$host" 2>/dev/null | ssh-keygen -lf - 2>/dev/null |
        awk '{ ty=$4; gsub(/[()]/,"",ty);
               n = (ty=="ED25519") ? "ssh-ed25519" : (ty=="RSA") ? "ssh-rsa" : "ecdsa-sha2-nistp" $1;
               print n, $1, $2 }'
done | paste -sd"|" | sed 's/|/; /g'
