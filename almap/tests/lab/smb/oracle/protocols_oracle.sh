#!/usr/bin/env bash
# protocols_oracle.sh HOST PORT - the SMB dialects a server accepts, as Samba's
# own smbclient sees them: one connection per dialect with the client's minimum
# and maximum protocol pinned to it, success = the share list comes back.
# Printed in the format of the smb-protocols plugin. Independent of the plugin.
set -u
host=$1; port=$2
out=""
for pair in "NT1:NT LM 0.12" "SMB2_02:SMB 2.0.2" "SMB2_10:SMB 2.1" "SMB3_00:SMB 3.0" "SMB3_02:SMB 3.0.2" "SMB3_11:SMB 3.1.1"; do
    lvl=${pair%%:*}; name=${pair#*:}
    if timeout 20 smbclient -N -L "//$host" -p "$port" --configfile=/dev/null \
        --option="client min protocol=$lvl" --option="client max protocol=$lvl" 2>&1 | grep -q Sharename; then
        out="$out${out:+; }$name"
    fi
done
if [ -z "$out" ]; then echo "smb-protocols: no SMB dialect accepted"; else echo "smb-protocols: $out"; fi
