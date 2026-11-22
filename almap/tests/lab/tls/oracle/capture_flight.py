#!/usr/bin/env python3
"""capture_flight.py - record a TLS server's handshake flight byte for byte.

Sends a TLS 1.2 ClientHello and writes everything the server sends up to and
including ServerHelloDone to OUTFILE, unmodified. The recording is replayed
by tests/lab/mock_server.py (with send_first=1) as a captured fixture.

Usage: python3 -I capture_flight.py HOST PORT OUTFILE   (lab targets only)
"""
import socket, struct, sys

host, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ciphers = [0xc02f, 0xc030, 0x009e, 0x002f, 0x0035, 0x000a]
body = b"\x03\x03" + b"\x55" * 32 + b"\x00" + struct.pack(">H", 2 * len(ciphers))
body += b"".join(struct.pack(">H", c) for c in ciphers) + b"\x01\x00"
ext = b"\x00\x0a\x00\x04\x00\x02\x00\x17" + b"\x00\x0b\x00\x02\x01\x00" + b"\x00\x0d\x00\x04\x00\x02\x04\x01"
body += struct.pack(">H", len(ext)) + ext
hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
s = socket.create_connection((host, port), timeout=5)
s.sendall(b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs)
got = b""
pending = b""
done = False
while not done:
    hdr = b""
    while len(hdr) < 5:
        c = s.recv(5 - len(hdr))
        if not c:
            sys.exit("closed before ServerHelloDone")
        hdr += c
    n = struct.unpack(">H", hdr[3:5])[0]
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c:
            sys.exit("closed inside a record")
        d += c
    got += hdr + d
    if hdr[0] == 22:
        pending += d
        while len(pending) >= 4:
            ml = struct.unpack(">I", b"\x00" + pending[1:4])[0]
            if len(pending) < 4 + ml:
                break
            if pending[0] == 14:
                done = True
            pending = pending[4 + ml:]
    elif hdr[0] == 21:
        sys.exit("alert instead of a flight")
open(out, "wb").write(got)
print("%d bytes written to %s" % (len(got), out))
