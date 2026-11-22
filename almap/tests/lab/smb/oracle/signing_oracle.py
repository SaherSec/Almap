#!/usr/bin/env python3
"""signing_oracle.py HOST PORT - the signing/authentication mode a server
announces in its NEGOTIATE replies, read with a second, separately written
client (struct-based, straight from [MS-SMB2] 2.2.3/2.2.4 and [MS-CIFS]
2.2.4.52), printed in the format of the smb-security-mode plugin."""
import socket, struct, sys

host, port = sys.argv[1], int(sys.argv[2])

def frame(b):
    return b"\x00" + struct.pack(">I", len(b))[1:] + b

def exchange(payload):
    try:
        s = socket.create_connection((host, port), 5)
        s.settimeout(5)
        s.sendall(frame(payload))
        h = b""
        while len(h) < 4:
            c = s.recv(4 - len(h))
            if not c:
                return None
            h += c
        n = int.from_bytes(h[1:], "big")
        d = b""
        while len(d) < n:
            c = s.recv(n - len(d))
            if not c:
                break
            d += c
        return d
    except OSError:
        return None

# SMB2: header 64 bytes, body per 2.2.3 with the 3.1.1 preauth context
dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
hdr = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, b"\0" * 16)
dl = b"".join(struct.pack("<H", d) for d in dialects)
fixed = 36 + 64
ctx_off = (fixed + len(dl) + 7) // 8 * 8
body = struct.pack("<HHHHI16sIHH", 36, len(dialects), 1, 0, 0, b"O" * 16, ctx_off, 1, 0) + dl
body += b"\0" * (ctx_off - fixed - len(dl) - 0 - 0)
salt = b"S" * 32
ctx = struct.pack("<HHIHHH", 1, 38, 0, 1, 32, 1) + salt
r2 = exchange(hdr + body + ctx)
parts = []
if r2 and r2[:4] == b"\xfeSMB" and struct.unpack("<I", r2[8:12])[0] == 0:
    mode = struct.unpack("<H", r2[66:68])[0]
    parts.append("SMB2 message signing " + ("required" if mode & 2 else "enabled but not required" if mode & 1 else "not enabled"))

# SMB1 NEGOTIATE with NT LM 0.12 only
dia = b"\x02NT LM 0.12\x00"
h1 = b"\xffSMB" + b"\x72" + b"\0" * 4 + b"\x18" + struct.pack("<H", 0xC843) + b"\0" * 12 + struct.pack("<HHHH", 0, 0xFFFE, 0, 0)
r1 = exchange(h1 + b"\x00" + struct.pack("<H", len(dia)) + dia)
if r1 and r1[:4] == b"\xffSMB" and r1[32] == 17 and struct.unpack("<H", r1[33:35])[0] == 0:
    m = r1[35]
    parts.append("SMB1 message signing %s, %s authentication, %s" % (
        "required" if m & 8 else "enabled but not required" if m & 4 else "not enabled",
        "user-level" if m & 1 else "share-level",
        "challenge/response passwords" if m & 2 else "plaintext passwords"))
print("smb-security-mode: " + "; ".join(parts) if parts else "smb-security-mode: no SMB dialect accepted")
