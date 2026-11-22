#!/usr/bin/env python3
"""ccs_oracle.py - independent CCS-injection (CVE-2014-0224) oracle for the TLS lab.

TLS 1.2 ClientHello, read to ServerHelloDone, then an early ChangeCipherSpec,
then a second one. Patched servers answer the first with alert 10
(unexpected_message). Vulnerable OpenSSL accepts it silently and answers the
second with alert 20 (bad_record_mac) or 21 (decryption_failed).

Usage: python3 -I ccs_oracle.py HOST PORT   (lab targets on 127.0.0.1 only)
"""
import socket, struct, sys
host, port = sys.argv[1], int(sys.argv[2])
ciphers=[0xc02f,0xc030,0x009e,0x002f,0x0035,0x000a]
body=b"\x03\x03"+b"\x22"*32+b"\x00"+struct.pack(">H",2*len(ciphers))+b"".join(struct.pack(">H",c) for c in ciphers)+b"\x01\x00"
ext=(b"\x00\x0a\x00\x04\x00\x02\x00\x17"+b"\x00\x0b\x00\x02\x01\x00"+b"\x00\x0d\x00\x04\x00\x02\x04\x01")
body+=struct.pack(">H",len(ext))+ext
hs=b"\x01"+struct.pack(">I",len(body))[1:]+body
s=socket.create_connection((host,port),timeout=5); s.sendall(b"\x16\x03\x01"+struct.pack(">H",len(hs))+hs)
def rec():
    h=b""
    while len(h)<5:
        c=s.recv(5-len(h))
        if not c: return None
        h+=c
    n=struct.unpack(">H",h[3:5])[0]; d=b""
    while len(d)<n:
        c=s.recv(n-len(d))
        if not c: return None
        d+=c
    return h[0],d
neg=b"\x03\x03"
done=False
while not done:
    r=rec()
    if r is None: print("closed during handshake"); sys.exit(2)
    if r[0]==21: print("alert in handshake",r[1].hex()); sys.exit(2)
    if r[0]==22:
        i=0
        while i+4<=len(r[1]):
            if r[1][i]==2: neg=r[1][i+4:i+6]
            if r[1][i]==14: done=True
            i+=4+struct.unpack(">I",b"\x00"+r[1][i+1:i+4])[0]
ccs=b"\x14"+neg+b"\x00\x01\x01"      # record version = negotiated version
s.settimeout(2)
for n in (1,2):
    s.sendall(ccs)
    try: r=rec()
    except socket.timeout: r="silent"
    if r is None: print("ccs#%d: connection closed"%n); continue
    if r=="silent": print("ccs#%d: silent"%n); continue
    print("ccs#%d: record type %d %s"%(n,r[0],r[1][:2].hex()))
    if r[0]==21: break
