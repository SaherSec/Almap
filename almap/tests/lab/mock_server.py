#!/usr/bin/env python3
"""mock_server.py - replay a recorded response, byte for byte.

Usage: python3 -I tests/lab/mock_server.py --proto tcp|udp --port N
           --fixture FILE [--after-bytes K] [--send-first] [--bind ADDR]

Binds 127.0.0.1 (never anything wider unless --bind says so), prints
"ready" on stdout once listening, and serves until it is killed.

  tcp  accepts one connection at a time. By default it reads the request
       up to the first CRLFCRLF (or EOF, or a 2 s timeout); --after-bytes K
       reads exactly K bytes instead; --send-first writes the fixture
       straight away without reading (banner protocols such as SSH, FTP,
       SMTP). Then it writes the fixture, shuts down and closes.
  udp  answers each datagram with the fixture.

Only fixtures that carry a .SOURCE record are meant to be replayed; the
plugin lint (tests/lint_plugins.sh) enforces that.
"""

import argparse
import socket
import sys

READ_TIMEOUT = 2.0


def read_request(conn, after_bytes):
    conn.settimeout(READ_TIMEOUT)
    data = b""
    try:
        while True:
            if after_bytes is not None:
                if len(data) >= after_bytes:
                    break
            elif b"\r\n\r\n" in data:
                break
            chunk = conn.recv(4096 if after_bytes is None else max(1, after_bytes - len(data)))
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    return data


def serve_tcp(args, payload):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(8)
    print("ready", flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            if not args.send_first:
                read_request(conn, args.after_bytes)
            conn.sendall(payload)
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            # let the client read before closing
            conn.settimeout(READ_TIMEOUT)
            try:
                while conn.recv(4096):
                    pass
            except (socket.timeout, OSError):
                pass
        except OSError:
            pass
        finally:
            conn.close()


def serve_udp(args, payload):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind((args.bind, args.port))
    print("ready", flush=True)
    while True:
        _, addr = srv.recvfrom(65535)
        srv.sendto(payload, addr)


def main():
    ap = argparse.ArgumentParser(description="replay a recorded response")
    ap.add_argument("--proto", choices=("tcp", "udp"), required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--after-bytes", type=int)
    ap.add_argument("--send-first", action="store_true")
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()
    with open(args.fixture, "rb") as fh:
        payload = fh.read()
    try:
        (serve_tcp if args.proto == "tcp" else serve_udp)(args, payload)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
