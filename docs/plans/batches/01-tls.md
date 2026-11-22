# Batch 11.1: TLS (family `tls`)

11 files merge into 5 checks. Targets: `tests/lab/tls` (one pod, host ports 19101-19105, all on 127.0.0.1).

## Lab targets (images pinned by digest in `tests/lab/tls/images.tsv`)

| Port | Server | Represents |
|---|---|---|
| 19101 | `docker.io/vulhub/openssl@sha256:3cf76769...` (OpenSSL 1.0.1c in nginx, TLS 1.0-1.2) | Heartbleed and CCS-injection **vulnerable**. Origin: the Vulhub project's own image (`openssl/CVE-2014-0160`). |
| 19105 | the same image with `ssl_protocols SSLv3 TLSv1` and CBC suites (ConfigMap `nginx.conf`) | POODLE **vulnerable** (SSLv3 + CBC negotiated) |
| 19102 | `docker.io/alpine/openssl@sha256:d8dc4590...` (OpenSSL 3.5.9 `s_server`, defaults) | patched against both; no SSLv3 |
| 19103 | same image, TLS 1.0-1.2, `AES128-SHA:AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256` | known suite list for `ssl-enum-ciphers` |
| 19104 | same image, `DHE-RSA-AES128-GCM-SHA256` with a 1024-bit `dhparam` | known group for `ssl-dh-params` |
| 19001 | plain nginx (control family, plain HTTP) | a non-TLS control: must never say VULNERABLE |

Ground truth for every port was established with **independent** clients before any plugin was trusted (a Heartbleed PoC and a CCS oracle written from the protocol; OpenSSL's own `s_client` for ciphers and DH): the 1.0.1c server leaks 16,384 bytes to a 1-byte heartbeat and answers the second early CCS with `bad_record_mac`; the 3.5.9 server answers the first early CCS with `unexpected_message` and refuses SSLv3.

## Checks

| Check | Merges | Tier | Evidence | Expected output |
|---|---|---|---|---|
| `ssl-heartbleed` | `ssl-heartbleed`, `ssl-heartbleed-2`, `ssl-heartbleed-full` | vuln | lab | 19101 `^ssl-heartbleed: VULNERABLE`; 19102 `^ssl-heartbleed: NOT VULNERABLE`; 19001 (plain HTTP) `nomatch:VULNERABLE` and `match:INFO` |
| `ssl-ccs-injection` | `ssl-ccs-injection`, `-2` | vuln | lab | 19101 `VULNERABLE`; 19102 `NOT VULNERABLE`; 19001 `nomatch:VULNERABLE` |
| `ssl-poodle` | `ssl-poodle`, `-2` | vuln | lab | 19105 `VULNERABLE`; 19102 `NOT VULNERABLE`; 19001 `nomatch:VULNERABLE` |
| `ssl-enum-ciphers` | `ssl-enum-ciphers`, `-2` | info | lab | 19103 lists the three suites per version exactly |
| `ssl-dh-params` | `ssl-dh-params`, `-2` | info | lab | 19104 `1024 bits`; 19102 reports no DHE group |

## What was wrong with the shipped code (found by running it)

- `ssl-heartbleed-full` said "heartbeat not honored" against the genuinely vulnerable server: a **false negative**. `ssl-heartbleed` and `-2` also said "not confirmed".
- `ar_tls_read_record` returned only the record payload and dropped the record type, so the callers' `resp[0] == AR_TLS_ALERT` checks looked at the wrong byte. An alert was treated as "accepted", so the CCS check could not tell a patched server from a vulnerable one.
- The CCS check treated silence as "not vulnerable", but a vulnerable OpenSSL accepts an early CCS silently.
- The suite-name table had wrong names (`0x0023`, `0x0006`).
- The shared helper `arsenal_tls.h` is rewritten (record-type-aware reader, streaming handshake parser, one IANA suite table used for names, CBC detection and the enumeration list).

## Decisions

- A verdict is only printed after a completed handshake. Anything inconclusive (not TLS, handshake refused, timeout) prints `INFO` with the reason and never a verdict word.
- `ssl-enum-ciphers` reports the suites it probed (about 50 common IANA suites, TLS 1.0-1.2); TLS 1.3 and suites outside that list are not enumerated, and the output says so.
- `ssl-heartbleed` no longer needs OpenSSL at build time (pure socket implementation), so `-lssl` is not required.
