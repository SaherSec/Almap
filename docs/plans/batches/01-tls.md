# Batch 11.1: TLS (family `tls`)

11 files merge into 5 checks. Targets: `tests/lab/tls` (one pod, host ports 19101-19106, all on 127.0.0.1) plus two captured fixtures replayed by the mock server.

## Lab targets (images pinned by digest in `tests/lab/tls/images.tsv`)

| Port | Server | Represents |
|---|---|---|
| 19101 | `docker.io/vulhub/openssl@sha256:3cf76769...` (OpenSSL 1.0.1c in nginx, TLS 1.0-1.2) | Heartbleed and CCS-injection **vulnerable**. Origin: the Vulhub project's own image (`openssl/CVE-2014-0160`). |
| 19105 | the same image with `ssl_protocols SSLv3 TLSv1` and CBC suites (ConfigMap `nginx.conf`) | POODLE **vulnerable** (SSLv3 + CBC negotiated) |
| 19102 | `docker.io/alpine/openssl@sha256:d8dc4590...` (OpenSSL 3.5.9 `s_server`, defaults) | patched against both; no SSLv3 |
| 19103 | same image, TLS 1.0-1.2, `AES128-SHA:AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256` | known suite list for `ssl-enum-ciphers` |
| 19104 | same image, `DHE-RSA-AES128-GCM-SHA256` with a 1024-bit `dhparam` | known group for `ssl-dh-params` |
| 19106 | `docker.io/vulhub/openssl@sha256:dffde83f...` (OpenSSL 1.1.1m `s_server`) | a second, older **patched** implementation (heartbeats compiled out) |
| fixture | `neg-plain-http`: real nginx HTTP bytes, replayed | non-TLS control: must say INFO, never a verdict |
| fixture | `neg-silent-after-flight`: the real TLS 1.2 handshake flight of the 1.0.1c server, replayed with the connection then closed | models a filter that drops the heartbeat / CCS record: must say INFO, never NOT VULNERABLE |

Ground truth for every port was established with **independent** clients before any plugin was trusted (a Heartbleed PoC and a CCS oracle written from the protocol; OpenSSL's own `s_client` for ciphers and DH): the 1.0.1c server leaks 16,384 bytes to a 1-byte heartbeat and answers the second early CCS with `bad_record_mac`; the 3.5.9 server answers the first early CCS with `unexpected_message` and refuses SSLv3.

## Checks

| Check | Merges | Tier | Evidence | Lab cases (30 in all) |
|---|---|---|---|---|
| `ssl-heartbleed` | `ssl-heartbleed`, `-2`, `-full` | vuln | lab | VULNERABLE on 19101 and on 19105 (TLS 1.0); NOT VULNERABLE (alert 10) on 19102, 19103, 19106; INFO on the plain-HTTP and silent-flight fixtures |
| `ssl-ccs-injection` | `ssl-ccs-injection`, `-2` | vuln | lab | VULNERABLE on 19101 and 19105; NOT VULNERABLE on 19102, 19103, 19106; INFO on both fixtures |
| `ssl-poodle` | `ssl-poodle`, `-2` | vuln | lab | VULNERABLE on 19105; NOT VULNERABLE on 19102, 19106 and 19101 (no SSLv3: alert 40); INFO on the plain-HTTP fixture |
| `ssl-enum-ciphers` | `ssl-enum-ciphers`, `-2` | info | lab | exact version/suite lists on 19103 and 19105 |
| `ssl-dh-params` | `ssl-dh-params`, `-2` | info | lab | 1024 bits on 19104; 2048 bits on 19102 and 19106; "no DHE suite negotiated" on 19103 |

## What was wrong with the shipped code (found by running it)

- `ssl-heartbleed-full` said "heartbeat not honored" against the genuinely vulnerable server: a **false negative**. `ssl-heartbleed` and `-2` also said "not confirmed".
- `ar_tls_read_record` returned only the record payload and dropped the record type, so the callers' `resp[0] == AR_TLS_ALERT` checks looked at the wrong byte. An alert was treated as "accepted", so the CCS check could not tell a patched server from a vulnerable one.
- The CCS check treated silence as "not vulnerable", but a vulnerable OpenSSL accepts an early CCS silently.
- The suite-name table had wrong names (`0x0023`, `0x0006`).
- The shared helper `arsenal_tls.h` is rewritten (record-type-aware reader, streaming handshake parser, one IANA suite table used for names, CBC detection and the enumeration list).

## Verdict rule (set by the batch review): silence is not evidence

- VULNERABLE needs positive proof (a 16 KiB heartbeat reply; a silently accepted early CCS followed by `bad_record_mac`/`decryption_failed`; SSLv3 negotiated with a CBC suite).
- NOT VULNERABLE only on the paths the lab verified: the alert `unexpected_message` (10) to a heartbeat record or an early CCS, and alert 40/70 to an SSLv3 hello that offered all 40 known CBC suites.
- Silence, a closed connection, any other alert and a non-TLS peer print INFO with the reason. A patched server that still supports heartbeats drops the request, and so does a filter in front of a vulnerable one; no lab target can tell those apart, so the plugin does not pretend to.
- Heartbeat and ChangeCipherSpec records carry the **negotiated** version. Using the ClientHello's version drew `protocol_version` (alert 70) from a TLS 1.0 server, which the first rewrite took for safety: a false negative on the vulnerable 19105 server, caught by the 19105 lab case. The committed oracles (`tests/lab/tls/oracle/`) had the same flaw until it was fixed and re-checked.

## Decisions

- A verdict is only printed after a completed handshake. Anything inconclusive (not TLS, handshake refused, timeout) prints `INFO` with the reason and never a verdict word.
- `ssl-enum-ciphers` reports the suites it probed (about 50 common IANA suites, TLS 1.0-1.2); TLS 1.3 and suites outside that list are not enumerated, and the output says so.
- `ssl-heartbleed` no longer needs OpenSSL at build time (pure socket implementation), so `-lssl` is not required.
- Not covered by a lab target (code paths exist, nothing to test them against): a patched server that supports heartbeats and silently drops the request (INFO by design); an interrupted `ssl-enum-ciphers` probe (output says "incomplete"); `ssl-poodle` silence (INFO). TLS 1.3-only servers are reported as "no probed suite negotiated".
