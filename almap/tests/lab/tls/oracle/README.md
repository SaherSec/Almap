# TLS lab oracles

The verdicts in `tests/lab/tls/cases.tsv` rest on what the lab servers really
do, so the ground truth was set with clients that were written from the
protocol and not from the plugins. They are kept here so the claim can be
re-checked:

| Script | What it establishes |
|---|---|
| `heartbleed_oracle.py HOST PORT` | A server that returns a heartbeat record far larger than a 1-byte request is Heartbleed-vulnerable. Prints only the length of the answer, never the bytes. |
| `ccs_oracle.py HOST PORT` | Patched servers answer an early ChangeCipherSpec with alert 10; vulnerable OpenSSL accepts it silently and answers the second one with alert 20 or 21. |
| `capture_flight.py HOST PORT OUT` | Records a server's handshake flight byte for byte (a captured fixture). |

Observed on the lab servers (`pod.yaml`), with the oracles in this directory:

| Port | Server | `heartbleed_oracle.py` | `ccs_oracle.py` |
|---|---|---|---|
| 19101 | OpenSSL 1.0.1c (nginx) | 16,384-byte reply | silent, then alert 20 |
| 19105 | OpenSSL 1.0.1c, TLS 1.0 / SSLv3 only | 16,384-byte reply | silent, then alert 21 |
| 19102 | OpenSSL 3.5.9 | alert (hello version `0303`; `0302` is refused at handshake) | alert 10 |
| 19106 | OpenSSL 1.1.1m | alert | alert 10 |

Both oracles must send their heartbeat / ChangeCipherSpec records with the
version the server **negotiated** (read from the ServerHello); a record with
another version draws `protocol_version` (alert 70) and looks like "safe". An
earlier version of these oracles got that wrong on 19105 and reported it as
not vulnerable, and so did the first version of the plugins; the lab case for
19105 exists to keep it that way.

Cipher lists and DH groups were checked with OpenSSL's own `s_client`
(`-cipher`, "Peer Temp Key"). Use these against the loopback lab only.
