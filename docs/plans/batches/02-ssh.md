# Batch 11.2: SSH (family `ssh`)

13 source files become 6 checks, all verified in the lab; 4 plugin names are removed (see below). Targets: `tests/lab/ssh` (seven pods, one OpenSSH release each, host ports 19201-19207, all on 127.0.0.1).

## Lab targets (images pinned by digest in `tests/lab/ssh/images.tsv`)

All are `linuxserver/openssh-server` images (Alpine builds of upstream OpenSSH), one per release, so the banner version is the only thing that changes between them.

| Port | OpenSSH | CVE-2024-6387 range (8.5p1 to 9.7p1) | CVE-2023-38408 range (< 9.3p2) | CVE-2023-25136 (9.1 only) |
|---|---|---|---|---|
| 19201 | 8.4p1 | outside | inside | outside |
| 19202 | 9.1p1 | inside | inside | **inside** |
| 19203 | 9.3p1 | inside | boundary (banner says `9.3`) | outside |
| 19204 | 9.3p2 | inside | boundary (banner says `9.3`) | outside |
| 19205 | 9.7p1 | **inside** | outside | outside |
| 19206 | 9.9p1 | outside | outside | outside |
| 19207 | 10.3p1 | outside | outside | outside |

Ground truth for every port: `ssh -V` inside the container, the raw banner bytes, `sshd -T` for the algorithm lists, and `ssh-keyscan` + `ssh-keygen -lf` from the host for the host keys (see `tests/lab/ssh/oracle/`).

## What the lab showed about the shipped code

Run against the real servers (OpenSSH 9.7p1, port 19205) before any change:

- `ssh2-enum-algos`, `ssh-auth-methods`: `KEXINIT failed`. They never sent the client identification string, and OpenSSH waits for it before it sends its KEXINIT. The helper `ar_ssh_open` was broken for every real server, so every check built on it could only ever print the banner.
- `ssh-hostkey`: `host-key algorithms not disclosed` (same cause). `ssh_hostkey` printed nothing.
- `ssh-brute`: `0 attempts`. It could not have worked even with the banner fixed: it sent USERAUTH requests in clear text straight after KEXINIT, and a real server only accepts authentication after the key exchange completed and the transport is encrypted. The same holds for `ssh-auth-methods`.
- The three `ssh-vuln-*-5` checks printed the banner plus "verify patch level" and never compared a version.

## Checks

| Check | Merges | Tier | Evidence | What it does |
|---|---|---|---|---|
| `ssh_version` | `ssh_version` (the Rust-only `ssh-version` went with the Rust port; the C name stays because tests and the control lab already use it) | info | lab | Protocol and software string from the identification line; skips pre-banner lines (RFC 4253 4.2) |
| `ssh2-enum-algos` | `ssh2-enum-algos`, `-2` | info | lab | The ten KEXINIT name-lists, in server order |
| `ssh-hostkey` | `ssh-hostkey`, `-2`, `ssh_hostkey` | info | lab | Real host keys: sends KEX_ECDH_INIT (curve25519) and reads the host key blob from KEX_ECDH_REPLY, which is cleartext. Prints type, size and SHA256 fingerprint for ed25519, ecdsa-nistp256 and RSA. No shared secret is computed, no authentication is attempted |
| `ssh-cve-2024-6387` | `ssh-vuln-cve2024-6387-5` | detect | lab | `DETECTED` when the banner version is in 8.5p1..9.7p1 |
| `ssh-cve-2023-38408` | `ssh-vuln-cve2023-38408-5` | detect | lab | `DETECTED` when below 9.3p2; `9.3` with no `pN` suffix is `INFO` (cannot be told from 9.3p1 / 9.3p2) |
| `ssh-cve-2023-25136` | `ssh-vuln-cve2023-25136-5` | detect | lab | `DETECTED` for exactly 9.1 |

Removed: `ssh-auth-methods`, `ssh-auth-methods-2`, `ssh-brute`, `ssh-brute-2` (see `docs/plans/plugin-renames.tsv`). A real implementation needs a full encrypted SSH transport (key exchange, cipher, MAC), i.e. a crypto implementation that does not exist in the plugin helpers, and `ssh-brute` additionally guesses passwords. They were not kept as `experimental` because an experimental plugin that cannot do what its name says is still a false claim of coverage. Cost if wrong: two plugin names disappear until someone writes the transport.

## Why the CVE checks are `detect`, not `vuln`

A banner proves the version, not the vulnerability: distributions backport fixes without changing the version, and Alpine published a patched `9.7_p1-r4` that still announces `OpenSSH_9.7`. So they print `DETECTED` / `NOT DETECTED` only, and the output says "banner only". A banner with a vendor comment (`Debian-...`, `Ubuntu-...`) prints `INFO`, because the version alone then says even less. The vendor path is covered by a unit test of the version parser (no real vendor server is in the lab).

## Decisions

- Output of every detect check names the version range and says it is banner-only.
- Versions below 4.4 (CVE-2024-6387 depends on old patches there) and non-OpenSSH servers print `INFO`.
- The Alpine builds in the lab announce `OpenSSH_9.3` for both 9.3p1 and 9.3p2 (no `pN`), which is why `ssh-cve-2023-38408` has an `INFO` outcome at the boundary. The lab pins both and checks that behaviour.

## Lab findings that shaped the code

- **Throttling.** OpenSSH 9.8+ (`PerSourcePenalties`, on by default) refuses a source address after a handful of connections that never authenticate. Eleven quick probes of the 10.3 server were enough: the later ones got no banner and the plugins printed "no SSH identification line". The lab turns it off for the 9.9 and 10.3 pods (a ConfigMap mounted as `sshd_config.d`) so the cases stay independent; the README lists it as a known limit, since `ssh-hostkey` opens three connections.
- **Output limit.** The script output buffer is about 1 KiB. `ssh2-enum-algos` on the first rewrite was cut in the middle of a list (`none,zlib@open`), which the oracle caught. It now prints a pair like `enc-c2s`/`enc-s2c` once when the two lists are identical, never cuts a list, and names any list that does not fit as omitted. No lab server is long enough to take the omission path, so that path is not lab-tested.
- Script output is one line (control characters become `.`), so multi-item results use `; `.

## Evidence summary (48 lab cases, `tests/lab/ssh/cases.tsv`)

- Seven OpenSSH servers for every check; each of `ssh2-enum-algos` and `ssh-hostkey` is compared with an independent client (`oracle:algos` = `ssh -vv`, `oracle:hostkeys` = `ssh-keyscan` + `ssh-keygen -l`; the oracle compare is a new `oracle:KIND` expectation in `tests/lab/lib.sh`). A non-SSH control (real nginx bytes, replayed) must give "no SSH identification line"/"no host key", and for the CVE checks never `DETECTED`.
- `tests/test_ssh.c` covers what no lab server shows: vendor banners (`Debian-`, `Ubuntu-`), `9.3pN`, three-component and non-OpenSSH banners, pre-banner lines, SHA-256 against NIST vectors, base64, and the RSA key size reader.
- Not covered by any target: the `DETECTED` outcome for 9.3p1 with an explicit `p1`, a vendor-build banner against a live server, the omitted-list path, a server that has no curve25519 key exchange.
