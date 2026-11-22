# Changelog

## Unreleased

### Plugins: SMB family (batch 11.3)

Before: 54 files, most of them printing a negotiate summary and "verify". After: 6 checks run in the podman lab (the four `info` checks are proven against the servers' real answers; for the two `detect` checks the lab proves only that the banner is read and the version ranges are applied, which is why they are `detect`), 4 that stay experimental, the rest removed. Lab: six Samba configurations (4.6.3, 4.12.2 and the current 4.23.8 in four protocol and signing settings, `tests/lab/smb`). Notes: [docs/plans/batches/03-smb.md](docs/plans/batches/03-smb.md).

- `smb_version`, `smb-protocols`, `smb-security-mode` and `smb-os-discovery` (tier `info`) are rewritten on a new `arsenal_smbx.h`. `smb-protocols` is compared with what Samba's `smbclient` accepts for each pinned dialect, `smb-security-mode` with a second client written from the protocol documents. The shipped `smb_version` printed `SMB 2.???` for every server (it read the SMB2 wildcard dialect of the SMB1 reply), and the other shipped checks printed "probe did not match" or an SMB1 dialect name on servers that have SMB1 switched off.
- `smb-os-discovery` reads the native OS, LAN Manager and domain strings (SMB1) and the computer and domain names of the NTLMSSP challenge (SMB1 and SMB2). Only the NTLMSSP negotiate message is sent; no credentials.
- `smb-cve-2017-7494` and `smb-cve-2021-44142` (tier `detect`) compare the Samba version from the SMB1 LAN Manager string with the documented ranges. They print `DETECTED` / `NOT DETECTED` and say they are banner-only, `INFO` for vendor builds, non-Samba servers and servers without SMB1 (where the version is not disclosed).
- `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-double-pulsar-backdoor` and `smb-vuln-cve2020-0796` stay `experimental`: they print which SMB facts they see and that the vulnerability is not decided. They need a Windows target to be verified.
- Removed (31 names): every enumeration, listing and brute-force check (they need an authenticated SMB session and DCE/RPC over named pipes, which the plugin helpers do not have) and the checks for flaws outside SMB (Zerologon, PrintNightmare, CLFS, RRAS, DNS RPC, print spooler) that only negotiated SMB and printed "verify".
- New unit test `tests/test_smb.c`: parsers against replies captured from the lab servers, every truncation of those replies, hostile NTLM offsets, every Samba version boundary, the time budget.

| Old name | New name | Why |
|---|---|---|
| `smb` | removed | Rust support module of the removed Rust plugin port (not a plugin); the C helper is almap/plugins/arsenal_smb.h |
| `smb-brute-2` | removed | removed with smb-brute: no authentication exchange exists in the plugin helpers (an NTLM session setup with credentials); the shipped copy sent a negotiate and printed a line, and it guessed passwords |
| `smb-brute-3` | removed | removed with smb-brute-2 |
| `smb-enum-domains-2` | removed | removed: needs authenticated or null-session DCE/RPC (SAMR/LSA over the IPC$ pipe), which the plugin helpers do not have; the shipped copy printed a negotiate summary |
| `smb-enum-domains-3` | removed | removed with smb-enum-domains-2 |
| `smb-enum-groups-2` | removed | removed: needs DCE/RPC over SMB (SAMR); see smb-enum-domains-2 |
| `smb-enum-groups-3` | removed | removed with smb-enum-groups-2 |
| `smb-enum-processes-2` | removed | removed: needs DCE/RPC over SMB (remote registry/performance data) and credentials |
| `smb-enum-processes-3` | removed | removed with smb-enum-processes-2 |
| `smb-enum-sessions-2` | removed | removed: needs DCE/RPC over SMB (SRVSVC NetSessEnum) |
| `smb-enum-sessions-3` | removed | removed with smb-enum-sessions-2 |
| `smb-enum-users` | removed | removed: needs DCE/RPC over SMB (SAMR/LSA) |
| `smb-enum-users-2` | removed | removed with smb-enum-users |
| `smb-enum-users-3` | removed | removed with smb-enum-users |
| `smb-enum-shares` | removed | removed: needs DCE/RPC (SRVSVC NetShareEnumAll); the shipped version guessed share names with SMB1 tree connects and said 'none accessible' for a server that offers a guest share |
| `smb-enum-shares-2` | removed | removed with smb-enum-shares |
| `smb-enum-shares-3` | removed | removed with smb-enum-shares |
| `smb-ls-2` | removed | removed: needs authenticated file access (tree connect, create, query directory) |
| `smb-ls-3` | removed | removed with smb-ls-2 |
| `smb-mbenum-2` | removed | removed: needs the browser service (NetServerEnum over a pipe) |
| `smb-mbenum-3` | removed | removed with smb-mbenum-2 |
| `smb-null-session-check-4` | removed | removed: needs an anonymous SMB session setup and IPC$ tree connect with a working transport; the shipped copy only negotiated |
| `smb-vuln-ms06-025-4` | removed | removed: the flaw is in the Routing and Remote Access RPC service, not in SMB; the shipped copy negotiated SMB and printed 'verify' |
| `smb-vuln-ms07-029-4` | removed | removed: the flaw is in the DNS server RPC interface, not in SMB; the shipped copy negotiated SMB and printed 'verify' |
| `smb-vuln-ms10-054-4` | removed | removed: needs an authenticated share and a crafted SMB1 request; the shipped copy negotiated SMB and printed 'verify' |
| `smb-vuln-ms10-061-4` | removed | removed: the flaw is in the print spooler RPC, not in SMB; the shipped copy negotiated SMB and printed 'verify' |
| `smb-vuln-cve2020-1472-4` | removed | removed: Zerologon is a Netlogon RPC flaw, not an SMB one; the shipped copy negotiated SMB and printed 'verify' |
| `smb-vuln-cve2021-34527-4` | removed | removed: PrintNightmare is a print spooler RPC flaw, not an SMB one; the shipped copy negotiated SMB and printed 'verify' |
| `smb-vuln-cve2022-24521-4` | removed | removed: CVE-2022-24521 is a local flaw in the Windows CLFS driver, not reachable over SMB; the shipped copy negotiated SMB and printed 'verify' |
| `smb-check-vulns-2` | removed | removed with its parts: it only said which SMB dialects answered and 'check MS08-067 and MS17-010'; smb-protocols reports the dialects |
| `smb-check-vulns-3` | removed | removed with smb-check-vulns-2 |
| `smb-os-discovery-2` | `smb-os-discovery` | numbered copy merged |
| `smb-os-discovery-3` | `smb-os-discovery` | numbered copy merged |
| `smb-security-mode-2` | `smb-security-mode` | numbered copy merged |
| `smb-security-mode-3` | `smb-security-mode` | numbered copy merged |
| `smb-security-mode-check-4` | `smb-security-mode` | merged |
| `smb-protocols-check-4` | `smb-protocols` | renamed and rewritten: one NEGOTIATE per dialect, so the accepted set is reported, not only the server's favourite |
| `smb-vuln-cve2017-7494-4` | `smb-cve-2017-7494` | renamed and rewritten as a banner version check (tier detect): it printed 'verify' and never read the Samba version |
| `smb-vuln-cve2021-44142-5` | `smb-cve-2021-44142` | renamed and rewritten as a banner version check (tier detect) |
| `smb-vuln-ms17-010-2` | `smb-vuln-ms17-010` | numbered copy merged |
| `smb-vuln-ms17-010-3` | `smb-vuln-ms17-010` | numbered copy merged |
| `smb-vuln-ms17-010-4` | `smb-vuln-ms17-010` | numbered copy merged |
| `smb-vuln-ms17-010-full` | `smb-vuln-ms17-010` | merged; its PeekNamedPipe probe used a non-extended-security session setup that current servers reject, so it never got past 'session setup failed'; it stays experimental and reports the SMB1 fact only |
| `smb-check-cve2017-0144-4` | `smb-vuln-ms17-010` | merged (same vulnerability, CVE-2017-0144) |
| `smb-vuln-ms08-067-2` | `smb-vuln-ms08-067` | numbered copy merged |
| `smb-vuln-ms08-067-3` | `smb-vuln-ms08-067` | numbered copy merged |
| `smb-vuln-ms08-067-4` | `smb-vuln-ms08-067` | numbered copy merged |
| `smb-double-pulsar-backdoor-2` | `smb-double-pulsar-backdoor` | numbered copy merged (the base name did not exist) |
| `smb-double-pulsar-backdoor-3` | `smb-double-pulsar-backdoor` | numbered copy merged |
| `smb-check-cve2020-0796-4` | `smb-vuln-cve2020-0796` | renamed; experimental, reports the SMB 3.1.1 compression context fact only |

### Plugins: SSH family (batch 11.2)

13 files became 6 checks, run in the podman lab against seven pinned OpenSSH releases (8.4p1 to 10.3p1, `tests/lab/ssh`). For `ssh_version`, `ssh2-enum-algos` and `ssh-hostkey` the lab proves the output against the real servers. For the three CVE checks it proves only that the banner is read and compared with the documented range correctly: no server in the lab is shown to be exploitable, which is why they are `detect`. Notes: [docs/plans/batches/02-ssh.md](docs/plans/batches/02-ssh.md).

- `ssh_version`, `ssh2-enum-algos` and `ssh-hostkey` (tier `info`) are rewritten on a new `arsenal_ssh.h`. The shipped helper never sent the client identification string, which OpenSSH waits for before its KEXINIT, so every KEXINIT-based check printed only the banner against a real server. `ssh-hostkey` now reads the real host keys from the cleartext key-exchange reply and prints type, size and SHA256 fingerprint; the lab compares them with `ssh-keyscan` and `ssh-keygen -l`, and the algorithm lists with what `ssh -vv` reports.
- `ssh-cve-2024-6387`, `ssh-cve-2023-38408` and `ssh-cve-2023-25136` (tier `detect`) compare the banner version with the documented range. They print `DETECTED` / `NOT DETECTED`, say they are banner-only (a bare `OpenSSH_9.7` is also what OpenBSD announces, and OpenBSD is not affected by CVE-2024-6387), and print `INFO` for vendor builds and for `9.3` without a patch level (the lab's Alpine builds announce `OpenSSH_9.3` for both 9.3p1 and 9.3p2).
- `ssh-auth-methods` and `ssh-brute` are removed: they need an encrypted SSH transport that the plugin helpers do not have.
- New unit test `tests/test_ssh.c`: banner parser (including values that once wrapped into a wrong version), every version boundary of the three decisions, SHA-256 against the NIST vectors, the identification exchange, and the time budget against a peer that drips or goes silent. `ssh-hostkey` names any key type it could not obtain.

| Old name | New name | Why |
|---|---|---|
| `ssh2-enum-algos-2` | `ssh2-enum-algos` | numbered copy merged |
| `ssh-hostkey-2` | `ssh-hostkey` | numbered copy merged |
| `ssh_hostkey` | `ssh-hostkey` | merged; it offered one host key algorithm and printed only the algorithm list, now the real host keys are read from the key exchange reply |
| `ssh-vuln-cve2024-6387-5` | `ssh-cve-2024-6387` | renamed and rewritten as a banner version check (tier detect): it never compared a version, and 'vuln' promised exploitability a banner cannot show |
| `ssh-vuln-cve2023-38408-5` | `ssh-cve-2023-38408` | renamed and rewritten as a banner version check (tier detect) |
| `ssh-vuln-cve2023-25136-5` | `ssh-cve-2023-25136` | renamed and rewritten as a banner version check (tier detect) |
| `ssh-auth-methods` | removed | removed: needs an encrypted SSH transport (key exchange, cipher, MAC) that the plugin helpers do not have; it sent the authentication request in clear text before the key exchange, which no real server answers |
| `ssh-auth-methods-2` | removed | removed with ssh-auth-methods |
| `ssh-brute` | removed | removed: cannot authenticate without the encrypted transport (0 attempts against a real sshd), and it guessed passwords |
| `ssh-brute-2` | removed | removed with ssh-brute |

## 5.1.0 - 2026-11-22

A security and honesty release. The Web UI no longer has the holes found in the code review, every plugin that has not been proven prints only `INFO`, and the README now states the real numbers. The plugin count went down; it will grow back with real, verified plugins.

### Security (Web UI)

All of these were found by the review of `2fe56ab` and verified by running the server. The audit that followed the fixes is in [docs/plans/2026-11-22-web-security-scan.md](docs/plans/2026-11-22-web-security-scan.md).

| Finding | Fix | Commits |
|---|---|---|
| S1: no authentication, listening on every interface | Binds `127.0.0.1` by default (`--web-bind` to change it); a random 128-bit token is printed at startup and every `/api/` call needs `Authorization: Bearer <token>` | `e5f84b4` |
| S2: `"script"` could `dlopen` any file, so a constructor ran | `script` takes only a plugin name; it resolves to a regular file directly inside `plugins/` after `realpath`, so paths, `..` and escaping symlinks are never loaded | `e5f84b4` |
| S3: cross-site requests and DNS rebinding | Host must be `localhost` or an IP on the listening port, a foreign `Origin` is refused, `POST /api/scan` needs `Content-Type: application/json`, and responses carry `nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'` and `no-store` | `e5f84b4`, `9387bb3`, `39720e3` |
| S4: one idle connection blocked the single-threaded server; no limit on a scan | Poll-based accept loop with a 2-second per-request deadline and 32 pending connections; one non-blocking scan at a time (409 for a second), killed after 300 seconds, when the client disconnects, or when the server stops; a non-blocking drainer for early error replies; a total deadline for sending a response | `a951999`, `08aa927`, `a5619f7`, `90f49c1`, `9d7f837`, `ed682a3` |
| S5: scan output was cut at 32 KiB and returned as invalid JSON; requests truncated silently | Output up to 16 MiB is returned whole, larger output is a valid JSON error; an oversize request is a 413, never truncated and parsed | `08aa927`, `9387bb3` |
| S6: `Content-Length` overflow, inherited sockets | Overflow-safe, bounded `Content-Length`; listener and client sockets are close-on-exec | `9387bb3`, `e5f84b4` |
| JSON string escapes were silently ignored (found by the audit) | A string value with an escape the parser does not decode is a 400 | `ad5a0e6` |

Reviews of these changes also caught problems in the first fixes (a blocking linger-close that let an unauthenticated client stall the server, a scan child that outlived a killed server, an unbounded drain loop); they were fixed before release.

### Plugins

- Every plugin now has a tier and a status in `almap/plugins/MANIFEST.tsv`; `tests/lint_plugins.sh` enforces which words a plugin may print. Until a plugin was proven, it was downgraded: all of them print lines that start `<name>: INFO`, with `VULNERABLE` and `DETECTED` removed from their output (`b6e356c`).
- Verified against real targets in the podman lab: 5 checks, all TLS (`ssl-heartbleed`, `ssl-ccs-injection`, `ssl-poodle`, `ssl-enum-ciphers`, `ssl-dh-params`; `1d54640`, `bf28ddb`). `docs/PLUGINS.md` reports four separate counts: Verified (lab) 5, Verified (captured fixture) 0, Detected (derived fixture) 0, Experimental 612, 617 checks in total.
- What running the old plugins against the lab showed: the shipped Heartbleed plugins answered "not vulnerable" for a genuinely vulnerable server; the CCS-injection plugin reported the vulnerability on a patched server (it read the TLS record payload and lost the record type, so an alert looked like acceptance); several cipher-suite names were wrong. The rewrites print a verdict only on paths the lab verified; silence, a closed connection or an unexpected alert print `INFO`.
- Numbered copies (`-2` to `-5`) are merged into one plugin per check, family by family; so far the TLS family (11 files, 5 checks). The other families keep their current names until their turn.
- `tools/build_plugins.sh` builds every plugin, lists every failure, builds in parallel, and the plugins build warning-free under `-Wall -Wextra -Werror`; `mongodb_info.c` compiles again.
- The Rust plugin port is removed. C is the only plugin source and no prebuilt plugin binaries are committed.
- Plugin names that changed or disappeared:

| Old name | New name | Why |
|---|---|---|
| `ssl-heartbleed-2` | `ssl-heartbleed` | numbered copy merged into the verified check |
| `ssl-heartbleed-full` | `ssl-heartbleed` | merged; the OpenSSL-linked version had a false negative against a vulnerable server and is replaced by the pure-socket check |
| `ssl-ccs-injection-2` | `ssl-ccs-injection` | numbered copy merged |
| `ssl-poodle-2` | `ssl-poodle` | numbered copy merged |
| `ssl-enum-ciphers-2` | `ssl-enum-ciphers` | numbered copy merged |
| `ssl-dh-params-2` | `ssl-dh-params` | numbered copy merged |
| `alscript` | removed | Rust support library of the removed Rust plugin port (not a plugin); the C loader is almap/c/alscript.c |
| `arsenal` | removed | Rust support library of the removed Rust plugin port (not a plugin); the C helpers are almap/plugins/arsenal_*.h |
| `smb` | removed | Rust support module of the removed Rust plugin port (not a plugin); the C helper is almap/plugins/arsenal_smb.h |
| `http-put` | `http-put` | the Rust build had no unnumbered C source; its C copies are http-put-2 and http-put-3, which merge into http-put in the HTTP batch (not ported earlier) |

### Repository, tests and CI

- Build products are no longer tracked (663 files). The history was rewritten with `git filter-repo` to remove the committed `.so` files and release tarball: `.git` went from 2.1 GiB to 1.8 MB. **Every commit hash changed**; clones made earlier must be re-cloned.
- `tests/run_all.sh` runs everything; a skipped test exits 77 and `--no-skips` makes it a failure. The raw-socket tests no longer pass silently without raw sockets, and `integration_syn.sh`, which had never been able to run, no longer hangs.
- GitHub Actions: `ci.yml` builds and runs every test with `--no-skips` as root; `lab.yml` runs each plugin family's lab and fails unless every check marked verified had all of its lab cases pass in that run.
- A podman lab (`tests/lab`) with images pinned by digest, published on 127.0.0.1 only, a fixture replay server, and committed independent oracles for the TLS ground truth.

### Documentation

README, `docs/GUIDE.md`, `almap/AGENTS.md` and `almap/README.md` were rewritten to match the code: real plugin counts, no unmeasured speed claims, a Known limits section, and the version everywhere is 5.1.0. `tests/check_readme_claims.sh` keeps them honest.

### Incompatible changes

- `POST /api/scan` requires `Content-Type: application/json`, a plugin is given by name, and a second scan while one runs gets 409.
- Plugin output of every unproven plugin now starts `<name>: INFO`.
- Merged plugins have new names (table above); there are no aliases.

### Known limits

See the README. In short: 5 of 617 plugins are proven, plugins run in-process without a sandbox, there is no privilege drop, the Web UI is single-threaded (a token holder can still delay it by reading slowly; a flood of idle connections can lock others out), and no speed claim is made because no benchmark was run.
