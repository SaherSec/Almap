<div align="center">

# ALmap

**A small, auditable network scanner for Linux, written in Goose and C.**

Async connect engine · Raw SYN/UDP · OS fingerprinting · Native C plugins · JSON/XML output · Built-in Web UI

`v5.1.0` · Linux x86-64 · MIT

</div>

---

ALmap is a network scanner with a small core you can read. The scanning logic lives in [Goose](https://github.com/aardappel/goose), a memory-safe systems language with no heap and no garbage collector. A thin C layer owns sockets, raw packets, threads and plugin loading.

The goal is not to replace Nmap everywhere. It is a scanner that is predictable, and simple enough to read end to end. Plugin results are only called a vulnerability when they were proven against a real vulnerable and a real patched target (see [Plugins](#plugins)).

```console
$ ./almap -t 192.168.1.0/24 -p 1-1024 --fast --timeout 500
$ sudo ./almap -t 192.168.1.10 -p 22,80,443 --scan syn --os --service --json
```

## Features

| | |
|---|---|
| **Async engine** | `--fast` runs one non-blocking `epoll` loop with up to 10,000 connects in flight. A token-bucket limits the rate. No root needed. |
| **Scan modes** | TCP connect, raw SYN, raw UDP and host discovery (TCP ping plus ICMP echo). |
| **OS fingerprinting** | Nmap-style T1–T7 + U1 probe sequence. Reads TTL, window, ISN, TCP options and IP-ID behaviour. No OS database ships: import Nmap's with `tools/import_nmap_os.py` for named matches; without it you get coarse labels (`linux-like`, `windows-like`, …). |
| **Service detection** | Built-in heuristics plus a runtime regex database. The shipped `signatures.db` has 6 rules; import Nmap's service-probe set (8k+ rules) with `tools/import_nmap.py`. |
| **AlScript plugins** | Plain `.so` files that export one C function. No VM and no Lua. 566 checks, 17 of them proven against real targets so far; the rest are experimental and print `INFO` only (see [Plugins](#plugins)). |
| **Evasion** | IP fragmentation, custom MTU, up to 5 decoys and source-MAC spoofing. |
| **Output** | Text, JSON, tab-separated table or XML. The order is always the same: targets as given, hosts ascending, ports as given. |
| **IPv6** | Connect scans and discovery. |
| **Web UI** | Dark-mode single-page app and JSON API, served from the same binary with raw POSIX sockets. No web framework. |

## Install

### Build from source

Requirements: Linux, GCC, and the Goose compiler 2026.3 or newer. Python 3 is only needed for the Nmap database importers.

```sh
git clone https://github.com/bo3tb1/Almap.git
cd Almap/almap
export GOOSE_STDLIB=/path/to/goose/stdlib

goose check almap.goose
goose build almap.goose --cc gcc -o almap
bash tools/build_plugins.sh        # optional: compile plugins/*.c into plugins/*.so
./almap --help
```

## Quick start

```sh
# Unprivileged connect scan
./almap -t 127.0.0.1 -p 22,80,443

# Fast async sweep of a /24
./almap -t 192.168.1.0/24 -p 1-1024 --fast --timeout 500

# Raw SYN scan with OS and service detection (root or CAP_NET_RAW)
sudo ./almap -t 192.168.1.10 -p 1-1024 --scan syn --os

# Discovery only
sudo ./almap -t 192.168.1.0/24 --discover

# UDP
sudo ./almap -t 192.168.1.10 -p 53,123,161 --scan udp

# Run a plugin on open ports, get JSON
./almap -t 127.0.0.1 -p 80 --script ./plugins/http_title.so --json
```

Instead of `sudo`, you can grant raw-socket access once:

```sh
sudo setcap cap_net_raw+ep ./almap
```

## Common options

| Flag | Description |
|---|---|
| `-t <targets>` | IPv4, IPv6 or CIDR, comma-separated (up to 64 entries) |
| `-iL <file>` | Read targets from a file |
| `-p <ports>` | `22,80,443`, `1-1024` or a mix |
| `--scan <mode>` | `connect` (default), `syn` or `udp` (`-sU`) |
| `--discover` | Host discovery only |
| `--fast` | Async epoll engine (IPv4 connect only) |
| `--service` / `--banners` | Version detection / banner grabbing |
| `--os` | OS fingerprinting (needs `--scan syn`) |
| `--script <so>` | Run an AlScript plugin on open ports |
| `-f`, `--mtu`, `-D`, `--spoof-mac` | Evasion controls (raw SYN) |
| `--sigdb <path>` / `--osdb <path>` | Service / OS signature database (default `~/.almap/signatures.db`, `~/.almap/os-signatures.db`) |
| `--rate <n>` | Port attempts per second |
| `--timeout <ms>` | Per-probe timeout (default 1000) |
| `--workers <n>` | Thread-pool size (default 10) |
| `--retries <n>` | Extra attempts after a timeout in `--fast` (0–10, default 3) |
| `--json` / `--table` / `--xml` | Structured output |
| `--web` / `--ui` `[--web-port N]` `[--web-bind IP]` | Start the Web UI (default `127.0.0.1:8080`; API calls need the printed token) |

Run `./almap --help` for every flag and its rules. The full guide is in **[docs/GUIDE.md](docs/GUIDE.md)**.

## Plugins

`almap/plugins/` holds the C source of every plugin. Each plugin has a tier and a status, recorded in [`almap/plugins/MANIFEST.tsv`](almap/plugins/MANIFEST.tsv) and summarised in [docs/PLUGINS.md](docs/PLUGINS.md):

```
Verified (lab): 17
Verified (captured fixture): 0
Detected (derived fixture): 0
Experimental: 549

Total checks: 566
```

The four counts are separate and are never added together.

- **Verified (lab)**: proven against real vulnerable, patched and neutral targets running in the podman lab (`tests/lab`). Only these can print `VULNERABLE` or `NOT VULNERABLE`.
- **Verified (captured fixture)**: proven against responses captured byte for byte from a cited source.
- **Detected (derived fixture)**: backed only by responses derived from a published scanner matcher. It can say `DETECTED` or `NOT DETECTED`, never `VULNERABLE`, because a matcher proves the product and not the vulnerability.
- **Experimental**: not proven yet. These plugins print lines that start `<name>: INFO` and make no claim about a vulnerability.

A verdict needs evidence: `VULNERABLE` needs positive proof, and `NOT VULNERABLE` is printed only on a path the lab verified. Silence, a closed connection or an unexpected reply is not evidence, so those print `INFO` with the reason.

The five verified checks are all TLS: `ssl-heartbleed`, `ssl-ccs-injection` and `ssl-poodle` (verdicts), and `ssl-enum-ciphers` and `ssl-dh-params` (they report what the server offers). Running the old plugins against the lab showed what proof is worth: the earlier Heartbleed plugins answered "not vulnerable" for a genuinely vulnerable server, and the CCS plugin reported the vulnerability on a patched one.

The count is lower than in earlier releases because the numbered copies (`-2` … `-5`) of the same probe were merged; the old and new names are listed in the [CHANGELOG](CHANGELOG.md). The remaining plugins are being verified family by family, and the counts above will change as they are.

`--script` runs one plugin per scan, on every open port. There is no category or port-based selection yet. Plugins are built from the C sources with `tools/build_plugins.sh`; no prebuilt plugin binaries are committed.

## Writing a plugin

```c
#include "../c/alscript.h"   /* when built from almap/plugins/ */

int almap_script_run(AlScriptContext *ctx) {
    /* ctx->target_ip, ctx->port, ctx->timeout_ms ...
       write up to 1023 bytes of output; return 0 on success */
    return 0;
}
```

```sh
gcc -std=c99 -Wall -Wextra -shared -fPIC -o myplugin.so myplugin.c
./almap -t 10.0.0.5 -p 80 --script ./myplugin.so
```

Plugins run inside the scanner process with its full privileges, so only load code you trust.

## Using Nmap's databases

ALmap does not ship Nmap's data. The two importers convert your local copy:

```sh
python3 tools/import_nmap.py    /usr/share/nmap/nmap-service-probes -o ~/.almap/signatures.db
python3 tools/import_nmap_os.py /usr/share/nmap/nmap-os-db          -o ~/.almap/os-signatures.db
```

Data you import from Nmap stays under Nmap's license.

## Web UI

```sh
./almap --web                          # listens on 127.0.0.1:8080
# open: http://127.0.0.1:8080/#token=3f9c…   (open this exact URL)
./almap --web --web-bind 0.0.0.0        # all interfaces (prints a warning)
```

At startup the server prints a random API token. The page reads it from the URL fragment, and every `/api/` call must send it as `Authorization: Bearer <token>`. The server also refuses requests whose `Host` is not `localhost` or an IP address on its port (this blocks DNS rebinding), and requests whose `Origin` is not its own. `POST /api/scan` needs `Content-Type: application/json`. The API's `script` field takes a plugin **name** such as `http_title`, never a path. Only a `.so` file directly inside `plugins/` next to the binary is loaded.

Requests are bounded: a request has 2 seconds to arrive, at most 8 KiB, and 32 connections can wait at once. One scan runs at a time (a second gets 409), a scan is killed after 300 seconds, when the client disconnects, or when the server stops, and its output is returned whole (up to 16 MiB) or as a JSON error, never cut off. Responses carry `nosniff`, `X-Frame-Options: DENY` and `Cache-Control: no-store`. The audit and what was fixed are in [docs/plans/2026-11-22-web-security-scan.md](docs/plans/2026-11-22-web-security-scan.md).

> **Security note:** Anyone who has the token can run scans, and plugins run as the user running ALmap. With `--web-bind 0.0.0.0`, the token travels over plain HTTP. Avoid running the Web UI as root on a shared network. See [Known limits](#known-limits).

## ALmap and Nmap

| | ALmap | Nmap |
|---|---|---|
| Codebase | Small: Goose + C | Large: C++ / Lua |
| Async connect engine | Yes, up to 10k in flight | Yes |
| Scripting | Native C plugins (5 verified checks so far, see [Plugins](#plugins)) | NSE (600+ Lua scripts) |
| IPv6 | Connect + discovery | Full |
| Platforms | Linux | Cross-platform |

Use Nmap when you need its huge script library, full IPv6 coverage, or Windows and macOS support. Use ALmap when you want a small, predictable Linux scanner you can read, extend in C, and script through clean JSON.

## Known limits

- **Plugins.** Only 17 of 566 are verified; the rest are experimental. The SMB version and Samba CVE checks read the version from the SMB1 "Native LAN Manager" string of an anonymous session setup, so they say `INFO` (version not disclosed) for any server with SMB1 switched off, which is the default of current Samba and Windows; they are banner-only and distributions backport fixes. `smb-os-discovery` and `smb-cve-*` send only the NTLMSSP negotiate message, never credentials. The SMB checks have only been run against Samba, never against a Windows server. The SSH checks open several connections that never authenticate (`ssh-hostkey` opens three); OpenSSH 9.8 and later throttles a source address that does this (`PerSourcePenalties`), after which the checks print that no SSH identification line came back. The SSH CVE checks read the banner only: distributions backport fixes without changing it, and OpenBSD announces the same string but is not affected by CVE-2024-6387. Each SSH connection has a time budget of twice `--timeout`; `ssh-hostkey` makes three connections. Plugins run inside the scanner process with its full privileges and no sandbox or isolation, so a crashing or hanging plugin takes the scan down with it. `--script` runs one plugin per scan on every open port; there is no selection by category or service.
- **Privileges.** A scan that opened raw sockets keeps root (or `CAP_NET_RAW`) for the whole life of the process; there is no privilege drop.
- **Web UI.** The server is single-threaded. Someone who has the token can still stall it by reading a large scan result very slowly (up to about 5 seconds plus 1 second per MiB, per scan). A flood of 32 idle connections, reopened every 2 seconds, can keep other clients out. A client that half-closes its connection after sending the request (for example `nc -N`) gets its scan killed without a reply. The scan child resolves the plugin path again when it loads it, so anyone who can write into `plugins/` can already run code as the ALmap user. With `--web-bind 0.0.0.0` the token and results travel in plain HTTP.
- **No benchmarks.** ALmap makes no speed claim against Nmap, masscan or any other scanner; none has been measured.
- **Databases.** No OS database ships (import Nmap's), and the shipped service database is small (see Features).
- **Platform.** Linux x86-64 only.

## Testing

```sh
cd almap
bash tests/run_all.sh                 # everything: build, unit and integration tests, lint
bash tests/run_all.sh --no-skips      # what CI runs: a skipped test is a failure
unshare -Urn bash -c 'ip link set lo up; bash tests/run_all.sh --no-skips'   # raw-socket tests without root
bash tests/lab/run.sh tls             # one plugin family against its pinned podman containers (needs podman)
```

The raw-socket tests (SYN, UDP, OS fingerprinting) need root or `CAP_NET_RAW`; without it they report `SKIP` instead of passing. CI (`.github/workflows`) builds, runs every test with `--no-skips`, runs every family's lab, and only counts a plugin as verified if all of its lab cases passed in that run.

## Roadmap

- [x] Web UI bound to `127.0.0.1` by default, with token auth, Host/Origin checks, bounded requests and plugin-name-only `script`
- [x] Plugin tiers with evidence rules, a podman lab and CI that fails on skipped tests
- [ ] Verify the remaining 549 plugins family by family (databases, DNS, then HTTP and the CVE checks; TLS, SSH and SMB are done); see [docs/PLUGINS.md](docs/PLUGINS.md)
- [ ] SSH transport layer (KEX + cipher + MAC) to bring back a real `ssh-auth-methods`
- [ ] SMB transport layer (authenticated session setup, tree connect, DCE/RPC over named pipes) to bring back share, user and group enumeration, `smb-ls`, `smb-brute` and a lab-verified MS17-010 / MS08-067 check (needs a Windows target in the lab)
- [ ] Select plugins by name pattern, category and port or service
- [ ] HTTPS for the Web UI when it is bound beyond localhost
- [ ] Published benchmarks against Nmap, masscan and RustScan
- [ ] Next.js dashboard (see [WEB_UI_PLAN.md](almap/WEB_UI_PLAN.md))
- [ ] Debian / Arch packages

## Legal

Use ALmap only on systems you own or have explicit, written permission to test. Scanning, packet spoofing and evasion can disrupt networks and may be illegal where you live. Evasion features do not make a scan legal or undetectable. You are responsible for how you use this tool.

## License

MIT. See [LICENSE](LICENSE).

---

<div align="center">

Made by **Saher** · [@SaherSec](https://x.com/SaherSec)

</div>
