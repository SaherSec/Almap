<div align="center">

# ALmap

**A fast, auditable network scanner for Linux, written in Goose and C.**

Async connect engine · Raw SYN/UDP · OS fingerprinting · Native C plugins · JSON/XML output · Built-in Web UI

`v5.0.0` · Linux x86-64 · MIT

</div>

---

ALmap is a network scanner with a small core you can read. The scanning logic lives in [Goose](https://github.com/aardappel/goose), a memory-safe systems language with no heap and no garbage collector. A thin C layer owns sockets, raw packets, threads and plugin loading.

The goal is not to replace Nmap everywhere. It is a scanner that is fast and predictable, and simple enough to read end to end.

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
| **AlScript plugins** | Plain `.so` files that export one C function. No VM and no Lua. 623 plugins: about 100 full protocol checks, the rest fingerprint/experimental (see [Plugins](#plugins)). |
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

`almap/plugins/` holds 623 C plugins. Most of them are small, and many are numbered variants (`-2` … `-5`) of the same probe:

- **About 100 are full protocol checks.** They speak SMB, TLS, SSH, DNS, SNMP, MSSQL, MySQL, PostgreSQL, Oracle TNS, VNC or Kerberos and parse the reply. Examples: `smb-vuln-ms17-010-full`, `ssl-enum-ciphers`, `ssh-hostkey`, `kerberos-asreq-full`.
- **The rest are fingerprints or experimental.** Most send one HTTP request or a fixed payload and match a status code or a substring. They hint that a product or an exposed path is there. They do not prove a vulnerability, even when the plugin is named after a CVE. Some only check that the port is open.

`--script` runs one plugin per scan, on every open port. There is no category or port-based selection yet.

Plugins are built from the C sources in `almap/plugins/` with `tools/build_plugins.sh`; no prebuilt plugin binaries are committed.

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

At startup the server prints a random API token. The page reads it from the URL fragment, and every `/api/` call must send it as `Authorization: Bearer <token>`. The server also refuses requests whose `Host` is not `localhost` or an IP address on its port (this blocks DNS rebinding), and requests whose `Origin` is not its own. The API's `script` field takes a plugin **name** such as `http_title`, never a path. Only a `.so` file directly inside `plugins/` next to the binary is loaded.

> **Security note:** Anyone who has the token can run scans, and plugins run as the user running ALmap. With `--web-bind 0.0.0.0`, the token travels over plain HTTP. Avoid running the Web UI as root on a shared network.

## ALmap and Nmap

| | ALmap | Nmap |
|---|---|---|
| Codebase | Small: Goose + C | Large: C++ / Lua |
| Async connect engine | Yes, up to 10k in flight | Yes |
| Scripting | Native C plugins (~100 full protocol checks) | NSE (600+ Lua scripts) |
| IPv6 | Connect + discovery | Full |
| Platforms | Linux | Cross-platform |

Use Nmap when you need its huge script library, full IPv6 coverage, or Windows and macOS support. Use ALmap when you want a small, predictable Linux scanner you can read, extend in C, and script through clean JSON.

## Roadmap

- [x] Web UI bound to `127.0.0.1` by default, with token auth, Host/Origin checks and plugin-name-only `script`
- [ ] HTTPS for the Web UI when it is bound beyond localhost
- [ ] Published benchmarks against Nmap, masscan and RustScan
- [ ] More AlScript plugins
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
