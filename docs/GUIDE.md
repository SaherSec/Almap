# ALmap v5.1.0

**A small, auditable network scanner for Linux, written in
[Goose](https://github.com/aardappel/goose) with a C data plane.**

ALmap is a network scanner built around an asynchronous `epoll` connect engine, bounded pthread worker pools, raw SYN/UDP
probing, host discovery, evasion controls, native C plugins, and
runtime service/OS signature databases. The Goose layer has no heap and
no garbage collector; all Goose state is fixed-capacity, while C owns
sockets, raw packets, threads, `dlopen`, and POSIX regex.

## What is new in 5.1.0

- **A hardened Web UI.** Loopback by default, a random API token on every
  `/api/` call, Host/Origin checks, JSON-only scan requests, bounded
  requests, one scan at a time with a wall-clock limit, complete JSON output.
- **Plugins with evidence rules.** Every plugin has a tier and a status in
  `plugins/MANIFEST.tsv`; only plugins proven against real vulnerable and
  patched targets may print `VULNERABLE` (see [AlScript native C
  plugins](#alscript-native-c-plugins) and [PLUGINS.md](PLUGINS.md)).
- **Tests that cannot hide.** One entry point (`tests/run_all.sh`), skipped
  tests exit 77 and fail CI, and a podman lab runs each plugin family
  against pinned containers.
- **A clean repository.** No committed binaries; the C sources are the only
  plugin source.

See the [CHANGELOG](../CHANGELOG.md) for details and the old-to-new plugin
names.

## Features

- **Async epoll engine (`--fast`).** One non-blocking `epoll` loop
  keeps up to 10,000 TCP connects in flight, paced by a token-bucket
  rate limiter. No root needed.
  ```sh
  # Copy-paste: async scan a /24, 500ms timeout, 1024 ports
  ./almap -t 192.168.1.0/24 -p 1-1024 --scan connect --fast --timeout 500
  ```
- **Advanced OS Fingerprinting (T1-T7 + U1).** After the SYN scan,
  `--os` sends the Nmap-style probe sequence (T1 `SYN` open, T2 `NULL`
  open, T3 `SYN|FIN|URG|PSH` open, T4 `ACK` open, T5 `SYN` closed,
  T6 `ACK` closed, T7 `FIN|PSH|URG` closed, plus U1 empty UDP → ICMP
  Port Unreachable) and analyzes TTL, window, ISN, TCP options, and
  IP ID behaviour (`ZERO`/`INC`/`RAND`/`BRKN`). Results collapse to
  one probe signature (`T1=SYNACK,T2=RST,...,U1=UNREACH,ID=ZERO`)
  matched against the full DB.
  ```sh
  # Copy-paste: T1-T7 OS fingerprint (requires root/CAP_NET_RAW)
  sudo ./almap -t 192.168.1.10 -p 22,80 --scan syn --os --timeout 1000
  sudo ./almap -t 192.168.1.10 -p 22,80 --scan syn --os --osdb /tmp/os-signatures.db --json
  ```
- **Evasion: Fragment, MTU, Decoys, MAC spoofing.** RFC 791 IP
  fragmentation, custom MTU, up to 5 decoy sources, source-MAC
  spoofing on the Ethernet segment (SYN/connect only, raw-socket
  effect on SYN).
  ```sh
  # Copy-paste: evasion SYN scans
  sudo ./almap -t 192.168.1.10 -p 80 --scan syn -f
  sudo ./almap -t 192.168.1.10 -p 80 --scan syn --mtu 64
  sudo ./almap -t 192.168.1.10 -p 80 --scan syn -D 10.0.0.1,10.0.0.2
  sudo ./almap -t 192.168.1.10 -p 80 --scan syn --spoof-mac aa:bb:cc:dd:ee:ff
  ```
- **AlScript C plugins (no VM, no Lua).** Ordinary `.so` files
  exporting `int almap_script_run(AlScriptContext*)`, run in-process
  with full privileges. Every plugin is built from the C sources in
  `plugins/`; five of them (the TLS checks) are proven against real
  targets so far and the rest are experimental and print `INFO` only.
  ```sh
  # Copy-paste: build the plugins and scan with one
  bash tools/build_plugins.sh
  ./almap -t 127.0.0.1 -p 80 --scan connect --script ./plugins/http_title.so
  ./almap -t 127.0.0.1 -p 22 --scan connect --script ./plugins/ssh_version.so --json
  ./almap -t 127.0.0.1 -p 21 --scan connect --script ./plugins/ftp_anon.so
  ```
- **Import of Nmap's databases.** The service DB (8k+ entries)
  and OS DB (1k+ unique of 6,100 Fingerprints) live in a dynamic C
  `malloc`/`realloc` hash table (16k buckets). 10,000-entry / 1,000-
  lookup benchmarks run in <1 ms.
  ```sh
  # Copy-paste: import the full Nmap DBs
  python3 tools/import_nmap.py /usr/share/nmap/nmap-service-probes -o ~/.almap/signatures.db
  python3 tools/import_nmap_os.py /usr/share/nmap/nmap-os-db -o ~/.almap/os-signatures.db
  ./almap -t 127.0.0.1 -p 22,80 --scan connect --service --sigdb ~/.almap/signatures.db
  ```
- **Native C Web UI.** Dark-mode SPA served by raw
  POSIX sockets (no mongoose/libmicrohttpd), embedded HTML/CSS/JS.
  API: `GET /api/status`, `POST /api/scan` (with `script` field).
  ```sh
  # Copy-paste: launch the Web UI on 8080
  ./almap --web            # prints "API token: <token>"
  TOKEN=<token from the startup output>
  curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/status
  curl -X POST http://127.0.0.1:8080/api/scan -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"targets":"127.0.0.1","ports":"80,443","scan_type":"connect","script":"http_title"}'
  ```


## Authorized use only

> **Warning: use ALmap only on systems you own or have explicit,
> written permission to test.**
>
> Port scanning, host discovery, raw-packet injection, spoofing, and
> evasion can disrupt networks and may be illegal where you live.
> Running a scan is not authorization. "Stealth", fragmentation, decoys,
> and MAC spoofing do not make scanning lawful or undetectable.
>
> SYN, UDP, evasion, and `--os` paths need root or `CAP_NET_RAW`.
> AlScript plugins are untrusted native code loaded into the scanner
> process with no sandbox and full process privileges. Run only code you
> wrote or trust.
>
> Imported Nmap databases remain subject to Nmap's licensing terms.
> OS labels are heuristic guesses, not facts. ALmap comes with no
> warranty; you are responsible for how you use it.

## Why ALmap

- **A non-blocking connect engine.** One `epoll` loop can keep up to
  10,000 TCP connect attempts in flight (`--fast`), with token-bucket
  rate limiting and deadline-driven timeouts. No speed comparison with
  other scanners has been measured.
- **Deterministic output.** Targets are emitted in input order, hosts
  ascending, and ports in CLI order. Text, JSON, table, and XML all use
  the same result model.
- **A small, auditable core.** Goose modules handle parsing, scan
  planning, and formatting; focused C files own the network I/O. No
  hidden runtime or garbage collector.
- **Extensible without a VM.** AlScript plugins are ordinary shared
  objects exporting one C function, and service/OS databases are plain
  text loaded at runtime.
- **Nmap data, ALmap engine.** Import Nmap's service probes and OS
  fingerprints into ALmap's compact formats with the Python tools in
  `tools/`.

## Feature comparison

| Capability | ALmap v5.1.0 | Nmap |
| --- | --- | --- |
| TCP connect / SYN / UDP scans | Yes | Yes |
| Asynchronous connect engine | Yes: `--fast`, up to 10,000 in flight | Yes, different engine |
| Host discovery | TCP ping + optional ICMP echo | Broad |
| Multiple targets / CIDR | `-t`, `-iL`, IPv4 `/24`–`/32`, IPv6 `/112`–`/128` | Broad |
| IPv6 | Connect and discovery only | Broad |
| Service detection | Built-in heuristics + full Nmap Regex DB (hash table, 8k+ entries) | Large probe database |
| OS fingerprinting | T1-T7+U1 probe signature + TTL/window/IPID/ISN/options + DB | Deep fingerprint database |
| Scripting | AlScript native C plugins (5 verified checks so far) | NSE (Lua) |
| Evasion | Fragmentation, MTU, decoys, MAC spoofing | Broader set |
| Output | Text, JSON, table, XML | Text, XML, grepable |
| Platforms | Linux (POSIX) | Cross-platform |
| Language/runtime | Goose + C, no Goose heap/GC | C++/Lua |

ALmap intentionally focuses on a compact, deterministic, Linux-native
scanner. Nmap remains the better choice when you need its full NSE
ecosystem, exhaustive probe coverage, or cross-platform support.

## Getting started

### Requirements

- Linux with a POSIX toolchain
- GCC and `pthread`/`dl` (standard on Linux)
- The Goose compiler, version 2026.3 or newer
- Python 3 only for the Nmap DB importers and some test listeners

### Build

```sh
# Adjust this path to your Goose installation.
export GOOSE_STDLIB="$HOME/Downloads/goose-v2026.3-linux-x64/stdlib"

goose check almap.goose
goose build almap.goose --cc gcc -o almap
./almap --help
```

The first line of `--help` should read `ALmap v5.1.0 - modular network
scanner`. If Goose cannot find its standard library, pass
`--stdlib /path/to/stdlib` or keep `GOOSE_STDLIB` exported for every
Goose command.

Build the sample AlScript plugin when you want to try `--script`:

```sh
gcc -std=c99 -Wall -Wextra -shared -fPIC \
    -o sample_banner.so plugins/sample_banner.c
```

### First scans

```sh
# Unprivileged TCP connect scan.
./almap -t 127.0.0.1 -p 22,80,443

# Asynchronous connect scan over a /24 (no root required).
./almap -t 192.168.1.0/24 -p 1-1024 --scan connect --fast --timeout 500

# Raw SYN scan, discovery, and UDP scan (root or CAP_NET_RAW).
sudo ./almap -t 192.168.1.10 -p 1-1024 --scan syn
sudo ./almap -t 192.168.1.0/24 --discover
sudo ./almap -t 192.168.1.10 -p 53,123,161 --scan udp

# Structured output.
./almap -t 127.0.0.1 -p 22,80 --json
./almap -t 127.0.0.1 -p 22,80 --table
./almap -t 127.0.0.1 -p 22,80 --xml
```

Run `./almap --help` for the complete flag list and validation rules.
Defaults: `--scan connect`, `--timeout 1000`, `--workers 10`,
`--rate 0` (unlimited).

## Feature guide

### Scan modes and execution paths

- **Connect** (default) completes a full TCP handshake. It needs no
  privileges and is the only IPv4/IPv6 mode.
- **SYN** sends raw TCP SYN packets and needs root or `CAP_NET_RAW`.
  It is IPv4-only.
- **UDP** sends raw UDP probes and needs root or `CAP_NET_RAW`. It is
  IPv4-only.
- **Discovery** uses TCP ping plus optional ICMP echo and supports
  IPv4 and IPv6.
- **`--fast`** uses the asynchronous `epoll` connect engine. It is
  IPv4, connect-only, and cannot be combined with banners, service
  detection, scripting, evasion, or `--os`.
- **`--workers 2..1000`** enables the bounded pthread pool for
  connect, SYN, and discovery paths. Ports are capped at 4,096 per
  worker-pool batch; `--fast` ignores `--workers`.
- **Banners and service detection** are IPv4 connect-only and force a
  sequential path.
- **IPv6** supports connect and discovery only. SYN, UDP, banners,
  service detection, AlScript, evasion, and `--os` reject IPv6 targets.

Output is deterministic: target entries in input order, hosts
ascending, and ports in the order supplied on the command line.

### Service detection and the custom service DB

`--service` performs basic version/banner detection on open connect-scan
ports. It understands HTTP `Server:` headers, SSH, FTP, SMTP, and MySQL
initial greetings, then falls back to cleaned banner text.

Custom signatures are loaded with `--sigdb <path>` (required to be
usable with `--service`). Without `--sigdb`, ALmap silently tries
`~/.almap/signatures.db` and then the built-in rules. The shipped
`signatures.db` mirrors the defaults.

Format, one rule per line:

```text
EXACT|<port_or_any>|<literal_substring>|<service_name>
REGEX|<port_or_any>|<posix_ere_pattern>|<service_name>
```

Examples:

```text
EXACT|80|Server:|http
REGEX|any|^SSH-[0-9]+\.[0-9]+-|ssh
REGEX|9000|^MYAPP/[0-9]+\.[0-9]+|myapp
```

- `EXACT` is a case-sensitive literal substring search.
- `REGEX` is POSIX extended regex (`regcomp`/`regexec`), not PCRE.
- `any` matches every port; a numeric port matches only that port.
- The pattern may contain `|`; the last `|` ends the pattern field.
- Blank lines and lines starting with `#` are ignored.
- First match wins; invalid lines are skipped; no fixed cap (Step 29
  full Nmap DB, 20,000+ entries via malloc/realloc + port hash table).

Try a custom database:

```sh
cat >/tmp/custom-signatures.db <<'EOF'
REGEX|any|^SSH-[0-9]+\.[0-9]+-|ssh
EXACT|8080|Server:|http-alt
EOF

./almap -t 127.0.0.1 -p 22,8080 --scan connect \
    --service --sigdb /tmp/custom-signatures.db
```

Install the shipped rules as the per-user default:

```sh
mkdir -p "$HOME/.almap"
cp signatures.db "$HOME/.almap/signatures.db"
```

### OS fingerprinting and the custom OS DB

`--os` performs advanced SYN/ACK + T1-T7/U1 OS fingerprinting. It requires
`--scan syn` and root or `CAP_NET_RAW`. Hosts without an open port are
reported as `unknown`; routers, NAT, and proxies can mislead the
result.

After the SYN scan, ALmap sends the Nmap-style probe sequence (raw
sockets, `IP_HDRINCL`, careful seq/checksums) to the first open and
first closed ports found for a host:

| Probe | Target | TCP flags / payload |
| --- | --- | --- |
| T1 | open | `SYN` (`0x02`) |
| T2 | open | `NULL` (`0x00`) |
| T3 | open | `SYN\|FIN\|URG\|PSH` (`0x2B`) |
| T4 | open | `ACK` (`0x10`) |
| T5 | closed | `SYN` |
| T6 | closed | `ACK` |
| T7 | closed | `FIN\|PSH\|URG` (`0x29`) |
| U1 | closed | empty UDP (ICMP Port Unreachable expected) |

Each reply is parsed for TTL, TCP window, ISN (sequence number),
and TCP options (`MSS`, `SACK`, `TS`, `WS`). IP IDs across probes
are classified as `ZERO` (all 0), `INC` (+1 incremental), `RAND`
(random), `BRKN` (duplicate/backwards), or `OTH`. The 8 replies are
formatted into one signature string:

```text
T1=SYNACK,T2=RST,T3=RST,T4=RST,T5=RST,T6=NONE,T7=NONE,U1=UNREACH,ID=ZERO,OPTS=MSS+SACK+TS,ISN=NONZERO
```

(`SYNACK`/`RST`/`NONE`/`OTHER`/`UNREACH` are the per-probe outcomes;
`ID`, `OPTS`, `ISN` summarize the SYN+ACK and the full sequence.)

Without a database, ALmap emits coarse labels from TTL/window/
options/IP-ID votes: `linux-like`, `windows-like`, `network-device`,
or `unknown` (Step 19 heuristics, unchanged as the fallback).

With `--osdb <path>` (or the default `~/.almap/os-signatures.db`),
matching rows take precedence. Format (6th `PROBE` field is optional
in Step 31):

```text
OS_NAME|MIN_TTL|MAX_TTL|WINDOW_SIZE|TCP_OPTIONS_FLAG|PROBE
```

Example:

```text
Linux 6.x|55|64|0|MSS,SACK,TIMESTAMPS|T1=SYNACK,T2=RST,T3=RST,T4=RST,T5=RST,T6=NONE,T7=NONE,U1=UNREACH,ID=ZERO
Windows 10/11|110|128|64240|MSS,SACK,TIMESTAMPS|T1=SYNACK,T2=RST,T3=RST,T4=RST,T5=RST,T6=RST,T7=NONE,U1=UNREACH,ID=INC
Network Device|1|255|0|
```

- `MIN_TTL` and `MAX_TTL` are inclusive decimal bounds in `1..255`.
- `WINDOW_SIZE` is `0..65535`; `0` matches any observed window.
- `TCP_OPTIONS_FLAG` is a comma list of `MSS`, `SACK`, `WS`/
  `WINDOWSCALE`, and `TS`/`TIMESTAMPS`; an empty field is a wildcard.
  All listed options must be present, extra options are allowed.
- `PROBE` (optional) is the T1-T7+U1 signature pattern. Empty is a
  wildcard; otherwise the collected signature must match exactly or
  as POSIX ERE (first match that also passes TTL/window/options wins).
  The probe field may itself contain `|` (everything after the 5th
  `|` is the probe).
- `OS_NAME` is 1..64 printable bytes and may contain spaces.
- First match wins; no fixed cap (Step 29 full Nmap DB, 20,000+ rows).
- An explicit unreadable `--osdb` path exits 1. The default path is
  optional so hosts without a DB keep the fallback labels.

Try it:

```sh
sudo ./almap -t 192.168.1.10 -p 22,80 --scan syn --os \
    --osdb /tmp/os-signatures.db --json
```

### Evasion controls

```sh
# 8-byte IP fragments (raw SYN effect).
sudo ./almap -t 192.168.1.10 -p 80 --scan syn -f

# Custom fragment MTU (multiple of 8, 32..65535; implies -f).
sudo ./almap -t 192.168.1.10 -p 80 --scan syn --mtu 64

# Up to five decoy source addresses.
sudo ./almap -t 192.168.1.10 -p 80 --scan syn \
    -D 10.0.0.1,10.0.0.2

# Source MAC spoofing on the local Ethernet segment.
sudo ./almap -t 192.168.1.10 -p 80 --scan syn \
    --spoof-mac aa:bb:cc:dd:ee:ff
```

Evasion flags are accepted only with `--scan syn` or `--scan connect`.
Fragmentation, MTU, decoys, and MAC spoofing shape raw SYN packets and
need root or `CAP_NET_RAW`; connect scans use the kernel TCP stack, so
those controls do not change the packets. Evasion cannot be combined
with `--fast`, `--os`, `--script`, `--banners`, or `--service`.

### AlScript native C plugins

AlScript plugins are shared objects exporting:

```c
int almap_script_run(AlScriptContext *ctx);
```

Include [`c/alscript.h`](c/alscript.h), run the plugin against open
ports with `--script`, and read its capped text output as `script_out`
in every output format:

```sh
gcc -std=c99 -Wall -Wextra -shared -fPIC \
    -o sample_banner.so plugins/sample_banner.c

./almap -t 127.0.0.1 -p 80 --scan connect \
    --script ./sample_banner.so

sudo ./almap -t 127.0.0.1 -p 80 --scan syn \
    --script ./sample_banner.so --json
```

Plugins run in-process with full privileges, no sandbox, and no
timeout isolation beyond the context's `timeout_ms`. Output is capped
at 1023 bytes. Load only plugins you trust.

**Tiers and evidence.** `plugins/MANIFEST.tsv` gives every plugin a tier
(`vuln`, `detect`, `info` or `experimental`) and a status (`lab`,
`captured`, `derived` or `experimental`). [PLUGINS.md](PLUGINS.md) is
generated from it and shows four separate counts: Verified (lab), Verified
(captured fixture), Detected (derived fixture) and Experimental. The rules,
enforced by `tests/lint_plugins.sh`:

- Only a `vuln` plugin proven in the lab (against a real vulnerable target,
  a real patched one and a neutral control) may print `VULNERABLE` or
  `NOT VULNERABLE`.
- A plugin backed only by fixtures prints `DETECTED` / `NOT DETECTED`,
  never `VULNERABLE`; a derived fixture comes from a published scanner
  matcher and proves the product, not the vulnerability.
- An experimental plugin prints lines that start `<name>: INFO`.
- Silence, a closed connection or an unexpected reply is never evidence:
  it prints `INFO` with the reason.
- Fixtures must be real captures with a `.SOURCE` record; none is invented.

The lab (`tests/lab/<family>`) starts pinned podman containers on
127.0.0.1 and runs each plugin against vulnerable, patched and neutral
targets: `bash tests/lab/run.sh tls`. Writing the cases first, from
independent ground truth, is how the TLS family found that the earlier
Heartbleed plugins missed a vulnerable server.

### Output formats

```sh
./almap -t 127.0.0.1 -p 22,80 --scan connect --service --json
./almap -t 127.0.0.1 -p 22,80 --scan connect --service --table
./almap -t 127.0.0.1 -p 22,80 --scan connect --service --xml
```

`--json`, `--table`, and `--xml` are mutually exclusive. JSON and XML
are suitable for automation; table output is tab-separated. IPv6
addresses are bracketed in text/table output (`[::1]:80`) and plain in
JSON/XML.

## Web UI

ALmap ships a lightweight, dependency-free Web UI in the same binary.
It is activated with `--web` (alias `--ui`) and serves a dark-mode
single-page frontend plus a JSON API on `127.0.0.1:8080` (override the
port with `--web-port <port>` or `--web <port>`, and the address with
`--web-bind <ipv4>`, for example `0.0.0.0` for all interfaces). The server uses native C
sockets (`c/http.c`); Goose (`modules/webui.goose`) owns routing, HTML
generation, JSON parsing, and validation, mirroring the CLI rules.

```sh
# Start the UI on the default port 8080.
./almap --web
# Start on a custom port.
./almap --web --web-port 18081
# Alias.
./almap --ui --web-port 18081
# Listen on all interfaces (prints a warning).
./almap --web --web-bind 0.0.0.0
```

### Access control

- **Token.** At startup the server prints a random 128-bit API token and a URL of the form `http://127.0.0.1:8080/#token=<token>`. Every `/api/` request must send `Authorization: Bearer <token>`, or it gets 401. The page reads the token from the URL fragment, keeps it in `sessionStorage` and removes it from the address bar. A new token is made at each start.
- **Host and Origin.** Every request needs a `Host` header that is `localhost` or an IPv4 address with the listening port. Hostnames are refused (403), which blocks DNS rebinding. A request that carries an `Origin` header other than `http://<Host>` is refused (403), which blocks cross-site requests from other pages.
- **Plugins.** The `script` field takes a plugin name (`http_title` or `http_title.so`). Paths, `..` and unknown names are refused (400). The name is resolved to `<directory of the almap binary>/plugins/<name>.so`, and only a regular file directly inside that directory is used, so a symlink that points elsewhere is refused.

Then open the URL printed at startup in a browser. The page has a form
for targets and ports, a scan-type select (Connect, SYN, UDP,
Discovery), toggles for Fast (async engine), OS fingerprinting,
Service detection, and Evasion, a timeout field, and a terminal-like
output window. It polls `GET /api/status` on load and `POST /api/scan`
on submit.

### API

```sh
TOKEN=<token printed at startup>
AUTH="Authorization: Bearer $TOKEN"

# Health check.
curl -H "$AUTH" http://127.0.0.1:8080/api/status
# {"status":"ok","version":"5.1.0","service":"almap-web"}

# Connect scan: returns ALmap's --json output.
curl -X POST http://127.0.0.1:8080/api/scan -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"targets":"127.0.0.1","ports":"80,443","scan_type":"connect","timeout":1000}'

# Discovery, Fast, OS, Service, and Evasion flags.
curl -X POST http://127.0.0.1:8080/api/scan -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"targets":"192.168.1.0/24","scan_type":"discovery","timeout":500}'
curl -X POST http://127.0.0.1:8080/api/scan -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"targets":"127.0.0.1","ports":"80","scan_type":"connect","fast":true}'
# A plugin, by name.
curl -X POST http://127.0.0.1:8080/api/scan -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"targets":"127.0.0.1","ports":"80","scan_type":"connect","script":"http_title"}'
```

`POST /api/scan` accepts `targets` (required), `ports` (required
unless discovery), `scan_type` (`connect` default, `syn`, `udp`,
`discovery`), `fast`, `os`, `service`, `evasion`, `discover`,
`timeout` (ms), `retries`, and `script` (a plugin name). It validates flag combinations exactly like the CLI
(for example, `fast` needs `connect`, `os` needs `syn`) and spawns
the ALmap binary as a child with `--json`, returning its JSON result
on success (200) or `{"error":"..."}` on failure (400/500). A missing
or wrong token returns 401; a foreign `Host` or `Origin` returns 403.
Unknown paths return 404. `POST /api/scan` requires `Content-Type:
application/json` (415 otherwise) and a request of at most 8 KiB (413).
A request has 2 seconds to arrive and at most 32 connections can wait at
once. Only one scan runs at a time (a second gets 409); a scan is killed
after 300 seconds (504), when its client disconnects, or when the server
stops, and its output (up to 16 MiB) is returned whole or as a JSON error
(500 with `"truncated":true`), never cut off. `/api/status` also reports
`"scan_running"`. Every response carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, a `frame-ancestors 'none'` policy and
`Cache-Control: no-store`. The server inherits its own privileges, so
SYN/UDP/OS scans still need root or `CAP_NET_RAW`.

Known limits: the server is single-threaded, so a token holder reading a
large result very slowly can still delay it (up to about 5 seconds plus 1
second per MiB); a flood of 32 idle connections can lock others out for 2
seconds at a time; a client that half-closes after sending its request gets
its scan killed without a reply. The security audit is in
[plans/2026-11-22-web-security-scan.md](plans/2026-11-22-web-security-scan.md).

## Importing Nmap databases

ALmap does not ship Nmap's databases. The importers convert a local
Nmap installation into ALmap's compact text formats. Nmap-derived data
remains subject to Nmap's license; do not commit generated databases to
the ALmap source tree.

### Service probes: `tools/import_nmap.py`

```sh
# Convert Nmap service probes into the default ALmap DB.
python3 tools/import_nmap.py /usr/share/nmap/nmap-service-probes \
    -o "$HOME/.almap/signatures.db"

# Keep only 128 rules, include softmatch lines, and print a summary.
python3 tools/import_nmap.py /usr/share/nmap/nmap-service-probes \
    --include-softmatch --max 128 \
    -o /tmp/signatures.db
```

The importer:

- reads `match` lines by default and `softmatch` with
  `--include-softmatch`;
- maps service names to TCP ports using the sibling `nmap-services`
  file when present (Nmap's `p/` field is a product name, not a port);
- accepts `--services PATH` to override that mapping, `--port N|any` to
  force a port, and `--all-ports` to emit one row per mapped port;
- translates common PCRE (`\d`, `\w`, `\s`, `\xNN`, `(?:...)`,
  `(?>...)`, named groups) to POSIX ERE;
- skips patterns it cannot represent safely (NUL/binary bytes,
  lookarounds, inline flags, patterns over 255 bytes) and reports the
  counts; and
- emits ALL valid signatures by default (`--max` 1..50000, default 50000;
  ~8k lines from Nmap 7.991, 14k with `--all-ports`). Patterns longer
  than 4096 bytes or with NUL/binary bytes are still skipped.

Use `-o -` (the default) to write to stdout.

### OS fingerprints: `tools/import_nmap_os.py`

```sh
# Convert Nmap OS fingerprints into the default ALmap OS DB.
python3 tools/import_nmap_os.py /usr/share/nmap/nmap-os-db \
    -o "$HOME/.almap/os-signatures.db"

# Smaller balanced sample.
python3 tools/import_nmap_os.py /usr/share/nmap/nmap-os-db \
    --max 64 -o /tmp/os-signatures.db
```

The importer:

- reads `Fingerprint` blocks and maps `Class` families to `Linux`,
  `Windows`, or `Network Device`;
- converts hexadecimal TTL ranges/alternatives to inclusive decimal
  bounds and clamps them to `1..255`;
- uses `WIN(W1=)` for the window (ranges/alternatives become the `0`
  wildcard);
- maps `OPS(O1=)` option letters `M`/`S`/`T` to
  `MSS`/`SACK`/`TIMESTAMPS`;
- removes duplicates; and
- imports ALL unique rows by default (`--max` 1..20000, default 20000;
  6100 Fingerprints deduplicate to ~1200 category rows) ordered
  deterministically (exact-window + narrowest TTL first per category,
  then round-robin) so first-match-wins favors specific rows.

Both importers use only the Python standard library.

## Tests

One entry point runs everything (build, unit tests, plugin lint, every
integration test) from the `almap/` directory:

```sh
export GOOSE_STDLIB="$HOME/Downloads/goose-v2026.3-linux-x64/stdlib"

bash tests/run_all.sh               # PASS / SKIP / FAIL per test and a summary
bash tests/run_all.sh --no-skips    # a skipped test is a failure (what CI runs)
bash tests/run_all.sh --only integration_syn
```

A test exits 0 for PASS, 77 for SKIP and anything else for FAIL. The
raw-socket tests (SYN, UDP, OS fingerprinting) need root or
`CAP_NET_RAW` and report SKIP without it. To run them without root, use a
user namespace with loopback enabled:

```sh
unshare -Urn bash -c 'ip link set lo up; bash tests/run_all.sh --no-skips'
```

The individual commands behind `run_all.sh` (from `AGENTS.md`):

```sh
goose check almap.goose
goose build tests/test_almap.goose --cc gcc -o /tmp/test_almap && /tmp/test_almap
gcc -std=c99 -Wall -Wextra -pthread -c c/*.c
bash tools/build_plugins.sh --werror
bash tests/lint_plugins.sh
```

The plugin lab needs podman and network access to pull its pinned images:

```sh
bash tests/lab/run.sh control        # nginx and OpenSSH, the neutral targets
bash tests/lab/run.sh tls            # the TLS family against vulnerable and patched servers
bash tests/lab/selftest.sh           # the lab runner itself
```

CI (`.github/workflows/ci.yml` and `lab.yml`) runs all of this on every push;
a plugin only counts as verified if all of its lab cases passed in that run.

## Release packaging

`tools/build_release.sh` typechecks the sources, builds the binary and
sample plugin, stages the service DB plus an optional OS DB, and writes
a versioned tarball under `dist/`. The fingerprint DBs are now dynamic
(C malloc/realloc + port hash table, no 256 cap) so the release can stage
full Nmap imports (8k+ service, 1k+ OS rows).

```sh
# Package with whichever OS DB can be found/imported automatically.
tools/build_release.sh

# Import Nmap's OS DB into the release package.
tools/build_release.sh --nmap-os-db /usr/share/nmap/nmap-os-db

# Include a prepared OS DB.
tools/build_release.sh --osdb "$HOME/.almap/os-signatures.db"
```

The archive is `dist/almap-<version>-linux-<arch>.tar.gz` and contains:

```text
almap-<version>-linux-<arch>/
  almap
  signatures.db
  os-signatures.db     # when available
  sample_banner.so
  README.md
  VERSION
```

A `.sha256` checksum is written beside the tarball when `sha256sum` is
available. The staging directory is removed by default; pass
`--keep-stage` to inspect it. `--max-os N` limits imported OS rows
(1..20000).

## Architecture

```text
almap.goose              CLI parsing, validation, dispatch, help
                         (--web starts the Web UI server)
modules/*.goose          Target/CIDR parsing, scan planning, output,
                         rate limiting, service/OS DB loading,
                         webui HTTP routing/HTML/JSON validation
c/net.c                  TCP connect and banner helpers
c/net6.c                 IPv6 connect helpers
c/raw.c                  Raw SYN, fragmentation, decoys, MAC spoofing
c/udp.c                  Raw UDP probes
c/icmp.c                 ICMP echo discovery
c/pool.c                 Bounded pthread worker pool
c/async.c                Non-blocking epoll connect engine
c/os.c                   SYN/ACK OS fingerprint helpers
c/alscript.c             dlopen/dlsym plugin loader
c/sigdb.c                Dynamic service DB (port hash table) + ERE bridge
c/osdb.c                 Dynamic OS DB (malloc/realloc, first-match)
c/http.c                 HTTP listen/accept/read/send + scan child exec
plugins/sample_banner.c  Example AlScript plugin
tools/import_nmap*.py    Nmap database importers
tests/                   Unit and loopback integration tests
```

The Goose layer stores all state in fixed-capacity arrays and has no
heap or garbage collector. C owns OS resources and releases file
descriptors, sockets, threads, and plugin handles on every path.
`almap.build` lists the C sources and links `pthread` and `dl`.

## Limits and known gaps

- Linux/POSIX only. There is no Windows or macOS build.
- Fixed capacities: 64 target entries, IPv4 `/24` and IPv6 `/112` as
  the smallest allowed CIDR blocks, 4,096 ports per pthread-pool or
  `--fast` batch, unbounded service/OS signatures (dynamic C tables),
  and 10,000
  in-flight sockets in `--fast`.
- IPv6 coverage is limited to connect scans and discovery.
- Service detection is intentionally small compared with Nmap's probe
  database. The importer is best-effort and skips unrepresentable PCRE.
- OS labels are heuristics. They are not Nmap-accurate fingerprinting.
- AlScript is not NSE: no Lua, no script library, one plugin per run,
  and no sandbox.
- Evasion can be defeated by normalization, filtering, and logging.
  It is not a guarantee of stealth.
- Raw modes and evasion require root or `CAP_NET_RAW`.

## Legal Disclaimer

**ALmap is provided "AS IS", without warranty of any kind,
express or implied, including without limitation the warranties of
merchantability, fitness for a particular purpose, and
non-infringement. In no event shall the authors or copyright holders
be liable for any claim, damages, or other liability, whether in an
action of contract, tort, or otherwise, arising from, out of, or in
connection with the software or the use or other dealings in the
software.**

- **Authorized use only.** Use ALmap exclusively on networks, hosts,
  and services you own or have explicit, prior, written permission to
  test. Scanning without authorization may violate the US Computer
  Fraud and Abuse Act (18 U.S.C. §1030), the EU Directive on
  attacks against information systems, and analogous laws. A
  "stealth" or "evasion" flag does not confer authorization.
- **Raw packets and evasion.** SYN/UDP/OS probing, fragmentation,
  decoy spoofing, and MAC spoofing originate crafted packets that can
  trigger IPS/IDS responses, consume bandwidth, crash fragile stacks,
  or violate acceptable-use policies. They require root or
  `CAP_NET_RAW` and can be logged or blocked.
- **No guarantee of accuracy.** Service names are banner/ERE
  heuristics; OS labels (`linux-like`, `windows-like`, etc. or any
  imported fingerprint) are probability guesses that NAT, proxies,
  firewalls, and patched stacks routinely defeat. Do not assert
  fingerprint results as facts in legal, compliance, or incident
  reports without independent verification.
- **Plugins are privileged native code.** AlScript `.so` files run
  in-process with full process privileges and no sandbox. Only load
  plugins you wrote or trust. A malicious plugin can read memory,
  write files, or escalate privilege.
- **Third-party terms.** Optional Nmap-derived databases (`nmap-service-probes`,
  `nmap-os-db`, `nmap-services`) remain subject to Nmap's license
  (NPSL). The Goose language is by Wouter van Oortmerssen. ALmap does
  not include Nmap source code and is not endorsed by the Nmap project.
- **No affiliation.** "Nmap alternative" is a descriptive comparison,
  not an affiliation, endorsement, or trademark claim. Nmap and Zenmap
  are trademarks of their respective owners.
- **Release artifacts.** Tarball binaries are built locally for
  authorized testing. Verify checksums (`*.sha256`) before use and
  rebuild from source on systems you do not control.

## License and provenance

ALmap is an original Goose + C project for authorized security testing.
The Goose language and toolchain are by Wouter van Oortmerssen.

ALmap does not include Nmap source code. The optional importers consume
data files from a local Nmap installation; databases generated from
Nmap data remain subject to Nmap's license and should not be committed
to this repository. Release tarballs are built locally on request and
are not part of the source tree.
