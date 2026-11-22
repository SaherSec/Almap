# Web UI security audit (Phase 2, Task 7)

Date: 2026-11-22. Scope: `almap/c/http.c`, `almap/c/http.h`, `almap/modules/webui.goose` at `9d7f837`, covering everything since the loopback/token commit (`e5f84b4^..9d7f837`).

## Method

The `claude-security` plugin skill was not loaded in the session that did the work (a plugin installed mid-session needs a Claude Code restart), so the audit was done by a dedicated security-review agent instead. It was given an explicit threat model and allowed to attack a locally built `./almap --web` over loopback only:

- a LAN client that can reach the port (the server can bind `0.0.0.0`),
- a malicious web page in the user's browser (CSRF, DNS rebinding),
- a local unprivileged user (symlinks, races, extra connections),
- hostile bytes in requests.

It assumed the attacker does not know the random API token. Re-running `claude-security` after a restart is still worth doing; it has not looked at this code yet.

## Result

No authentication bypass, argument injection, plugin-path escape or memory-safety bug was found. Fixes for the weaker findings are listed below.

### Fixed

| Finding | Severity | Fix |
|---|---|---|
| F1: a client reading a large result slowly (one byte at a time) resets the 5 s send timeout and stalls the single-threaded server | Low (needs the token) | `ed682a3`: every send has a total wall-clock budget of 5 s + 1 s per MiB (`ALMAP_WEB_SEND_BASE_MS` overridable). Deterministic socketpair test `test_send_deadline`. |
| F4: a JSON string value with an escape (for example `"script":"a\"b"`) was silently ignored, so the scan ran without the plugin and returned 200 | Info | `ad5a0e6`: such a value in `targets`, `ports`, `scan_type` or `script` gets a 400 with a JSON error that names the field and does not echo the value. |
| F4: no `X-Content-Type-Options`, `X-Frame-Options`, frame-ancestors or cache headers | Info | `39720e3`: every response carries `nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'` and `Cache-Control: no-store`. No `script-src` is set because the page uses inline script. |

### Accepted and documented (not fixed)

| Finding | Why it stands | Documented in |
|---|---|---|
| F1 remainder: the send is still a bounded blocking wait on the single thread. A token holder who reads a 16 MiB result at 1 byte/s can hold the server for about 21 s per scan, repeatedly. | Needs the token, which already allows running scans. A real fix needs an output queue and non-blocking sends. | README known limits; follow-up. |
| F2: 32 half-open connections make the server drop new connections for 2 s, and reopening them every 2 s keeps legitimate clients out. | The server never blocks on them and each slot expires at its deadline. Loopback is the default bind. Evicting the oldest pending slot would help and needs a design change. | README known limits. |
| F3: with `--web-bind 0.0.0.0` the token and scan output travel in plaintext, and the token is printed in full to stdout. | Intended: the user chooses to expose it. The README security note already says so. | README. |
| F5: the child's `dlopen` re-resolves the plugin path (small TOCTOU window). | Exploiting it needs write access to `plugins/`, which already allows planting a plugin. | README. |
| After SIGKILL the reap uses a blocking `waitpid`. | Only blocks if the child is stuck in uninterruptible I/O. | Known limit. |
| Half-close: a client that calls `shutdown(SHUT_WR)` after sending the request (for example `nc -N`) is treated as a hang-up and its scan is killed with no reply. | Required by the design (a peer hang-up kills the scan). curl, browsers and Python requests are unaffected. | README known limits. |
| F4 details: `Authorization : Bearer` (space before the colon) and a lowercase `bearer` scheme are accepted, and the first of duplicate `Host` headers wins. | Harmless here: no proxy and no keep-alive. | None needed. |

### Suspected, not verified

- A busy loop when the process runs out of file descriptors (`EMFILE`). Needs fd exhaustion; deferred.
- End-to-end test of the 300 s default wall-clock limit (a 1 s override is tested).
- A grandchild that calls `setsid` could escape the process-group kill. Plugins run inside the scanner process, so there is no such grandchild today.

### Checked and found safe

- Every `/api/` path variant, HEAD and OPTIONS, wrong, prefix and extended tokens, duplicate or folded `Authorization`.
- Host and Origin tricks: foreign host, IPv6, trailing dot, `Origin: null`, foreign origin.
- Request framing: duplicate Content-Length, oversized headers, NUL bytes, chunked bodies.
- Argument injection attempts (targets `-h`, ports `-1`, scan_type `--help`, script traversal or absolute path): all rejected with 400.
- Plugin names: symlink, directory and loop names are refused; a symlink inside `plugins/` that stays inside is allowed.
- The scan child is killed on client hang-up and when the server is killed; it does not inherit the listener, client sockets or pipe ends; the server's fd count returns to its baseline.
- A result over the 16 MiB cap returns a 500 with valid JSON.
- Scan output is shown with `textContent`; the token is 128 bits from `/dev/urandom` with a constant-time compare.
- `gcc -fanalyzer` reports only one false positive (the fd in the forked child before `exec`).
