# Almap v5.1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every README claim true and test-backed: finish repo hygiene and Web UI security, turn every merged plugin into a verified (or honestly `experimental`) check, add CI, and release v5.1.0.

**Architecture:** Changes stay inside the existing layout: Goose modules (`almap/modules/`), the C core (`almap/c/`), C plugins (`almap/plugins/`) and shell integration tests (`almap/tests/`). New pieces are a plugin manifest plus lint, a podman lab plus a fixture replay server under `almap/tests/lab/`, a `PLUGINS.md` generator in `almap/tools/`, and `.github/workflows/`.

**Tech Stack:** Goose 2026.3, gcc (C99), bash, Python 3 (tools/tests only, stdlib only), rootless podman 6.2 (`podman kube play`), GitHub Actions.

**Spec:** `docs/plans/2026-11-22-almap-fix-design.md`

## Global Constraints

- Goose: `~/Downloads/goose-v2026.3-linux-x64/goose`, with `export GOOSE_STDLIB="$HOME/Downloads/goose-v2026.3-linux-x64/stdlib"` before any Goose command. In CI: `https://github.com/aardappel/goose/releases` asset `goose-v2026.3-linux-x64.tar.gz`, sha256 `06ac30284338269d3996d457412bf4f2b47c1f9a5601de65b6317187fe78d5c9`.
- Build checks (from `almap/AGENTS.md`): `goose check almap.goose`; `goose build tests/test_almap.goose --cc gcc -o /tmp/test_almap && /tmp/test_almap`; `gcc -std=c99 -Wall -Wextra -pthread -c c/*.c`.
- Plugins: gcc, `-std=c99 -Wall -Wextra -shared -fPIC`. OpenSSL users add `-lssl -lcrypto`. C is the only source of truth.
- Verdict words by tier: `vuln` → `VULNERABLE`/`NOT VULNERABLE`; `detect` → `DETECTED`/`NOT DETECTED`; `info` → facts; `experimental` → `INFO` lines only.
- `VULNERABLE` requires a lab test: the real vulnerable target gives `VULNERABLE`, the real patched one gives `NOT VULNERABLE`, and a neutral control does not give `VULNERABLE`. No fixture kind ever backs `VULNERABLE`.
- Fixtures: `captured` (byte-for-byte from a citable source) or `derived` (from a published matcher, citing the template URL at a fixed commit, containing nothing beyond what the matcher requires). Never invented. No source → `experimental`.
- Four separate counts everywhere, never summed: **verified (lab)**, **verified (captured fixture)**, **detected (derived fixture)**, **experimental**.
- Lab containers: images pinned by digest, internal podman network, ports published on `127.0.0.1` only.
- Merged names drop the `-2`…`-5` suffix. There are no aliases. Every rename or deletion gets a row in `docs/plans/plugin-renames.tsv` (`old<TAB>new<TAB>reason`, where `new` is `-` for deleted).
- Integration scripts exit `0` = pass, `1` = fail, `77` = skipped. CI treats `77` as failure.
- One commit per task (a family batch may be several tasks). Every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No history rewrite. No tag or push without the user's approval.
- The CI run is the authority for "verified". Local results before Phase 4 are provisional.

## Review Focus

1. **A `.so` plugin left from the Rust era but now untracked still loads.** After Phase 1, `plugins/*.so` that came from Rust stay on disk. Expect `build_plugins.sh --clean` to remove every `.so` without a `.c` so a stale binary can't shadow a fixed check. Test lands in Task 2.
2. **The scan client disconnects mid-scan.** Expect the child to be killed within 1 s and the server to accept the next scan. Test lands in Task 6.
3. **A scan's output is exactly at the cap, or one byte over it.** Expect at-cap output returned whole as valid JSON, and over-cap output to get the fixed error JSON, never a cut body. Test lands in Task 6 (cap overridable by `ALMAP_WEB_OUT_CAP` env for testing).
4. **A plugin prints a verdict word inside a longer word or in lower case** (`detected (HTTP 200)`, `vulnerable?`). Expect the lint to match case-insensitively on word boundaries, so old-style lower-case verdicts are caught too. Test lands in Task 8.
5. **A lab image digest disappears from its registry.** Expect the lab runner to fail loudly with the image name, not to mark the check `experimental` or pass. Test lands in Task 10.

---

## File Structure

| Path | Responsibility | Tasks |
|---|---|---|
| `.gitignore` | Ignore local copies and every build product | 1 |
| `docs/REPO_HISTORY.md` | Options for shrinking `.git`; no action | 1 |
| `almap/tests/check_repo_hygiene.sh` | No tracked build products; ignore rules work | 1 |
| `almap/tools/build_plugins.sh` | Build all plugins, `--out DIR`, `--werror`, `--clean`, report every failure | 2, 3 |
| `almap/tests/integration_build_plugins.sh` | Build script behaviour | 2, 3 |
| `almap/plugins/*.h` | Shared helpers, warning-free | 3 |
| `almap/c/http.c`, `almap/c/http.h` (new) | Request reading, event loop, scan lifecycle | 4–6 |
| `almap/tests/test_http.c` | C unit tests for the HTTP layer | 4–6 |
| `almap/modules/webui.goose` | Routing, JSON, access checks; uses the new C event API | 4–6 |
| `almap/tests/integration_web.sh` | Web UI behaviour end to end | 4–6 |
| `almap/plugins/MANIFEST.tsv` | One row per check: `name family tier status evidence` | 8, 11+ |
| `almap/tests/lint_plugins.sh` | Verdict-word, manifest, test and fixture rules | 8 |
| `almap/tools/gen_plugins_md.py` → `docs/PLUGINS.md` | The four counts plus a per-family table | 9 |
| `almap/tests/lab/run.sh`, `almap/tests/lab/lib.sh` | Start targets, run checks, compare verdicts, tear down | 10 |
| `almap/tests/lab/<family>/pod.yaml`, `…/images.tsv` | Lab targets per family | 10, 11+ |
| `almap/tests/lab/<family>/cases.tsv` | `check target expected_line_regex` | 11+ |
| `almap/tests/lab/mock_server.py` | Replay a fixture over TCP or UDP | 10 |
| `almap/tests/fixtures/<check>/<case>.bin` + `<case>.SOURCE` | Recorded responses and their provenance | 10, 11+ |
| `docs/plans/plugin-renames.tsv` | Old→new name table | 11+ |
| `almap/tests/run_all.sh` | Run every test and report pass, fail and skip | 13 |
| `.github/workflows/ci.yml`, `.github/workflows/lab.yml` | CI | 14, 15 |
| `CHANGELOG.md`, `README.md`, `docs/GUIDE.md`, `almap/AGENTS.md`, `almap/README.md`, `almap/VERSION` | Release docs | 16 |

---

## Phase 1: Repo hygiene

### Task 1: Ignore and untrack build products; write the history options

**Files:**
- Modify: `.gitignore`
- Create: `almap/tests/check_repo_hygiene.sh`, `docs/REPO_HISTORY.md`

**Interfaces:**
- Produces: `check_repo_hygiene.sh` (exit 0/1), used by `run_all.sh` (Task 13).

- [ ] **Step 1: Write the failing test** `almap/tests/check_repo_hygiene.sh`. It asserts:
  - `git ls-files` matches none of `\.so$`, `\.o$`, `^almap/almap$`, `^almap/dist/`.
  - `git check-ignore -q` succeeds for `almap-claude/x`, `almap-opencode/x`, `almap-opencode-rust/x`, `ALMAP_REVIEW.md`, `almap/plugins/foo.so`, `almap/c/x.o`, `almap/almap`, `almap/dist/x.tar.gz`.
- [ ] **Step 2: Run it.** `bash almap/tests/check_repo_hygiene.sh`. Expected: FAIL, listing 661 tracked build products and the two unignored directories.
- [ ] **Step 3: Implement.**
  - Append to `.gitignore`: `almap-claude/`, `almap-opencode/`, `*.so`, `*.o`, `/almap/almap`, `/almap/dist/`.
  - `git rm --cached -q` every tracked `*.so`, `*.o`, `almap/almap`, and `almap/dist/*`. Working-tree files stay.
- [ ] **Step 4: Write `docs/REPO_HISTORY.md`.**
  - Current size: `du -sh .git`, plus the bytes taken by `*.so` blobs (`git rev-list --objects --all | git cat-file --batch-check`).
  - Three options, each with the steps it takes, its estimated resulting size, and who it breaks:
    1. leave history as is
    2. `git filter-repo --path-glob '*.so' --path-glob '*.o' --path almap/almap --path almap/dist --invert-paths`, then force-push and re-clone
    3. start a fresh repository and archive the old one
  - No recommendation is acted on.
- [ ] **Step 5: Run it.** Expected: PASS. `git diff --cached --name-status | grep -v '^D'` lists only `.gitignore`, the new test and the doc.
- [ ] **Step 6: Commit.** Message: `Repo hygiene: ignore local copies and build products, stop tracking binaries`.

### Task 2: Fix `mongodb_info.c` and make the plugin build report every failure

**Files:**
- Modify: `almap/plugins/mongodb_info.c:168`, `almap/tools/build_plugins.sh`
- Create: `almap/tests/integration_build_plugins.sh`

**Interfaces:**
- Produces: `tools/build_plugins.sh [--out DIR] [--werror] [--clean] [NAME...]`.
  - Builds `plugins/<name>.c` → `<out>/<name>.so` (default out is `plugins/`).
  - Prints `[build_plugins] FAILED: <name>` for each failure, then `[build_plugins] done: <ok> built, <failed> failed`.
  - Exits 1 if any failed.
  - `--clean` deletes every `<out>/*.so` with no matching `.c` before building.
  - Links `-lssl -lcrypto` for plugins whose source contains `#include <openssl/`.
  - Later tasks and CI call this.

- [ ] **Step 1: Write the failing test** `integration_build_plugins.sh`, with these cases:
  - **(a)** A full build to `$TMPD/out` exits 0 and produces exactly `ls plugins/*.c | wc -l` `.so` files.
  - **(b)** A copy of `plugins/` into `$TMPD/p` with an extra `zz_broken.c` (syntax error), built with `PLUGINS_DIR=$TMPD/p`: exits 1, output contains `FAILED: zz_broken`, and every other `.so` is still produced.
  - **(c)** `--clean` with a stray `$TMPD/out/stale.so`: `stale.so` is gone afterwards.
- [ ] **Step 2: Run it.** Expected: FAIL at (a) with `strnlen` undeclared.
- [ ] **Step 3: Implement.**
  - Replace `strnlen` in `mongodb_info.c` with a bounded loop over `doclen - pos`.
  - Rewrite the loop in `build_plugins.sh` to collect failures instead of aborting (keep `set -uo pipefail`, drop `-e`).
  - Add `--out`, `--werror` (adds `-Werror`), `--clean`, positional names and the `PLUGINS_DIR` env override (default `plugins`).
- [ ] **Step 4: Run** `integration_build_plugins.sh` and `tests/integration_script.sh`. Expected: both PASS.
- [ ] **Step 5: Commit.** Message: `Plugins: fix mongodb_info build, make build_plugins report all failures`.

### Task 3: Warning-free plugin build

**Files:**
- Modify: `almap/plugins/*.h` (14 headers); any `plugins/*.c` with a real warning
- Modify: `almap/tests/integration_build_plugins.sh`

- [ ] **Step 1: Add the failing case.** (d) `build_plugins.sh --werror --out $TMPD/w` exits 0.
- [ ] **Step 2: Run it.** Expected: FAIL. 618 plugins warn.
- [ ] **Step 3: Implement.** Mark the shared header helpers `static inline` (or `__attribute__((unused))` where inlining is wrong). Then fix every remaining warning in the `.c` files by fixing the code, not by casting it away. Record each real bug found in the commit message.
- [ ] **Step 4: Run it.** Expected: PASS, with 0 lines containing `warning:`.
- [ ] **Step 5: Commit.** Message: `Plugins: build warning-free under -Wall -Wextra -Werror`.

**After Task 3:** report `docs/REPO_HISTORY.md` to the user (the summary only, no action).

---

## Phase 2: Web UI security (what `7ec659f` left)

Constants, in the new `almap/c/http.h`, each overridable by an env var of the same name for tests:

```c
#define ALMAP_WEB_MAX_CLIENTS     32        /* pending connections held at once */
#define ALMAP_WEB_REQ_DEADLINE_MS 2000      /* whole request (headers+body) */
#define ALMAP_WEB_REQ_CAP         8192      /* request bytes */
#define ALMAP_WEB_OUT_CAP         (16 * 1024 * 1024) /* scan output bytes */
#define ALMAP_WEB_SCAN_LIMIT_S    300       /* scan child wall clock */
#define ALMAP_WEB_CL_MAX          ALMAP_WEB_REQ_CAP
```

### Task 4: Request parsing: `Content-Length` bound, 413, `Content-Type`

**Files:**
- Create: `almap/c/http.h`, `almap/tests/test_http.c`
- Modify: `almap/c/http.c:54-110` (`has_content_length`), `almap/c/http.c:186-243` (`almap_http_read`), `almap/modules/webui.goose` (scan route), `almap/tests/integration_web.sh`

**Interfaces:**
- Produces:
  - `int almap_http_parse_content_length(const unsigned char *hdr, int hdr_len, long *out)`. Returns 0 if absent, 1 if valid with `0 <= *out <= ALMAP_WEB_CL_MAX`, and -1 if malformed, overflowing or too large.
  - `almap_http_read` returns `-413` when the request exceeds `ALMAP_WEB_REQ_CAP` and `-400` for a bad `Content-Length`.
  - Goose sends `413 {"error":"request too large"}` or `400`, respectively.

- [ ] **Step 1: Write the failing tests.**
  - `test_http.c` (built as `gcc -std=c99 -Wall -Wextra -I c tests/test_http.c c/http.c -o /tmp/test_http`) covers: absent → 0; `12` → 1 and 12; `8192` → 1; `8193` → -1; a 23-digit value → -1; `-1` → -1; `1x` → -1; header-name case `content-length:` → 1.
  - Add to `integration_web.sh`:
    - a 9,000-byte body → HTTP 413
    - `Content-Length: 99999999999999999999999` → 400
    - `POST /api/scan` with valid token and `Content-Type: text/plain` → 415 `{"error":"Content-Type must be application/json"}`
- [ ] **Step 2: Run both.** Expected: FAIL (the function doesn't exist; the oversize request is truncated and parsed; text/plain is accepted).
- [ ] **Step 3: Implement** the parser with an overflow-safe accumulation (stop once the value exceeds `ALMAP_WEB_CL_MAX`). Wire it into `almap_http_read`. Map the negative returns in `webui.goose`. Check the `Content-Type` media type (case-insensitive, parameters such as `; charset=utf-8` allowed) on `/api/scan` before the JSON parse.
- [ ] **Step 4: Run** `/tmp/test_http`, `integration_web.sh`, and the Goose unit tests. Expected: all PASS.
- [ ] **Step 5: Commit.** Message: `Web UI: bound Content-Length, 413 on oversize requests, require JSON Content-Type`.

### Task 5: Slow clients can't block the server

**Files:**
- Modify: `almap/c/http.c` (new event loop), `almap/c/http.h`, `almap/modules/webui.goose:746-795` (`serve` loop), `almap/tests/test_http.c`, `almap/tests/integration_web.sh`

**Interfaces:**
- Produces:
  - `int almap_http_next(int listen_fd, unsigned char *buf, int cap, int *client_fd, int *kind)`.
  - It runs a `poll` loop over the listener and up to `ALMAP_WEB_MAX_CLIENTS` pending clients, with non-blocking accepted sockets.
  - Each client is dropped (closed, no reply) once `ALMAP_WEB_REQ_DEADLINE_MS` has passed since accept without a complete request.
  - On return, `*kind` is one of:
    - `ALMAP_EV_REQUEST` (1): a complete request is in `buf`; returns its length.
    - `ALMAP_EV_TOO_LARGE` (2) or `ALMAP_EV_BAD_LENGTH` (3): Goose replies 413 or 400.
    - `ALMAP_EV_SCAN_DONE` (4): used by Task 6; returns 0.
  - Over `ALMAP_WEB_MAX_CLIENTS`, new connections are accepted and closed immediately.
  - `almap_http_read` is removed. Goose's `serve` loop switches on `kind`.

- [ ] **Step 1: Write the failing tests** in `integration_web.sh`:
  - Open 10 idle TCP connections (Python helper), then time `GET /api/status`. It must take under 0.5 s.
  - A client sending one header byte every 300 ms is closed by the server within 2.5 s of connecting.
  - After 40 idle connections, `/api/status` still answers.
  - In `test_http.c`: `almap_http_next` over a socketpair-fed listener returns `ALMAP_EV_REQUEST` for a request split across 3 writes.
- [ ] **Step 2: Run them.** Expected: FAIL. The status call takes ≈ 5 s per idle connection (the review measured 15.4 s behind 3).
- [ ] **Step 3: Implement** `almap_http_next`, with per-client buffers allocated in C (one `ALMAP_WEB_REQ_CAP` buffer per slot). Move `serve` to it.
- [ ] **Step 4: Run** all web tests and the unit tests. Expected: PASS.
- [ ] **Step 5: Commit.** Message: `Web UI: poll-based accept loop with a per-request deadline`.

### Task 6: Scan child lifecycle and untruncated output

**Files:**
- Modify: `almap/c/http.c` (replace the blocking `almap_http_run_scan`), `almap/c/http.h`, `almap/modules/webui.goose:600-735` (`handle_scan`), `almap/tests/integration_web.sh`, `almap/tests/test_http.c`

**Interfaces:**
- Consumes: `almap_http_next` and `ALMAP_EV_SCAN_DONE` from Task 5.
- Produces:
  - `int almap_http_scan_start(int client_fd, <the same scan arguments as today's almap_http_run_scan up to and including script>)`. Returns 0 if started, -1 if a scan is already running (Goose replies 409 `{"error":"a scan is already running"}`), and -2 on spawn error (500).
  - The child's stdout goes into a C-owned growable buffer. The event loop watches the child pipe and the requesting client (`POLLRDHUP`/`POLLHUP`). It sends `SIGKILL` to the child at `ALMAP_WEB_SCAN_LIMIT_S` or on client hang-up, and reaps it.
  - When the child ends, `almap_http_next` returns `ALMAP_EV_SCAN_DONE` with `*client_fd` set to the requester (or -1 if it hung up).
  - `int almap_http_scan_result(unsigned char *head, int head_cap, int *exit_code, int *state)`. `state` is one of `ALMAP_SCAN_OK` (0), `ALMAP_SCAN_FAILED` (1, non-zero exit; `head` holds up to `head_cap` bytes of output for the error JSON), `ALMAP_SCAN_OVER_CAP` (2), `ALMAP_SCAN_TIMED_OUT` (3) or `ALMAP_SCAN_ABANDONED` (4).
  - `int almap_http_scan_send_body(int client_fd)` sends `200` with the whole buffered output (or `[]` if empty), used for `ALMAP_SCAN_OK` only.
  - Goose formats the other states:
    - `500 {"error":…,"exit_code":N}` (as today)
    - `500 {"error":"scan output exceeded <cap> bytes","truncated":true}`
    - `504 {"error":"scan exceeded <limit> s wall-clock limit"}`
    - for abandoned: nothing
  - `/api/status` gains `"scan_running": true|false`.

- [ ] **Step 1: Write the failing tests** in `integration_web.sh`:
  - A scan of 2,000 ports on 127.0.0.1 returns 200, and `python3 -c 'import json,sys; json.load(sys.stdin)'` accepts the body.
  - With `ALMAP_WEB_OUT_CAP=4096`, the same scan returns 500 and its body parses with `"truncated": true`.
  - At exactly the cap (calibrate the port count so the output is at most 4096 bytes), the result is 200 and valid JSON.
  - While a slow scan runs (`--timeout 5000`, 1 filtered port via `ALMAP_TEST_BLACKHOLE` = a non-routable address such as 192.0.2.1): a second `/api/scan` → 409; `/api/status` → 200 with `"scan_running":true` in under 0.5 s.
  - With `ALMAP_WEB_SCAN_LIMIT_S=1`, a slow scan → 504, and no `almap` child remains (`pgrep -P $WEB_PID` is empty).
  - Disconnecting the scan client: the child is gone within 1 s, and the next scan starts (not 409).
- [ ] **Step 2: Run them.** Expected: FAIL (invalid JSON at 32 KB, the server blocks during the scan, no 409/504).
- [ ] **Step 3: Implement** the interfaces above. Remove `almap_http_run_scan` and the Goose `out_buf: u8[32768]`.
- [ ] **Step 4: Run** all web tests, the unit tests, and `gcc -std=c99 -Wall -Wextra -pthread -c c/*.c` (0 warnings). Expected: PASS.
- [ ] **Step 5: Commit.** Message: `Web UI: one non-blocking scan at a time, wall-clock and disconnect kill, full JSON output up to 16 MiB`.

### Task 7: Security scan of the Web UI

- [ ] **Step 1:** Run the `claude-security` skill with the "Scan changes" job on `7ec659f^..HEAD`, scoped to `almap/c/http.c`, `almap/c/http.h` and `almap/modules/webui.goose`.
- [ ] **Step 2:** For each verified finding, write a failing test in `integration_web.sh` or `test_http.c`, fix it, and commit it on its own (`Web UI: fix <finding>`). Unfixed or rejected findings go in `docs/plans/2026-11-22-web-security-scan.md` with the reason. That file is committed.
- [ ] **Step 3:** Report the findings summary to the user.

---

## Phase 3: Plugins

### Task 8: Manifest, tier lint and the day-one downgrade

**Files:**
- Create: `almap/plugins/MANIFEST.tsv`, `almap/tests/lint_plugins.sh`, `almap/tools/downgrade_plugins.py` (one-off; kept for the record)
- Modify: every `almap/plugins/*.c` (mechanically)

**Interfaces:**
- Produces:
  - `MANIFEST.tsv` columns: `name<TAB>family<TAB>tier<TAB>status<TAB>evidence`.
    - `tier` ∈ `vuln|detect|info|experimental`.
    - `status` ∈ `lab|captured|derived|experimental`. This is the four-count bucket: `lab` = verified (lab), `captured` = verified (captured fixture), `derived` = detected (derived fixture).
    - `evidence` = `lab/<family>` or `fixtures/<name>` or `-`.
  - `lint_plugins.sh` exits 0 or 1 and prints one `LINT: <name>: <rule>` per violation. Rules:
    1. Every `plugins/*.c` has exactly one manifest row, and every row has a `.c`.
    2. Verdict words in string literals, matched case-insensitively on word boundaries: `VULNERABLE`/`NOT VULNERABLE` only if `tier=vuln`; `DETECTED`/`NOT DETECTED` only if `tier=detect`; `experimental` plugins may emit only lines starting `<name>: INFO`.
    3. `tier=vuln` requires `status=lab`.
    4. `status=lab` requires at least one row for the check in `tests/lab/*/cases.tsv`. `status=captured|derived` requires `tests/fixtures/<name>/` with at least one positive and one negative case.
    5. Every `tests/fixtures/*/*.bin` has a `.SOURCE` with the keys `kind` (`captured` or `derived`), `url`, `retrieved` (YYYY-MM-DD), `shows` and `basis`. A `derived` one also needs `template_commit`.
    6. `status=captured` requires all of the check's fixtures to be `kind: captured`.
    7. `status=derived` requires `tier=detect`.
  - Family values: `tls ssh smb db dns services http http-cve cloud iot`.

- [ ] **Step 1: Write lint self-tests** (`almap/tests/lint_plugins_selftest.sh`). Each builds a temp plugins/fixtures tree violating one rule and checks that lint fails naming that rule. This covers rules 1–7, plus Review Focus 4: `detected (HTTP 200)` and `vulnerable?` in an `experimental` plugin are flagged.
- [ ] **Step 2: Run them.** Expected: FAIL (no lint yet).
- [ ] **Step 3: Implement** `lint_plugins.sh`, using a bash wrapper around `python3 -I` for the parsing.
- [ ] **Step 4: Run** the self-tests. Expected: PASS. Run lint on the real tree. Expected: FAIL (no manifest).
- [ ] **Step 5: Downgrade.**
  - `downgrade_plugins.py` writes `MANIFEST.tsv`, with every plugin `experimental`/`experimental`/`-` and the family taken from its name prefix.
  - It rewrites each plugin's `ar_out` and `ctx->emit` format strings so that every emitted line is `<name>: INFO <original text with the verdict words replaced: VULNERABLE→"matches probe for", detected→"probe matched", not detected→"probe did not match">`.
  - Rebuild all plugins (`build_plugins.sh --werror`). Run `integration_script.sh` and update its expectations for the 6 hand-written plugins.
- [ ] **Step 6: Run** lint (PASS), the build (PASS) and `integration_script.sh` (PASS).
- [ ] **Step 7: Commit.** Message: `Plugins: tier manifest and lint; mark every plugin experimental until verified`.

### Task 9: `docs/PLUGINS.md` generator

**Files:**
- Create: `almap/tools/gen_plugins_md.py`, `docs/PLUGINS.md`, `almap/tests/check_plugins_md.sh`

**Interfaces:**
- Produces:
  - `python3 -I tools/gen_plugins_md.py [--check]` reads `MANIFEST.tsv` and writes `docs/PLUGINS.md`. `--check` exits 1 if the file on disk differs.
  - The header has exactly these four lines, with the counts as integers:
    - `Verified (lab): N`
    - `Verified (captured fixture): N`
    - `Detected (derived fixture): N`
    - `Experimental: N`
  - Then `Total checks: N`, a per-family table (the same four columns plus a total), and a per-check table (name, family, tier, status, evidence).
  - There is no combined "verified" figure anywhere.
  - Task 16 uses the four counts for the README.

- [ ] **Step 1: Write `check_plugins_md.sh`.** It runs `gen_plugins_md.py --check`. It also asserts that the file does not match `-i 'verified:'` without the `(lab)` or `(captured fixture)` qualifier.
- [ ] **Step 2: Run it.** Expected: FAIL.
- [ ] **Step 3: Implement the generator.** Generate the file (expected now: 0 / 0 / 0 / 623, total 623).
- [ ] **Step 4: Run it.** Expected: PASS.
- [ ] **Step 5: Commit.** Message: `Docs: generated PLUGINS.md with four separate counts`.

### Task 10: Lab runner and fixture replay server

**Files:**
- Create: `almap/tests/lab/run.sh`, `almap/tests/lab/lib.sh`, `almap/tests/lab/mock_server.py`, `almap/tests/lab/control/pod.yaml`, `almap/tests/lab/control/images.tsv`, `almap/tests/lab/selftest.sh`

**Interfaces:**
- Produces:
  - `images.tsv` columns: `role<TAB>image@sha256:…<TAB>origin_url<TAB>represents`. `role` ∈ `vuln|patched|control|service`, and `represents` is something like `OpenSSL 1.0.1f (CVE-2014-0160)`.
  - `pod.yaml` is a `podman kube play` file with one pod per role. Ports are published as `127.0.0.1:<hostPort>`, and `hostPort` comes from a `ports.tsv` (`role<TAB>containerPort<TAB>hostPort`).
  - `cases.tsv` columns: `check<TAB>role<TAB>port<TAB>expect` with `expect` ∈ `match:<ERE>` | `nomatch:<ERE>` | `fixture:<case>`.
  - `tests/lab/run.sh <family> [check…]`:
    - Pulls every image by digest. A pull failure gives exit 1 with `LAB: cannot pull <image>` (Review Focus 5).
    - Plays the pods, waits for each port (30 s each), runs `./almap -t 127.0.0.1 -p <port> --script <check> --json` per case, compares the plugin output against `expect`, prints `PASS|FAIL <check> <role>`, tears down with `podman kube down`, and exits 1 on any failure.
    - Runs fixture cases through `mock_server.py`.
  - `mock_server.py --proto tcp|udp --port N --fixture DIR/case.bin [--after-bytes K]` reads K request bytes (default: up to the first `\r\n\r\n` for TCP, or one datagram for UDP), writes the fixture bytes verbatim, then closes.
  - The `control` family supplies the neutral targets every family uses: plain nginx and plain OpenSSH, pinned by digest.

- [ ] **Step 1: Write `selftest.sh`.** It covers:
  - `run.sh control` with a case using `http_title` → nginx expects `match:Welcome to nginx`.
  - A fixture case replaying a 2-line HTTP response, whose `.SOURCE` cites nginx's own default page. Expect `match:`.
  - A deliberately wrong digest in a temp copy of `images.tsv`: exit 1 with `LAB: cannot pull`.
- [ ] **Step 2: Run it.** Expected: FAIL (no runner yet).
- [ ] **Step 3: Implement** `run.sh`, `lib.sh`, `mock_server.py` and the control pod.
- [ ] **Step 4: Run it.** Expected: PASS. Check that `podman ps -a` shows no lab containers afterwards.
- [ ] **Step 5: Commit.** Message: `Tests: podman lab runner and fixture replay server`.

### Task 11.x: Family batches (repeat per family)

Order, with distinct check names (before merging) from the current tree:

| # | Family (`MANIFEST` value) | Name prefixes | Approx. names | Notes |
|---|---|---|---|---|
| 11.1 | `tls` | `ssl*`, `tls*` | 6 | Fix the `ar_tls_heartbleed` single-record bug. Link `ssl-heartbleed-full` with OpenSSL. |
| 11.2 | `ssh` | `ssh*` | 9 | Port `ssh-version` (Rust-only), merging with `ssh_version.c`. `ssh-vuln-cve2024-6387` gets a real version comparison. |
| 11.3 | `smb` | `smb*` | 31 | `ms17-010` variants merge into `-full` logic. `ms08-067` becomes a real check or `experimental`. |
| 11.4 | `db` | `mysql* pgsql* ms-sql* mongodb* redis* oracle*` | 40 | Port `mysql-version` and `redis-info`. `pgsql-brute` must send real passwords or be renamed. |
| 11.5 | `dns` | `dns*` | 4 | Port `dns-version`. |
| 11.6 | `services` | `ftp* smtp* imap* pop3* ldap* kerberos* snmp* vnc* rdp* mqtt* nfs* rpc* telnet* sip* upnp* svc-* ntp*`, other non-HTTP | ≈ 105 | Port `ftp-syst`, `ldap-rootdse`, `ntp-version`, `rdp-info`, `snmp-sysdescr`, `telnet-banner` and `vnc-auth`. Kerberos principal/realm stays hardcoded (the plugin context only has IP and port); say so in the output. Split by protocol into several tasks. |
| 11.7 | `http` | `http-*` (not CVE), `http-check-*`, `http_*`, `tomcat-*`, `weblogic-*` | ≈ 75 | Port `http-options`, `http-put` and `http-server-headers`. |
| 11.8 | `http-cve` | `http-vuln-*` | 122 | Sub-batches by product, about 10 checks each. |
| 11.9 | `cloud` | `docker* kubernetes* cloud-*` | 17 | |
| 11.10 | `iot` | `iot-*` | 50 | Mostly fixture-only (`detect`, or `experimental`). |

**Each batch's first step** is to write `docs/plans/batches/<nn>-<family>.md`, listing every check in the family with:
- the merge source files
- the target tier
- the lab images (with digest and origin) or fixture sources (URL; captured or derived)
- the exact expected verdict lines

That file is committed with the batch's first task. If a batch would need to change anything in the design (a new tier, an exception to a rule), stop and ask the user. Otherwise, proceed.

**Per check, inside a batch task:**

- [ ] **Step 1: Merge.** Fold `name`, `name-2`…`name-5` into `plugins/<name>.c`, keeping the strongest logic. If only a suffixed file exists, rename it. Delete the others and their manifest rows. Add rows to `plugin-renames.tsv`. Port any Rust-only check from `rust_plugins/<name>.rs` to C here.
- [ ] **Step 2: Write the cases first.**
  - Lab rows in `tests/lab/<family>/cases.tsv`:
    - `vuln`: vulnerable `match:^<name>: VULNERABLE`, patched `match:^<name>: NOT VULNERABLE`, control `nomatch:VULNERABLE`
    - `detect`: product `match:DETECTED`, control `match:NOT DETECTED`
    - `info`: the service `match:` on the reported field(s), for example `version 8\.0\.36`
  - Fixture cases with `.SOURCE` files.
  - Set the manifest row to its target tier and status.
- [ ] **Step 3: Run** `tests/lab/run.sh <family> <name>` and `lint_plugins.sh`. Expected: FAIL (the old body can't pass).
- [ ] **Step 4: Rewrite** the plugin until it does a real protocol exchange and the verdict its tier needs: a version comparison or protocol-level proof for `vuln`, and parsed fields for `info`. Output lines start `<name>: `. Remote strings go through `ar_clean`.
- [ ] **Step 5: Run** the family lab, lint and `build_plugins.sh --werror`. Expected: PASS. If the check can't reach its tier, set it back to `experimental`, keep `INFO` output only, and write the reason in the batch file.
- [ ] **Step 6:** After the batch, regenerate `docs/PLUGINS.md`, then commit with message `Plugins (<family>): <n> checks merged, <a> lab / <b> captured / <c> derived / <d> experimental`.

### Task 12: Remove the Rust port

**Files:** Delete `almap/rust_plugins/`. Modify `README.md` and `almap/README.md` where they mention it.

- [ ] **Step 1:** Assert that every `rust_plugins/*.rs` whose name has no `plugins/*.c` is listed in `plugin-renames.tsv` (ported under another name or deliberately dropped with a reason). A one-line check in `check_repo_hygiene.sh` fails until that's true.
- [ ] **Step 2:** `git rm -r almap/rust_plugins`. Run `build_plugins.sh --clean`, so no Rust `.so` is left in the working tree.
- [ ] **Step 3: Run** the hygiene check, lint and `integration_script.sh`. Expected: PASS.
- [ ] **Step 4: Commit.** Message: `Remove the Rust plugin port; C sources are the only plugin source`.

---

## Phase 4: CI

### Task 13: Skips are visible; one test entry point

**Files:**
- Modify: every `almap/tests/integration_*.sh` that has a "skipping" path (`integration_syn.sh`, `integration_os.sh`, `integration_osdb.sh`, `integration_udp.sh`, `integration_workers_syn.sh`, and any other the grep finds), so it exits `77`
- Create: `almap/tests/run_all.sh`

**Interfaces:**
- Produces: `tests/run_all.sh [--no-skips]` runs:
  - the hygiene check
  - the plugin build with `--werror`
  - the C unit tests
  - the Goose unit tests
  - every `integration_*.sh`
  - lint and its self-test
  - `check_plugins_md.sh`

  It prints `PASS|FAIL|SKIP <name>` and a summary. It exits 1 on any FAIL. With `--no-skips`, any SKIP also exits 1 with `SKIP is a failure here: <name>`.

- [ ] **Step 1: Write the test.** As a normal user, `run_all.sh --no-skips` must exit 1 and name `integration_syn.sh`. `unshare -Urn bash -c 'ip link set lo up; tests/run_all.sh --no-skips'` must exit 0.
- [ ] **Step 2: Run it.** Expected: FAIL (the scripts exit 0 when skipping, and `run_all.sh` doesn't exist).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run it.** Expected: PASS for both.
- [ ] **Step 5: Commit.** Message: `Tests: skipped raw-socket tests exit 77; run_all.sh with --no-skips`.

### Task 14: Build and test workflow

**Files:** Create `.github/workflows/ci.yml`.

- [ ] **Step 1: Write the workflow.**
  - Triggers: `on: push, pull_request`. `permissions: contents: read`. Every `uses:` is pinned to a full commit SHA with a version comment. There is no `${{ github.event.* }}` inside `run:`.
  - Steps: download and verify Goose (the sha256 above), `apt-get install` gcc, libssl-dev, curl and python3, then `sudo -E tests/run_all.sh --no-skips` (root, so the raw-socket tests run).
- [ ] **Step 2: Review** the workflow with the `github-actions-hardening` skill and fix what it reports.
- [ ] **Step 3: Verify** with `act`, if installed, or by pushing to a branch **after asking the user**. Expected: green. Also prove that a deliberately skipped test fails the run, using a temporary commit on that branch that is then dropped.
- [ ] **Step 4: Commit.** Message: `CI: build and run all tests; skipped tests fail the run`.

### Task 15: Lab workflow (the authority for "verified")

**Files:** Create `.github/workflows/lab.yml` and `almap/tools/check_verified.py`.

**Interfaces:**
- Produces: `python3 -I tools/check_verified.py <results-dir>`. It reads the per-family runner output and exits 1 if any manifest row with `status ∈ {lab,captured,derived}` lacks a PASS for each of its cases.

- [ ] **Step 1: Write the failing test.** In `tests/check_verified_selftest.sh`, a results dir missing one case for a `lab` check must exit 1 and name it.
- [ ] **Step 2: Implement** `check_verified.py`.
- [ ] **Step 3: Write `lab.yml`.**
  - It uses a matrix over the families in `MANIFEST.tsv`.
  - It installs a pinned podman (the distro package at a fixed version, recorded in the workflow) and runs `tests/lab/run.sh <family>`.
  - Results are uploaded as artifacts, and a final job runs `check_verified.py`.
  - The same pinning and permission rules apply as in Task 14, plus the hardening review.
- [ ] **Step 4: Verify** on a branch push (after asking the user). Expected: all families green.
- [ ] **Step 5: Commit.** Message: `CI: per-family lab runs; verified status must pass in CI`.

---

## Phase 5: Release v5.1.0 (gate: every Task 11.x batch done, Task 12 done, CI green)

### Task 16: Version, docs, changelog, release artifacts

**Files:**
- Modify:
  - `almap/VERSION`
  - `almap/almap.goose:75`
  - `almap/modules/webui.goose:13,65`
  - `README.md`, `docs/GUIDE.md`, `almap/AGENTS.md`, `almap/README.md`
  - `almap/tools/build_release.sh`
- Create: `CHANGELOG.md`, `almap/tests/check_readme_claims.sh`

- [ ] **Step 1: Write `check_readme_claims.sh`.** It asserts:
  - `README.md` contains the four counts exactly as in `docs/PLUGINS.md` header lines, and no other plugin total except `Total checks: N`.
  - `almap --version` and the `/api/status` version are `5.1.0`.
  - `docs/GUIDE.md` and `almap/AGENTS.md` have no `v4.0`, `V4.0.0` or `5-script` strings, and `almap/README.md` has no literal `\n`.
  - `CHANGELOG.md` has a `## 5.1.0` section that includes every row of `plugin-renames.tsv`.
- [ ] **Step 2: Run it.** Expected: FAIL.
- [ ] **Step 3: Version.** Bump it to 5.1.0 everywhere listed.
- [ ] **Step 4: Rewrite the docs.**
  - `README.md`: go through it line by line and make every claim true or remove it. Use the four counts, describe the tiers and their verdict words, and list the known limits: no privilege drop, no plugin isolation, one plugin per run, the Kerberos realm is hardcoded, and no benchmarks.
  - `docs/GUIDE.md`: bring it to v5.1.0, covering the Web UI token and bind, the tiers, the lab, and `run_all.sh`.
- [ ] **Step 5: Write `CHANGELOG.md` 5.1.0.**
  - Security: S1–S6, each with its commit hash.
  - Hygiene.
  - The plugin tiers and the four counts.
  - The old→new name table generated from `plugin-renames.tsv`.
  - Known limits.
- [ ] **Step 6: Update `build_release.sh`.** It packages the binary, the gcc-built plugins (`build_plugins.sh --werror --clean`), `signatures.db`, `MANIFEST.tsv` and `docs/PLUGINS.md` into `dist/almap-5.1.0-linux-x86_64.tar.gz` plus a `.sha256` file. Nothing is committed.
- [ ] **Step 7: Run** `check_readme_claims.sh` and `run_all.sh`. Expected: PASS. Build the release tarball and list its contents.
- [ ] **Step 8: Commit.** Message: `Release 5.1.0: honest README counts, CHANGELOG, GUIDE for v5`.
- [ ] **Step 9: Ask the user** before tagging `v5.1.0` or pushing.
