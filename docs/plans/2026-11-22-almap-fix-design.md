# Almap v5.1.0: fix it properly (design)

Date: 2026-11-22. Source review: `ALMAP_REVIEW.md` (local only, not tracked).

## Intent

Almap should be a scanner whose output can be trusted. Today the Web UI was an RCE/DoS hole (mostly fixed in `7ec659f`). The build step in the README fails. 660 binaries are tracked. Most of the 623 plugins are templated probes, and about 103 of them can print `VULNERABLE` without any check that tells a vulnerable host from a patched one.

The goal is that **every claim in the README is true and backed by a test**. Every plugin that stays becomes a real implementation whose verdict has been checked against evidence. The README number then drops to the real count of merged, verified checks. It grows back later with new real plugins.

## Goals

1. **Hygiene.** Nothing built is tracked. The documented build works and reports every failure.
2. **Web UI security finished.** Loopback by default, a token, Host/Origin checks and name-only `script` are already done. Close the slow-client DoS, silent truncation and the `Content-Length` overflow, and bound the scan child.
3. **Plugins.** Merge the numbered copies into one check per name. Each check ends in exactly one of the verified tiers below, or in the `experimental` tier. Progress is tracked in `docs/PLUGINS.md` as verified / total.
4. **CI.** GitHub Actions builds everything and runs every test. A skipped raw-socket test is a failure, not a green run.
5. **Release v5.1.0.** Honest README numbers, a `CHANGELOG.md` with the security fixes and the old→new plugin name table, and `docs/GUIDE.md` brought up to v5.

## Non-goals (v5.1.0)

- **Data-driven HTTP probe engine** (one engine plus a check table). This is a separate project after 5.1.0.
- Plugin selection by category, glob or port rule (`--script vuln`). `--script` stays one plugin name or `.so` per run.
- Rewriting git history. We only stop tracking binaries. The options for shrinking `.git` are written up for the user to decide (see Phase 1).
- Privilege dropping after raw sockets are opened, seccomp, and plugin isolation. These are listed as known limits in the README.
- Rust plugins. C is the source of truth (see Decisions).
- Benchmarks against Nmap, masscan or RustScan. The README must not claim a speed it has not measured (see Phase 5).

## Anti-goals (a failure even if it "works")

- Any plugin prints `VULNERABLE` without a passing lab test that shows `VULNERABLE` on a real vulnerable target and `NOT VULNERABLE` on the patched one.
- A fixture response that was hand-invented or "reconstructed" instead of copied from a citable source.
- A CI run that is green while raw-socket or lab tests were skipped.
- A README number that is not generated from, or checked against, `docs/PLUGINS.md`.
- Vulnerable lab containers reachable from anything but the local machine.

## Decisions already made (by the user)

| Topic | Decision |
|---|---|
| Plugin merge | **Merge by name.** `foo`, `foo-2`…`foo-5` become one `foo.c` (no numeric suffix) that keeps the best logic of the copies. The others are deleted. That gives about 494 checks before any are dropped. |
| Unverifiable checks | Checks that are kept but cannot be lab-tested print only `DETECTED` / `NOT DETECTED`, verified against fixtures. |
| Fixtures | Every recorded response comes from a real, citable source (vendor advisory, public PoC or scanner-template repo, published capture). The source is noted in the fixture. No invented responses. With no real source, the plugin is `experimental` and prints `INFO` only. |
| Fixture kinds | **Captured**: a byte-for-byte response from a published capture, advisory or PoC write-up. **Derived**: built from a published scanner-template matcher. It is labelled `derived`, cites the template's commit, and contains nothing beyond what the matcher requires. A check backed only by derived fixtures may print `DETECTED`/`NOT DETECTED`, **never** `VULNERABLE` (a matcher proves the product, not the vulnerability). |
| Counting | Four separate numbers everywhere (PLUGINS.md, README): **verified (lab)**, **verified (captured fixture)**, **detected (derived fixture)**, **experimental**. They are never added into one "verified" number. |
| Rust-only plugins | The 14 plugins with a Rust `.so` but no `.c` (`dns-version`, `ftp-syst`, `http-options`, `http-put`, `http-server-headers`, `ldap-rootdse`, `mysql-version`, `ntp-version`, `rdp-info`, `redis-info`, `snmp-sysdescr`, `ssh-version`, `telnet-banner`, `vnc-auth`) are ported to C in their family batches. Where a C twin exists (`ssh_version.c`), they are merged and recorded in the rename table. |
| Release gate | v5.1.0 ships only after every family batch is done: every check ends verified, detected or `experimental`. |
| Authority | CI is the authority for "verified". A check marked verified must pass its test in CI; CI installs a pinned podman. Before Phase 4, local runs are provisional. |
| Plugin source of truth | The C sources. The Rust `.so` builds are dropped, and gcc builds of the `.c` files ship. |
| Old names | No aliases (there are no users yet). The CHANGELOG carries the old→new name table. |
| Untracked copies | `almap-claude/` and `almap-opencode/` go into `.gitignore` and are not deleted. |
| Toolchain | Goose at `~/Downloads/goose-v2026.3-linux-x64/goose`, with `GOOSE_STDLIB` set to the `stdlib/` next to it. |
| Process | Superpowers flow. Wait for approval before code. One commit per task, tests for everything. |

## Approaches considered (plugin merge)

1. **Merge by name, one C file per check (picked).** It keeps the plugin format (one `.so`, one exported function) and keeps C as the source of truth. It's the most files to fix, but they split cleanly into batches by protocol family.
2. **Data-driven HTTP engine plus a check table.** Fewer files and one-line false-positive fixes. But it changes the plugin model and needs a manifest and a selector. Rejected for 5.1.0 and kept as a later project.
3. **Hybrid: 1 now, 2 later.** This is effectively what was picked: 1 is done in this release and 2 is written down as a non-goal.

## Verdict vocabulary and tiers

Each check is in exactly one tier. Its tier decides which words it may print.

| Tier | May print | Proof needed for "verified" |
|---|---|---|
| `vuln` | `VULNERABLE`, `NOT VULNERABLE` | A lab test where the real vulnerable target gives `VULNERABLE`, the real patched target gives `NOT VULNERABLE`, and a neutral control (a plain web server or a plain service of the same protocol) does not give `VULNERABLE`. |
| `detect` | `DETECTED`, `NOT DETECTED` | Either a lab test against the real product (positive) plus a control (negative), **or**, when no lab target can run, a fixture replay (captured or derived; see Decisions): at least one cited positive fixture gives `DETECTED`, and at least one cited negative fixture (another product's real response) plus the neutral control give `NOT DETECTED`. |
| `info` | Facts read from the service (version, banner, auth mode…) | A lab test against the real service that checks the reported fields. |
| `experimental` | `INFO` lines only | Not counted as verified. The source lint enforces the word restrictions. |

**Counts.** `docs/PLUGINS.md` (and the README) report four numbers, never summed into one: **verified (lab)** (`vuln`/`detect`/`info` proven against real lab targets), **verified (captured fixture)** (`detect` proven with captured fixtures), **detected (derived fixture)** (`detect` backed only by derived fixtures), and **experimental**. Plus the total and a per-family breakdown. A `vuln` check needs a lab test; no fixture kind can back `VULNERABLE`.

**Enforcement.** A source lint test (`tests/lint_plugins.sh`) fails if a plugin prints a word its tier does not allow. It also fails if a `vuln`/`detect`/`info` plugin has no test, or if a fixture has no source record. The lint lands early (Phase 3, first task), together with a mechanical pass that moves every not-yet-reviewed plugin to `experimental` and downgrades its `VULNERABLE`/`detected` output to `INFO`. So the false positives stop on day one, and each family batch then raises its checks back up.

## Phase design

### Phase 1: repo hygiene

- Add to `.gitignore`: `almap-claude/`, `almap-opencode/` (the first two entries, `ALMAP_REVIEW.md` and `almap-opencode-rust/`, are already there), `*.so`, `*.o`, the `almap/almap` binary, `almap/dist/`, and test/build scratch.
- `git rm --cached` the 637 `.so` files, the `.o` files, `almap/almap` and the 4.0.0 tarball and its `.sha256`. The working-tree files stay.
- Remove `almap/rust_plugins/`, since C is the source of truth. It stays in history. *(Builder's call; see the list at the end.)*
- Fix `mongodb_info.c` (`strnlen` under `-std=c99`) with a bounded local loop or a `_POSIX_C_SOURCE` define. Make `build_plugins.sh` build every plugin, then print the failures and exit non-zero if any failed. No more `set -e` abort halfway.
- Make the shared headers stop generating "unused static function" warnings (for example `static inline` or `__attribute__((unused))`), so `-Wall -Wextra` output means something. Then fix the real warnings that this uncovers.
- `integration_script.sh` passes again.
- **History options write-up** (`docs/REPO_HISTORY.md`), presented to the user at the end of Phase 1 with no action taken: leave history as is; `git filter-repo` to strip `*.so`/`*.o`/binaries (requires a force push, and every clone must be re-cloned); or start a fresh repository and keep the old one as an archive. Each option is given with its size estimate.

### Phase 2: Web UI security (remaining items)

Already done in `7ec659f`: S1 (loopback plus `--web-bind`), the token, S3 (Host/Origin), S2 (name-only `script`, `realpath` inside `plugins/`) and close-on-exec sockets. Those keep their tests. What's left:

- **Slow-client DoS (S4).** One idle or slow connection must not delay other requests. Acceptance: with 10 idle connections open, `/api/status` answers in under 500 ms, and a client that trickles headers is dropped at a total deadline of about 2 s (not per `read`). The builder picks the mechanism (a `poll` loop in `c/http.c` is the likely fit).
- **Scan child bounds.** Only one scan runs at a time, and a second one gets `409` with a JSON error. The child is killed at a wall-clock limit and when the requesting client disconnects. `/api/status` keeps answering while a scan runs.
- **Truncated JSON (S5).** Scan output is no longer cut at 32 KB. Either it is collected up to a documented cap (for example 16 MB) and returned whole, or it is rejected with a valid JSON error saying it exceeded the cap. A response is never invalid JSON. A request body over the 8 KB cap gets `413`, not silent truncation.
- **`Content-Length`** is parsed with an overflow guard and an upper bound.
- **`Content-Type: application/json`** is required on `/api/scan` (the review's item 1; closes the "simple request" form of CSRF on top of the Origin check). *(Builder's call; it's in the review, not in the user's list.)*
- Tests: each item gets an integration case in `integration_web.sh` that fails against the current binary. That covers idle connections, trickling headers, a 2,000-port scan returning valid JSON, an oversize body, an overflowing `Content-Length`, a second concurrent scan, and a client disconnect killing the child.
- The installed `claude-security` plugin is run as a scan of the Web UI changes before Phase 2 closes, and its verified findings are fixed or written up.

### Phase 3: plugins

**3.0 Framework (before any family).**
- The tier vocabulary above, the source lint, and the mechanical downgrade to `experimental`.
- A machine-readable manifest (`almap/plugins/MANIFEST.tsv` with name, family, tier, status and lab/fixture reference). `docs/PLUGINS.md` is generated from it plus the last test results by a script, and a test checks that the generated file is current.
- The lab: `tests/lab/<family>/` holds `podman kube play` YAML (built into podman 6.2; no compose provider is installed here) and a runner script. Images are pinned **by digest**, with each image's origin and the CVE/patch level it represents noted next to it. Containers sit on an internal podman network, and ports are published only on `127.0.0.1`. The runner takes a family (or one check), starts the targets, runs each plugin against vulnerable, patched and control targets, compares the exact verdict line, and tears everything down.
- The fixture mock server is `tests/lab/mock_server.py`. It replays raw recorded responses (TCP or UDP) from `tests/fixtures/<check>/<case>.bin`. A `SOURCE` file sits next to each case with the kind (`captured` or `derived`), the URL (for a derived one, the template URL at a fixed commit), the retrieval date, what the response shows and the license or quote basis. The lint rejects a fixture without one. It also rejects a `vuln` check that is backed by fixtures alone.
- Plugin build flags: gcc, `-std=c99 -Wall -Wextra -shared -fPIC`. Plugins that need OpenSSL link it explicitly (this fixes `ssl-heartbleed-full`'s undefined `SSL_*` symbols).

**3.1… Family batches.** The order runs from most-used to most lab-friendly: SSL/TLS → SSH → SMB → databases (MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Oracle) → DNS → mail/FTP/LDAP/Kerberos/SNMP/other services (`svc-*`) → HTTP generic (`http-*`, `http-check-*`) → HTTP CVEs (`http-vuln-*`, split into sub-batches by product) → cloud/container (`docker-*`, `kubernetes-*`, `cloud-*`) → IoT (`iot-*`, mostly fixture-only).

Each batch:
1. Merge the numbered copies of each name into one `.c`, delete the rest, and add rows to the old→new table (`docs/plans/plugin-renames.tsv`, copied into the CHANGELOG at release).
2. For each check, pick its tier, then rewrite it until it is a real implementation of that tier. That means a real protocol exchange and a version comparison or protocol-level proof for `vuln`. Connect-only and "probe sent" bodies are not acceptable in any verified tier.
3. Add lab targets and/or cited fixtures, plus the tests.
4. Checks that cannot reach a verified tier stay `experimental` (`INFO` only). Checks whose names are misleading (for example `pgsql-brute`, which never sends a password) are either made to do what the name says, or renamed and recorded in the table. *(Which one is the builder's call per check.)*
5. Regenerate `docs/PLUGINS.md`. One commit per batch task (splitting a large family into several tasks is fine).

### Phase 4: CI

- `.github/workflows/ci.yml` runs on push and pull request with `permissions: contents: read`, and every action pinned to a commit SHA. It is reviewed with the installed `github-actions-hardening` skill.
- Jobs: build (the Goose toolchain is downloaded from its release URL and checked against a pinned sha256), C core `-Wall -Wextra` with no warnings, plugin build, unit tests, integration tests, plugin lint, and lab tests as a matrix per family on `ubuntu-latest` with podman.
- **Skips fail the run.** Integration scripts exit `77` for "skipped" instead of `0`. CI runs raw-socket tests with root (`sudo`) or `unshare -Urn`, and any `77` fails the job with a message naming the test. Locally, `77` stays a visible skip and is reported as such by a top-level `tests/run_all.sh`.

### Phase 5: release v5.1.0

- The release gate is that every family batch is done.
- `VERSION`, the `--version` output and the docs all say 5.1.0.
- README audit: every claim is checked line by line and is either true with a test or rewritten. Plugin numbers are the four separate counts from `docs/PLUGINS.md` (a test compares them). "Fast" stays only as a description of the engine (epoll, 10,000 in flight); no comparative claim is made.
- `CHANGELOG.md` covers the security fixes (S1–S6 with commits), hygiene, the plugin tiers, the old→new names, and the known limits.
- `docs/GUIDE.md`, `almap/AGENTS.md` and `almap/README.md` are brought to v5.1.0 (the last one currently has literal `\n` text).
- `tools/build_release.sh` produces the tarball (the binary plus gcc-built plugins) and its sha256 as release artifacts, which are not committed. Tagging and pushing are done only after the user approves.

## Constraints

- Linux only. gcc, Goose 2026.3 at the path above, and rootless podman 6.2.
- Labs and fixtures use only public images and public sources. Nothing is scanned except local lab containers.
- Repo-relative paths in docs. No personal data in commits beyond the existing git identity.

## Left to the builder (marked as calls)

- Removing `almap/rust_plugins/` (it follows from "C is the source of truth").
- Requiring `Content-Type: application/json`.
- The mechanism for the concurrent web server, the output cap value, and the wall-clock limit value.
- The manifest format and the `PLUGINS.md` generator.
- Rename or rewrite for checks with misleading names.
- `plugins/almap-autopilot/` (a Node bundle) moves out of `plugins/` to `tools/`, or is left alone and excluded from counts. Default: excluded from counts and left alone.
- How to split large families into commit-sized tasks.
