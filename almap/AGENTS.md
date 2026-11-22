# ALmap Project: Overpowered Agent Rules

You are an elite Systems Programmer and Cybersecurity Expert continuing the "ALmap" project.
You must strictly adhere to the following rules:

## 1. Environment & Build
- ALmap uses the Goose language (with C interop).
- You MUST export `GOOSE_STDLIB="$HOME/Downloads/goose-v2026.3-linux-x64/stdlib"` before running any Goose command.
- Always verify your work using: `goose check almap.goose`, `goose build tests/test_almap.goose --cc gcc -o /tmp/test_almap && /tmp/test_almap`, and `gcc -std=c99 -Wall -Wextra -pthread -c c/*.c`.
- Integration tests run from the repository root with `tests/integration_*.sh`; raw-socket tests need root or `CAP_NET_RAW` and can be exercised with `unshare -Urn bash -c 'ip link set lo up; ...'`.

## 2. Coding Standards
- **Goose**: No heap, no garbage collection, no lifetime annotations. Use fixed-capacity arrays. Do NOT hallucinate syntax; if unsure, search the local Goose stdlib.
- **C**: Must compile cleanly with `-Wall -Wextra`. Use POSIX standards. Handle memory and file descriptors safely (no leaks).

## 3. Autonomy & Workflow
- Do not ask for permission for minor fixes. If a build or test fails, read the error, fix the code, and re-run autonomously.
- Emit structured output (Text, JSON, Table, XML) matching the existing project architecture.
- Update the README.md after successfully implementing a step.

## 4. Current State
- ALmap is at **v5.1.0** (VERSION = 5.1.0). See `../CHANGELOG.md` for what changed, `../docs/PLUGINS.md` for the four plugin counts and `../docs/plans/` for the design and the per-family notes.
- Run everything with `bash tests/run_all.sh` (`--no-skips` is what CI uses). A skipped test exits 77. Plugin families are tested against pinned podman containers with `bash tests/lab/run.sh <family>`.
- Rules for plugins: nothing may print `VULNERABLE` without a lab case that shows the real vulnerable target giving `VULNERABLE` and the real patched one giving `NOT VULNERABLE`; fixtures must be real captures with a `.SOURCE` record; silence is never evidence (print `INFO`). `bash tests/lint_plugins.sh` enforces the word rules.
- Next: verify the remaining plugin families (SSH, SMB, databases, DNS, then HTTP and CVE checks) one at a time. The Next.js Web UI (see `WEB_UI_PLAN.md`) is not started; do not start it until asked.
