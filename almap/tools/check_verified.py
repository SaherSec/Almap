#!/usr/bin/env python3
"""check_verified.py - did CI really prove every check marked verified?

Usage: python3 -I tools/check_verified.py [--manifest FILE] [--lab DIR] RESULTS_DIR

RESULTS_DIR holds the per-family output of tests/lab/run.sh (one *.log per
family, lines "PASS|FAIL <check> <role> <port>"). For every manifest row with
status lab, captured or derived, all of its cases in LAB/*/cases.tsv must have
run and passed: exactly as many PASS lines as cases, and no FAIL line. A check
that fails this is named ("VERIFY: <check>: ...") and the exit status is 1.
Experimental checks need no results. Exit 2 if the results directory or the
manifest cannot be read, so a missing result can never look like a pass.
"""

import argparse
import glob
import os
import re
import sys

COLUMNS = ("name", "family", "tier", "status", "evidence")
BUCKETS = (
    ("lab", "Verified (lab)"),
    ("captured", "Verified (captured fixture)"),
    ("derived", "Detected (derived fixture)"),
)
LINE = re.compile(r"^(PASS|FAIL) (\S+) (\S+) (\S+)")


def main():
    ap = argparse.ArgumentParser(description="check that CI proved every verified check")
    ap.add_argument("--manifest", default="plugins/MANIFEST.tsv")
    ap.add_argument("--lab", default="tests/lab")
    ap.add_argument("results")
    args = ap.parse_args()

    if not os.path.isdir(args.results):
        print("check_verified: results directory %s not found" % args.results, file=sys.stderr)
        return 2
    try:
        lines = open(args.manifest, encoding="utf-8").read().splitlines()
    except OSError as exc:
        print("check_verified: %s" % exc, file=sys.stderr)
        return 2
    rows = []
    for i, line in enumerate(lines):
        if not line.strip() or line.startswith("#") or i == 0:
            continue
        cols = line.split("\t")
        if len(cols) == len(COLUMNS):
            rows.append(dict(zip(COLUMNS, cols)))

    cases = {}
    for path in glob.glob(os.path.join(args.lab, "*", "cases.tsv")):
        for line in open(path, encoding="utf-8").read().splitlines():
            if line.strip() and not line.startswith("#"):
                check = line.split("\t")[0]
                cases[check] = cases.get(check, 0) + 1

    passed, failed = {}, {}
    for path in glob.glob(os.path.join(args.results, "*.log")):
        for line in open(path, encoding="utf-8", errors="replace").read().splitlines():
            m = LINE.match(line)
            if m:
                table = passed if m.group(1) == "PASS" else failed
                table[m.group(2)] = table.get(m.group(2), 0) + 1

    problems = []
    confirmed = {s: 0 for s, _ in BUCKETS}
    for row in rows:
        status = row["status"]
        if status not in confirmed:
            continue
        name = row["name"]
        want = cases.get(name, 0)
        if want == 0:
            problems.append("VERIFY: %s: no lab case in %s/*/cases.tsv (status %s)" % (name, args.lab, status))
        elif failed.get(name, 0) > 0:
            problems.append("VERIFY: %s: %d case(s) FAILED" % (name, failed[name]))
        elif passed.get(name, 0) != want:
            problems.append("VERIFY: %s: expected %d passing case(s), CI ran %d" % (name, want, passed.get(name, 0)))
        else:
            confirmed[status] += 1

    for p in problems:
        print(p)
    for status, label in BUCKETS:
        print("%s: %d" % (label, confirmed[status]))
    if problems:
        print("check_verified: %d check(s) not proven in CI" % len(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
