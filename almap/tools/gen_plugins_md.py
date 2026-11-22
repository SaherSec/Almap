#!/usr/bin/env python3
"""gen_plugins_md.py - generate docs/PLUGINS.md from plugins/MANIFEST.tsv.

Usage: python3 -I tools/gen_plugins_md.py [--manifest FILE] [--out FILE] [--check]

Writes the four separate counts (never one combined number), the total, a
per-family table and a per-check table. With --check nothing is written:
exit 1 if the file is missing or differs from what would be generated.
Exit 2 on a malformed manifest.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MANIFEST = os.path.join(HERE, "..", "plugins", "MANIFEST.tsv")
DEFAULT_OUT = os.path.join(HERE, "..", "..", "docs", "PLUGINS.md")

COLUMNS = ("name", "family", "tier", "status", "evidence")
# status -> label of its count; the order is the order shown
COUNTS = (
    ("lab", "Verified (lab)"),
    ("captured", "Verified (captured fixture)"),
    ("derived", "Detected (derived fixture)"),
    ("experimental", "Experimental"),
)


def read_manifest(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        header = False
        for lineno, line in enumerate(fh.read().splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            cols = line.split("\t")
            if not header:
                header = True
                if tuple(cols) != COLUMNS:
                    raise ValueError("line %d: header must be %s" % (lineno, "\\t".join(COLUMNS)))
                continue
            if len(cols) != len(COLUMNS):
                raise ValueError("line %d: expected %d columns, got %d" % (lineno, len(COLUMNS), len(cols)))
            row = dict(zip(COLUMNS, cols))
            if row["status"] not in dict(COUNTS):
                raise ValueError("line %d: unknown status '%s'" % (lineno, row["status"]))
            rows.append(row)
    return rows


def render(rows):
    by_status = {s: 0 for s, _ in COUNTS}
    fam = {}
    for r in rows:
        by_status[r["status"]] += 1
        f = fam.setdefault(r["family"], {s: 0 for s, _ in COUNTS})
        f[r["status"]] += 1

    out = []
    out.append("# Plugin status")
    out.append("")
    out.append("Generated from `almap/plugins/MANIFEST.tsv` by `almap/tools/gen_plugins_md.py`. Do not edit by hand.")
    out.append("")
    out.append("```")
    for status, label in COUNTS:
        out.append("%s: %d" % (label, by_status[status]))
    out.append("")
    out.append("Total checks: %d" % len(rows))
    out.append("```")
    out.append("")
    out.append("The four counts are separate and are never added together.")
    out.append("")
    out.append("- **Verified (lab)**: the verdict was proven against real vulnerable, patched and neutral targets running in the podman lab.")
    out.append("- **Verified (captured fixture)**: proven against responses captured byte for byte from a cited source.")
    out.append("- **Detected (derived fixture)**: backed only by responses derived from a published scanner matcher. It can say DETECTED or NOT DETECTED, never VULNERABLE.")
    out.append("- **Experimental**: not yet proven; it prints INFO lines only.")
    out.append("")
    out.append("## By family")
    out.append("")
    out.append("| Family | Lab | Captured | Derived | Experimental | Total |")
    out.append("|---|---|---|---|---|---|")
    for name in sorted(fam):
        f = fam[name]
        out.append("| %s | %d | %d | %d | %d | %d |" % (
            name, f["lab"], f["captured"], f["derived"], f["experimental"], sum(f.values())))
    out.append("")
    out.append("## All checks")
    out.append("")
    out.append("| Check | Family | Tier | Status | Evidence |")
    out.append("|---|---|---|---|---|")
    for r in sorted(rows, key=lambda r: r["name"]):
        out.append("| %s | %s | %s | %s | %s |" % (r["name"], r["family"], r["tier"], r["status"], r["evidence"]))
    out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="generate docs/PLUGINS.md")
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="do not write; exit 1 if the file is stale")
    args = ap.parse_args()

    try:
        text = render(read_manifest(args.manifest))
    except (OSError, ValueError) as exc:
        print("gen_plugins_md: %s" % exc, file=sys.stderr)
        return 2

    if args.check:
        try:
            current = open(args.out, encoding="utf-8").read()
        except OSError:
            print("gen_plugins_md: %s is missing; run tools/gen_plugins_md.py" % args.out, file=sys.stderr)
            return 1
        if current != text:
            print("gen_plugins_md: %s is out of date; run tools/gen_plugins_md.py" % args.out, file=sys.stderr)
            return 1
        return 0

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
