#!/usr/bin/env python3
"""lint_plugins.py - enforce the plugin tier rules.

Usage: python3 -I tools/lint_plugins.py [--plugins DIR] [--manifest FILE]
                                        [--fixtures DIR] [--lab DIR]

Prints one "LINT: <name>: <rule>: <what>" line per violation and exits 1
if there is any (0 if clean). Rules (see docs/plans/2026-11-22-almap-fix-design.md):

  rule1   every plugins/*.c has exactly one MANIFEST.tsv row and every row
          has a .c; family, tier and status are valid values
  rule2   verdict words only for the tier that may print them
          (VULNERABLE / NOT VULNERABLE: vuln; DETECTED / NOT DETECTED:
          detect); matched case-insensitively on word boundaries in
          printed (and unclassified) string literals and in shared
          headers; an experimental plugin's ar_out lines must start
          '<name>: INFO'
  rule3   tier vuln needs status lab; rule3b: tier experimental and
          status experimental go together
  rule4   status lab needs a row in lab/*/cases.tsv; status captured or
          derived needs fixtures/<name>/ with a pos-*.bin and a neg-*.bin
  rule5   every fixtures/*/*.bin has a complete .SOURCE (kind, url,
          retrieved YYYY-MM-DD, shows, basis; derived also template_commit)
  rule6   status captured needs every fixture of the check to be captured
  rule7   status derived needs tier detect
"""

import argparse
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import plugin_lex as lx  # noqa: E402

TIERS = ("vuln", "detect", "info", "experimental")
STATUSES = ("lab", "captured", "derived", "experimental")
FAMILIES = ("tls", "ssh", "smb", "db", "dns", "services", "http", "http-cve", "cloud", "iot")
COLUMNS = ("name", "family", "tier", "status", "evidence")
SOURCE_KEYS = ("kind", "url", "retrieved", "shows", "basis")

problems = []


def problem(name, rule, what):
    problems.append("LINT: %s: %s: %s" % (name, rule, what))


def read_manifest(path):
    """Return {name: row-dict}; report malformed and duplicate rows."""
    rows = {}
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        problem("MANIFEST.tsv", "rule1", "cannot read %s" % path)
        return rows
    header_seen = False
    for lineno, line in enumerate(lines, 1):
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if not header_seen:
            header_seen = True
            if tuple(cols) != COLUMNS:
                problem("MANIFEST.tsv", "rule1", "line %d: header must be %s" % (lineno, "\\t".join(COLUMNS)))
            continue
        if len(cols) != len(COLUMNS):
            problem("MANIFEST.tsv", "rule1", "line %d: expected %d columns, got %d" % (lineno, len(COLUMNS), len(cols)))
            continue
        row = dict(zip(COLUMNS, cols))
        name = row["name"]
        if name in rows:
            problem(name, "rule1", "duplicate manifest row (line %d)" % lineno)
            continue
        rows[name] = row
        for col, allowed in (("family", FAMILIES), ("tier", TIERS), ("status", STATUSES)):
            if row[col] not in allowed:
                problem(name, "rule1", "invalid %s '%s' (allowed: %s)" % (col, row[col], ", ".join(allowed)))
    return rows


def lab_checks(lab_dir):
    """Return the set of check names that appear in lab/*/cases.tsv."""
    names = set()
    for path in glob.glob(os.path.join(lab_dir, "*", "cases.tsv")):
        for line in open(path, encoding="utf-8").read().splitlines():
            if line.strip() and not line.startswith("#"):
                names.add(line.split("\t")[0])
    return names


def parse_source(path):
    keys = {}
    for line in open(path, encoding="utf-8").read().splitlines():
        if ":" in line and not line.startswith("#"):
            k, v = line.split(":", 1)
            keys[k.strip()] = v.strip()
    return keys


def lint_fixtures(fixtures_dir):
    """Rule 5 for every fixture; returns {check: {stem: kind-or-None}}."""
    kinds = {}
    for binpath in sorted(glob.glob(os.path.join(fixtures_dir, "*", "*.bin"))):
        check = os.path.basename(os.path.dirname(binpath))
        stem = os.path.basename(binpath)[:-4]
        label = "%s/%s" % (check, stem)
        src = binpath[:-4] + ".SOURCE"
        kind = None
        if not os.path.isfile(src):
            problem(label, "rule5", "no %s.SOURCE next to the fixture" % stem)
        else:
            keys = parse_source(src)
            missing = [k for k in SOURCE_KEYS if not keys.get(k)]
            if missing:
                problem(label, "rule5", ".SOURCE missing key(s): %s" % ", ".join(missing))
            kind = keys.get("kind")
            if kind not in ("captured", "derived"):
                problem(label, "rule5", ".SOURCE kind must be captured or derived, got '%s'" % kind)
            if keys.get("retrieved") and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", keys["retrieved"]):
                problem(label, "rule5", ".SOURCE retrieved must be YYYY-MM-DD, got '%s'" % keys["retrieved"])
            if kind == "derived" and not keys.get("template_commit"):
                problem(label, "rule5", "derived .SOURCE needs template_commit")
        kinds.setdefault(check, {})[stem] = kind
    return kinds


def lint_source_file(path, name, tier, is_header=False):
    """Rule 2 on one .c or .h file."""
    src = open(path, encoding="utf-8", errors="replace").read()
    toks = lx.lex(src)
    for lit in lx.literals(toks):
        if lx.is_matcher(lit):
            continue  # data searched for in / sent to the target, not output
        for word in lx.verdict_words(lit.text):
            need = lx.word_needs_tier(word)
            if is_header:
                problem(name, "rule2", "'%s' in a shared header (headers may not print verdicts)" % word)
            elif tier != need:
                problem(name, "rule2", "'%s' is not allowed for tier %s (needs tier %s)" % (word, tier, need))
    if tier == "experimental" and not is_header:
        prefix = name + ": INFO"
        for _, first in lx.first_ar_out_literals(toks):
            if first is None:
                problem(name, "rule2", "ar_out format is not a string literal; cannot check the INFO prefix")
            elif not first.startswith(prefix):
                problem(name, "rule2", "experimental line must start '%s', got '%s'" % (prefix, first[:40]))


def main():
    ap = argparse.ArgumentParser(description="lint the AlScript plugin tiers")
    ap.add_argument("--plugins", default="plugins")
    ap.add_argument("--manifest")
    ap.add_argument("--fixtures", default="tests/fixtures")
    ap.add_argument("--lab", default="tests/lab")
    args = ap.parse_args()
    manifest = args.manifest or os.path.join(args.plugins, "MANIFEST.tsv")

    rows = read_manifest(manifest)
    sources = {os.path.basename(p)[:-2]: p for p in glob.glob(os.path.join(args.plugins, "*.c"))}

    # rule 1: .c <-> row
    for name in sorted(sources):
        if name not in rows:
            problem(name, "rule1", "no manifest row for this plugin")
    for name in sorted(rows):
        if name not in sources:
            problem(name, "rule1", "manifest row has no %s.c" % name)

    fixture_kinds = lint_fixtures(args.fixtures)
    lab = lab_checks(args.lab)

    for name in sorted(rows):
        row = rows[name]
        tier, status = row["tier"], row["status"]
        # rule 3 / 3b / 7
        if tier == "vuln" and status != "lab":
            problem(name, "rule3", "tier vuln needs status lab (VULNERABLE needs a lab test), got %s" % status)
        if (tier == "experimental") != (status == "experimental"):
            problem(name, "rule3b", "tier %s and status %s must both be experimental or neither" % (tier, status))
        if status == "derived" and tier != "detect":
            problem(name, "rule7", "status derived needs tier detect, got %s" % tier)
        # rule 4 / 6
        if status == "lab" and name not in lab:
            problem(name, "rule4", "status lab but no row for it in %s/*/cases.tsv" % args.lab)
        if status in ("captured", "derived"):
            stems = fixture_kinds.get(name, {})
            if not any(s.startswith("pos-") for s in stems) or not any(s.startswith("neg-") for s in stems):
                problem(name, "rule4", "status %s needs fixtures/%s/ with a pos-*.bin and a neg-*.bin" % (status, name))
            if status == "captured":
                bad = sorted(s for s, k in stems.items() if k != "captured")
                if bad:
                    problem(name, "rule6", "status captured but fixture(s) not kind captured: %s" % ", ".join(bad))
        # rule 2 on the source itself
        if name in sources:
            lint_source_file(sources[name], name, tier)

    for hdr in sorted(glob.glob(os.path.join(args.plugins, "*.h"))):
        lint_source_file(hdr, os.path.basename(hdr), None, is_header=True)

    for line in problems:
        print(line)
    if problems:
        print("lint: %d problem(s)" % len(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
