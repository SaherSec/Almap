#!/usr/bin/env python3
"""downgrade_plugins.py - one-off day-one downgrade of every plugin.

Usage: python3 -I tools/downgrade_plugins.py [--plugins DIR]

Writes plugins/MANIFEST.tsv with every plugin at tier experimental /
status experimental, and rewrites each plugin's printed text so that no
plugin claims a verdict until a family batch has verified it:

  * every ar_out(ctx, "<fmt>") line now starts '<name>: INFO ' (an
    existing '<name>: ' prefix gets INFO inserted; any other text is kept
    after the new prefix, so no information is lost)
  * verdict words in printed literals are replaced:
      not vulnerable -> probe did not match     vulnerable -> matches probe for
      not detected   -> probe did not match     detected   -> probe matched
  * literals that are arguments of matcher/payload calls (strstr, ...) are
    data searched for in or sent to the target and are not touched.

Kept in the repository for the record; running it twice changes nothing.
"""

import argparse
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import plugin_lex as lx  # noqa: E402

SUBS = (
    (re.compile(r"\bnot\s+vulnerable\b", re.IGNORECASE), "probe did not match"),
    (re.compile(r"\bvulnerable\b", re.IGNORECASE), "matches probe for"),
    (re.compile(r"\bnot\s+detected\b", re.IGNORECASE), "probe did not match"),
    (re.compile(r"\bdetected\b", re.IGNORECASE), "probe matched"),
)

# name prefix -> family; first match wins (checked in this order)
FAMILY_RULES = (
    (re.compile(r"^http-vuln-"), "http-cve"),
    (re.compile(r"^(ssl|tls)[-_]"), "tls"),
    (re.compile(r"^ssh\d?[-_]"), "ssh"),
    (re.compile(r"^smb\d?[-_]"), "smb"),
    (re.compile(r"^(mysql|pgsql|ms-sql|mssql|mongodb|redis|oracle|couchdb|memcached|cassandra|influxdb|elasticsearch)[-_]"), "db"),
    (re.compile(r"^dns[-_]"), "dns"),
    (re.compile(r"^(docker|kubernetes|cloud)[-_]"), "cloud"),
    (re.compile(r"^iot[-_]"), "iot"),
    (re.compile(r"^(http|tomcat|weblogic)[-_]"), "http"),
)


def family_of(name):
    for rx, fam in FAMILY_RULES:
        if rx.match(name):
            return fam
    return "services"


def substitute(text):
    for rx, repl in SUBS:
        text = rx.sub(repl, text)
    return text


def with_info_prefix(name, text):
    head = name + ": "
    if text.startswith(head + "INFO"):
        return text  # already downgraded
    if text.startswith(head):
        return head + "INFO " + text[len(head):]
    return head + "INFO " + text


def downgrade_source(name, src):
    """Return (new_source, rewritten_literal_count)."""
    toks = lx.lex(src)
    lits = lx.literals(toks)
    first_ar_out = {}  # literal start offset -> True
    for k, t in enumerate(toks):
        if t.kind == "id" and t.text == "ar_out" and k + 4 < len(toks):
            if toks[k + 1].text == "(" and toks[k + 2].text == "ctx" and toks[k + 3].text == "," and toks[k + 4].kind == "str":
                first_ar_out[toks[k + 4].start] = True
    edits = []
    for lit in lits:
        if lx.is_matcher(lit):
            continue
        new = lit.text
        if lit.start in first_ar_out:
            new = with_info_prefix(name, new)
        if lx.verdict_words(new):
            new = substitute(new)
        if new != lit.text:
            edits.append((lit.start + 1, lit.end - 1, new))
    out = src
    for start, end, new in sorted(edits, reverse=True):
        out = out[:start] + new + out[end:]
    return out, len(edits)


def main():
    ap = argparse.ArgumentParser(description="day-one plugin downgrade")
    ap.add_argument("--plugins", default="plugins")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.plugins, "*.c")))
    rows = []
    changed = 0
    literals_changed = 0
    for path in files:
        name = os.path.basename(path)[:-2]
        src = open(path, encoding="utf-8").read()
        new, n = downgrade_source(name, src)
        if new != src:
            open(path, "w", encoding="utf-8").write(new)
            changed += 1
            literals_changed += n
        rows.append((name, family_of(name)))

    with open(os.path.join(args.plugins, "MANIFEST.tsv"), "w", encoding="utf-8") as fh:
        fh.write("name\tfamily\ttier\tstatus\tevidence\n")
        for name, fam in rows:
            fh.write("%s\t%s\texperimental\texperimental\t-\n" % (name, fam))

    fams = {}
    for _, fam in rows:
        fams[fam] = fams.get(fam, 0) + 1
    print("plugins: %d, files rewritten: %d, literals rewritten: %d" % (len(rows), changed, literals_changed))
    print("families: " + ", ".join("%s=%d" % kv for kv in sorted(fams.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
