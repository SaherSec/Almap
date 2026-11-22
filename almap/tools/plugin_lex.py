"""plugin_lex.py - a small C lexer for the AlScript plugins.

Used by tools/lint_plugins.py and tools/downgrade_plugins.py. It drops
comments and keeps every string literal with its byte offsets, and it
classifies each string literal by the call it is an argument of (which
call, which argument, and whether the call writes into ctx->output_buf).
No third-party modules.
"""

import re
from collections import namedtuple

# kind: 'str' (text excludes the quotes), 'chr', 'id' or 'p' (punctuation)
Token = namedtuple("Token", "kind text start end")

# A string literal and the call it is an argument of.
#   call:       callee name, or None outside a call
#   argidx:     0-based argument position inside that call
#   dst_output: the call's first argument mentions output_buf
Literal = namedtuple("Literal", "start end text call argidx dst_output")

# Calls whose string arguments are data searched for in, or sent to, the
# target: never output.
MATCHER_CALLS = frozenset(
    [
        "strstr", "strcasestr", "strcmp", "strncmp", "strcasecmp",
        "strncasecmp", "memcmp", "ar_contains_ci", "ar_starts_ci",
        "ar_http_request", "ar_http_get", "ar_http_head", "ar_http_post",
    ]
)

# What a plugin may only print according to its tier.
_VULN_RE = re.compile(r"\b(?:not\s+vulnerable|vulnerable)\b", re.IGNORECASE)
_DET_RE = re.compile(r"\b(?:not\s+detected|detected)\b", re.IGNORECASE)
VERDICT_RE = re.compile(
    r"\b(?:not\s+vulnerable|vulnerable|not\s+detected|detected)\b", re.IGNORECASE
)


def lex(src):
    """Return the tokens of C source `src`, without comments."""
    toks = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            kind = "str" if c == '"' else "chr"
            text = src[i + 1 : j] if c == '"' else src[i : j + 1]
            toks.append(Token(kind, text, i, j + 1))
            i = j + 1
            continue
        if c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            toks.append(Token("id", src[i:j], i, j))
            i = j
            continue
        if c.isspace():
            i += 1
            continue
        toks.append(Token("p", c, i, i + 1))
        i += 1
    return toks


def literals(tokens):
    """Return every string literal in `tokens` as a Literal."""
    stack = []  # one [callee, argidx, dst_output] per open parenthesis
    out = []
    for k, t in enumerate(tokens):
        if t.kind == "p":
            if t.text == "(":
                prev = tokens[k - 1] if k else None
                callee = prev.text if prev is not None and prev.kind == "id" else None
                stack.append([callee, 0, False])
            elif t.text == ")":
                if stack:
                    stack.pop()
            elif t.text == "," and stack:
                stack[-1][1] += 1
        elif t.kind == "id":
            if t.text == "output_buf" and stack and stack[-1][1] == 0:
                stack[-1][2] = True
        elif t.kind == "str":
            if stack:
                callee, argidx, dst = stack[-1]
            else:
                callee, argidx, dst = None, 0, False
            out.append(Literal(t.start, t.end, t.text, callee, argidx, dst))
    return out


def is_emitted(lit):
    """True if the literal is printed: an argument of ar_out/ar_append, or
    of a call that writes into ctx->output_buf (first argument)."""
    if lit.argidx < 1:
        return False
    return lit.call in ("ar_out", "ar_append") or lit.dst_output


def is_matcher(lit):
    return lit.call in MATCHER_CALLS


def verdict_words(text):
    """Return the verdict words found in `text`, upper-cased."""
    return [re.sub(r"\s+", " ", m.group(0)).upper() for m in VERDICT_RE.finditer(text)]


def word_needs_tier(word):
    """The tier that may print `word` ('vuln' or 'detect')."""
    return "vuln" if "VULNERABLE" in word else "detect"


def first_ar_out_literals(tokens):
    """For every `ar_out(ctx, ...)` call return (token_index_of_ar_out,
    first_literal_or_None). None means the format is not a plain literal."""
    res = []
    for k, t in enumerate(tokens):
        if t.kind == "id" and t.text == "ar_out" and k + 1 < len(tokens) and tokens[k + 1].text == "(":
            ok = (
                k + 4 < len(tokens)
                and tokens[k + 2].text == "ctx"
                and tokens[k + 3].text == ","
                and tokens[k + 4].kind == "str"
            )
            res.append((k, tokens[k + 4].text if ok else None))
    return res
