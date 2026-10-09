#!/usr/bin/env python3
"""Validate an AI narrative against the bundle.

The AI layer reasons; it never sources a number. Every count or age it
quotes must trace to a fact in the bundle. This validator is the mechanical
half of that contract: it extracts "number claims" from the narrative and
flags any number that does not match a fact PATH (and value) in the bundle.

  validate_narrative.py <narrative.md|-> <bundle.json>

A claim is `<int> <two following words>` (e.g. "704 pods", "26 days",
"1 515 PVCs"). A claim matches when some scalar bundle fact equals the
number AND its path shares a token with the following words, or (for prose
units) any fact value contains the number as a token. Exit 1 when anything
is unverifiable - with line numbers, so the author can fix the narrative.
"""

import json
import re
import sys

CLAIM_RE = re.compile(r"\b(\d[\d, ]{0,12}\d)\s+([A-Za-z][\w.\-/]{0,28}(?:\s[a-z][\w.\-/]{0,28})?|%)")
_PATH_STOP = {"the", "and", "for", "with", "older", "than", "that", "this",
              "are", "was", "were", "into", "from", "over", "since"}


def flatten(value, out, path=""):
    """Every scalar leaf -> (path, value) so a number in the narrative can
    find its path."""
    if isinstance(value, dict):
        for k, v in value.items():
            flatten(v, out, "%s.%s" % (path, k) if path else k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            flatten(v, out, path)
    else:
        out.append((path, value))


def claims(text):
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in CLAIM_RE.finditer(line):
            num_s = m.group(1).replace(" ", "").replace(",", "")
            try:
                num = float(num_s)
            except ValueError:
                continue
            words = re.findall(r"[a-z][\w.\-/]+", m.group(2).lower())
            toks = [w for w in words if w not in _PATH_STOP and len(w) > 2]
            yield lineno, num, toks, line.strip()


def main():
    if len(sys.argv) != 3:
        print("usage: validate_narrative.py <narrative.md|-> <bundle.json>",
              file=sys.stderr)
        return 2
    src, bundle_path = sys.argv[1], sys.argv[2]
    text = sys.stdin.read() if src == "-" else open(src).read()
    bundle = json.load(open(bundle_path))

    leaves = []
    for path, entry in (bundle.get("facts") or {}).items():
        flatten(entry.get("value"), leaves, path)

    def matches(num, toks):
        hit_with_token = False
        hit_any = False
        for path, value in leaves:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            if abs((value or 0) - num) > max(0.01, abs(num) * 0.005):
                continue
            hit_any = True
            ptoks = set(re.split(r"[._/\-:\s]+", str(path).lower()))
            if any(t in ptoks for t in toks):
                hit_with_token = True
        return hit_with_token, hit_any

    bad = []
    for lineno, num, toks, line in claims(text):
        strong, weak = matches(num, toks)
        if not (strong or weak):
            bad.append((lineno, num, toks, line))

    print("claims checked, %d flagged" % len(bad), file=sys.stderr)
    for lineno, num, toks, line in bad[:40]:
        print("line %d: number %s (%s) matches no fact path: %s"
              % (lineno, num, " ".join(toks) or "no context", line[:140]))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
