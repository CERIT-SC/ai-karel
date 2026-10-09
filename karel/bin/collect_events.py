#!/usr/bin/env python3
"""Daily event collection for Karel: one filtered, bounded pass.

Replaces `kubectl get events -A -o json` (32,008 objects on 2026-10-07) with
a few server-side filtered requests - see lib/events_collect.py. Output is
one JSON document with node / platform / tenant-pattern aggregates.

  collect_events.py --once        # the k_events manifest command

Exits 0 and reports per-request status unless the collector itself fails.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "lib"))

import events_collect      # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true",
                    help="one bounded pass (the only mode so far)")
    args = ap.parse_args()
    if not args.once:
        ap.error("only --once is implemented")

    doc = events_collect.collect()
    json.dump(doc, sys.stdout)
    ok = sum(1 for r in doc["requests"] if r["status"] == "ok")
    print("collect_events: %d/%d requests ok, %d node keys, %d platform keys"
          % (ok, len(doc["requests"]), len(doc["node"]), len(doc["platform"])),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
