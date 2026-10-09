#!/usr/bin/env python3
"""
Fetch apiserver /metrics and reduce it to a small whitelist.

Raw /metrics is several MB of text - useless to store daily and useless to a
model. We keep a few dozen numbers. Counters are stored raw; the DELTA between
daily snapshots is what gives you a rate, which is the whole point of keeping
state. Gauges (etcd db size, deprecated API usage) are meaningful as-is.

Writes JSON to stdout. Never fails hard - an empty result is a valid answer.
"""

import json
import re
import subprocess
import sys

# metric family -> how to reduce it
#   sum      : sum all series (optionally filtered by label predicate)
#   max      : max across series
#   by       : group by a label, sum within group
WHITELIST = [
    # --- etcd / storage: the classic control-plane outage path
    ("etcd_db_total_size_in_bytes",                 "max",  None,  "k8s.etcd.db_bytes"),
    ("apiserver_storage_db_total_size_in_bytes",    "max",  None,  "k8s.etcd.db_bytes_alt"),
    ("etcd_server_has_leader",                      "min",  None,  "k8s.etcd.has_leader"),
    ("etcd_server_leader_changes_seen_total",       "max",  None,  "k8s.etcd.leader_changes_total"),
    ("etcd_server_proposals_failed_total",          "sum",  None,  "k8s.etcd.proposals_failed_total"),
    ("apiserver_storage_objects",                   "sum",  None,  "k8s.etcd.objects_total"),

    # --- apiserver request health. Counters -> rates via snapshot diff.
    ("apiserver_request_total",                     "sum",  None,  "k8s.apiserver.requests_total"),
    ("apiserver_request_total",                     "sum",  ("code", r"^5\d\d$"), "k8s.apiserver.requests_5xx_total"),
    ("apiserver_request_total",                     "sum",  ("code", r"^429$"),   "k8s.apiserver.requests_429_total"),
    ("apiserver_request_terminations_total",        "sum",  None,  "k8s.apiserver.terminations_total"),
    ("apiserver_flowcontrol_rejected_requests_total", "sum", None, "k8s.apiserver.flowcontrol_rejected_total"),
    ("apiserver_current_inflight_requests",         "sum",  None,  "k8s.apiserver.inflight"),

    # --- deprecation: what is ACTUALLY being called, not what is theoretically deprecated
    ("apiserver_requested_deprecated_apis",         "by",   "removed_release", "k8s.apiserver.deprecated_apis"),

    # --- process health
    ("process_resident_memory_bytes",               "max",  None,  "k8s.apiserver.rss_bytes"),
    # Instance fingerprint. /metrics is served by whichever apiserver the
    # service VIP picked, so this is the only way to tell a restart from a
    # different instance answering.
    ("process_start_time_seconds",                  "max",  None,  "k8s.apiserver.start_time"),
    ("go_goroutines",                               "max",  None,  "k8s.apiserver.goroutines"),

    # --- audit / webhook latency indicators
    ("apiserver_admission_webhook_rejection_count", "sum",  None,  "k8s.apiserver.webhook_rejections_total"),
]

LINE_RE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?\s+([0-9.eE+\-]+|NaN|\+Inf|-Inf)\s*$')
LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def _labels(s):
    return {m.group(1): m.group(2) for m in LABEL_RE.finditer(s or "")}


def main():
    try:
        raw = subprocess.run(
            ["kubectl", "get", "--raw", "/metrics"],
            capture_output=True, text=True, timeout=45)
    except Exception as exc:
        json.dump({"error": "fetch failed: %s" % exc, "metrics": {}}, sys.stdout)
        return 0

    if raw.returncode != 0:
        json.dump({"error": (raw.stderr or "").strip()[:200], "metrics": {}}, sys.stdout)
        return 0

    wanted = {}
    for family, mode, pred, out_key in WHITELIST:
        wanted.setdefault(family, []).append((mode, pred, out_key))

    acc = {}
    for line in raw.stdout.splitlines():
        if not line or line[0] == "#":
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        family = m.group(1)
        # histogram/summary suffixes map back to the base family
        base = family
        for suf in ("_bucket", "_sum", "_count"):
            if family.endswith(suf):
                base = family[: -len(suf)]
                break
        rules = wanted.get(family) or (wanted.get(base) if base != family else None)
        if not rules:
            continue
        try:
            val = float(m.group(4))
        except ValueError:
            continue
        labels = _labels(m.group(3))

        for mode, pred, out_key in rules:
            if mode == "by":
                if family != base:
                    continue
                key = labels.get(pred) or "unknown"
                d = acc.setdefault(out_key, {})
                d[key] = d.get(key, 0.0) + val
                continue
            if pred:
                lbl, pattern = pred
                if not re.match(pattern, labels.get(lbl, "")):
                    continue
            if family != base and mode in ("sum", "max", "min"):
                continue  # don't fold histogram buckets into scalar reductions
            cur = acc.get(out_key)
            if mode == "sum":
                acc[out_key] = (cur or 0.0) + val
            elif mode == "max":
                acc[out_key] = val if cur is None else max(cur, val)
            elif mode == "min":
                acc[out_key] = val if cur is None else min(cur, val)

    # normalise floats that are really integers
    out = {}
    for k, v in acc.items():
        if isinstance(v, float) and v.is_integer():
            out[k] = int(v)
        else:
            out[k] = v

    json.dump({"metrics": out, "families_seen": len(acc)}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
