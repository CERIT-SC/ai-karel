#!/usr/bin/env python3
"""
Event buffer - run this as a SEPARATE CronJob every 15 minutes.

Kubernetes Events default to a 1-hour TTL. A daily report therefore sees the
last hour of a 24-hour window and will confidently describe a quiet night.
OOMKills, evictions, FailedScheduling, probe failures and image pull errors
are all Events, so this is the single biggest blind spot in a daily-only
collector.

Each pass runs the SAME filtered collection as the daily run
(lib/events_collect.py: node events, platform warnings, tenant patterns -
bounded even in a 30,000-event tenant burst) and merges it into a per-day
ConfigMap in Karel's namespace. The daily run reads it via
fetch_event_buffer.py.

Deliberately lossy: aggregate keys with counts and first/last seen. Never
event messages - they are unbounded and often carry application data we do
not want to email. Every write records `_meta`: written-at, per-request
status and item counts, and dropped counts, so a stopped or partially
denied CronJob is visible in the daily report.
"""

import datetime
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "lib"))

import events_collect      # noqa: E402

NS = os.environ.get("KAREL_NS", "ai-karel-ns")
MAX_WRITES_KEPT = 110        # > the 96 a day needs; bounded ConfigMap size


def _iso_now():
    return datetime.datetime.now(datetime.timezone.utc)


def run(args, timeout=60):
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=timeout)


def cm_name():
    return "karel-events-%s" % _iso_now().strftime("%Y-%m-%d")


def load_existing(name):
    r = run(["kubectl", "-n", NS, "get", "configmap", name,
             "-o", "jsonpath={.data.events}"])
    if r.returncode != 0 or not r.stdout.strip():
        return {}
    try:
        return json.loads(r.stdout)
    except Exception:
        return {}


def main():
    doc = events_collect.collect()
    failed = [r["name"] for r in doc["requests"] if r["status"] != "ok"]

    name = cm_name()
    buf = load_existing(name)
    events_collect.merge_buffers(buf.setdefault("node", {}), doc["node"])
    events_collect.merge_buffers(buf.setdefault("platform", {}),
                                 doc["platform"])
    for reason, p in doc["patterns"].items():
        cur = buf.setdefault("patterns", {}).get(reason)
        if cur is None or (p.get("count") or 0) >= (cur.get("count") or 0):
            buf["patterns"][reason] = p
    for k, v in (doc.get("dropped") or {}).items():
        if v:
            d = buf.setdefault("dropped", {})
            d[k] = d.get(k, 0) + v

    meta = buf.setdefault("_meta", {"writes": []})
    meta["writes"].append({
        "written_at": doc["captured_at"],
        "requests": [{"name": r["name"], "status": r["status"],
                      "items": r["items"]} for r in doc["requests"]],
        "dropped": doc.get("dropped") or {},
    })
    meta["writes"] = meta["writes"][-MAX_WRITES_KEPT:]
    meta["buffer_format"] = 2

    payload = json.dumps(buf, separators=(",", ":"))
    if len(payload) > 900_000:
        # Hard backstop for etcd: cut the largest keys, keep the structure.
        print("event-buffer: payload too large (%d), truncating platform keys"
              % len(payload), file=sys.stderr)
        keep = sorted(buf["platform"].items(),
                      key=lambda kv: -(kv[1].get("count") or 0))[:200]
        buf["platform"] = dict(keep)
        buf["_meta"]["hard_truncated"] = True
        payload = json.dumps(buf, separators=(",", ":"))

    tmp = "/tmp/events.json"
    with open(tmp, "wt") as fh:
        fh.write(payload)

    gen = run(["kubectl", "-n", NS, "create", "configmap", name,
               "--from-file=events=" + tmp, "--dry-run=client", "-o", "yaml"])
    if gen.returncode != 0:
        print("event-buffer: dry-run failed: %s"
              % (gen.stderr or "")[:200], file=sys.stderr)
        return 0
    ap = subprocess.run(["kubectl", "-n", NS, "apply", "-f", "-"],
                        input=gen.stdout, capture_output=True, text=True,
                        timeout=60)
    if ap.returncode != 0:
        print("event-buffer: apply failed: %s"
              % (ap.stderr or "")[:200], file=sys.stderr)
        return 0

    run(["kubectl", "-n", NS, "label", "configmap", name,
         "app=karel", "karel/kind=event-buffer", "--overwrite"])
    print("event-buffer: %d node keys, %d platform keys, %d patterns, "
          "%d failed requests" % (len(buf["node"]), len(buf["platform"]),
                                  len(buf["patterns"]), len(failed)),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
