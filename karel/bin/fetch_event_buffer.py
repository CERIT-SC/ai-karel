#!/usr/bin/env python3
"""Read the accumulated event buffers (today + yesterday) for the daily run.

Emits the SAME document shape as collect_events.py --once, plus a `buffer`
block describing the CronJob writes (when the last write happened, how many
of the expected writes succeeded, which sub-requests failed), so the report
can say "events: 24 h buffer, 96 of 96 writes" vs "events: live 1 h only" -
and can tell a stopped CronJob from a quiet night.

Entries are kept only for the KAREL_SINCE window (their `last` timestamp).
"""

import datetime
import json
import os
import subprocess
import sys

NS = os.environ.get("KAREL_NS", "ai-karel-ns")
WRITE_INTERVAL_MIN = 15


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _parse(ts):
    if not ts:
        return None
    s = str(ts).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _since(now):
    env = os.environ.get("KAREL_SINCE")
    if env:
        s = _parse(env)
        if s is not None:
            return max(s, now - datetime.timedelta(hours=48))
    return now - datetime.timedelta(hours=26)


def fetch(day):
    name = "karel-events-%s" % day
    r = subprocess.run(
        ["kubectl", "-n", NS, "get", "configmap", name, "-o", "jsonpath={.data.events}"],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


def _merge(dst, src, since=None):
    for key, v in (src or {}).items():
        if since is not None:
            last = _parse(v.get("last"))
            if last is not None and last < since:
                continue
        cur = dst.get(key)
        if cur is None:
            dst[key] = dict(v)
        else:
            # events carry over midnight rarely; summing two cumulative
            # snapshots of the same condition would double count - take max
            cur["count"] = max(cur.get("count") or 0, v.get("count") or 0)
            if v.get("first") and (not cur.get("first") or v["first"] < cur["first"]):
                cur["first"] = v["first"]
            if v.get("last") and (not cur.get("last") or v["last"] > cur["last"]):
                cur["last"] = v["last"]


def main():
    now = _now()
    since = _since(now)
    today = now.strftime("%Y-%m-%d")
    yday = (now - datetime.timedelta(days=1)).strftime("%Y-%m-%d")

    node, platform, patterns, dropped = {}, {}, {}, {}
    writes, sources = [], []
    for day in (yday, today):
        buf = fetch(day)
        if buf is None:
            continue
        sources.append(day)
        meta = buf.get("_meta") or {}
        for w in meta.get("writes") or []:
            at = _parse(w.get("written_at"))
            if at is None or (day == yday and at < since):
                continue
            writes.append(w)
        _merge(node, buf.get("node"), since=since)
        _merge(platform, buf.get("platform"), since=since)
        _merge(patterns, buf.get("patterns"))
        for k, v in (buf.get("dropped") or {}).items():
            dropped[k] = dropped.get(k, 0) + v

    writes.sort(key=lambda w: w.get("written_at") or "")
    last_write = writes[-1]["written_at"] if writes else None
    span_h = max(0.0, (now - since).total_seconds() / 3600.0)
    expected = max(1, int(span_h * 60 / WRITE_INTERVAL_MIN))
    failed_requests = sorted({r["name"] for w in writes
                              for r in w.get("requests", [])
                              if r.get("status") != "ok"})
    write_meta = {
        "writes": len(writes),
        "expected_writes": expected,
        "last_write_at": last_write,
        "last_write_age_m": (round((now - _parse(last_write)).total_seconds() / 60.0, 1)
                             if _parse(last_write) else None),
        "failed_requests": failed_requests,
        "source_days": sources,
        "window_from": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    ok_writes = sum(1 for w in writes
                    if all(r.get("status") == "ok"
                           for r in w.get("requests", [])))

    json.dump({
        "available": bool(sources),
        "captured_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "requests": [],
        "node": node,
        "platform": platform,
        "patterns": patterns,
        "dropped": dropped,
        "buffer": dict(write_meta, ok_writes=ok_writes),
        "requests_status": "ok" if not failed_requests else "failed",
    }, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
