"""
Filtered, bounded event collection - shared by the 15-minute CronJob
(bin/event_buffer.py) and the daily run (bin/collect_events.py --once).

Replaces the old "get every event, keep the 800 noisiest" with a few
server-side filtered requests, so output stays bounded during a 30,000-event
tenant burst and node events are never dropped:

  1. node events        involvedObject.kind=Node, ALL types (NodeNotReady is
                        a Normal event; filtering type=Warning would lose it)
  2. platform warnings  type=Warning, one request per platform namespace
  3. tenant patterns    reason=<R>,type=Warning, one request per pattern
                        reason; aggregated to counts + namespaces, and
                        platform namespaces are excluded from the result

Aggregation: per event OBJECT take the maximum of its cumulative count (event
objects are cumulative while the condition lasts), then sum across objects
with the same key. Pod names collapse to owner names: a ReplicaSet hash and
the 5-character pod suffix go, StatefulSet ordinals stay.

Truncation is by tier, never by count: node keys are never dropped (bounded
by nodes x reasons), platform keys are capped at MAX_PLATFORM_KEYS, and the
dropped counts are recorded - never silently.
"""

import datetime
import json
import re
import subprocess

MAX_PLATFORM_KEYS = 600
KUBECTL_TIMEOUT = 45

# reason -> what widespread occurrence points at (used in finding titles)
PATTERN_REASONS = {
    "FailedCreatePodSandBox": "CNI (Calico)",
    "FailedMount":            "CSI node plugins / storage backend",
    "FailedAttachVolume":     "CSI node plugins / storage backend",
    "ProvisioningFailed":     "CSI provisioner / storage backend",
    "FailedScheduling":       "cluster capacity",
    "Evicted":                "node pressure",
}

# Reasons that are node-level in nature; platform findings stay WARN for
# these, pod-level noise stays INFO (same policy as the old rule).
NODE_REASONS = {"NodeNotReady", "OOMKilling", "SystemOOM", "Evicted", "Rebooted",
                "FailedCreatePodSandBox", "NodeHasDiskPressure",
                "NodeHasInsufficientMemory", "FreeDiskSpaceFailed",
                "ImageGCFailed", "ContainerGCFailed"}

_RS_SUFFIX = re.compile(r"-[a-f0-9]{8,10}-[a-z0-9]{5}$")
_POD_SUFFIX = re.compile(r"-[a-z0-9]{5}$")


def owner_name(pod_name):
    """Pod -> owning workload name. ReplicaSet hash + pod suffix are stripped,
    StatefulSet ordinals ('-3') are kept."""
    if not pod_name:
        return pod_name
    if _RS_SUFFIX.search(pod_name):
        return _RS_SUFFIX.sub("", pod_name)
    return _POD_SUFFIX.sub("", pod_name)


def kubectl_raw(argv, timeout=KUBECTL_TIMEOUT, runner=None):
    """-> (stdout|None, error|None). `runner` is injectable for tests."""
    if runner is None:
        def runner(args, tmo):
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=tmo)
    try:
        r = runner(["kubectl"] + argv, timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except OSError as exc:
        return None, str(exc)
    if r.returncode != 0:
        return None, (r.stderr or "").strip()[:160]
    return r.stdout or "", None


def kubectl_json(argv, timeout=KUBECTL_TIMEOUT, runner=None):
    """Small documents only (the namespace list)."""
    text, err = kubectl_raw(argv, timeout=timeout, runner=runner)
    if err:
        return None, err
    try:
        return json.loads(text or "{}"), None
    except ValueError:
        return None, "unparseable output"


def _items(doc):
    return doc.get("items") or []


def iter_items(text):
    """Yield items of a kubectl list JSON ONE AT A TIME.

    A tenant burst is tens of thousands of event objects; parsing the whole
    document at once peaks the CronJob's RSS far above its limit. The output
    text itself is a fraction of the parsed objects' cost, so streaming from
    the text keeps peak memory to the wire size plus the aggregates."""
    dec = json.JSONDecoder()
    i = text.find('"items"')
    if i < 0:
        return
    j = text.find("[", i)
    if j < 0:
        return
    pos, n = j + 1, len(text)
    while pos < n:
        while pos < n and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= n or text[pos] == "]":
            return
        try:
            obj, end = dec.raw_decode(text, pos)
        except ValueError:
            return
        yield obj
        pos = end


def _times(e):
    last = e.get("lastTimestamp") or e.get("eventTime") or \
        (e.get("series") or {}).get("lastObservedTime")
    first = e.get("firstTimestamp") or last
    return first, last


def accum_events(store, items, key_fn, per_uid=None):
    """key_fn(event) -> key or None. Events are cumulative while alive, so
    per UID only the maximum counts; UIDs sharing a key are summed."""
    tmp = {}
    for e in items:
        key = key_fn(e)
        if key is None:
            continue
        uid = (e.get("metadata") or {}).get("uid") or id(e)
        first, last = _times(e)
        count = e.get("count") or (e.get("series") or {}).get("count") or 1
        slot = tmp.setdefault((key, uid), {"count": 0, "first": first,
                                           "last": last})
        slot["count"] = max(slot["count"], count)
        if first and (not slot["first"] or first < slot["first"]):
            slot["first"] = first
        if last and (not slot["last"] or last > slot["last"]):
            slot["last"] = last
    for (key, uid), v in tmp.items():
        cur = store.get(key)
        if cur is None:
            store[key] = {"count": v["count"], "first": v["first"],
                          "last": v["last"]}
        else:
            cur["count"] += v["count"]
            if v["first"] and (not cur["first"] or v["first"] < cur["first"]):
                cur["first"] = v["first"]
            if v["last"] and (not cur["last"] or v["last"] > cur["last"]):
                cur["last"] = v["last"]
    return store


def merge_buffers(dst, src):
    """Merge a previous 15-min pass. Counts take the max (cumulative
    snapshots of the same objects), first/last extend."""
    for key, v in (src or {}).items():
        cur = dst.get(key)
        if cur is None:
            dst[key] = dict(v)
        else:
            cur["count"] = max(cur.get("count") or 0, v.get("count") or 0)
            if v.get("first") and (not cur.get("first")
                                   or v["first"] < cur["first"]):
                cur["first"] = v["first"]
            if v.get("last") and (not cur.get("last")
                                  or v["last"] > cur["last"]):
                cur["last"] = v["last"]
    return dst


def collect(runner=None, platform_ns=None, now=None, skip_patterns=False):
    """One bounded collection pass. `platform_ns` and `runner` are injectable
    so tests run without a cluster. skip_patterns=True handles clusters where
    field-selector on reason is denied.

    Returns the aggregate document:
      {"captured_at", "requests": [{name, status, items}], "node": {...},
       "platform": {...}, "patterns": {...}, "dropped": {...}}
    """
    import scope                       # late: bin/ and lib/ share sys.path

    now = now or datetime.datetime.now(datetime.timezone.utc)
    requests = []
    node_acc, plat_acc, patterns = {}, {}, {}

    # ------------------------------------------------- 1. node events (all)
    text, err = kubectl_raw(
        ["get", "events", "-A", "-o", "json",
         "--field-selector", "involvedObject.kind=Node"], runner=runner)
    n_items = 0
    if text is not None:
        def node_key(e):
            io = e.get("involvedObject") or {}
            node = io.get("name")
            reason = e.get("reason") or "Unknown"
            return "Node|%s|%s" % (node, reason) if node else None
        for e in iter_items(text):
            accum_events(node_acc, [e], node_key)
            n_items += 1
    requests.append({"name": "nodes",
                     "status": "ok" if err is None else "failed",
                     "error": err, "items": n_items})

    # --------------------------------------------- 2. platform ns warnings
    if platform_ns is None:
        nsdoc, nserr = kubectl_json(["get", "namespaces", "-o", "json"],
                                    runner=runner)
        requests.append({"name": "namespaces",
                         "status": "ok" if nserr is None else "failed",
                         "error": nserr,
                         "items": len(_items(nsdoc)) if nsdoc else 0})
        names = [(i.get("metadata") or {}).get("name")
                 for i in _items(nsdoc)] if nsdoc else []
        platform_ns = sorted(n for n in names if n and scope.is_platform(n))

    for ns in platform_ns:
        text, err = kubectl_raw(
            ["get", "events", "-n", ns, "-o", "json",
             "--field-selector", "type=Warning"], runner=runner)
        n_items = 0
        if text is not None:
            def plat_key(e):
                io = e.get("involvedObject") or {}
                kind = io.get("kind") or "-"
                name = io.get("name") or "-"
                if kind == "Pod":
                    name = owner_name(name) or name
                reason = e.get("reason") or "Unknown"
                return "%s|%s|%s|%s" % (ns, kind, name, reason)
            for e in iter_items(text):
                accum_events(plat_acc, [e], plat_key)
                n_items += 1
        requests.append({"name": "platform/%s" % ns,
                         "status": "ok" if err is None else "failed",
                         "error": err, "items": n_items})

    # ------------------------------------------------ 3. tenant patterns
    dropped = {"platform_keys": 0, "reasons": 0}
    if not skip_patterns:
        for reason in sorted(PATTERN_REASONS):
            text, err = kubectl_raw(
                ["get", "events", "-A", "-o", "json",
                 "--field-selector", "reason=%s,type=Warning" % reason],
                runner=runner)
            n_items, total, by_ns = 0, 0, {}
            if text is not None:
                for e in iter_items(text):
                    n_items += 1
                    io = e.get("involvedObject") or {}
                    ns = io.get("namespace") or \
                        (e.get("metadata") or {}).get("namespace") or "-"
                    if scope.is_platform(ns):
                        continue      # already collected in pass 2, exactly
                    count = e.get("count") or \
                        (e.get("series") or {}).get("count") or 1
                    total += count
                    by_ns[ns] = by_ns.get(ns, 0) + count
            requests.append({"name": "pattern/%s" % reason,
                             "status": "ok" if err is None else "failed",
                             "error": err, "items": n_items})
            if total:
                patterns[reason] = {
                    "suspect": PATTERN_REASONS[reason],
                    "count": total,
                    "ns_count": len(by_ns),
                    "top": sorted(by_ns.items(), key=lambda kv: (-kv[1], kv[0]))[:5],
                }
    if len(patterns) > 20:
        keep = sorted(patterns.items(), key=lambda kv: -kv[1]["count"])[:20]
        dropped["reasons"] = len(patterns) - len(keep)
        patterns = dict(keep)

    if len(plat_acc) > MAX_PLATFORM_KEYS:
        keep = sorted(plat_acc.items(),
                      key=lambda kv: -(kv[1].get("count") or 0))[:MAX_PLATFORM_KEYS]
        dropped["platform_keys"] = len(plat_acc) - len(keep)
        plat_acc = dict(keep)

    return {
        "captured_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "requests": requests,
        "node": node_acc,
        "platform": plat_acc,
        "patterns": patterns,
        "dropped": dropped,
    }
