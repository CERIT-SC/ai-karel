#!/usr/bin/env python3
"""
Karel Prometheus collector.

Prometheus changes what Karel can honestly claim. Without it, Karel sees one
instant per day and any statement about a trend is a two-point extrapolation.
With it:

  * rates are real (per-instance scraping, so counters are comparable)
  * peaks are measured, not inferred from requests
  * transients are visible - a node that went NotReady at 03:00 and recovered
    leaves no trace in a point-in-time report
  * forecasts use predict_linear over two weeks instead of yesterday-vs-today

What it does NOT provide: configuration. Node reservations, webhook config,
RBAC - none of that is a time series. The structural rules stay exactly as
they are.

Two hard rules, both learned earlier in this codebase:

  1. Prometheus lives on the cluster it monitors. When the cluster is sick,
     Prometheus may be down, and that is precisely when its history is wanted.
     Unreachable is a FINDING, never a crash, and never silence.
  2. Absence of a metric is not zero. A query that returns no series means
     "not scraped" or "does not exist on this release", which is different
     from "the value is zero". Those are recorded distinctly.

stdlib only - no requests, no prometheus_api_client.
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROM_URL = os.environ.get(
    "PROM_URL",
    "http://rancher-monitoring-prometheus.cattle-monitoring-system.svc:9090")
ALERTMANAGER_URL = os.environ.get(
    "ALERTMANAGER_URL",
    "http://rancher-monitoring-alertmanager.cattle-monitoring-system.svc:9093")
MANIFEST = os.environ.get("PROM_MANIFEST", "/etc/karel/prom-queries.json")
OUT = os.environ.get("OUT_PROM", "/tmp/out-prom")
BUDGET = int(os.environ.get("PROM_BUDGET", "180"))
MAX_TIER = int(os.environ.get("PROM_MAX_TIER", "3"))
TOKEN_FILE = os.environ.get("PROM_TOKEN_FILE", "")


def _ctx():
    c = ssl.create_default_context()
    if os.environ.get("PROM_INSECURE_TLS") == "1":
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    return c


def _get(url, timeout):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if TOKEN_FILE and os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as fh:
            req.add_header("Authorization", "Bearer " + fh.read().strip())
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def query(expr, timeout):
    """Instant query. Returns (status, result-or-error)."""
    url = "%s/api/v1/query?%s" % (
        PROM_URL.rstrip("/"), urllib.parse.urlencode({"query": expr}))
    try:
        doc = _get(url, timeout)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = json.loads(e.read().decode("utf-8", "replace")).get("error", "")
        except Exception:
            pass
        return "failed", "HTTP %s %s" % (e.code, body[:160])
    except Exception as exc:
        return "unreachable", "%s: %s" % (type(exc).__name__, str(exc)[:160])

    if doc.get("status") != "success":
        return "failed", str(doc.get("error"))[:160]
    return "ok", (doc.get("data") or {}).get("result") or []


def _num(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    # PromQL returns NaN for empty histogram quantiles; that is "unknown"
    return None if f != f else f


def reduce_result(result, mode):
    """Collapse a PromQL result into something a rule can use.

    Returns (value, n_series). value is None when there were no series, which
    the caller must treat as 'not scraped', never as zero.
    """
    if not result:
        return None, 0
    n = len(result)

    if mode == "scalar" or mode is None:
        return _num(result[0].get("value", [None, None])[1]), n

    if mode in ("max", "min"):
        vals = [v for v in (_num(s.get("value", [None, None])[1]) for s in result)
                if v is not None]
        if not vals:
            return None, n
        return (max(vals) if mode == "max" else min(vals)), n

    if mode == "sum":
        vals = [v for v in (_num(s.get("value", [None, None])[1]) for s in result)
                if v is not None]
        return (sum(vals) if vals else None), n

    if mode and mode.startswith("by:"):
        key = mode[3:]
        out = {}
        for s in result:
            k = (s.get("metric") or {}).get(key)
            v = _num(s.get("value", [None, None])[1])
            if k is not None and v is not None:
                out[k] = v
        return (out or None), n

    if mode and mode.startswith("count_by:"):
        key = mode[len("count_by:"):]
        out = {}
        for s in result:
            k = (s.get("metric") or {}).get(key, "?")
            out[k] = out.get(k, 0) + 1
        return (out or None), n

    if mode and mode.startswith("labels:"):
        keys = mode[len("labels:"):].split(",")
        out = []
        for s in result[:40]:
            m = s.get("metric") or {}
            out.append({
                "labels": {k: m.get(k) for k in keys},
                "value": _num(s.get("value", [None, None])[1]),
            })
        return (out or None), n

    return _num(result[0].get("value", [None, None])[1]), n


# Object-identifying labels of the kube-prometheus/rancher default ruleset, in
# pick order. Subject labels first - aggregated rules (quota, HPA, daemonsets)
# keep the scrape source's pod as plumbing, so `pod` ranks last. A generic
# histogram over whichever of these an alert carries is what lets the rules
# layer aggregate 1,400 KubeJobFailed into "the failing jobs of one tenant"
# without knowing each rule's label schema.
_GROUP_OBJECT_LABELS = ("persistentvolumeclaim", "job_name", "resourcequota",
                        "horizontalpodautoscaler", "deployment", "statefulset",
                        "daemonset", "node", "pod")
_GROUP_CAP = 100  # per histogram; the drop is recorded, never silent


def _hist_add(hist, key):
    """key -> hist[key] += 1, capped. Returns 1 when the add was dropped."""
    if key in hist or len(hist) < _GROUP_CAP:
        hist[key] = hist.get(key, 0) + 1
        return 0
    return 1


def fetch_alerts():
    """Active alerts. Alertmanager already encodes what this org thinks matters -
    ignoring it would mean Karel re-deriving judgements someone made deliberately.

    Alerts fire per label-set, not per problem: one tenant's failing CronJob is
    1,400 KubeJobFailed. Aggregation therefore happens here, in the collector -
    what crosses into the bundle is counts per alertname with namespace and
    object histograms, first/last firing times, and a bounded sample, never the
    full alert stream.
    """
    for path in ("/api/v2/alerts?silenced=false&inhibited=false&active=true",
                 "/api/v1/alerts"):
        last = "no response"
        try:
            doc = _get(ALERTMANAGER_URL.rstrip("/") + path, 20)
        except Exception as exc:
            last = "%s: %s" % (type(exc).__name__, str(exc)[:120])
            continue
        items = doc if isinstance(doc, list) else (doc.get("data") or {}).get("alerts", [])
        out = []
        groups = {}
        for a in items or []:
            labels = a.get("labels") or {}
            ann = a.get("annotations") or {}
            entry = {
                "name": labels.get("alertname"),
                "severity": labels.get("severity"),
                "namespace": labels.get("namespace"),
                "instance": labels.get("instance") or labels.get("pod"),
                "summary": (ann.get("summary") or ann.get("description") or "")[:200],
                "startsAt": a.get("startsAt"),
            }
            out.append(entry)

            g = groups.setdefault(entry["name"] or "?", {
                "count": 0, "severities": {}, "namespaces": {}, "objects": {},
                "ns_dropped": 0, "obj_dropped": 0,
                "oldest": None, "newest": None, "samples": []})
            g["count"] += 1
            sev = (labels.get("severity") or "unknown").lower()
            g["severities"][sev] = g["severities"].get(sev, 0) + 1
            ns = labels.get("namespace")
            if ns:
                g["ns_dropped"] += _hist_add(g["namespaces"], ns)
            obj = next((labels.get(k) for k in _GROUP_OBJECT_LABELS
                        if labels.get(k)), None)
            if obj:
                g["obj_dropped"] += _hist_add(
                    g["objects"], "%s/%s" % (ns, obj) if ns else obj)
            starts = a.get("startsAt")
            if starts:
                if not g["oldest"] or starts < g["oldest"]:
                    g["oldest"] = starts
                if not g["newest"] or starts > g["newest"]:
                    g["newest"] = starts
            if len(g["samples"]) < 3:
                g["samples"].append(entry)
        return {"available": True, "count": len(out), "alerts": out[:60],
                "groups": groups}
    return {"available": False, "error": last}


def fetch_targets():
    """Down scrape targets are monitoring blind spots. Nothing else reports them
    to a human on a schedule."""
    try:
        doc = _get(PROM_URL.rstrip("/") + "/api/v1/targets?state=active", 25)
    except Exception as exc:
        return {"available": False, "error": "%s: %s" % (type(exc).__name__, exc)}
    active = ((doc.get("data") or {}).get("activeTargets")) or []
    down = [{"job": t.get("labels", {}).get("job"),
             "instance": t.get("labels", {}).get("instance"),
             "error": (t.get("lastError") or "")[:160]}
            for t in active if t.get("health") != "up"]
    return {"available": True, "total": len(active),
            "down": down[:40], "down_count": len(down)}


def main():
    os.makedirs(OUT, exist_ok=True)
    started = time.time()
    meta = {"prom_url": PROM_URL, "alertmanager_url": ALERTMANAGER_URL,
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started))}

    # Fast probe: if Prometheus is unreachable, say so in seconds rather than
    # burning the whole budget on timeouts.
    st, res = query("vector(1)", 10)
    if st != "ok":
        with open(os.path.join(OUT, "result.json"), "wt") as fh:
            json.dump({"meta": meta, "reachable": False, "error": res,
                       "queries": {}, "alerts": {"available": False},
                       "targets": {"available": False}}, fh)
        print("prom: unreachable (%s)" % res, file=sys.stderr)
        return 0

    try:
        with open(MANIFEST) as fh:
            manifest = json.load(fh)
    except Exception as exc:
        print("prom: cannot read manifest: %s" % exc, file=sys.stderr)
        manifest = {"queries": []}

    queries = sorted(manifest.get("queries") or [],
                     key=lambda q: q.get("tier", 2))
    results = {}
    for q in queries:
        name = q.get("name")
        if not name or q.get("tier", 2) > MAX_TIER:
            continue
        if time.time() - started > BUDGET:
            results[name] = {"status": "skipped_budget"}
            continue

        st, res = query(q["expr"], q.get("timeout", 30))
        # A query can fail because the metric does not exist on this release.
        # Try the declared fallback before recording a failure.
        if st == "ok" and not res and q.get("fallback"):
            st2, res2 = query(q["fallback"], q.get("timeout", 30))
            if st2 == "ok" and res2:
                st, res = st2, res2
                results.setdefault(name, {})["used_fallback"] = True

        entry = results.setdefault(name, {})
        entry["status"] = st
        entry["window_days"] = q.get("window_days", 1)
        entry["empty_means"] = q.get("empty_means", "absent")
        if q.get("source_job"):
            entry["source_job"] = q["source_job"]
        if st != "ok":
            entry["error"] = res
            continue
        value, n = reduce_result(res, q.get("reduce"))
        entry["series"] = n
        if n == 0:
            # An empty result is ambiguous and the manifest disambiguates it.
            # A filtering expression returning nothing means nothing matched -
            # good news. A plain gauge returning nothing means it is not
            # scraped - a blind spot. Conflating them turns "no node went
            # NotReady" into "we cannot see node readiness".
            entry["status"] = ("no_match" if q.get("empty_means") == "none"
                               else "no_series")
        elif value is None:
            # Series existed but the reduction produced nothing - usually the
            # label named in `reduce` is absent from this metric.
            entry["status"] = "reduce_failed"
            entry["error"] = "reduce %r matched no labels in %d series" % (
                q.get("reduce"), n)
        else:
            entry["value"] = value

    payload = {
        "meta": meta,
        "reachable": True,
        "queries": results,
        "alerts": fetch_alerts(),
        "targets": fetch_targets(),
        "elapsed_seconds": round(time.time() - started, 1),
    }
    with open(os.path.join(OUT, "result.json"), "wt") as fh:
        json.dump(payload, fh)

    ok = sum(1 for v in results.values() if v.get("status") == "ok")
    print("prom: %d/%d ok, %d alerts, %d targets down, %.1fs"
          % (ok, len(results), payload["alerts"].get("count", 0),
             payload["targets"].get("down_count", 0), payload["elapsed_seconds"]),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
