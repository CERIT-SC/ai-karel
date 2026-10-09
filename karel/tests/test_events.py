#!/usr/bin/env python3
"""Tests for the filtered event collection (lib/events_collect.py,
bin/collect_events.py) and the event rules. The 30,000-event burst is
generated at test time, not committed."""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import ROOT, check, facts, finish              # noqa: E402

import events_collect   # noqa: E402
import rules_k8s        # noqa: E402


class R(object):
    def __init__(self, stdout, rc=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, rc, stderr


def runner_for(docs, default_items=()):
    """docs: list of (match-string, doc) — first match on the joined argv."""
    calls = []

    def runner(argv, timeout):
        calls.append(argv)
        joined = " ".join(argv)
        for match, doc in docs:
            if match in joined:
                return R(json.dumps(doc))
        return R(json.dumps({"items": list(default_items)}))
    return runner, calls


def ev(uid, ns, kind, name, reason, etype="Warning", count=1,
       last="2026-10-07T12:00:00Z"):
    return {"metadata": {"uid": uid, "name": uid, "namespace": ns or "default",
                         "creationTimestamp": "2026-10-07T10:00:00Z"},
            "involvedObject": {"kind": kind, "namespace": ns,
                               "name": name},
            "reason": reason, "type": etype, "count": count,
            "lastTimestamp": last, "firstTimestamp": "2026-10-07T11:00:00Z"}


# --------------------------------------------------------------------------
print("\nno unfiltered `get events -A` ever leaves the collector")

node_doc = {"items": [ev("n1", "default", "Node", "kub-a9", "NodeNotReady",
                         etype="Normal", count=3)]}
runner, calls = runner_for([("involvedObject.kind=Node", node_doc)],
                           default_items=[])
doc = events_collect.collect(runner=runner, platform_ns=["kube-system"])
bad = [c for c in calls
       if c[:3] == ["get", "events", "-A"] and "--field-selector" not in c]
check("every cluster-wide events request carries a field-selector", not bad,
      bad)


# --------------------------------------------------------------------------
print("\na NodeNotReady Normal event in default is kept")

check("node key recorded even though it is Normal and in default",
      doc["node"].get("Node|kub-a9|NodeNotReady", {}).get("count") == 3,
      doc["node"])


# --------------------------------------------------------------------------
print("\n30,000 tenant events + 1 node event: node survives, memory bounded")

child = r'''
import json, resource, sys
sys.path.insert(0, sys.argv[1])
import events_collect
# ru_maxrss: bytes on macOS, KiB on Linux
_RSS_DIV = 1024.0 ** 2 if sys.platform == "darwin" else 1024.0

def ev(i, ns):
    return {"metadata": {"uid": "u%d" % i, "name": "e%d" % i,
                         "namespace": ns,
                         "creationTimestamp": "2026-10-07T10:00:00Z"},
            "involvedObject": {"kind": "Pod", "namespace": ns,
                               "name": "web-%d" % (i % 700)},
            "reason": "FailedCreatePodSandBox", "type": "Warning",
            "count": (i % 9) + 1,
            "lastTimestamp": "2026-10-07T12:00:00Z"}

items = [ev(i, "tenant-%d" % (i % 120)) for i in range(30000)]
node = {"items": [{"metadata": {"uid": "n1", "namespace": "default"},
                   "involvedObject": {"kind": "Node", "name": "kub-a9"},
                   "reason": "NodeNotReady", "type": "Normal", "count": 1,
                   "lastTimestamp": "2026-10-07T12:00:00Z"}]}
plat = {"items": [dict(items[i],
                       metadata=dict(items[i]["metadata"],
                                     name="p%d" % i, uid="p%d" % i),
                       involvedObject={"kind": "Pod",
                                       "namespace": "kube-system",
                                       "name": "w%d" % i})
                  for i in range(1500)]}

class R(object):
    def __init__(self, doc):
        self.stdout, self.returncode, self.stderr = json.dumps(doc), 0, ""

def runner(argv, timeout):
    joined = " ".join(argv)
    if "involvedObject.kind=Node" in joined:
        return R(node)
    if "-n" in argv and "kube-system" in argv:
        return R(plat)
    if "reason=" in joined:
        return R({"items": items})
    return R({"items": []})

doc = events_collect.collect(runner=runner, platform_ns=["kube-system"])
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / _RSS_DIV
out = {"node_survived": "Node|kub-a9|NodeNotReady" in doc["node"],
       "platform_keys": len(doc["platform"]),
       "dropped": doc["dropped"].get("platform_keys", 0),
       "peak_mib": round(peak, 1)}
print(json.dumps(out))
'''
r = subprocess.run([sys.executable, "-c", child,
                    os.path.join(ROOT, "lib")],
                   capture_output=True, text=True, timeout=300)
res = json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {}
check("node event survives platform-key truncation",
      res.get("node_survived") is True, (r.stderr or "")[-200:])
check("platform keys capped and the drop recorded",
      res.get("platform_keys") == 600 and res.get("dropped") >= 900, res)
check("collector peak RSS under 128 MiB with 30k events",
      res.get("peak_mib", 9999) < 128, res.get("peak_mib"))


# --------------------------------------------------------------------------
print("\nwidespread tenant pattern -> WARN naming the suspect; small -> row")

b = facts({"k8s.events.patterns": {
    "FailedCreatePodSandBox": {"suspect": "CNI (Calico)", "count": 5000,
                               "ns_count": 40,
                               "top": [["tenant-1", 900], ["tenant-2", 800]]}}})
fs = rules_k8s.r_tenant_event_patterns(b)
check("40 namespaces -> WARN naming CNI",
      any(f["id"] == "K8S_TENANT_EVENT_PATTERN:FailedCreatePodSandBox"
          and f["severity"] == "warn" and "CNI" in f["title"] for f in fs), fs)

b2 = facts({"k8s.events.patterns": {
    "FailedCreatePodSandBox": {"suspect": "CNI (Calico)", "count": 30,
                               "ns_count": 3,
                               "top": [["tenant-1", 20], ["tenant-2", 7]]}},
            "k8s.pod.backoff": [], "k8s.pod.backoff_count": 0})
fs2 = rules_k8s.r_tenant_event_patterns(b2)
check("3 namespaces -> no WARN", not fs2, fs2)
fs3 = rules_k8s.r_tenant_summary(b2)
rows = (fs3[0]["table"]["rows"] if fs3 else [])
check("3 namespaces -> a row in the tenant summary instead",
      any(r[0] == "events: FailedCreatePodSandBox" for r in rows), rows)


# --------------------------------------------------------------------------
print("\nplatform-namespace events are not double-counted in patterns")

plat_ev = ev("pp", "kube-system", "Pod", "coredns-abc1", "FailedMount")
tenant_ev = ev("tt", "tenant-x", "Pod", "web-abc1", "FailedMount")
runner, calls = runner_for(
    [("involvedObject.kind=Node", {"items": []}),
     ("reason=FailedMount", {"items": [plat_ev, tenant_ev]})],
    default_items=[])
doc = events_collect.collect(runner=runner, platform_ns=["kube-system"])
pat = (doc["patterns"].get("FailedMount") or {})
check("platform pod excluded from the tenant pattern aggregate",
      pat.get("count") == 1 and pat.get("ns_count") == 1, pat)


# --------------------------------------------------------------------------
print("\na stale buffer is a coverage gap, not a quiet night")

b = facts({"k8s.events.buffer": {"writes": 90, "ok_writes": 90,
                                 "expected_writes": 96,
                                 "last_write_age_m": 121.0,
                                 "failed_requests": []},
           "k8s.events.node_by_reason": {}, "k8s.events.platform_by_reason": {}})
fs = rules_k8s.r_events(b)
check("2 h since the last write -> KAREL_EVENT_BUFFER_STALE",
      any(f["id"] == "KAREL_EVENT_BUFFER_STALE" for f in fs), fs)

b = facts({"k8s.events.buffer": {"writes": 96, "ok_writes": 90,
                                 "expected_writes": 96, "last_write_age_m": 4.0,
                                 "failed_requests": ["pattern/Evicted"]},
           "k8s.events.node_by_reason": {}, "k8s.events.platform_by_reason": {}})
fs = rules_k8s.r_events(b)
check("a failed sub-request is named in the same item",
      any(f["id"] == "KAREL_EVENT_BUFFER_STALE" and
          any("pattern/Evicted" in d for d in f["detail"]) for f in fs), fs)


# --------------------------------------------------------------------------
print("\nowner names: ReplicaSet hash and pod suffix go, STS ordinals stay")

check("replicaset pod -> owner",
      events_collect.owner_name("web-7d9c68f5b9-abcde") == "web")
check("statefulset pod keeps ordinal",
      events_collect.owner_name("alertmanager-0") == "alertmanager-0")
check("bare pod without controller suffix survives",
      events_collect.owner_name("static-mirror") == "static-mirror")


finish()
