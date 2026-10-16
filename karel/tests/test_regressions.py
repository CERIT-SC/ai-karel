#!/usr/bin/env python3
"""Regression tests for false positives found on the real cluster.

Each test is named for the wrong thing it prevents.
Run: python3 tests/test_regressions.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, FAILURES   # noqa: E402  shared with the other suites

import normalize          # noqa: E402
import normalize_k8s      # noqa: E402
import report             # noqa: E402
import rules_headroom     # noqa: E402
import suppress           # noqa: E402
import rules as _r        # noqa: E402
import rules_k8s as _rk   # noqa: E402
import rules_maintenance as _rm   # noqa: E402
import normalize_prom as _np      # noqa: E402


NODE = "kub-ceph-c1.priv.cerit-sc.cz"
NODES = ["n1", "n2", "n3", "n4"]


# --------------------------------------------------------------------------
print("\ndaemonset pods must not count as pinned")

F = normalize.Facts()

pods = {"items": [
    # a DaemonSet replica: one per node BY DESIGN, not a scheduling constraint
    {"metadata": {"namespace": "cattle-monitoring-system",
                  "name": "pushprox-kube-proxy-client-zbk49",
                  "ownerReferences": [{"kind": "DaemonSet", "name": "pushprox"}]},
     "spec": {"nodeName": NODE,
              "affinity": {"nodeAffinity": {
                  "requiredDuringSchedulingIgnoredDuringExecution": {
                      "nodeSelectorTerms": [{"matchFields": [
                          {"key": "metadata.name", "operator": "In",
                           "values": [NODE]}]}]}}},
              "containers": [{"name": "c", "resources": {}}]},
     "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}},
    # podAntiAffinity is about SPREADING, not pinning
    {"metadata": {"namespace": "app", "name": "spread-1",
                  "ownerReferences": [{"kind": "ReplicaSet", "name": "spread-abc123"}]},
     "spec": {"nodeName": NODE,
              "affinity": {"podAntiAffinity": {
                  "requiredDuringSchedulingIgnoredDuringExecution": [{"topologyKey": "x"}]}},
              "containers": [{"name": "c", "resources": {}}]},
     "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}},
    # a genuine pin: StatefulSet bound to one host
    {"metadata": {"namespace": "cattle-monitoring-system",
                  "name": "alertmanager-0",
                  "ownerReferences": [{"kind": "StatefulSet", "name": "alertmanager"}]},
     "spec": {"nodeName": NODE,
              "nodeSelector": {"kubernetes.io/hostname": NODE},
              "containers": [{"name": "c", "resources": {}}]},
     "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}},
]}
normalize_k8s.p_pods(pods, F, "k_pods")
pinned = F.get_value("k8s.node.pinned_pods", {}) or {}
names = pinned.get(NODE, [])
check("daemonset excluded", not any("pushprox" in n for n in names), names)
check("antiaffinity excluded", not any("spread" in n for n in names), names)
check("real hostname pin kept", any("alertmanager" in n for n in names), names)


# --------------------------------------------------------------------------
print("\nnode-scoped-by-design workloads are configurable, not hard-coded")

check("no default node-scoped apps",
      normalize_k8s.NODE_SCOPED_APPS == set(), normalize_k8s.NODE_SCOPED_APPS)
check("prepare pod excluded from node-scoped",
      normalize_k8s._node_scoped_app(
          {"name": "web-prepare-nodeX-q868f"}) is None)


# --------------------------------------------------------------------------
print("\nquantity parser (all Kubernetes suffixes)")

check("Ki with capital K", normalize_k8s.mem_bytes("792228952Ki") == 792228952 * 1024)
check("Gi", normalize_k8s.mem_bytes("62Gi") == 62 * 1024 ** 3)
check("bare bytes", normalize_k8s.mem_bytes("8589934592") == 8589934592)
check("decimal G is not Gi", normalize_k8s.mem_bytes("2G") == 2 * 10 ** 9)
check("lowercase k is decimal", normalize_k8s.mem_bytes("1k") == 1000)
check("fractional Gi", normalize_k8s.mem_bytes("1.5Gi") == 1610612736)
check("millicores", normalize_k8s.cpu_millis("500m") == 500)
check("whole cores", normalize_k8s.cpu_millis("48") == 48000)
check("fractional cores", normalize_k8s.cpu_millis("0.5") == 500)
check("garbage is None, not zero", normalize_k8s.mem_bytes("garbage") is None)
check("None is None", normalize_k8s.cpu_millis(None) is None)


# --------------------------------------------------------------------------
print("\nrke2 release extraction")

check("full version read from the version tag",
      normalize_k8s.rke2_release("v1.35.6+rke2r1") == "v1.35.6+rke2r1")
check("multi-digit release",
      normalize_k8s.rke2_release("v1.35.6+rke2r12") == "v1.35.6+rke2r12")
check("a plain upstream kubelet is not an rke2 node",
      normalize_k8s.rke2_release("v1.35.6") is None)
check("k3s is not reported as rke2",
      normalize_k8s.rke2_release("v1.35.6+k3s1") is None)
check("no version at all is None",
      normalize_k8s.rke2_release(None) is None)
check("an untagged rke2 node is not guessed at",
      normalize_k8s.rke2_release("v1.35.6") is None)


# --------------------------------------------------------------------------
print("\na stuck VolumeAttachment names the volume and the pod it blocks")

_va = {"items": [{
    "metadata": {"name": "csi-abc"},
    "spec": {"attacher": "csi.ceph.com", "nodeName": "node-03",
             "source": {"persistentVolumeName": "pv-1"}},
    "status": {"attached": False,
               "attachError": {"message": "rpc error: context deadline exceeded"}}}]}
_pv = {"items": [{"metadata": {"name": "pv-1"}, "status": {"phase": "Bound"},
                  "spec": {"claimRef": {"namespace": "app", "name": "data-0"}}}]}
_pods = {"items": [{"metadata": {"namespace": "app", "name": "worker-0"},
                    "spec": {"nodeName": "node-03",
                             "volumes": [{"name": "d",
                                          "persistentVolumeClaim": {"claimName": "data-0"}}],
                             "containers": [{"name": "c", "resources": {}}]},
                    "status": {"phase": "Pending", "conditions": []}}]}

VF = normalize.Facts()
normalize_k8s.p_volumeattach(_va, VF, "k_volumeattach")
normalize_k8s.p_pv(_pv, VF, "k_pv")
normalize_k8s.p_pods(_pods, VF, "k_pods")
_vb = {"facts": dict(VF), "collection": {"commands": {}, "complete": True, "sources": {}}}
_vf = _rk.r_storage_k8s(_vb)
check("the stuck attachment is reported",
      len(_vf) == 1 and _vf[0]["code"] == "K8S_VOLUME_ATTACH_STUCK", _vf)
_d = _vf[0]["detail"][0] if _vf else ""
check("it names the volume, not just the CSI handle",
      "csi-abc" in _d and "pv-1" in _d, _d)
check("it names the claim and the node", "app/data-0" in _d and "node-03" in _d, _d)
check("it names the pod the attachment is blocking",
      "app/worker-0" in _d, _d)
check("it carries the CSI error", "deadline exceeded" in _d, _d)
check("one line per attachment (collapse() must not split an entry)",
      len(_vf[0]["detail"]) == 1, _vf[0]["detail"])

# An attachment whose PV has no recorded claimRef must say the join failed
# rather than silently omitting the pod.
OF = normalize.Facts()
normalize_k8s.p_volumeattach(_va, OF, "k_volumeattach")
_od = _rk.r_storage_k8s(
    {"facts": dict(OF),
     "collection": {"commands": {}, "complete": True, "sources": {}}})[0]["detail"][0]
check("an unjoinable attachment says so explicitly",
      "unknown" in _od and "claimRef" in _od, _od)

# Bare names from an older bundle stay readable instead of crashing.
check("a pre-enrichment bundle still renders",
      "no further detail" in _rk.r_storage_k8s(facts({
          "k8s.volumeattachment.unattached_count": 1,
          "k8s.volumeattachment.unattached": ["csi-old"]}))[0]["detail"][0])

# A misplaced attachment (attached=true) is not a finding.
OK = normalize.Facts()
normalize_k8s.p_volumeattach({"items": [{"metadata": {"name": "csi-ok"},
                                         "status": {"attached": True}}]},
                             OK, "k_volumeattach")
check("a healthy attachment raises nothing",
      not _rk.r_storage_k8s({"facts": dict(OK), "collection": {
          "commands": {}, "complete": True, "sources": {}}}))


# --------------------------------------------------------------------------
print("\nrepeated detail lines collapse")

lines = ["mgr module web crashed in daemon mgr.a on host %s at "
         "2026-08-21T10:5%d:%02d.195387Z" % (NODE, i % 10, i % 60)
         for i in range(10)]
c = report.collapse(lines)
check("collapsed to a summary", len(c) == 5, len(c))
check("summary names the count", "and 6 more" in c[-1], c[-1])
mixed = report.collapse(["pod.1 is down", "pod.2 is down", "pool x is full"])
check("distinct lines preserved", len(mixed) == 3, mixed)


# --------------------------------------------------------------------------
print("\nsuppression ledger")

fs = [
    {"id": "K8S_SCALED_TO_ZERO:app/idle", "code": "K8S_SCALED_TO_ZERO",
     "subject": "app/idle", "severity": "info", "title": "scaled to zero",
     "detail": [], "evidence": [], "remediation": [], "metric": None, "causes": []},
    {"id": "K8S_NODE_NOT_READY", "code": "K8S_NODE_NOT_READY", "subject": None,
     "severity": "crit", "title": "nodes not ready", "detail": [], "evidence": [],
     "remediation": [], "metric": None, "causes": []},
]
ledger = suppress.load({"suppressions": [
    {"pattern": "K8S_SCALED_TO_ZERO:*", "until": "permanent",
     "reason": "intentionally idle", "by": "platform"},
    {"id": "GONE", "until": "2030-01-01", "reason": "stale entry"},
    {"id": "OLD", "until": "2020-01-01", "reason": "long expired"},
]})
vis, sup, meta = suppress.apply(fs, ledger)
mcodes = {m["code"] for m in meta}
check("pattern suppression applied", len(sup) == 1 and sup[0]["id"].endswith("app/idle"))
check("unsuppressed finding still visible", any(f["id"] == "K8S_NODE_NOT_READY" for f in vis))
check("expired suppression reported", "KAREL_SUPPRESSION_EXPIRED" in mcodes, mcodes)
check("unused suppression reported", "KAREL_SUPPRESSION_UNUSED" in mcodes, mcodes)
check("permanent suppression reported every run",
      "KAREL_SUPPRESSION_PERMANENT" in mcodes, mcodes)


# --------------------------------------------------------------------------
print("\nelapsed label reflects the real baseline gap")

check("3 minutes is not '24h'",
      report._elapsed_label({"collected_at": "2026-08-22T12:06:46Z"},
                            {"collected_at": "2026-08-22T12:09:52Z"}) == "3m")
check("one day reads as hours or days",
      report._elapsed_label({"collected_at": "2026-08-21T04:00:00Z"},
                            {"collected_at": "2026-08-22T04:00:00Z"}) == "24h")
check("no baseline is labelled honestly",
      report._elapsed_label({}, {"collected_at": "2026-08-22T04:00:00Z"})
      == "vs baseline")


# --------------------------------------------------------------------------
print("\nnode loss only reports what is worse than losing a node")


def _nl(overrides=None, nodes=NODES, cpu_req=1000, mem_req=2 ** 30):
    base = {
        "k8s.node.names": nodes,
        "k8s.node.allocatable_cpu_m": {n: 64000 for n in nodes},
        "k8s.node.allocatable_mem_bytes": {n: 2 ** 38 for n in nodes},
        "k8s.node.requests": {n: {"cpu_m": cpu_req, "mem_bytes": mem_req}
                              for n in nodes},
    }
    base.update(overrides or {})
    return facts(base)


def _codes(fs):
    return [f["code"] for f in fs]


check("a comfortable cluster produces no node-loss finding",
      not rules_headroom.r_node_loss(_nl()))

# The regression: 51 nodes, requests at 90% everywhere. Losing any node leaves
# 91.8% - degraded, as losing a node always is. That is not a finding.
BIG = ["kub-%02d" % i for i in range(51)]
fs = rules_headroom.r_node_loss(_nl(nodes=BIG, cpu_req=57600))
check("a busy but N+1 cluster gets no per-node 'would degrade' warnings",
      fs == [], _codes(fs))

# survivors genuinely cannot hold the load -> ONE finding, not one per node
fs = rules_headroom.r_node_loss(_nl(cpu_req=56000))
check("not N+1 is reported once, for the cluster",
      _codes(fs) == ["K8S_NOT_N_PLUS_ONE"], _codes(fs))
check("not N+1 is a WARN (nothing is broken yet)",
      fs and fs[0]["severity"] == "warn")
check("it names the node whose loss was simulated and the shortfall",
      fs and any("without" in d and "nowhere to go" in d for d in fs[0]["detail"]))

# cordoned and tainted nodes do not absorb a failure
fs = rules_headroom.r_node_loss(_nl(
    {"k8s.node.unschedulable": ["n4"], "k8s.node.n3.taints":
     ["node-role.kubernetes.io/control-plane"]},
    nodes=NODES + ["n5"], cpu_req=45000))     # 105% of the real pool, 88% if
                                               # cordoned/tainted nodes counted
check("cordoned and tainted nodes are not counted as spare capacity",
      _codes(fs) == ["K8S_NOT_N_PLUS_ONE"], _codes(fs))

# none of these are node-loss findings any more
quiet = _nl({"k8s.node.pinned_pods": {"n1": ["app/legacy-0"]},
             "k8s.pv.node_local": ["pv-local@n3"],
             "k8s.pdb.blocking": ["app/db-primary (healthy 1/1)"],
             "k8s.node.single_replica_owners": {"n2": ["app/a", "app/b"]}})
check("pins, local PVs, PDBs and single replicas are not node-loss warnings",
      rules_headroom.r_node_loss(quiet) == [],
      _codes(rules_headroom.r_node_loss(quiet)))

# etcd: healthy 3 members is the design, not a risk
check("a healthy 3-member etcd is not reported",
      not rules_headroom.r_node_loss(_nl(
          {"k8s.controlplane.etcd_nodes": ["n1", "n2", "n3"]})))
fs = rules_headroom.r_node_loss(_nl({"k8s.controlplane.etcd_nodes": ["n1", "n2"]}))
check("a 2-member etcd has no fault tolerance (WARN, by design)",
      [(f["code"], f["severity"]) for f in fs]
      == [("K8S_ETCD_NO_FAULT_TOLERANCE", "warn")], fs)
fs = rules_headroom.r_node_loss(_nl({"k8s.controlplane.etcd_nodes": ["n1", "n2", "n3"],
                                     "k8s.node.not_ready": ["n3"]}))
check("3 members with one down is CRIT: the margin is already spent",
      ("K8S_ETCD_NO_FAULT_TOLERANCE", "crit") in
      [(f["code"], f["severity"]) for f in fs], fs)

# redundancy that is not
fs = rules_headroom.r_node_loss(_nl({"k8s.workload.colocated": [
    "kube-system/coredns (2 replicas on n1)", "alice-ns/web (3 replicas on n2)"]}))
check("platform replicas all on one node are reported",
      _codes(fs) == ["K8S_REPLICAS_COLOCATED"]
      and any("coredns" in d for d in fs[0]["detail"]), fs)
check("tenant co-location is not a platform finding",
      not any("alice-ns" in d for f in fs for d in f["detail"]))

# PDBs belong to drains, and the count is the real one, not the sample's
fs = rules_headroom.r_drain_blockers(facts({
    "k8s.pdb.blocking": ["ns%d/p (healthy 1/1)" % i for i in range(30)],
    "k8s.pdb.blocking_count": 199}))
check("PDB drain blockers are INFO and counted from the full total",
      fs and fs[0]["severity"] == "info" and "199" in fs[0]["title"],
      fs and fs[0]["title"])

b = _nl(cpu_req=48000)
rules_headroom.derive_capacity(b)
check("headroom is always computed into facts for Key metrics",
      b["facts"]["k8s.capacity.cpu_req_pct"]["value"] == 75.0
      and b["facts"]["k8s.capacity.cpu_req_pct_after_loss"]["value"] == 100.0,
      {k: v["value"] for k, v in b["facts"].items() if "capacity" in k})


# --------------------------------------------------------------------------
print("\nplatform vs tenant scope")

import scope as _sc  # noqa: E402

check("kube-system, cattle-*, *-system, *-operator are platform",
      all(_sc.is_platform(n) for n in ("kube-system", "cattle-logging-system",
                                       "calico-system", "spark-operator",
                                       "csi-storage", "gpu-operator")))
check("tenant namespaces are not platform",
      not any(_sc.is_platform(n) for n in ("gdi-ega-ns", "default", "acgt-app")))
check("any namespace containing 'operator' is platform",
      all(_sc.is_platform(n) for n in ("postgresoperator", "ray-operator",
                                       "flink-operator-system", "operators")),
      [_sc.is_platform(n) for n in ("postgresoperator", "operators")])
os.environ["KAREL_PLATFORM_NAMESPACES"] = "beegfs, clusterwide-*"
check("KAREL_PLATFORM_NAMESPACES extends the defaults",
      _sc.is_platform("beegfs") and _sc.is_platform("clusterwide-traefik")
      and _sc.is_platform("kube-system"))
del os.environ["KAREL_PLATFORM_NAMESPACES"]
check("platform entries survive truncation",
      _sc.platform_first(["a-ns/x", "b-ns/y", "kube-system/z"])[0] == "kube-system/z")

# truncated list + true count: the count wins (40 shown, 116 real)
sample = (["cattle-logging-system/fluentbit-%d:fb" % i for i in range(10)] +
          ["tenant%02d-ns/p:c" % i for i in range(30)])
b = facts({"k8s.pod.oomkilled": sample, "k8s.pod.oomkilled_count": 116})
_sc.derive(b)
fv = {k: v["value"] for k, v in b["facts"].items()}
check("tenant count comes from the total, not len(sample)",
      fv["k8s.pod.oomkilled.tenant_count"] == 106, fv.get("k8s.pod.oomkilled.tenant_count"))
check("a sampled list is marked partial", fv.get("k8s.pod.oomkilled.partial") is True)

# lastState.terminated survives until the container's NEXT termination, so an
# OOMKill from months ago is still visible on every run. Only kills inside
# OOMKILL_RECENT_DAYS may be announced - otherwise the same old kill re-fires
# forever.
import datetime as _dt  # noqa: E402


def _oom_pod(finished_at):
    term = {"reason": "OOMKilled", "exitCode": 137}
    if finished_at:
        term["finishedAt"] = finished_at
    return {"items": [{
        "metadata": {"namespace": "kube-system", "name": "agent-1"},
        "spec": {"nodeName": "n1", "containers": [{"name": "main"}]},
        "status": {"phase": "Running",
                   "containerStatuses": [{"name": "main", "restartCount": 3,
                                          "state": {"running": {}},
                                          "lastState": {"terminated": term}}]}}]}


def _days_ago(d):
    return (_dt.datetime.utcnow() - _dt.timedelta(days=d)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


F = normalize.Facts()
normalize_k8s.p_pods(_oom_pod(_days_ago(0.5)), F, "t")
check("a recent OOMKill is reported, with its age visible",
      F.get_value("k8s.pod.oomkilled")
      == ["kube-system/agent-1:main on n1 (killed 12h ago)"],
      F.get_value("k8s.pod.oomkilled"))
F = normalize.Facts()
normalize_k8s.p_pods(_oom_pod(_days_ago(3)), F, "t")
check("an OOMKill older than two days is not re-reported",
      F.get_value("k8s.pod.oomkilled") == [], F.get_value("k8s.pod.oomkilled"))
F = normalize.Facts()
normalize_k8s.p_pods(_oom_pod(_days_ago(30)), F, "t")
check("nor one from weeks ago",
      F.get_value("k8s.pod.oomkilled") == [], F.get_value("k8s.pod.oomkilled"))

# OOMKills are news for every namespace: a kill in a tenant namespace is a
# cluster fact, not tenant-only bookkeeping. The finding lists both.
b = facts({"k8s.pod.oomkilled": ["kube-system/a:c on n1 (killed 9h ago)",
                                 "ml-team-ns/q:c on n2 (killed 20h ago)"],
           "k8s.pod.oomkilled_count": 2})
_sc.derive(b)
fs = _rk.r_workloads(b)
oom_f = [f for f in fs if f["id"] == "K8S_OOMKILLED"]
check("the finding lists tenant OOMKills alongside platform ones",
      len(oom_f) == 1 and "ml-team-ns/q:c" in str(oom_f[0]["detail"])
      and "kube-system/a:c" in str(oom_f[0]["detail"]), fs)
check("and states the platform/tenant split",
      len(oom_f) == 1 and "1 platform, 1 tenant" in oom_f[0]["title"],
      oom_f[0]["title"] if oom_f else None)

F = normalize.Facts()
normalize_k8s._problem_list(F, "t", "k8s.pod.backoff",
                            ["b-ns/p:c=CrashLoopBackOff"] * 50 +
                            ["kube-system/q:c=CrashLoopBackOff"])
check("parsers record exact per-namespace counts",
      F.get_value("k8s.pod.backoff_by_ns") == {"b-ns": 50, "kube-system": 1}
      and F.get_value("k8s.pod.backoff_count") == 51)

b = facts({"k8s.pod.backoff": ["gdi-ega-ns/a:x=CrashLoopBackOff",
                               "gdi-ega-ns/b:x=CrashLoopBackOff",
                               "alice-ns/c:x=ImagePullBackOff",
                               "bob-ns/d:x=CrashLoopBackOff",
                               "csi-storage/csi-node-x:r=CrashLoopBackOff"],
           "k8s.pod.backoff_count": 5,
           "k8s.deployment.paused": ["alice-ns/web"]})
_sc.derive(b)
fs = _rk.r_workloads(b)
bo = [f for f in fs if f["code"] == "K8S_PODS_BACKOFF"]
check("tenant backoff does not make a CRIT",
      bo and bo[0]["severity"] == "warn" and "1 platform" in bo[0]["title"],
      [(f["severity"], f["title"]) for f in bo])
ts = _rk.r_tenant_summary(b)
_ts_rows = {r[0]: r[1] for r in ts[0]["table"]["rows"]} if ts else {}
check("tenant problems become one summary table",
      len(ts) == 1 and ts[0]["severity"] == "info" and ts[0].get("table")
      and _ts_rows.get("containers in CrashLoop/ImagePull backoff") == 4
      and _ts_rows.get("Deployments with rollout paused") == 1,
      ts and ts[0].get("table"))
check("a tenant's paused Deployment is not an (age-escalating) finding",
      not _rm.r_k8s_paused(b))


# --------------------------------------------------------------------------
print("\nwebhooks are grouped by backing Service and scoped")


def _wh(groups=None, svc="cattle-system/webhook-service", n=14):
    hooks = {}
    for i in range(n):
        w = {"failurePolicy": "Fail", "service": svc, "timeoutSeconds": 10,
             "kind": "validating", "configuration": "validating-webhook-configuration"}
        if groups is not None:
            w["api_groups"] = groups
            w["resources"] = ["%s/thing%d" % (g or "core", i) for g in groups]
        hooks["validating-webhook-configuration/h%d.x" % i] = w
    return hooks


def _whb(groups=None, crds=None, services=None):
    d = {"k8s.webhook.validating": _wh(groups),
         "k8s.service.ready_endpoints": {"other/svc": 2}}
    if crds is not None:
        d["k8s.crd.groups"] = crds
    if services is not None:
        d["k8s.service.names"] = services
    return facts(d)


fs = _rk.r_webhooks(_whb())
check("14 hooks on one dead Service are one finding", len(fs) == 1, len(fs))
check("unknown scope stays CRIT (unknown is not safe)",
      fs and fs[0]["severity"] == "crit")
check("a Service with no EndpointSlice at all is called out as likely gone",
      fs and "likely gone" in fs[0]["title"], fs and fs[0]["title"])
fs = _rk.r_webhooks(_whb(groups=["apps"], services=[]))
check("built-in resources -> CRIT", fs and fs[0]["severity"] == "crit")
fs = _rk.r_webhooks(_whb(groups=["cluster.x-k8s.io"], crds=["cluster.x-k8s.io"],
                         services=["cattle-system/webhook-service"]))
check("an installed CRD group only -> WARN", fs and fs[0]["severity"] == "warn",
      fs and fs[0]["severity"])
fs = _rk.r_webhooks(_whb(groups=["cluster.x-k8s.io"], crds=["cert-manager.io"],
                         services=[]))
check("a CRD group that is not installed -> INFO leftover with a delete hint",
      fs and fs[0]["severity"] == "info"
      and any("kubectl delete validatingwebhookconfiguration" in r
              for r in fs[0]["remediation"]), fs and fs[0])

F = normalize.Facts()
normalize_k8s.p_validatingwh({"items": [{"metadata": {"name": "c"}, "webhooks": [
    {"name": "h", "failurePolicy": "Fail",
     "clientConfig": {"service": {"namespace": "n", "name": "s"}},
     "rules": [{"apiGroups": [""], "resources": ["pods"],
                "operations": ["CREATE"]}],
     "objectSelector": {"matchLabels": {"a": "b"}}}]}]}, F, "t")
w = F.get_value("k8s.webhook.validating")["c/h"]
check("the webhook parser records what each hook intercepts",
      w["api_groups"] == [""] and w["resources"] == ["core/pods"]
      and w["object_selector"] is True, w)


# --------------------------------------------------------------------------
print("\ncronjobs and jobs")

check("cron period: daily", normalize_k8s.cron_period_days("0 3 * * *") == 1.0)
check("cron period: weekly", normalize_k8s.cron_period_days("0 0 * * 0") == 7.0)
check("cron period: monthly", normalize_k8s.cron_period_days("0 0 1 * *") == 31.0)
check("cron period: weekdays (Fri -> Mon gap)",
      normalize_k8s.cron_period_days("0 2 * * 1-5") == 3.0)
check("cron period: macro", normalize_k8s.cron_period_days("@weekly") == 7.0)
check("cron period: unparseable is None", normalize_k8s.cron_period_days("bad") is None)

import datetime as _dt  # noqa: E402


def _ago(days):
    return (_dt.datetime.utcnow() - _dt.timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


F = normalize.Facts()
normalize_k8s.p_cronjobs({"items": [
    {"metadata": {"namespace": "a", "name": "weekly"},
     "spec": {"schedule": "0 0 * * 0"}, "status": {"lastScheduleTime": _ago(4)}},
    {"metadata": {"namespace": "a", "name": "monthly"},
     "spec": {"schedule": "0 0 1 * *"}, "status": {"lastScheduleTime": _ago(7)}},
    {"metadata": {"namespace": "a", "name": "daily-dead"},
     "spec": {"schedule": "0 3 * * *"}, "status": {"lastScheduleTime": _ago(3)}},
    {"metadata": {"namespace": "a", "name": "suspended"},
     "spec": {"schedule": "0 3 * * *", "suspend": True},
     "status": {"lastScheduleTime": _ago(100)}},
]}, F, "t")
stale = F.get_value("k8s.cronjob.stale")
check("weekly/monthly CronJobs are not stale mid-cycle",
      not any("weekly" in x or "monthly" in x for x in stale), stale)
check("a daily CronJob idle for 3 days is stale",
      any("daily-dead" in x for x in stale), stale)
check("suspended CronJobs are not stale", not any("suspended" in x for x in stale))

F = normalize.Facts()
normalize_k8s.p_jobs({"items": [
    {"metadata": {"namespace": "a", "name": "retried-ok"},
     "status": {"failed": 1, "succeeded": 1,
                "conditions": [{"type": "Complete", "status": "True"}]}},
    {"metadata": {"namespace": "a", "name": "dead"},
     "status": {"failed": 6, "conditions": [
         {"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}]}},
]}, F, "t")
check("a Job that succeeded on retry is not failed",
      F.get_value("k8s.job.failed_count") == 1
      and "dead" in F.get_value("k8s.job.failed")[0], F.get_value("k8s.job.failed"))


# --------------------------------------------------------------------------
print("\ncollection failures are classified once")

cmds = {"k_a": {"status": "eacces", "expected": "ok", "rc": "1",
                "stderr_head": ["Error from server (Forbidden): x is forbidden"]},
        "k_b": {"status": "failed", "expected": "ok", "rc": "2",
                "stderr_head": ["/opt/homebrew/Cellar/python@3.14/3.14.8/Frameworks/"
                                "Python.framework/Versions/3.14/bin/Python: can't open "
                                "file '/opt/karel/bin/x.py': [Errno 2] No such file"]},
        "k_ok": {"status": "ok", "expected": "ok", "has_parser": True, "parse_ok": True}}
b = {"facts": {}, "collection": {"commands": cmds, "complete": True, "sources": {}}}
codes = {f["code"]: f for f in _r.r_collection(b) + _rk.r_k8s_collection(b)}
check("a denial is an RBAC gap and only that",
      "KAREL_K8S_RBAC_GAP" in codes
      and codes["KAREL_K8S_RBAC_GAP"]["detail"][0] == "k_a")
check("a script that cannot start is a failed command, not an RBAC gap",
      "KAREL_COMMAND_FAILED" in codes
      and "k_a" not in " ".join(codes["KAREL_COMMAND_FAILED"]["detail"]))
check("the error keeps the message, not the interpreter path",
      "can't open file" in codes["KAREL_COMMAND_FAILED"]["detail"][0]
      and "homebrew" not in codes["KAREL_COMMAND_FAILED"]["detail"][0],
      codes["KAREL_COMMAND_FAILED"]["detail"])
check("it is identified as an installation problem",
      "installation" in codes["KAREL_COMMAND_FAILED"]["remediation"][0])

ranked = _r.rank([
    {"id": "KAREL_X", "code": "KAREL_X", "severity": "warn"},
    {"id": "K8S_Y", "code": "K8S_Y", "severity": "warn"},
    {"id": "KAREL_Z", "code": "KAREL_Z", "severity": "crit"}])
check("cluster findings rank above Karel bookkeeping within a severity",
      [f["id"] for f in ranked] == ["KAREL_Z", "K8S_Y", "KAREL_X"],
      [f["id"] for f in ranked])


# --------------------------------------------------------------------------
print("\nimage cache is not a disk measurement")

names = ["n%d" % i for i in range(6)]
d = {"k8s.node.names": names}
for i, n in enumerate(names):
    d["k8s.node.%s.ephemeral_alloc_bytes" % n] = (417 if i == 0 else 6000) * 2 ** 30
    d["k8s.node.%s.image_cache_bytes" % n] = 500 * 2 ** 30
    d["k8s.node.%s.image_cache_pct" % n] = 118.5 if i == 0 else 8.3
fs = _rk.r_image_cache(facts(d))
check("a small-disk outlier is reported, without an impossible percentage",
      fs and "n0" in fs[0]["title"] and "%" not in fs[0]["title"]
      and fs[0]["severity"] == "info", fs and fs[0]["title"])


# --------------------------------------------------------------------------
print("\na rule rewrite is not a fix")

rows = report._group_resolved(
    [{"id": "K8S_NODE_LOSS_IMPACT:n%d" % i, "severity": "warn"} for i in range(51)] +
    [{"id": "K8S_PODS_BACKOFF", "severity": "crit"}])
check("retired ids are grouped per code", len(rows) == 2, rows)
check("the group says how many", any(r[2] == "51" for r in rows), rows)


print("\nreport-level grouping")
g = report._collapse_groups([
    {"id": "X:n1", "code": "X", "subject": "n1", "severity": "warn", "title": "t",
     "detail": [], "evidence": [], "remediation": [], "group_key": "g1"},
    {"id": "X:n2", "code": "X", "subject": "n2", "severity": "crit", "title": "t",
     "detail": [], "evidence": [], "remediation": [], "group_key": "g1"},
    {"id": "Y", "code": "Y", "subject": None, "severity": "warn", "title": "u",
     "detail": [], "evidence": [], "remediation": []},
])
check("group collapses to one rendered entry", len(g) == 2, len(g))
check("group takes the worst member severity",
      any(f["severity"] == "crit" for f in g))
check("ungrouped finding untouched", any(f["id"] == "Y" for f in g))


# --------------------------------------------------------------------------
print("\nruleset fingerprint")

fp1 = _r.ruleset_fingerprint([_rk, rules_headroom, _rm])
fp2 = _r.ruleset_fingerprint([_rk, rules_headroom, _rm])
fp3 = _r.ruleset_fingerprint([_rk, rules_headroom])
check("fingerprint is stable", fp1 == fp2)
check("fingerprint changes when the rule set changes", fp1 != fp3)


def _fake_module(name, rule_fns, thresholds=None):
    m = type(sys)(name)
    m.RULES = rule_fns
    if thresholds is not None:
        m.THRESHOLDS = thresholds
    return m


def _r_a(bundle):
    return []


def _r_a_changed(bundle):
    # same name after rebinding, different body
    return [1]


_r_a_changed.__name__ = "_r_a"

m1 = _fake_module("fake", [_r_a], {"x": 1})
m2 = _fake_module("fake", [_r_a_changed], {"x": 1})
m3 = _fake_module("fake", [_r_a], {"x": 2})

f1 = _r.ruleset_fingerprint([m1])
check("fingerprint is stable across calls", f1 == _r.ruleset_fingerprint([m1]))
check("editing a rule body is detected", f1 != _r.ruleset_fingerprint([m2]))
check("changing a threshold is detected", f1 != _r.ruleset_fingerprint([m3]))
check("removing a rule is detected",
      f1 != _r.ruleset_fingerprint([_fake_module("fake", [], {"x": 1})]))


# --------------------------------------------------------------------------
print("\nmetric deltas across a rule change")


def _lc(metric_now, metric_prev, changed):
    fs = [{"id": "X", "code": "X", "subject": None, "severity": "warn",
           "title": "t", "detail": [], "evidence": [], "remediation": [],
           "metric": metric_now, "causes": []}]
    prev = {"X": {"first_seen": "2026-08-30T00:00:00Z", "severity": "warn",
                  "metric": metric_prev, "evidence": []}}
    out, _, _ = _r.apply_lifecycle(fs, prev, "2026-08-31T13:10:45Z", set(),
                                   ruleset_changed=changed)
    return out[0]


check("a normal delta is reported",
      _lc(5.0, 2.0, False).get("metric_delta") == 3.0)
check("no delta is reported when the rule set changed",
      _lc(1.0, 85488.0, True).get("metric_delta") is None)
check("and a redefined metric does not read as escalating",
      _lc(85488.0, 1.0, True)["state"] != "escalating")
check("but a genuine rise still escalates when rules are unchanged",
      _lc(85488.0, 1.0, False)["state"] == "escalating")


print("\nage-based escalation")


def aged(days, limit):
    f = {"id": "K8S_DEPLOYMENT_PAUSED:app/api", "code": "K8S_DEPLOYMENT_PAUSED",
         "subject": "app/api", "severity": "warn", "title": "paused", "detail": [],
         "evidence": ["k_deployments"], "remediation": [], "metric": None,
         "causes": [], "escalate_after_days": limit}
    import datetime
    now = datetime.datetime(2026, 8, 22)
    seen = now - datetime.timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    prev = {f["id"]: {"first_seen": seen.strftime(fmt), "severity": "warn",
                      "metric": None, "evidence": ["k_deployments"]}}
    out, _, _ = _r.apply_lifecycle([f], prev, now.strftime(fmt), {"k_deployments"})
    return out[0]


check("fresh finding stays warn", aged(0, 3)["severity"] == "warn")
check("within threshold stays warn", aged(2, 3)["severity"] == "warn")
check("a forgotten pause escalates to crit", aged(9, 3)["severity"] == "crit")
check("escalation is labelled as age-driven", aged(9, 3).get("aged_from") == "warn")
check("no threshold means no age escalation", aged(99, None)["severity"] == "warn")


# --------------------------------------------------------------------------
print("\napiserver counters behind a load balancer")


def _api_bundle(n_api, tot, err, start):
    f = {"k8s.controlplane.apiserver_nodes": {"value": ["n%d" % i for i in range(n_api)],
                                              "source": "t"},
         "k8s.apiserver.requests_total": {"value": tot, "source": "t"},
         "k8s.apiserver.requests_5xx_total": {"value": err, "source": "t"},
         "k8s.apiserver.start_time": {"value": start, "source": "t"}}
    return {"facts": f, "collection": {"commands": {}, "complete": True, "sources": {}}}


codes = {f["code"] for f in rules_headroom.r_deltas(
    _api_bundle(3, 9_000_000, 300, 1000.0),
    {"k8s.apiserver.requests_total": 9_400_000,
     "k8s.apiserver.requests_5xx_total": 12_400,
     "k8s.apiserver.start_time": 1000.0})}
check("no fabricated restart with multiple apiservers",
      "K8S_APISERVER_RESTARTED" not in codes, codes)
check("no fabricated error rate with multiple apiservers",
      "K8S_APISERVER_ERROR_RATE" not in codes, codes)
check("non-comparability is stated instead",
      "KAREL_APISERVER_METRICS_NOT_COMPARABLE" in codes, codes)

codes = {f["code"] for f in rules_headroom.r_deltas(
    _api_bundle(1, 9_400_000, 12_400, 1000.0),
    {"k8s.apiserver.requests_total": 9_000_000,
     "k8s.apiserver.requests_5xx_total": 4_400,
     "k8s.apiserver.start_time": 1000.0})}
check("single apiserver still yields a real error rate",
      "K8S_APISERVER_ERROR_RATE" in codes, codes)

codes = {f["code"] for f in rules_headroom.r_deltas(
    _api_bundle(1, 100, 0, 2000.0),
    {"k8s.apiserver.requests_total": 9_000_000,
     "k8s.apiserver.requests_5xx_total": 300,
     "k8s.apiserver.start_time": 1000.0})}
check("restart claimed only when start time changed",
      "K8S_APISERVER_RESTARTED" in codes, codes)


# --------------------------------------------------------------------------
print("\ninformational is split from Karel's blind spots")
_info = [
    {"id": "A", "code": "K8S_SCALED_TO_ZERO", "subject": "app/idle", "severity": "info",
     "title": "workload app/idle scaled to zero", "detail": [], "evidence": [],
     "remediation": []},
    {"id": "B", "code": "KAREL_CERT_COVERAGE_GAP", "subject": None, "severity": "info",
     "title": "kubelet certs not visible from a pod", "detail": [], "evidence": [],
     "remediation": []},
]
_txt = report.render(
    {"facts": {}, "run_id": "r", "collected_at": "2026-08-22T22:20:46Z",
     "collection": {"complete": True, "sources": {}, "commands": {}}},
    _info, [], {})
check("cluster observations under Informational",
      "### Informational" in _txt and "scaled to zero" in _txt)
check("tool limits under their own heading",
      "### What this report cannot see" in _txt)
check("a KAREL_ info is not listed as a cluster observation",
      _txt.index("### What this report cannot see")
      < _txt.index("kubelet certs not visible"))


print("\ndelta label reflects the real baseline gap")
_bb = {"facts": {}, "run_id": "r", "collected_at": "2026-08-31T13:10:45Z",
       "collection": {"complete": True, "sources": {}, "commands": {}}}
_ff = [{"id": "X", "code": "X", "subject": None, "severity": "warn", "title": "t",
        "detail": [], "evidence": [], "remediation": [], "metric": 5.0,
        "metric_delta": 3.0, "state": "open", "days_open": 3}]
_t2 = report.render(_bb, _ff, [], {"collected_at": "2026-08-31T10:31:11Z"})
check("a 2h baseline is labelled 2h, not 'yesterday'",
      "change over 2h" in _t2 and "since yesterday" not in _t2)


# --------------------------------------------------------------------------
print("\nmarkdown: pre-existing code spans survive")
check("single-word span not double-escaped",
      "\\`" not in report.md("Cluster flag `noout` is set"))
check("multi-word span not double-escaped",
      "\\`" not in report.md("makes `kubectl get` fail"))
check("stray backtick still escaped",
      "\\`" in report.md("a literal ` stray backtick"))


# --------------------------------------------------------------------------
print("\npseudo-evidence and self-findings must be resolvable")

_ob = _r.observability({"facts": {"prom.reachable": {"value": True, "source": "p"}},
                        "collection": {"commands": {
                            "k_nodes": {"status": "ok", "parse_ok": True},
                            "k_events": {"status": "failed"}}}})
check("a working command counts as observable", "k_nodes" in _ob, sorted(_ob))
check("index.tsv counts as observable", "index.tsv" in _ob, sorted(_ob))
check("prom counts as observable when the collector ran", "prom" in _ob)
check("a failed command does not", "k_events" not in _ob, sorted(_ob))

_prev = {
    "KAREL_COLLECTOR_TIMEOUT": {"first_seen": "2026-08-28T00:00:00Z",
                                "severity": "warn", "metric": None,
                                "evidence": ["k_nodes"]},
}
_, _res, _car = _r.apply_lifecycle([], _prev, "2026-08-31T14:14:51Z", set())
check("a KAREL_ finding resolves even when its command is still broken",
      [x["id"] for x in _res] == ["KAREL_COLLECTOR_TIMEOUT"],
      (sorted(x["id"] for x in _res), sorted(x["id"] for x in _car)))


print("\na query suppressed for short history is not observable")
_d8 = None
import tempfile as _tf
import json as _json
_d8 = _tf.mkdtemp()
_json.dump({"reachable": True, "queries": {
    "prom_retention_days": {"status": "ok", "series": 1, "value": 0.02,
                            "window_days": 0, "empty_means": "absent"},
    "etcd_db_predict_30d": {"status": "ok", "series": 1, "value": 1.4e9,
                            "window_days": 14, "empty_means": "absent"}},
    "alerts": {"available": False}, "targets": {"available": False}},
    open(os.path.join(_d8, "result.json"), "w"))
_PF = normalize.Facts()
_PC = {}
_np.ingest(_d8, _PF, _PC)
_pb = {"facts": dict(_PF), "collection": {"commands": _PC, "complete": True,
                                          "sources": {}}}
_pobs = _r.observability(_pb)
check("a query suppressed for short history is not observable",
      "prom:etcd_db_predict_30d" not in _pobs)
_, _res2, _car2 = _r.apply_lifecycle([], {
    "K8S_ETCD_FORECAST": {"first_seen": "2026-08-28T00:00:00Z",
                          "severity": "crit", "metric": None,
                          "evidence": ["prom:etcd_db_predict_30d"]},
    "PROM_TARGETS_DOWN": {"first_seen": "2026-08-28T00:00:00Z",
                          "severity": "warn", "metric": None,
                          "evidence": ["prom"]}},
    "2026-08-31T14:14:51Z", _pobs)
check("a suppressed forecast is carried forward, not called resolved",
      [x["id"] for x in _car2] == ["K8S_ETCD_FORECAST"],
      ([x["id"] for x in _res2], [x["id"] for x in _car2]))
check("a collector-wide finding still resolves",
      [x["id"] for x in _res2] == ["PROM_TARGETS_DOWN"])


# --------------------------------------------------------------------------
print("\nprometheus collector")


def _mk_prom(doc):
    d = _tf.mkdtemp()
    _json.dump(doc, open(os.path.join(d, "result.json"), "w"))
    return d


def _prom_bundle(doc):
    d = _mk_prom(doc)
    F = normalize.Facts()
    C = {}
    _np.ingest(d, F, C)
    b = facts({})
    b["facts"].update(dict(F))
    b["collection"]["commands"] = C
    return b, F


_PROM = {
    "reachable": True,
    "queries": {
        "prom_retention_days": {"status": "ok", "series": 1, "value": 20.0,
                                "window_days": 0, "empty_means": "absent"},
        "etcd_db_predict_30d": {"status": "ok", "series": 1, "value": 3.6e9,
                                "window_days": 14, "empty_means": "absent"},
        "etcd_leader_changes_24h": {"status": "ok", "series": 1, "value": 5,
                                    "window_days": 1, "empty_means": "absent"},
        "etcd_fsync_p99_24h": {"status": "ok", "series": 1, "value": 0.071,
                               "window_days": 1, "empty_means": "absent"},
        "apiserver_5xx_rate_24h": {"status": "ok", "series": 1, "value": 0.05,
                                   "window_days": 1, "empty_means": "absent"},
        "pod_oomkills_24h": {"status": "ok", "series": 1, "window_days": 1,
                             "empty_means": "none",
                             "value": [{"labels": {"namespace": "app", "pod": "x"},
                                        "value": 3}]},
        "node_notready_minutes_24h": {"status": "ok", "series": 1, "window_days": 1,
                                      "empty_means": "none", "value": {"n3": 6.0}},
        "etcd_scrub_absent": {"status": "no_series", "series": 0,
                              "window_days": 0, "empty_means": "absent"},
        "bad_reduce": {"status": "reduce_failed", "series": 3,
                       "error": "reduce matched no labels",
                       "window_days": 0, "empty_means": "absent"},
    },
    "alerts": {"available": True, "count": 2, "alerts": [
        {"name": "KubeAPIDown", "severity": "critical", "namespace": "kube-system",
         "instance": "n1", "summary": "apiserver down", "startsAt": "2026-08-21"}]},
    "targets": {"available": True, "total": 45, "down_count": 1,
                "down": [{"job": "node-exporter", "instance": "10.0.0.1:9100",
                          "error": "context deadline exceeded"}]},
}
_pb, _PFx = _prom_bundle(_PROM)

check("reachable recorded", _PFx.get_value("prom.reachable") is True)
check("a genuinely absent metric stays absent",
      _PFx.get_value("prom.missing.etcd_scrub_absent") is True
      and _PFx.get_value("prom.etcd_scrub_absent") is None)
check("a failed reduction is recorded, not silently dropped",
      _PFx.get_value("prom.reduce_failed.bad_reduce"))

codes = {f["code"] for f in _np.r_prom_transients(_pb)}
check("etcd leader churn surfaced", "K8S_ETCD_LEADER_CHURN" in codes, codes)
check("node flap surfaced", "K8S_NODE_FLAPPED" in codes, codes)
check("OOMKills over 24h surfaced", "K8S_OOMKILLS_24H" in codes, codes)

codes = {f["code"] for f in _np.r_prom_rates(_pb)}
check("apiserver error rate surfaced", "K8S_APISERVER_ERROR_RATE" in codes, codes)
check("etcd slow disk surfaced", "K8S_ETCD_SLOW_DISK" in codes, codes)

check("etcd forecast emitted", any(f["code"] == "K8S_ETCD_FORECAST"
                                   for f in _np.r_prom_forecasts(_pb)))

codes = {f["code"] for f in _np.r_prom_health(_pb)}
check("down scrape targets surfaced", "PROM_TARGETS_DOWN" in codes, codes)
check("absent metrics reported as absent", "KAREL_PROM_METRICS_ABSENT" in codes, codes)
check("reduce failure raises a finding", "KAREL_PROM_REDUCE_FAILED" in codes, codes)

codes = {f["code"] for f in _np.r_prom_alerts(_pb)}
check("Alertmanager alerts surfaced, categorised",
      "PROM_ALERTS_CONTROL_PLANE" in codes, codes)
sev = [f["severity"] for f in _np.r_prom_alerts(_pb)]
check("a critical alert makes its category critical", "crit" in sev, sev)

# the always-firing watchdog is not a finding; a watchdog-only state is confirmed
_wd = {"reachable": True, "queries": {}, "targets": {"available": False},
       "alerts": {"available": True, "count": 2, "alerts": [
           {"name": "Watchdog", "severity": "none", "summary": "always firing"},
           {"name": "InfoInhibitor", "severity": "none",
            "summary": "inhibits info alerts"}]}}
_wb, _ = _prom_bundle(_wd)
_wf = _np.r_prom_alerts(_wb)
check("watchdog and InfoInhibitor are not reported as findings",
      not any(f["code"].startswith("PROM_ALERTS") for f in _wf), _wf)
check("but a watchdog-only state is confirmed positively",
      any(f["code"] == "PROM_NO_REAL_ALERTS" for f in _wf), _wf)

# grouped alerts: 1,400 KubeJobFailed is one tenant's backlog, not 1,400 lines
_grp = {"reachable": True, "queries": {}, "targets": {"available": False},
        "alerts": {"available": True, "count": 1411, "alerts": [], "groups": {
    "KubeJobFailed": {"count": 1400, "severities": {"warning": 1400},
                      "namespaces": {"bigtenant-ns": 1390, "other-ns": 10},
                      "objects": {}, "ns_dropped": 0, "obj_dropped": 96,
                      "oldest": "2026-06-01T00:23:11Z",
                      "newest": "2026-10-14T18:12:01Z", "samples": []},
    "KubeJobNotCompleted": {"count": 2, "severities": {"warning": 2},
                            "namespaces": {"foldify-ns": 2},
                            "objects": {"foldify-ns/etl-step": 2},
                            "ns_dropped": 0, "obj_dropped": 0,
                            "oldest": "2026-10-14T00:37:00Z",
                            "newest": "2026-10-14T12:00:00Z", "samples": []},
    "KubePersistentVolumeInodesFillingUp": {
        "count": 4, "severities": {"critical": 4},
        "namespaces": {"a-ns": 2, "b-ns": 2},
        "objects": {"a-ns/pvc-db-backup": 2, "b-ns/pvc-db-backup": 2},
        "ns_dropped": 0, "obj_dropped": 0,
        "oldest": "2026-10-14T20:48:00Z", "newest": "2026-10-14T20:51:00Z",
        "samples": []},
    "CustomTotallyNewAlert": {"count": 5, "severities": {"info": 5},
                              "namespaces": {}, "objects": {},
                              "ns_dropped": 0, "obj_dropped": 0,
                              "oldest": "2026-10-14T09:00:00Z",
                              "newest": "2026-10-14T09:05:00Z",
                              "samples": [{"target": "x"}]},
}}}
_gb2, _ = _prom_bundle(_grp)
_af = {f["code"]: f for f in _np.r_prom_alerts(_gb2)}
check("jobs aggregate into one finding", "PROM_ALERTS_JOBS" in _af, sorted(_af))
check("a dominant namespace is named in the title",
      "bigtenant-ns" in _af.get("PROM_ALERTS_JOBS", {}).get("title", ""),
      _af.get("PROM_ALERTS_JOBS", {}).get("title"))
check("the per-rule counts survive the fold",
      any("1400" in d and "KubeJobFailed" in d
          for d in _af.get("PROM_ALERTS_JOBS", {}).get("detail", [])),
      _af.get("PROM_ALERTS_JOBS", {}).get("detail"))
check("a weeks-old alert group is called out",
      any("continuously" in d for d in _af.get("PROM_ALERTS_JOBS", {}).get("detail", [])),
      _af.get("PROM_ALERTS_JOBS", {}).get("detail"))
check("a capped object histogram says what was dropped",
      any("aggregation cap" in d for d in _af.get("PROM_ALERTS_JOBS", {}).get("detail", [])),
      _af.get("PROM_ALERTS_JOBS", {}).get("detail"))
check("storage is its own category and stays critical",
      _af.get("PROM_ALERTS_STORAGE", {}).get("severity") == "crit",
      _af.get("PROM_ALERTS_STORAGE", {}))
check("storage lists the PVCs, not 4 near-identical lines",
      any("pvc-db-backup" in d for d in _af.get("PROM_ALERTS_STORAGE", {}).get("detail", [])),
      _af.get("PROM_ALERTS_STORAGE", {}).get("detail"))
check("an unknown alert name is listed, never folded silent",
      _af.get("PROM_ALERTS_OTHER", {}).get("severity") == "info" and
      "CustomTotallyNewAlert" in _af.get("PROM_ALERTS_OTHER", {}).get("title", ""),
      _af.get("PROM_ALERTS_OTHER", {}))

# a wholly-down job is a config problem, not N outages
_gap = {
    "reachable": True,
    "queries": {
        "prom_retention_days": {"status": "ok", "series": 1, "value": 8.9,
                                "window_days": 0, "empty_means": "absent",
                                "source_job": "prometheus"},
        "node_notready_minutes_24h": {"status": "no_series", "series": 0,
                                      "window_days": 1, "empty_means": "none",
                                      "source_job": "kube-state-metrics"},
        "pod_oomkills_24h": {"status": "no_series", "series": 0,
                             "window_days": 1, "empty_means": "none",
                             "source_job": "kube-state-metrics"},
    },
    "alerts": {"available": True, "count": 0, "alerts": []},
    "targets": {"available": True, "total": 10, "down_count": 3,
                "down": [{"job": "kube-state-metrics", "instance": "a", "error": "refused"}]},
}
_gb, _GF = _prom_bundle(_gap)
_GF.add("prom.up_by_job", {"kube-state-metrics": 1}, "prom")
_gb["facts"] = dict(_GF)
codes = {f["code"] for f in _np.r_prom_health(_gb)}
check("a wholly-down job is distinguished from instance failures",
      "PROM_JOB_ENTIRELY_DOWN" in codes, codes)
_gf = _np.r_scrape_gap_consequences(_gb)
check("a down job is linked to its absent queries", len(_gf) == 1, _gf)
if _gf:
    check("it names the findings that cannot fire",
          any("OOMKills" in d for d in _gf[0]["detail"]))
    check("it says absent is not healthy",
          any("ABSENT, not healthy" in d for d in _gf[0]["detail"]))

# short retention suppresses time-window queries rather than reporting them
_starved, _SF = _prom_bundle({
    "reachable": True,
    "queries": {
        "prom_retention_days": {"status": "ok", "series": 1, "value": 0.02,
                                "window_days": 0, "empty_means": "absent"},
        "etcd_db_predict_30d": {"status": "ok", "series": 1, "value": 1.4e9,
                                "window_days": 14, "empty_means": "absent"},
    },
    "alerts": {"available": False}, "targets": {"available": False}})
check("a 14d forecast is suppressed on 30 minutes of history",
      _SF.get_value("prom.etcd_db_predict_30d") is None
      and _SF.get_value("prom.starved.etcd_db_predict_30d"))
codes = {f["code"] for f in _np.r_prom_health(_starved)}
check("insufficient history raises a finding",
      "KAREL_PROM_INSUFFICIENT_HISTORY" in codes, codes)

# unreachable path
_ub, _UF = _prom_bundle({"reachable": False, "error": "refused", "queries": {},
                         "alerts": {"available": False},
                         "targets": {"available": False}})
codes = {f["code"] for f in _np.r_prom_health(_ub)}
check("unreachable Prometheus is a finding, not a crash",
      "KAREL_PROM_UNREACHABLE" in codes, codes)
check("no fabricated values when unreachable",
      not any(k.startswith("prom.") and k.endswith("_24h") for k in _UF))


# --------------------------------------------------------------------------
print("\ncommands that ignore -f json")

import gzip as _gz4
import tempfile as _tf4


def _mk_out(cases, declared_text):
    d = _tf4.mkdtemp()
    os.makedirs(os.path.join(d, "raw"), exist_ok=True)
    rows = []
    for n, body in cases.items():
        for suf, content in ((".stdout", body), (".stderr", "")):
            with _gz4.open(os.path.join(d, "raw", n + suf + ".gz"), "wt") as fh:
                fh.write(content)
        rows.append((n, "0", "1", "2", "ok", str(len(body))))
    with open(os.path.join(d, "index.tsv"), "wt") as fh:
        fh.write("\n".join("\t".join(r) for r in rows) + "\n")
    with open(os.path.join(d, "text_commands.json"), "wt") as fh:
        _json.dump(declared_text, fh)
    with open(os.path.join(d, "expected_status.json"), "wt") as fh:
        fh.write("{}")
    open(os.path.join(d, "COMPLETE"), "w").close()
    return d


def _build_k8s(d):
    return normalize.build_bundle([
        {"label": "k8s", "dir": d, "parsers": normalize_k8s.PARSERS,
         "text": normalize_k8s.TEXT_COMMANDS}])


_d6 = _mk_out({
    "k_readyz": "readyz check passed",
    "k_livez": "livez check passed",
    "k_top_nodes": "n1 4000m 6% 7738Mi 1%",
    # valid JSON, but the wrong SHAPE for its parser: a list where an object
    # is expected -> the parser raises, and that is a real parse failure
    "k_version": "[]",
}, ["k_readyz", "k_livez", "k_top_nodes"])
bb6 = _build_k8s(_d6)
c6 = bb6["collection"]["commands"]

check("a declared text command parses instead of failing",
      c6["k_readyz"]["parse_ok"] is True, c6["k_readyz"])
check("its value is extracted from the text",
      (bb6["facts"].get("k8s.apiserver.readyz_ok") or {}).get("value") is True)
check("non-JSON from a command with no parser is not a parse failure",
      c6["k_top_nodes"].get("parse_ok") is True)
check("a wrong-shaped response IS a parse failure",
      c6["k_version"]["parse_ok"] is False and c6["k_version"].get("parse_error"))

fs6 = _r.r_collection(bb6)
pf = [f for f in fs6 if f["code"] == "KAREL_PARSE_FAILURE"]
check("only the real failure is reported",
      len(pf) == 1 and pf[0]["metric"] == 1.0, [f["code"] for f in fs6])
check("the parser error text is shown",
      pf and any("AttributeError" in d for d in pf[0]["detail"]), pf)


# --------------------------------------------------------------------------
print("\nper-source completeness")


def _mk_src(complete, label=""):
    d = _tf4.mkdtemp()
    os.makedirs(os.path.join(d, "raw"), exist_ok=True)
    open(os.path.join(d, "index.tsv"), "w").close()
    if complete:
        open(os.path.join(d, "COMPLETE"), "w").close()
    return d


_k8sd = _mk_src(False)
bb2 = normalize.build_bundle([
    {"label": "k8s", "dir": _k8sd, "parsers": normalize_k8s.PARSERS,
     "text": normalize_k8s.TEXT_COMMANDS},
    {"label": "prom", "dir": "/nonexistent-prom", "parsers": "prom"},
])
srcs = bb2["collection"].get("sources") or {}
check("per-source completeness recorded", set(srcs) == {"k8s", "prom"}, srcs)
check("the incomplete source is named", srcs["k8s"]["complete"] is False)
check("a missing collector directory is recorded, not skipped",
      srcs["prom"]["complete"] is False and srcs["prom"].get("reason"))

fs = _r.r_collection(bb2)
codes = {(f["code"], f.get("subject")) for f in fs}
check("k8s incompleteness raises a named finding",
      ("KAREL_SOURCE_INCOMPLETE", "k8s") in codes, codes)
check("absent Prometheus raises a named finding",
      ("KAREL_SOURCE_INCOMPLETE", "prom") in codes, codes)
check("Prometheus absence is info, k8s is warn",
      {f["severity"] for f in fs if f.get("subject") == "prom"} == {"info"}
      and {f["severity"] for f in fs if f.get("subject") == "k8s"} == {"warn"})

_txt2 = report.render(bb2, fs, [], {})
check("the report names the failing collector",
      "k8s" in _txt2 and "prom" in _txt2)
check("the reason is shown, not just the fact",
      "sentinel missing" in _txt2)


# --------------------------------------------------------------------------
print("\nreal-cluster pod shapes")

_real = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "fixtures", "real-pods.json.gz")
_nodesf = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "real-nodes.json.gz")
if os.path.exists(_real):
    import gzip as _gz
    F = normalize.Facts()
    normalize_k8s.p_pods(_json.load(_gz.open(_real, "rt")), F, "k_pods")
    pin = F.get_value("k8s.node.pinned_pods", {}) or {}
    flat = [p for v in pin.values() for p in v]
    check("one-shot Job pods are not 'pinned'",
          not any("-prepare-" in p for p in flat), flat[:3])
    check("static control-plane pods are not 'pinned'",
          not any(p.split("/")[-1].startswith(("etcd-", "kube-apiserver-"))
                  for p in flat), flat[:3])
    check("etcd member nodes detected",
          len(F.get_value("k8s.controlplane.etcd_nodes", []) or []) == 3,
          F.get_value("k8s.controlplane.etcd_nodes"))
    check("request coverage measured",
          (F.get_value("k8s.pod.containers_no_cpu_request") or 0) > 0)
    check("BestEffort pods counted",
          (F.get_value("k8s.pod.besteffort_count") or 0) > 0)
else:
    print("  SKIP  (no real-pods fixture)")

print("\nnode facts from real node objects")
if os.path.exists(_nodesf):
    import gzip as _gz2
    NF = normalize.Facts()
    normalize_k8s.p_nodes(_json.load(_gz2.open(_nodesf, "rt")), NF, "k_nodes")
    check("allocatable memory parsed from Ki",
          all(NF.get_value("k8s.node.%s.allocatable_mem_bytes" % n)
              for n in NF.get_value("k8s.node.names", [])))
    check("etcd voters from the node condition",
          len(NF.get_value("k8s.controlplane.etcd_nodes", []) or []) == 3)
    check("condition is preferred over static-pod inference",
          NF.get_value("k8s.controlplane.etcd_source") is not None)
    resv = NF.get_value("k8s.node.reserved_mem_bytes", {}) or {}
    check("zero reservation detected", sum(1 for v in resv.values() if not v) == 3, resv)
    check("reservation drift detected", len(set(resv.values())) > 1)
    rels = NF.get_value("k8s.node.rke2_releases", {}) or {}
    check("rke2 version read from the kubelet version",
          set(rels.values()) == {"v1.35.6+rke2r1"}, rels)
    check("a homogeneous fleet reports one release",
          NF.get_value("k8s.node.rke2_release_count") == 1)
    check("kernel version recorded",
          all(NF.get_value("k8s.node.%s.kernel" % n)
              for n in NF.get_value("k8s.node.names", [])))
else:
    print("  SKIP  (no real-nodes fixture)")


print("\npod requests match the cluster's own accounting")
if os.path.exists(_real) and os.path.exists(_nodesf):
    RF = normalize.Facts()
    normalize_k8s.p_pods(_json.load(_gz.open(_real, "rt")), RF, "k_pods")
    got = RF.get_value("k8s.node.requests", {}) or {}
    # management.cattle.io/pod-requests as computed independently by Rancher
    expect = {
        "kub-ceph-c1.priv.cerit-sc.cz": (21650, 438897341312, 75),
        "kub-ceph-c2.priv.cerit-sc.cz": (22065, 472160269184, 66),
        "kub-ceph-c3.priv.cerit-sc.cz": (22515, 605152041088, 70),
        "kub-ceph-c4.priv.cerit-sc.cz": (9375, 567503679616, 61),
    }
    for node, (ec, em, ep) in expect.items():
        g = got.get(node, {})
        check("%s cpu requests" % node.split(".")[0], g.get("cpu_m") == ec,
              "%s != %s" % (g.get("cpu_m"), ec))
        check("%s memory requests" % node.split(".")[0], g.get("mem_bytes") == em,
              "%s != %s" % (g.get("mem_bytes"), em))
        check("%s pod count" % node.split(".")[0], g.get("pods") == ep,
              "%s != %s" % (g.get("pods"), ep))
else:
    print("  SKIP  (fixtures missing)")


print("\nrequests vs usage are reported as different things")
if os.path.exists(_nodesf) and os.path.exists(_real):
    GF = normalize.Facts()
    normalize_k8s.p_nodes(_json.load(_gz2.open(_nodesf, "rt")), GF, "k_nodes")
    normalize_k8s.p_pods(_json.load(_gz.open(_real, "rt")), GF, "k_pods")
    normalize_k8s.p_top_nodes(
        "\n".join("%s 4000m 6%% 7738Mi 1%%" % n
                  for n in GF.get_value("k8s.node.names", [])), GF, "k_top_nodes")
    gb = facts({})
    gb["facts"].update(dict(GF))
    fs = _rk.r_request_vs_usage(gb)
    check("large request/usage divergence is surfaced", len(fs) == 1, fs)
    if fs:
        check("it explains that headroom is reservation arithmetic",
              any("reservation arithmetic" in d for d in fs[0]["detail"]))
else:
    print("  SKIP  (fixtures missing)")


# --------------------------------------------------------------------------
print("\nthe real entry point runs")

import subprocess as _sp
import shutil as _sh5

_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
_PIPE = os.path.join(_ROOT, "lib", "pipeline.py")
_SRC = "/tmp/outs"


def _run_pipeline(prev, drop=()):
    """Invoke pipeline.py exactly as run.sh does."""
    d = _tf5.mkdtemp()
    for sub in ("out", "out-prom"):
        src = os.path.join(_SRC, sub)
        if sub in drop or not os.path.isdir(src):
            continue
        _sh5.copytree(src, os.path.join(d, sub))
    for junk in ("report.md", "report.html", "bundle.json", "findings.json",
                 "summary.json"):
        f = os.path.join(d, "out", junk)
        if os.path.exists(f):
            os.remove(f)
    rep = os.path.join(d, "report.md")
    r = _sp.run([sys.executable, _PIPE,
                 "--out", os.path.join(d, "out"),
                 "--prom-out", os.path.join(d, "out-prom"),
                 "--prev", prev, "--suppressions", "/dev/null",
                 "--report", rep],
                capture_output=True, text=True, timeout=180)
    ok = r.returncode == 0 and os.path.exists(rep) and os.path.getsize(rep) > 200
    err = (r.stderr or "")[-400:]
    _sh5.rmtree(d, ignore_errors=True)
    return ok, err


import tempfile as _tf5

if os.path.isdir(os.path.join(_SRC, "out")):
    ok, err = _run_pipeline(os.path.join(_SRC, "out", "snapshot.json"))
    check("pipeline.py exits 0 and writes a report", ok, err)
    ok, err = _run_pipeline("/dev/null")
    check("pipeline.py works with no previous snapshot", ok, err)
    ok, err = _run_pipeline(os.path.join(_SRC, "out", "snapshot.json"),
                            drop=("out-prom",))
    check("pipeline.py works with no Prometheus output", ok, err)
else:
    print("  SKIP  (no collector output at %s)" % _SRC)


# --------------------------------------------------------------------------
print("\nreplaying a saved bundle")

_BUNDLE = os.path.join(_ROOT, "out", "bundle.json")
if os.path.exists(_BUNDLE):
    d = _tf5.mkdtemp()
    rep = os.path.join(d, "report.md")
    r = _sp.run([sys.executable, _PIPE, "--from-bundle", _BUNDLE, "--out", d,
                 "--prev", "/dev/null", "--suppressions", "/dev/null",
                 "--bundle", os.path.join(d, "bundle.json"),
                 "--snapshot", os.path.join(d, "snapshot.json"), "--report", rep],
                capture_output=True, text=True, timeout=180)
    text = open(rep).read() if os.path.exists(rep) else ""
    check("--from-bundle replays a real bundle", r.returncode == 0 and text,
          (r.stderr or "")[-300:])
    check("the replay has no per-node 'would degrade' warnings",
          "would degrade the cluster" not in text)
    check("the replay has at most one CRIT per dead webhook Service",
          text.count("#### CRIT — ") <= 3, text.count("#### CRIT — "))
    import json as _js5
    summ = _js5.load(open(os.path.join(d, "summary.json")))
    check("summary.json counts match the report headline",
          ("%d critical, %d warning" % (summ["counts"]["crit"],
                                         summ["counts"]["warn"])) in text,
          summ["counts"])
    _sh5.rmtree(d, ignore_errors=True)
else:
    print("  SKIP  (no saved bundle at %s)" % _BUNDLE)


# --------------------------------------------------------------------------
print("\nstatic analysis gate")
try:
    import importlib.util as _ilu
    _has_pyflakes = _ilu.find_spec("pyflakes") is not None
except Exception:
    _has_pyflakes = False
if _has_pyflakes:
    _r2 = _sp.run([sys.executable, "-m", "pyflakes"] +
                  [os.path.join(_ROOT, d, f)
                   for d in ("lib", "bin", "tests")
                   for f in sorted(os.listdir(os.path.join(_ROOT, d)))
                   if f.endswith(".py")],
                  capture_output=True, text=True)
    check("pyflakes is clean (catches use-before-assignment)",
          _r2.returncode == 0, (_r2.stdout or _r2.stderr)[:300])
else:
    print("  SKIP  (pyflakes not installed)")


print("\n%s" % ("-" * 60))
if FAILURES:
    print("%d FAILURE(S): %s" % (len(FAILURES), ", ".join(FAILURES)))
    sys.exit(1)
print("all regression tests pass")
