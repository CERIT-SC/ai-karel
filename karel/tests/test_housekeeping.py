#!/usr/bin/env python3
"""Tests for the housekeeping derive step, state handling and writers."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import housekeeping    # noqa: E402
import logscan         # noqa: E402

NOW = logscan.parse_ts("2026-10-07T12:00:00Z")


def bundle_with(pairs, commands=None):
    b = facts(pairs)
    b["collected_at"] = "2026-10-07T12:00:00Z"
    b["collection"]["commands"] = commands or {}
    return b


def svc(nn, uid, type="ClusterIP", selector=None, created="2026-09-01T00:00:00Z",
        owners=None, lb=None, keep=None):
    return {"uid": uid, "type": type,
            "selector": selector or {}, "owner_kinds": owners or [],
            "created": created, "lb_ips": lb or [], "keep": keep}


def base(hk_commands_ok=True):
    """The smallest bundle that makes derive() run: every source ok."""
    cmds = {}
    if hk_commands_ok:
        for c in ("k_services", "k_endpointslices", "k_deployments",
                  "k_statefulsets", "k_pods", "k_pvc", "k_pv", "k_namespaces",
                  "k_ingresses", "k_hpa"):
            cmds[c] = {"status": "ok"}
    return cmds


# --------------------------------------------------------------------------
print("\nService exclusions: the 508-Service flood shrinks to real orphans")

pairs = {
    "k8s.service.names": ["a/ext", "a/broken", "a/idle", "a/owned", "a/young",
                          "a/orphan", "a/lb"],
    "k8s.service.info": {
        "a/ext":    svc("a/ext", "u1", type="ExternalName"),
        "a/broken": svc("a/broken", "u2", selector={"app": "b"}),
        "a/idle":   svc("a/idle", "u3", selector={"app": "idle"}),
        "a/owned":  svc("a/owned", "u4", owners=["Cluster"]),
        "a/young":  svc("a/young", "u5", created="2026-10-07T09:00:00Z"),
        "a/orphan": svc("a/orphan", "u6"),
        "a/lb":     svc("a/lb", "u7", type="LoadBalancer", lb=["10.0.0.9"]),
    },
    "k8s.service.endpoints": {
        "a/broken": {"ready": 0, "total": 3},     # pods exist, broken
        "a/idle":   {"ready": 0, "total": 0},
        "a/orphan": {"ready": 0, "total": 0},
    },
    "k8s.deployment.templates": {
        "Deployment:a/idle": {"replicas": 0, "labels": {"app": "idle"}}},
    "k8s.statefulset.templates": {},
}
b = bundle_with(pairs, base())
state = housekeeping.derive(b, {}, now=NOW)
items = b["facts"]["k8s.housekeeping.items"]["value"]
cats = {i["name"]: i["category"] for i in items if i["kind"] == "Service"}
check("ExternalName excluded", "ext" not in cats, cats)
check("broken-workload service excluded (that is a workload finding)",
      "broken" not in cats)
check("scaled-to-zero service counted as idle, not listed",
      "idle" not in cats
      and b["facts"]["k8s.housekeeping.idle_services"]["value"] == 1)
check("operator-owned excluded", "owned" not in cats)
check("younger than 1 day excluded", "young" not in cats)
check("a true orphan is svc_no_backend", cats.get("orphan") == "svc_no_backend")
check("a LoadBalancer orphan is lb_ip_abandoned with a cost",
      cats.get("lb") == "lb_ip_abandoned", cats)


# --------------------------------------------------------------------------
print("\nIngress backends: missing is certain, orphaned is likely")

pairs.update({
    "k8s.ingress.info": {
        "a/gone": {"uid": "i1", "hosts": ["gone.example"], "backends": ["nope"],
                   "created": "2026-01-01T00:00:00Z", "keep": None},
        "a/dead": {"uid": "i2", "hosts": ["dead.example"],
                   "backends": ["orphan", "lb"], "created": "2026-01-01T00:00:00Z",
                   "keep": None},
        "a/live": {"uid": "i3", "hosts": ["live.example"], "backends": ["ext"],
                   "created": "2026-01-01T00:00:00Z", "keep": None},
    },
    "k8s.hpa.info": {
        "a/stuck": {"uid": "h1", "target_kind": "Deployment",
                    "target_name": "gone", "able_to_scale": False,
                    "able_reason": "FailedGetScale",
                    "created": "2026-01-01T00:00:00Z", "keep": None},
    },
})
b = bundle_with(pairs, base())
housekeeping.derive(b, {}, now=NOW)
items = b["facts"]["k8s.housekeeping.items"]["value"]
by_name = {i["name"]: i for i in items}
check("missing backend -> certain, with a delete command",
      by_name["gone"]["confidence"] == "certain"
      and by_name["gone"]["category"] == "ingress_backend_missing"
      and "delete ingress" in (by_name["gone"]["proposed_command"] or ""))
check("all backends orphaned -> likely, no command",
      by_name["dead"]["confidence"] == "likely"
      and by_name["dead"]["category"] == "ingress_backend_abandoned"
      and not by_name["dead"].get("proposed_command"))
check("live backend -> not listed", "live" not in by_name)
check("HPA with FailedGetScale -> hpa_target_missing",
      by_name["stuck"]["category"] == "hpa_target_missing"
      and by_name["stuck"]["confidence"] == "certain", by_name.get("stuck"))


# --------------------------------------------------------------------------
print("\nunused PVC: ask, and never a proposed delete command")

pairs2 = {
    "k8s.pvc.info": {
        "t/data": {"uid": "p1", "size_bytes": 20 * 1024**3,
                   "created": "2026-01-01T00:00:00Z", "phase": "Bound",
                   "keep": None},
    },
    "k8s.pvc.pod_users": {},
    "k8s.pv.info": {
        "pv-1": {"uid": "v1", "size_bytes": 20 * 1024**3,
                 "created": "2026-01-01T00:00:00Z", "phase": "Released",
                 "keep": None},
    },
}
b = bundle_with(pairs2, base())
housekeeping.derive(b, {}, now=NOW)
items = b["facts"]["k8s.housekeeping.items"]["value"]
pvc = [i for i in items if i["name"] == "data"]
check("Bound, unreferenced, older than 7 d -> pvc_unused ask",
      pvc and pvc[0]["confidence"] == "ask"
      and pvc[0]["category"] == "pvc_unused", pvc)
check("pvc_unused never carries a delete command - the object is data",
      not pvc[0].get("proposed_command"))
pv = [i for i in items if i["name"] == "pv-1"]
check("Released PV -> pv_released", pv and pv[0]["category"] == "pv_released")


# --------------------------------------------------------------------------
print("\nsame name, new UID -> age 0; failed source keeps old ages")

b = bundle_with(pairs2, base())
prev = {"version": 1, "items": {
    # the same ns/name under the OLD uid: recreate must reset the age
    "p1-old": {"category": "pvc_unused", "ns": "t",
               "kind": "PersistentVolumeClaim", "name": "data",
               "first_seen": "2026-09-01T00:00:00Z"},
    "gone-svc": {"category": "svc_no_backend", "ns": "t", "kind": "Service",
                 "name": "gone", "first_seen": "2026-09-01T00:00:00Z"},
}}
housekeeping.derive(b, dict(prev), now=NOW)
item = [i for i in b["facts"]["k8s.housekeeping.items"]["value"]
        if i["name"] == "data"][0]
check("a recreated object (new UID) starts at age 0", item["age_days"] == 0,
      item.get("first_seen"))

cmds_no_svc = dict(base())
cmds_no_svc["k_services"] = {"status": "failed"}
b2 = bundle_with(pairs2, cmds_no_svc)
st = housekeeping.derive(b2, dict(prev), now=NOW)
check("k_services failed -> its entries are kept, not pruned",
      "gone-svc" in st["items"], st["items"])
b3 = bundle_with(pairs2, base())
st = housekeeping.derive(b3, dict(prev), now=NOW)
check("k_services ok -> the vanished entry is pruned",
      "gone-svc" not in st["items"], st["items"])


# --------------------------------------------------------------------------
print("\nkeep annotation on object and namespace")

pairs3 = {
    "k8s.service.info": {
        "keepme/named": svc("keepme/named", "k1", keep="legacy dashboards"),
        "other/plain": svc("other/plain", "k2"),
    },
    "k8s.service.names": ["keepme/named", "other/plain"],
    "k8s.service.endpoints": {},
    "k8s.ns.info": {
        "keepme": {"uid": "n1", "created": "2025-01-01T00:00:00Z",
                   "phase": "Active", "deletion_timestamp": None,
                   "keep": "whole namespace is deliberate"},
        "other": {"uid": "n2", "created": "2025-01-01T00:00:00Z",
                  "phase": "Active", "deletion_timestamp": None, "keep": None},
    },
    "k8s.deployment.templates": {}, "k8s.statefulset.templates": {},
}
b = bundle_with(pairs3, base())
housekeeping.derive(b, {}, now=NOW)
total = b["facts"]["k8s.housekeeping.total"]["value"]
kept = b["facts"]["k8s.housekeeping.kept"]["value"]
check("object annotation -> kept, excluded from the backlog",
      total == 1 and any(k["name"] == "named"
                         and k["keep_reason"] == "legacy dashboards"
                         for k in kept), (total, kept))


# --------------------------------------------------------------------------
print("\nhousekeeping.csv: golden columns and stable order")

csv_text = housekeeping.render_csv(
    [{"ns": "t", "kind": "PersistentVolumeClaim", "name": "data", "uid": "p1",
      "category": "pvc_unused", "confidence": "ask",
      "reason": "Bound, referenced by no pod, older than 7 days",
      "cost": "20.0 GiB", "first_seen": "2026-09-23T12:00:00Z",
      "age_days": 14, "tenant_ready": False}], [])
first = csv_text.splitlines()
check("csv header",
      first[0] == "namespace,kind,name,uid,category,confidence,reason,cost,"
                  "first_seen,age_days,tenant_ready,kept_reason,"
                  "proposed_command,age_source,created")
check("csv row values",
      first[1].startswith("t,PersistentVolumeClaim,data,p1,pvc_unused,ask,")
      and first[1].endswith(",seen,"), first[1])


# --------------------------------------------------------------------------
print("\nstate above 800 KiB is a WARN")

b = facts({"k8s.housekeeping.state_bytes": 900 * 1024})
fs = housekeeping.r_housekeeping_state_size(b)
check("state over the warn line",
      any(f["id"] == "KAREL_HOUSEKEEPING_STATE_LARGE" for f in fs), fs)
b = facts({"k8s.housekeeping.state_bytes": 100})
check("small state is silent", housekeeping.r_housekeeping_state_size(b) == [])


# --------------------------------------------------------------------------
print("\nfindings: INFO table, LB WARN, stuck-namespace WARN")

b = facts({
    "k8s.housekeeping.total": 412, "k8s.housekeeping.ns_count": 97,
    "k8s.housekeeping.kept_count": 2, "k8s.housekeeping.idle_services": 3,
    "k8s.housekeeping.tenant_ready_total": 150,
    "k8s.housekeeping.table": [["svc_no_backend", 300, 80, "30d", "", 100]],
    "k8s.housekeeping.lb_old": ["prod/legacy"],
    "k8s.housekeeping.ns_stuck": ["old-test"],
})
fs = housekeeping.r_housekeeping(b, {"k8s.housekeeping.total": 435.0})
hk = [f for f in fs if f["id"] == "K8S_HOUSEKEEPING"]
check("backlog line has the since-last-run delta",
      hk and "; -23 since the previous run" in hk[0]["title"], hk[0]["title"])
check("the summary table is attached to the section",
      hk and hk[0].get("section") == "Housekeeping" and hk[0].get("table"))
check("abandoned LB over a week -> WARN",
      any(f["id"] == "K8S_LB_IP_ABANDONED" and f["severity"] == "warn"
          for f in fs), fs)
check("stuck Terminating ns -> WARN",
      any(f["id"] == "K8S_NAMESPACE_STUCK_TERMINATING"
          and "old-test" in str(f["detail"]) for f in fs), fs)


# --------------------------------------------------------------------------
print("\nage semantics: transition times win, created is context, seen is the floor")

pairs4 = {
    "k8s.pvc.info": {},
    "k8s.pv.info": {
        # a PV whose phase flipped 40 days ago: tenant-ready on day ONE
        "pv-old": {"uid": "v-1", "size_bytes": 10 * 1024**3,
                   "created": "2024-01-01T00:00:00Z", "phase": "Released",
                   "last_transition": "2026-08-28T12:00:00Z", "keep": None},
        # one with NO transition recorded: falls back to Karel's first_seen
        "pv-2": {"uid": "v-2", "size_bytes": 10 * 1024**3,
                 "created": "2024-01-01T00:00:00Z", "phase": "Released",
                 "last_transition": None, "keep": None},
    },
    "k8s.service.names": ["old/orphan"],
    "k8s.service.info": {
        "old/orphan": {"uid": "so-1", "type": "ClusterIP", "selector": {},
                       "owner_kinds": [], "created": "2024-01-01T00:00:00Z",
                       "lb_ips": [], "keep": None},
    },
    "k8s.service.endpoints": {},
    "k8s.deployment.templates": {}, "k8s.statefulset.templates": {},
}
b = bundle_with(pairs4, base())
housekeeping.derive(b, {}, now=NOW)
items4 = {i["name"]: i for i in b["facts"]["k8s.housekeeping.items"]["value"]}
pv_old = items4["pv-old"]
check("a transition recorded 40 days ago ages 40 days on the FIRST run",
      pv_old["age_days"] == 40 and pv_old["age_source"] == "transition",
      (pv_old["age_days"], pv_old["age_source"]))
check("...and is tenant-ready immediately",
      pv_old["tenant_ready"] is True)
pv2 = items4["pv-2"]
check("no transition -> falls back to first_seen (age 0 today, not ready)",
      pv2["age_source"] == "seen" and pv2["age_days"] == 0
      and pv2["tenant_ready"] is False)
svc = items4["orphan"]
check("an object from 2024 shows created and seen side by side",
      svc["age_days"] == 0 and svc["age_source"] == "seen"
      and "2024" in (svc["created"] or ""), svc.get("created"))

csv2 = housekeeping.render_csv(
    [items4["orphan"]], [])
hdr = csv2.splitlines()[0]
check("csv gained age_source and created columns",
      hdr.endswith("age_source,created"))


# --------------------------------------------------------------------------
print("\ndemo workloads are grouped per namespace, matched by image")

demo_pairs = {
    "k8s.deployment.templates": {
        "Deployment:hello-1/web": {"replicas": 1, "labels": {},
                                   "images": ["paulbouwer/hello-kubernetes:1.9"],
                                   "created": "2025-05-01T00:00:00Z",
                                   "keep": None},
        "Deployment:other/app": {"replicas": 1, "labels": {},
                                 "images": ["registry/real-app:2.0"],
                                 "created": "2025-05-01T00:00:00Z",
                                 "keep": None},
    },
    "k8s.statefulset.templates": {},
    "k8s.service.info": {"hello-2/api": {"uid": "s1", "type": "ClusterIP",
                                          "selector": {}, "owner_kinds": [],
                                          "created": "2025-01-01T00:00:00Z",
                                          "lb_ips": [], "keep": None}},
    "k8s.service.names": ["hello-2/api"],
    "k8s.service.endpoints": {"hello-2/api": {"ready": 2, "total": 2}},
    "k8s.ingress.info": {"hello-2/web": {"uid": "i9", "hosts": ["h.example"],
                                          "backends": ["api"],
                                          "created": "2025-01-01T00:00:00Z",
                                          "keep": None}},
}
b = bundle_with(demo_pairs, base())
housekeeping.derive(b, {}, now=NOW)
demo = [i for i in b["facts"]["k8s.housekeeping.items"]["value"]
        if i["category"] == "demo_workload"]
check("image-matched namespace is a demo group item",
      [i["ns"] for i in demo] == ["hello-1"], demo)
check("the mismatch is stated (running, nothing exposing)",
      demo and "nothing exposes" in demo[0]["reason"], demo)
check("a namespace with only orphaned svc+ingress needs no image match"
      " - it is covered by the existing categories",
      not any(i["ns"] == "hello-2" and i["category"] == "demo_workload"
              for i in b["facts"]["k8s.housekeeping.items"]["value"]))


# --------------------------------------------------------------------------
print("\nday-over-day: a namespace that leaves and returns is a regression")

def hk_run(pairs_extra, prev_facts):
    pairs = dict(pairs2)
    pairs.update(pairs_extra)
    b = bundle_with(pairs, base())
    housekeeping.derive(b, {}, now=NOW, prev_facts=prev_facts)
    return b

orphan_svc = lambda n: {
    "k8s.service.info": {n: {"uid": "u-%s" % n, "type": "ClusterIP",
                             "selector": {}, "owner_kinds": [],
                             "created": "2020-01-01T00:00:00Z", "lb_ips": [],
                             "keep": None}},
    "k8s.service.names": [n],
}
b1 = hk_run(orphan_svc("gdi/web"), {})
fv1 = {k: v["value"] for k, v in b1["facts"].items()
       if "housekeeping.ns_set.svc_no_backend" in k
       or "ns_ever" in k or "ns_runs" in k}
check("first run records the namespace set",
      fv1.get("k8s.housekeeping.ns_set.svc_no_backend") == "gdi")

b2 = hk_run({}, fv1)
fv2 = {k: v["value"] for k, v in b2["facts"].items()
       if "housekeeping.ns_set.svc_no_backend" in k or "ns_ever" in k
       or "ns_runs" in k or "change.svc_no_backend" in k
       or ".count." in k}
check("second run: namespace gone, ever-set keeps its memory",
      fv2.get("k8s.housekeeping.ns_set.svc_no_backend") == ""
      and "gdi" in (fv2.get("k8s.housekeeping.ns_ever.svc_no_backend") or ""))

b3 = hk_run(orphan_svc("gdi/web"), fv2)
ch3 = b3["facts"]["k8s.housekeeping.change.svc_no_backend"]["value"]
check("third run: its return is a regression",
      ch3["regress"] == ["gdi"], ch3)
check("count and delta render", ch3["count"] == 1 and ch3["delta"] == 1, ch3)

run4 = hk_run(orphan_svc("gdi/web"), {k: v["value"] for k, v in b3["facts"].items()
                                      if "ns_" in k or ".count." in k})
ch4 = run4["facts"]["k8s.housekeeping.change.svc_no_backend"]["value"]
check("two consecutive runs of presence is persistence",
      ch4["persist"] == [("gdi", 2)], ch4)


finish()
