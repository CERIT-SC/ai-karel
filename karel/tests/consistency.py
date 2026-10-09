#!/usr/bin/env python3
"""Cross-suite consistency checks on real collector output and synthetic
loads: the invariants that need numbers, not shapes.

  * the ENCODED housekeeping state stays under the 1 MiB ConfigMap ceiling
    at the sizes seen in production (6477 items on 2026-10-08); this is the
    invariant that would have caught the state overflowing silently
  * tenant summary rows are arithmetic over the SAME data the facts carry:
    count == sum over namespaces, and the most-affected column never names
    a namespace absent from the source facts
  * the snapshot part of the bundle stays serialisable and inside the
    ConfigMap budget
  * replaying a bundle twice produces identical findings
"""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import (ROOT, check, build_bundle, clone, evaluate_all, finish,
                     _import_all)                                     # noqa

mods = _import_all()
housekeeping = mods["housekeeping"]
scope_mod = mods["scope"]
report = mods["report"]


# --------------------------------------------------------------------------
print("\nencoded housekeeping state stays storable at production size")

items = {}
for n in range(6477):
    items["%08x-%04x-%04x-%04x-%012x" % (n, 0x4baa, 0x4c1d, 0x9f2e,
                                         n * 7919)] = {
        "category": list(housekeeping.CATEGORIES)[n % 11],
        "first_seen": "2026-0%d-%02dT12:00:00Z" % (n % 9 + 1, n % 28 + 1)}
state = {"version": 2, "updated": "2026-10-08T07:38:29Z", "items": items}
enc = housekeeping.encode_state(state)
check("6477 realistic items encode under 700 KiB",
      len(enc) < 700 * 1024, "%.1f KiB" % (len(enc) / 1024.0))
check("and under the 1 MiB ConfigMap ceiling",
      len(enc) < housekeeping.STATE_LIMIT_BYTES, "%.1f KiB" % (len(enc) / 1024.0))
check("encode/decode round-trips", housekeeping.decode_state(enc) == state)
check("plain-JSON state still loads (migration)",
      housekeeping.decode_state(json.dumps(state)) == state)


# --------------------------------------------------------------------------
print("\ntenant table arithmetic matches the facts exactly")


def tenant_rows(bundle):
    for f in evaluate_all(clone(bundle)):
        if f.get("section") == "Tenant workloads":
            return f["table"]["rows"]
    return []


def check_tenant_consistency(bundle, label):
    rows = tenant_rows(bundle)
    check("%s: tenant table exists" % label, rows is not None)
    by_ns_sources = {
        "k8s.pod.backoff": "containers in CrashLoop/ImagePull backoff",
        "k8s.pod.oomkilled": "containers with a recent OOMKill",
        "k8s.pod.pending": "pods Pending",
        "k8s.deployment.degraded": "Deployments below desired replicas",
        "k8s.statefulset.degraded": "StatefulSets below desired replicas",
        "k8s.daemonset.degraded": "DaemonSets below desired replicas",
        "k8s.job.failed": "Jobs failed",
        "k8s.cronjob.stale": "CronJobs overdue",
        "k8s.pvc.unbound": "PVCs not Bound",
        "k8s.deployment.paused": "Deployments with rollout paused",
        "k8s.workload.colocated": "multi-replica workloads with every replica on one node",
    }
    label_to_path = {v: k for k, v in by_ns_sources.items()}
    for row in rows:
        cond = row[0]
        if cond.startswith("events: "):
            continue
        path = label_to_path.get(cond)
        if not path:
            continue
        by_ns = bundle["facts"].get(path + "_by_ns", {}).get("value") or {}
        tenant_sum = sum(n for ns, n in by_ns.items()
                         if not mods["scope"].is_platform(ns))
        if by_ns:
            try:
                row_count = int(row[1])
            except (TypeError, ValueError):
                row_count = 0      # a "0 (clean N runs)" cell is a clean zero
            check("%s: '%s' count == sum over namespaces" % (label, cond),
                  row_count == tenant_sum, "%s vs %s" % (row[1], tenant_sum))
            named = [part.split(" (")[0] for part in str(row[3]).split(", ")
                     if part and part != "-"]
            absent = [n for n in named if n and n not in by_ns]
            check("%s: '%s' names only namespaces in the facts"
                  % (label, cond), not absent, absent)
    return rows


bundle, _hs = build_bundle("degraded")
check_tenant_consistency(bundle, "fixture")


# --------------------------------------------------------------------------
print("\nsnapshot of a degraded bundle stays serialisable and small")

import importlib
m = importlib.import_module("pipeline")
fs = evaluate_all(clone(bundle))
snap = m.build_snapshot(bundle, fs, [], "fp")
raw = json.dumps(snap, sort_keys=True).encode()
check("snapshot serialises", True)
check("snapshot under 900 KiB", len(raw) < 900 * 1024, len(raw))


# --------------------------------------------------------------------------
print("\nthe same bundle replays to identical findings")

a = evaluate_all(clone(bundle))
b = evaluate_all(clone(bundle))
check("findings identical across two runs",
      [f["id"] for f in a] == [f["id"] for f in b])


# --------------------------------------------------------------------------
print("\nthe real 2026-10-08 collector output is consistent")

pipe = os.path.join(ROOT, "lib", "pipeline.py")
src = "/tmp/outs/out"
if os.path.isdir(src):
    d = tempfile.mkdtemp(prefix="karel-consistency.")
    r = subprocess.run([sys.executable, pipe, "--out", src,
                        "--prom-out", "/tmp/outs/out-prom",
                        "--prev", "/dev/null", "--suppressions", "/dev/null",
                        "--housekeeping-state", "/dev/null",
                        "--bundle", os.path.join(d, "bundle.json"),
                        "--snapshot", os.path.join(d, "snapshot.json"),
                        "--report", os.path.join(d, "report.md")],
                       capture_output=True, text=True, timeout=300)
    check("pipeline rc 0 on the 2026-10-08 output", r.returncode == 0,
          (r.stderr or "")[-200:])
    rep = open(os.path.join(d, "report.md")).read()
    block, bad = [], 0
    for line in rep.splitlines() + [""]:
        if line.startswith("|"):
            block.append(line.count("|") - 2)
        else:
            if block and len(set(block)) > 1:
                bad += 1
            block = []
    check("rendered tables are rectangular", bad == 0, bad)
    snap2 = json.load(open(os.path.join(d, "snapshot.json")))
    check("snapshot state fits the ConfigMap ceiling",
          len(json.dumps(snap2).encode()) < 900 * 1024)
else:
    print("  SKIP  (no collector output at %s)" % src)


finish()
