#!/usr/bin/env python3
"""etcd snapshot staleness: local and S3 copies are independent clocks,
and only the k3s.cattle.io snapshotfile CRs prove either of them."""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import normalize        # noqa: E402
import normalize_k8s    # noqa: E402
import rules_k8s        # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)


def _ts(age_h):
    return ((NOW - datetime.timedelta(hours=age_h))
            .strftime("%Y-%m-%dT%H:%M:%SZ"))


def snap(node, kind, age_h):
    loc = "s3://bucket/etcd/node" if kind == "s3" else \
        "file:///var/lib/rancher/rke2/server/db/snapshots/x"
    return {"metadata": {"name": "%s-etcd-snapshot-%s-%d" % (kind, node, age_h * 100),
                         "creationTimestamp": _ts(age_h)},
            "spec": {"nodeName": node, "location": loc,
                     "snapshotName": "etcd-snapshot-%s" % node},
            "status": {"size": 1600000000}}


def etcd_bundle(items, extra=None):
    F = normalize.Facts()
    normalize_k8s.p_etcd_snapshots({"items": items}, F, "k_etcd_snapshots")
    pairs = {k: v["value"] for k, v in F.items()}
    if extra:
        pairs.update(extra)
    return facts(pairs)


FRESH = [snap("a5", "local", 0.3), snap("a5", "s3", 0.3),
         snap("a6", "local", 0.7), snap("a6", "s3", 0.7),
         snolder := snap("a6", "s3", 2.7), snap("a7", "local", 1.2),
         snap("a7", "s3", 1.2)]

b = etcd_bundle(FRESH, {"k8s.controlplane.etcd_nodes":
                        ["a5", "a6", "a7"]})
fs = rules_k8s.r_etcd_snapshot(b)
check("fresh snapshot cycle on all nodes -> healthy one-liner",
      any(f["id"] == "K8S_ETCD_SNAPSHOTS_HEALTHY" for f in fs), fs)
check("cadence detected near the 2 h schedule",
      1.0 <= (b["facts"]["k8s.etcd.snapshot_cadence_h"]["value"] or 99) <= 3.0,
      b["facts"]["k8s.etcd.snapshot_cadence_h"]["value"])


# --------------------------------------------------------------------------
print("\nS3 rot is flagged independently of healthy local copies")

ROTTEN = [snap("a5", "local", 0.3),          # local fresh
          snap("a5", "s3", 26),              # S3 last a day ago
          snap("a6", "local", 0.5), snap("a6", "s3", 0.6)]
b = etcd_bundle(ROTTEN, {"k8s.controlplane.etcd_nodes": ["a5", "a6"]})
fs = rules_k8s.r_etcd_snapshot(b)
check("stale S3 with fresh local -> K8S_ETCD_SNAPSHOT_S3_STALE",
      any(f["id"] == "K8S_ETCD_SNAPSHOT_S3_STALE"
          and f["severity"] == "warn"
          and f.get("escalate_after_days") == 2
          and any("a5" in d for d in f["detail"]) for f in fs), fs)
check("local backups still healthy on the rotten run",
      not rules_k8s.r_etcd_snapshot(etcd_bundle(
          [snap("a5", "local", 0.3), snap("a5", "s3", 26),
           snap("a6", "local", 0.5), snap("a6", "s3", 0.6)]))[0]["id"]
      .startswith("K8S_ETCD_SNAPSHOT_STALE"))


# --------------------------------------------------------------------------
print("\nno S3 record at all, and a node with no records")

b = etcd_bundle([snap("a5", "local", 0.5)],
                {"k8s.controlplane.etcd_nodes": ["a5", "a6"]})
fs = rules_k8s.r_etcd_snapshot(b)
check("local-only counts as S3-stale",
      any(f["id"] == "K8S_ETCD_SNAPSHOT_S3_STALE"
          and any("never any S3" in d for d in f["detail"]) for f in fs), fs)
check("an etcd node with zero records is named on both",
      any(f["id"] == "K8S_ETCD_SNAPSHOT_STALE"
          and any("a6" in d for d in f["detail"]) for f in fs)
      and any(f["id"] == "K8S_ETCD_SNAPSHOT_S3_STALE"
              and any("a6" in d for d in f["detail"]) for f in fs), fs)


# --------------------------------------------------------------------------
print("\nno snapshot CRD here stays silent (absent is not zero)")

check("no facts -> no findings",
      rules_k8s.r_etcd_snapshot(facts({})) == [])


finish()
