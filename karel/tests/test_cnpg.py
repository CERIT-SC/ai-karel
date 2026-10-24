#!/usr/bin/env python3
"""CloudNativePG cluster health checks: unhealthy clusters are findings,
a healthy fleet is one line, an absent CRD is a cannot-see note."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import normalize        # noqa: E402
import normalize_k8s    # noqa: E402
import rules_k8s        # noqa: E402

CLUSTERS = {"items": [
    {"metadata": {"namespace": "apps", "name": "pg-ok"},
     "spec": {"instances": 3},
     "status": {"phase": "Cluster in healthy state", "instances": 3,
                "readyInstances": 3,
                "conditions": [{"type": "Ready", "status": "True",
                                "reason": "ClusterIsReady"}]}},
    {"metadata": {"namespace": "apps", "name": "pg-degraded"},
     "spec": {"instances": 3},
     "status": {"phase": "Cluster in healthy state", "instances": 3,
                "readyInstances": 2,
                "conditions": [{"type": "Ready", "status": "False",
                                "reason": "ReplicaNotReady"}]}},
    {"metadata": {"namespace": "apps", "name": "pg-down"},
     "spec": {"instances": 2},
     "status": {"phase": "Failing over", "instances": 2,
                "readyInstances": 0,
                "conditions": [{"type": "Ready", "status": "False",
                                "reason": "ClusterIsNotReady"}]}},
    # a cluster the operator has not reconciled yet: no status at all -
    # absent is not bad, so it must not be flagged
    {"metadata": {"namespace": "apps", "name": "pg-just-created"},
     "spec": {"instances": 1}},
]}

F = normalize.Facts()
normalize_k8s.p_cnpg_clusters(CLUSTERS, F, "k_cnpg_clusters")
pairs = {k: v["value"] for k, v in F.items()}
b = facts(pairs)
b["collection"]["commands"] = {"k_cnpg_clusters": {"status": "ok"}}

fs = rules_k8s.r_cnpg(b)
ids = [(f["id"], f["severity"]) for f in fs]
check("degraded cluster is WARN naming the shortfall",
      any(f["id"] == "K8S_CNPG_CLUSTER_UNHEALTHY:apps/pg-degraded"
          and f["severity"] == "warn"
          and any("2 of 3 instances ready" in d for d in f["detail"])
          for f in fs), ids)
check("cluster with zero ready instances is CRIT naming the phase",
      any(f["id"] == "K8S_CNPG_CLUSTER_UNHEALTHY:apps/pg-down"
          and f["severity"] == "crit"
          and any("Failing over" in d for d in f["detail"])
          for f in fs), ids)
check("healthy cluster does not alarm", not any(
    f["id"] == "K8S_CNPG_CLUSTER_UNHEALTHY:apps/pg-ok" for f in fs), ids)
check("status-less cluster is not blamed (missing is absent, not bad)",
      not any(f["id"] == "K8S_CNPG_CLUSTER_UNHEALTHY:apps/pg-just-created"
              for f in fs), ids)
check("no clean line while any cluster is unhealthy",
      not any(f["id"] == "K8S_CNPG_HEALTHY" for f in fs), ids)
check("every unhealthy cluster is a finding of its own",
      sorted(f["id"] for f in fs)
      == ["K8S_CNPG_CLUSTER_UNHEALTHY:apps/pg-degraded",
          "K8S_CNPG_CLUSTER_UNHEALTHY:apps/pg-down"], ids)

print("\nall healthy gives the one-liner; absent CRD is a cannot-see note")

F2 = normalize.Facts()
normalize_k8s.p_cnpg_clusters({"items": [CLUSTERS["items"][0]]}, F2,
                              "k_cnpg_clusters")
b2 = facts({k: v["value"] for k, v in F2.items()})
b2["collection"]["commands"] = {"k_cnpg_clusters": {"status": "ok"}}
fs2 = rules_k8s.r_cnpg(b2)
check("healthy one-liner",
      any(f["id"] == "K8S_CNPG_HEALTHY"
          and f["title"] == "1 CNPG clusters, all healthy"
          for f in fs2), fs2)

b3 = facts({})
b3["collection"]["commands"] = {
    "k_cnpg_clusters": {"status": "eacces", "expected": "eacces"}}
fs3 = rules_k8s.r_cnpg(b3)
check("absent CRD is a quiet cannot-see note, not a WARN",
      fs3 and fs3[0]["id"] == "KAREL_CNPG_CRD_ABSENT"
      and fs3[0]["severity"] == "info", fs3)

b4 = facts({})
b4["collection"]["commands"] = {
    "k_cnpg_clusters": {"status": "failed", "expected": "ok"}}
fs4 = rules_k8s.r_cnpg(b4)
check("an unexpected failure is the collector's finding, not the CNPG rule's",
      fs4 == [], fs4)


finish()
