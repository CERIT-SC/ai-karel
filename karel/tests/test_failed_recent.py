#!/usr/bin/env python3
"""P0: recent Failed pods land in the tenant table, grouped; old ones move
to housekeeping; never in both."""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import normalize        # noqa: E402
import normalize_k8s    # noqa: E402
import rules_k8s        # noqa: E402
import housekeeping     # noqa: E402
import scope            # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)


def _ago(hours):
    return (NOW - datetime.timedelta(hours=hours)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")


def failed_pod(name, ns, owner_kind, owner_name, reason, hours=0, days=0):
    return {
        "metadata": {"namespace": ns, "name": name,
                     "creationTimestamp": _ago(days * 24 + hours),
                     "ownerReferences": [{"kind": owner_kind,
                                          "name": owner_name}]},
        "spec": {"containers": [{"name": "c", "resources": {}}]},
        "status": {"phase": "Failed",
                   "containerStatuses": [{
                       "name": "c",
                       "state": {"terminated": {
                           "reason": reason, "exitCode": 1,
                           "finishedAt": _ago(days * 24 + hours)}}}]}}


# 704 Failed pods from one Job array, 2 days old, one namespace
items = [failed_pod("c-scale-repro-challenge-%05d" % i, "c-scale-ns",
                    "Job", "c-scale-repro-challenge",
                    "Error", hours=48) for i in range(704)]
# ...and one 10-day-old pod in another namespace
items.append(failed_pod("old-job-1", "other-ns", "Job", "old-job",
                        "Error", hours=24, days=10))

F = normalize.Facts()
normalize_k8s.p_pods({"items": items}, F, "k_pods")

check("grouped as one entry per owner+reason, not 704",
      len(F.get_value("k8s.pod.failed_recent_groups") or {}) == 1)
check("the pod total is still exact",
      F.get_value("k8s.pod.failed_recent_count") == 704)
check("namespace counts exact", (F.get_value("k8s.pod.failed_recent_by_ns")
      or {}).get("c-scale-ns") == 704)

b = facts({k: v["value"] for k, v in F.items() if "_by_ns" in k
           or k.endswith("_count") or k.startswith("k8s.pod.failed")})
scope.derive(b)
fs = rules_k8s.r_tenant_summary(b)
rows = fs[0]["table"]["rows"]
row = [r for r in rows if r[0] == "pods Failed (last 7 days)"]
check("one tenant row for the whole array", len(row) == 1, rows)
check("row names the Job array in most-affected",
      row and "c-scale-repro-challenge (704)" in row[0][3], row)

# housekeeping sees only the 10-day-old one
hk_items_bundle = facts({k: v["value"] for k, v in F.items()})
hk_items_bundle["facts"]["k8s.ns.info"] = {
    "value": {"c-scale-ns": {"uid": "n1", "created": "2025-01-01T00:00:00Z",
                             "phase": "Active", "keep": None}}, "source": "t"}
hk_items_bundle["collected_at"] = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
housekeeping.derive(hk_items_bundle, {}, now=NOW)
hk = hk_items_bundle["facts"]["k8s.housekeeping.items"]["value"]
old_items = [i for i in hk if i["category"] == "failed_pods_old"]
check("the 10-day pod is failed_pods_old",
      old_items and old_items[0]["ns"] == "other-ns", old_items)
check("the recent array is not in housekeeping yet",
      not any(i["ns"] == "c-scale-ns" for i in hk if
              i["category"] == "failed_pods_old"))


finish()
