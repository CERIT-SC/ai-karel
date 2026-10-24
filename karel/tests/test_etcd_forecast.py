#!/usr/bin/env python3
"""etcd is compacted on the 1st of each month: the threat is the quota being
reached BEFORE the next compaction, not the raw 30d forecast line."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import normalize_prom   # noqa: E402

GIB = 1024 ** 3


def bundle(now_gib, pred_gib=None, ts="2026-10-24T09:00:00Z"):
    b = facts({
        "prom.etcd_db_size_now": now_gib * GIB,
        "prom.etcd_db_predict_30d": (pred_gib * GIB) if pred_gib else None,
    })
    if pred_gib is None:
        b["facts"].pop("prom.etcd_db_predict_30d")
    b["collected_at"] = ts
    return b


def find(fs, code):
    return [f for f in fs if f["id"] == code]


# collected 2026-10-24: next compaction 2026-11-01, ~7.6 days away
print("current size critical at 85% of quota")

fs = normalize_prom.r_prom_forecasts(bundle(3.6))
check(">= 85% of quota fires K8S_ETCD_NEAR_QUOTA as crit",
      [f["severity"] for f in find(fs, "K8S_ETCD_NEAR_QUOTA")] == ["crit"], fs)
check("below 85% no near-quota finding",
      not find(normalize_prom.r_prom_forecasts(bundle(3.3)),
               "K8S_ETCD_NEAR_QUOTA"))


print("\ngrowth hitting the quota before the monthly compaction")

# 2 -> 5 GiB in 30d = 0.1 GiB/day; (4-2)/0.1 = 20d to quota > 7.6d: safe
fs = normalize_prom.r_prom_forecasts(bundle(2.0, 5.0))
check("slow growth does not warn before compaction",
      not find(fs, "K8S_ETCD_QUOTA_BEFORE_COMPACTION"), str([f["id"] for f in fs]))
# 3 -> 15 GiB in 30d = 0.4 GiB/day; (4-3)/0.4 = 2.5d < 7.6d: warn
fs = normalize_prom.r_prom_forecasts(bundle(3.0, 15.0))
q = find(fs, "K8S_ETCD_QUOTA_BEFORE_COMPACTION")
check("quota before compaction warns, with the dates in the detail",
      len(q) == 1 and q[0]["severity"] == "warn"
      and any("2026-11-01" in d for d in q[0]["detail"]),
      q and q[0]["title"])
# shrinking database never threatens
check("no growth, no compaction warning",
      not find(normalize_prom.r_prom_forecasts(bundle(2.0, 1.0)),
               "K8S_ETCD_QUOTA_BEFORE_COMPACTION"))


print("\nthe plain 30d forecast line stays, annotated with the compaction date")

fs = normalize_prom.r_prom_forecasts(bundle(3.0, 15.0))
fc = find(fs, "K8S_ETCD_FORECAST")
check(">= 60% forecast still fires and names the next compaction",
      len(fc) == 1
      and any("2026-11-01" in d and "upper bound" in d
              for d in fc[0]["detail"]), fc and fc[0]["title"])
check("size_now alone, no forecast: no compaction math, no crash",
      not find(normalize_prom.r_prom_forecasts(bundle(3.0)),
               "K8S_ETCD_QUOTA_BEFORE_COMPACTION"))


finish()
