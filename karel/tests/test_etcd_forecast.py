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
    b = facts({})
    if now_gib is not None:
        b["facts"]["prom.etcd_db_size_now"] = {
            "value": now_gib * GIB, "source": "t"}
    if pred_gib is not None:
        b["facts"]["prom.etcd_db_predict_30d"] = {
            "value": pred_gib * GIB, "source": "t"}
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


print("\nprojection at the next compaction")

# 2 -> 5 GiB in 30d = 0.1 GiB/day; at compaction 2+0.1*7.6 = 2.76 = 69%: quiet
fs = normalize_prom.r_prom_forecasts(bundle(2.0, 5.0))
check("safe projection fires NOTHING (no false warn when the month fits)",
      fs == [], str([f["id"] for f in fs]))
# 2 -> 7.7 GiB in 30d = 0.19/d; quota in 10.5d > 7.6d, at compaction 86%: warn
fs = normalize_prom.r_prom_forecasts(bundle(2.0, 7.7))
h = find(fs, "K8S_ETCD_HIGH_AT_COMPACTION")
check(">= 85% projected at compaction warns, with the date in the detail",
      len(h) == 1 and h[0]["severity"] == "warn"
      and any("2026-11-01" in d for d in h[0]["detail"]),
      str(h and h[0]["title"]))


print("\nthe raw 30d line is a fallback for bundles without size_now")

fs = normalize_prom.r_prom_forecasts(bundle(None, 3.0))
fc = find(fs, "K8S_ETCD_FORECAST")
check("no size fact: legacy forecast still fires, annotated + framed as raw",
      len(fc) == 1
      and any("2026-11-01" in d and "upper bound" in d
              for d in fc[0]["detail"])
      and any("current db size unknown" in d for d in fc[0]["detail"]),
      str(fc and fc[0]["title"]))
check("size_now known: K8S_ETCD_FORECAST never fires",
      not find(normalize_prom.r_prom_forecasts(bundle(2.0, 7.7)),
               "K8S_ETCD_FORECAST"))
check("size_now alone, no forecast: no compaction math, no crash",
      not find(normalize_prom.r_prom_forecasts(bundle(3.0)),
               "K8S_ETCD_QUOTA_BEFORE_COMPACTION"))


finish()
