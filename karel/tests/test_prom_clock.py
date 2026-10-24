#!/usr/bin/env python3
"""Clock truth: Alertmanager/Karel skew and node timex drift are findings,
small offsets are silence."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import normalize_prom   # noqa: E402


def bundle(skew=None, timex=None):
    b = facts({})
    if skew is not None:
        b["facts"]["prom.alerts_clock_skew_seconds"] = {
            "value": skew, "source": "t"}
    if timex is not None:
        b["facts"]["prom.node_timex_offset_max"] = {
            "value": timex, "source": "t"}
    return b


fs = normalize_prom.r_prom_clock(bundle())
check("no facts: no findings, no crash", fs == [])

fs = normalize_prom.r_prom_clock(bundle(0, 0.001))
check("aligned clocks are silent", fs == [])

fs = normalize_prom.r_prom_clock(bundle(540, 0.001))
check("alertmanager 9 minutes ahead warns, timex quoted in the detail",
      [f["id"] for f in fs] == ["K8S_ALERTMGR_CLOCK_SKEW"]
      and any("0.001" in d for d in fs[0]["detail"]),
      str([f["id"] for f in fs]))

fs = normalize_prom.r_prom_clock(bundle(-4000))
check("a large negative skew is caught too",
      [f["id"] for f in fs] == ["K8S_ALERTMGR_CLOCK_SKEW"])

fs = normalize_prom.r_prom_clock(bundle(0, 2.5))
check("2.5 s kernel offset warns on the node clock",
      [f["id"] for f in fs] == ["K8S_NODE_CLOCK_SKEW"],
      str([f["id"] for f in fs]))

finish()
