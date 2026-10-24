#!/usr/bin/env python3
"""nfs-csi PVCs live in one shared volume: N identical fullness rows are
ONE finding about the volume, local classes stay per-PVC."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import normalize_prom   # noqa: E402


def prom_pvc(nn, pct):
    ns, pvc = nn.split("/", 1)
    return {"labels": {"namespace": ns, "persistentvolumeclaim": pvc},
            "value": pct}


b = facts({
    "prom.pvc_used_pct_max": [
        prom_pvc("team-a/data-01", 97.8),
        prom_pvc("team-b/data-02", 95.5),
        prom_pvc("team-c/big-03", 96.2),
        prom_pvc("fast/local-ssd", 88.0),
        prom_pvc("fast/zfs-local", 92.1),
        prom_pvc("team-d/small-04", 60.0),     # below every warn line
        prom_pvc("team-e/mid-05", 90.0),       # nfs: 85-95 is silent now
    ],
    "k8s.pvc.storageclass_map": {
        "team-a/data-01": "nfs-csi",
        "team-b/data-02": "nfs-csi",
        "team-c/big-03": "nfs-csi-replicated",
        "fast/local-ssd": "zfs-csi",
        "fast/zfs-local": "zfs-csi",
        "team-d/small-04": "nfs-csi",
        "team-e/mid-05": "nfs-csi",
    },
    "k8s.storageclass.names": ["nfs-csi", "nfs-csi-replicated", "zfs-csi",
                               "beegfs-csi"],
})
fs = normalize_prom.r_prom_peaks(b)
near = [f for f in fs if f["id"].startswith("K8S_PVC_NEARFULL")]
shared = [f for f in near if f["id"] == "K8S_PVC_NEARFULL:nfs-csi-shared"]
check("nfs-csi rows collapse into ONE shared-volume finding",
      len(shared) == 1, [f["id"] for f in fs])
check("it names the shared cause, with the spread in the detail",
      shared and "shared nfs-csi volume" in shared[0]["title"]
      and any("95.5%" in d and "97.8%" in d for d in shared[0]["detail"]),
      shared and shared[0]["title"])
check("nfs rows in 85..95 no longer fire (95% nfs warn line)",
      shared[0]["metric"] == 3.0, shared[0]["metric"])
check("max >= 97% makes the shared finding critical",
      shared[0]["severity"] == "crit", shared[0]["severity"])
local = [f for f in near if f["id"] == "K8S_PVC_NEARFULL"]
check("local-class PVCs keep their per-PVC entries at the 85% line",
      len(local) == 1 and local[0]["severity"] == "warn"
      and any("zfs-local" in d for d in local[0]["detail"])
      and any("local-ssd" in d for d in local[0]["detail"]), local)


# --------------------------------------------------------------------------
print("\nnfs peak in 95..97 stays a warning, not a critical")

b3 = facts({
    "prom.pvc_used_pct_max": [prom_pvc("t/a", 95.5), prom_pvc("t/b", 96.9)],
    "k8s.pvc.storageclass_map": {"t/a": "nfs-csi", "t/b": "nfs-csi"},
    "k8s.storageclass.names": ["nfs-csi"],
})
s3 = [f for f in normalize_prom.r_prom_peaks(b3)
      if f["id"] == "K8S_PVC_NEARFULL:nfs-csi-shared"]
check("95-97% shared volume is warn",
      len(s3) == 1 and s3[0]["severity"] == "warn"
      and "critical mark" not in s3[0]["title"],
      str(s3[0]["title"]) if s3 else "no shared finding")


# --------------------------------------------------------------------------
print("\nwithout the class map (old bundle), every row stays per-PVC")

b2 = facts({"prom.pvc_used_pct_max": [prom_pvc("a/x", 91.0),
                                      prom_pvc("b/y", 92.0)]})
fs2 = normalize_prom.r_prom_peaks(b2)
check("no map -> no grouping, no false 'shared volume' claim",
      [f["id"] for f in fs2 if f["id"].startswith("K8S_PVC_NEARFULL")]
      == ["K8S_PVC_NEARFULL"], fs2)


finish()
