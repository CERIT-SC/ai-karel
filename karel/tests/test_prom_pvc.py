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
        prom_pvc("team-a/data-01", 89.0),
        prom_pvc("team-b/data-02", 88.2),
        prom_pvc("team-c/big-03", 90.5),
        prom_pvc("fast/local-ssd", 88.0),
        prom_pvc("fast/zfs-local", 92.1),
        prom_pvc("team-d/small-04", 60.0),     # below the 85% warn line
    ],
    "k8s.pvc.storageclass_map": {
        "team-a/data-01": "nfs-csi",
        "team-b/data-02": "nfs-csi",
        "team-c/big-03": "nfs-csi-replicated",
        "fast/local-ssd": "zfs-csi",
        "fast/zfs-local": "zfs-csi",
        "team-d/small-04": "nfs-csi",
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
      and any("88.2%" in d and "90.5%" in d for d in shared[0]["detail"]),
      shared and shared[0]["title"])
check("all nfs-csi classes are caught by the prefix family",
      shared[0]["metric"] == 3.0, shared[0]["metric"])
local = [f for f in near if f["id"] == "K8S_PVC_NEARFULL"]
check("local-class PVCs keep their per-PVC entries",
      len(local) == 1 and any("zfs-local" in d for d in local[0]["detail"])
      and any("local-ssd" in d for d in local[0]["detail"]), local)


# --------------------------------------------------------------------------
print("\nwithout the class map (old bundle), every row stays per-PVC")

b2 = facts({"prom.pvc_used_pct_max": [prom_pvc("a/x", 91.0),
                                      prom_pvc("b/y", 92.0)]})
fs2 = normalize_prom.r_prom_peaks(b2)
check("no map -> no grouping, no false 'shared volume' claim",
      [f["id"] for f in fs2 if f["id"].startswith("K8S_PVC_NEARFULL")]
      == ["K8S_PVC_NEARFULL"], fs2)


finish()
