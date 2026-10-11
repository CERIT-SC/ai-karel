#!/usr/bin/env python3
"""Tests for GPU health collection and rules, and the node-versions table."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import normalize        # noqa: E402
import normalize_k8s    # noqa: E402
import rules_gpu        # noqa: E402
import rules_k8s        # noqa: E402


def node_obj(name, cap=None, alloc=None, labels=None):
    return {"metadata": {"name": name, "labels": labels or {}},
            "status": {
                "capacity": dict(cap or {}, **{"cpu": "8", "memory": "64Gi",
                                               "pods": "110"}),
                "allocatable": dict(alloc or {}, **{"cpu": "7800m",
                                                    "memory": "60Gi",
                                                    "pods": "110"}),
                "conditions": [{"type": "Ready", "status": "True"}],
                "nodeInfo": {"kubeletVersion": "v1.35.6+rke2r1",
                             "osImage": "Ubuntu 24.04.2 LTS",
                             "kernelVersion": "6.8.0-51-generic",
                             "containerRuntimeVersion": "containerd://2.0.5"},
            }}


GPU_L = {"nvidia.com/gpu.present": "true",
         "nvidia.com/gpu.product": "NVIDIA-H100",
         "nvidia.com/cuda.driver-version.full": "550.90.07"}


# --------------------------------------------------------------------------
print("\nGPU health: allocatable below capacity, zero advertised, the 25% bar")

F = normalize.Facts()
normalize_k8s.p_nodes({"items": [
    node_obj("gpu-01", {"nvidia.com/gpu": "8"}, {"nvidia.com/gpu": "7"}, GPU_L),
    node_obj("gpu-02", {"nvidia.com/gpu": "8"}, {"nvidia.com/gpu": "8"}, GPU_L),
    node_obj("gpu-03", {}, {}, GPU_L),
    node_obj("gpu-04", {"nvidia.com/gpu": "8"}, {"nvidia.com/gpu": "8"}, GPU_L),
    node_obj("gpu-05", {"nvidia.com/gpu": "8"}, {"nvidia.com/gpu": "8"}, GPU_L),
    node_obj("cpu-01", {}, {}, {}),
]}, F, "k_nodes")
gn = F.get_value("k8s.node.gpu_nodes", [])
check("GPU nodes are detected from capacity OR labels",
      set(gn) == {"gpu-01", "gpu-02", "gpu-03", "gpu-04", "gpu-05"}, gn)

b = facts({k: v["value"] for k, v in F.items()})
fs = rules_gpu.r_gpu_health(b)
check("allocatable 7 of 8 -> K8S_GPU_UNHEALTHY warn",
      any(f["id"] == "K8S_GPU_UNHEALTHY" and f["severity"] == "warn"
          and "gpu-01" in str(f["detail"]) for f in fs), fs)
check("GPU-labelled node with no resource -> K8S_GPU_NOT_ADVERTISED",
      any(f["id"] == "K8S_GPU_NOT_ADVERTISED" and "gpu-03" in str(f["detail"])
          for f in fs), fs)
crit = [f for f in fs if f["id"] == "K8S_GPU_NOT_ADVERTISED"
        and f["severity"] == "crit"]
check("1 of 5 GPU nodes dark is under the 25% bar (WARN, not CRIT)", not crit)

F2 = normalize.Facts()
normalize_k8s.p_nodes({"items": [
    node_obj("gpu-01", {}, {}, GPU_L), node_obj("gpu-02", {}, {}, GPU_L),
    node_obj("gpu-03", {"nvidia.com/gpu": "8"}, {"nvidia.com/gpu": "8"}, GPU_L)]},
    F2, "k_nodes")
fs = rules_gpu.r_gpu_health(facts({k: v["value"] for k, v in F2.items()}))
check("2 of 3 GPU nodes dark -> CRIT",
      any(f["id"] == "K8S_GPU_NOT_ADVERTISED" and f["severity"] == "crit"
          for f in fs), fs)


# --------------------------------------------------------------------------
print("\nold and new driver-version label schemes agree")

old = dict(GPU_L)
del old["nvidia.com/cuda.driver-version.full"]
old.update({"nvidia.com/cuda.driver.major": "550",
            "nvidia.com/cuda.driver.minor": "90",
            "nvidia.com/cuda.driver.rev": "07"})
check("both schemes parse to the same version",
      normalize_k8s._gpu_driver_version(GPU_L)
      == normalize_k8s._gpu_driver_version(old) == "550.90.07")


# --------------------------------------------------------------------------
print("\ndriver_mismatch: one GPU finding, no separate backoff/DaemonSet entries")

pods = {"items": [{
    "metadata": {"namespace": "gpu-operator", "name": "nvidia-dcgm-exporter-abcde",
                 "ownerReferences": [{"kind": "DaemonSet",
                                      "name": "nvidia-dcgm-exporter"}]},
    "spec": {"nodeName": "gpu-01",
             "containers": [{"name": "dcgm", "resources": {}}]},
    "status": {"phase": "Running",
               "conditions": [{"type": "Ready", "status": "False"}],
               "containerStatuses": [
                   {"name": "dcgm", "restartCount": 14,
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}}]}
F = normalize.Facts()
normalize_k8s.p_pods(pods, F, "k_pods")
p = F.get_value("k8s.pod.gpu_operator_by_node", {})
check("gpu-operator pod health is per node",
      p.get("gpu-01", {}).get("waiting_reason") == "CrashLoopBackOff", p)

b = facts({k: v["value"] for k, v in F.items()})
b["facts"].update({k: {"value": v, "source": "t"} for k, v in {
    "k8s.log.gpu_crash.class.driver_mismatch": {"kind": "error", "count": 3},
    "k8s.node.gpu_nodes": ["gpu-01"],
    "k8s.node.gpu": {"gpu-01": {"nvidia.com/gpu": {"capacity": 8,
                                                   "allocatable": 8}}},
    "k8s.node.names": ["gpu-01"],
}.items()})
rules_gpu.derive(b)
import scope     # noqa: E402
scope.derive(b)
fs = rules_gpu.r_gpu_health(b)
stk = [f for f in fs if f["id"].startswith("K8S_GPU_STACK_DEGRADED")]
check("K8S_GPU_STACK_DEGRADED with the reboot cause named",
      len(stk) == 1 and "reboot required" in str(stk[0]["detail"])
      and "reboot required" in stk[0]["title"], fs)

fs2 = rules_k8s.r_workloads(b)
check("the gpu-operator pod is NOT a second backoff finding",
      not any(f["id"] == "K8S_PODS_BACKOFF" for f in fs2), fs2)
check("nor a second degraded-DaemonSet finding",
      not any(f["id"].startswith("K8S_WORKLOAD_DEGRADED") for f in fs2), fs2)


# --------------------------------------------------------------------------
print("\nno ClusterPolicy CRD (or no GPUs) -> no operator finding")

b = facts({})
check("no GPU facts at all -> completely silent", rules_gpu.r_gpu_health(b) == [])
b = facts({"k8s.node.gpu_nodes": ["gpu-01"],
           "k8s.node.gpu": {"gpu-01": {"nvidia.com/gpu": {"capacity": 8,
                                                          "allocatable": 8}}}})
check("GPU nodes but no clusterpolicy fact -> no NOT_READY finding",
      not any(f["id"] == "K8S_GPU_OPERATOR_NOT_READY"
              for f in rules_gpu.r_gpu_health(b)))
b["facts"]["k8s.gpu.clusterpolicy_states"] = {
    "value": {"gpu-cluster-policy": "notReady"}, "source": "t"}
check("clusterpolicy notReady -> WARN",
      any(f["id"] == "K8S_GPU_OPERATOR_NOT_READY"
          for f in rules_gpu.r_gpu_health(b)))


# --------------------------------------------------------------------------
print("\nnode versions: majority is the target, KAREL_NODE_TARGETS overrides")

F = normalize.Facts()
nodes = [node_obj("n%d" % i) for i in range(1, 4)]
nodes[2]["status"]["nodeInfo"]["kernelVersion"] = "6.8.0-49-generic"
normalize_k8s.p_nodes({"items": nodes}, F, "k_nodes")
b = facts({k: v["value"] for k, v in F.items()})
fs = rules_gpu.r_node_versions(b)
check("a node-versions section is produced once", len(fs) == 1
      and fs[0].get("section") == "Node versions", len(fs))
kernel = [r for r in fs[0]["table"]["rows"] if r[0] == "kernel"]
check("behind lists the laggard"
      , kernel and "n3" in kernel[0][2] and len(kernel) == 1, fs[0]["table"]["rows"])

os.environ["KAREL_NODE_TARGETS"] = '{"kernel": "6.8.0-49-generic"}'
fs = rules_gpu.r_node_versions(b)
kernel = [r for r in fs[0]["table"]["rows"] if r[0] == "kernel"]
check("KAREL_NODE_TARGETS overrides the majority rule",
      kernel and kernel[0][2] == "n1, n2", kernel)
os.environ["KAREL_NODE_TARGETS"] = ""
fs = rules_gpu.r_kernel_skew(b)
check("two kernels -> K8S_KERNEL_SKEW info",
      any(f["id"] == "K8S_KERNEL_SKEW" and f["severity"] == "info" for f in fs))


# --------------------------------------------------------------------------
print("\nGPU driver upgrade state: 'behind' is not 'blocked'")


def gpu_node(name, driver, state=None):
    labels = dict(GPU_L)
    labels["nvidia.com/cuda.driver-version.full"] = driver
    if state:
        labels["nvidia.com/gpu-driver-upgrade-state"] = state
    n = node_obj(name, {"nvidia.com/gpu": "8"}, {"nvidia.com/gpu": "8"},
                 labels)
    return n


F = normalize.Facts()
normalize_k8s.p_nodes({"items": [
    gpu_node("kub-b1", "580.82.07"),
    gpu_node("kub-b2", "580.82.07"),
    gpu_node("kub-b3", "580.82.07"),
    gpu_node("kub-b8", "580.82.07"),
    gpu_node("kub-b4", "570.133.20", state="upgrade-required"),
    gpu_node("kub-b5", "570.133.20", state="wait-for-jobs-required"),
    gpu_node("kub-b6", "570.133.20", state="upgrade-failed"),
    gpu_node("kub-b7", "570.133.20"),
]}, F, "k_nodes")
hv = facts({k: v["value"] for k, v in F.items()})
hv["facts"]["k8s.pod.gpu_users"] = {
    "value": {"kub-b5": ["ml/big-job-77"]}, "source": "t"}
hv["facts"]["k8s.ns.info"] = {"value": {}, "source": "t"}
hv["collected_at"] = "2026-10-08T09:00:00Z"
import rules_gpu as _rg
_rg.derive(hv)
import housekeeping as _hk
_hk.derive(hv, {}, now=None)

check("upgrade-required reports as pending, not blocked (the kub-b4 case)",
      _rg._f(hv, "k8s.gpu.upgrade_pending") == ["kub-b4"],
      {k: hv["facts"].get(k, {}).get("value")
       for k in hv["facts"] if "upgrade_" in k})
check("wait-for-jobs is blocked by workload, named with its GPU pod",
      _rg._f(hv, "k8s.gpu.upgrade_blocked_nodes") == ["kub-b5"])
check("upgrade-failed is its own bucket", _rg._f(hv, "k8s.gpu.upgrade_failed")
      == ["kub-b6"])
check("behind with no state and no updater activity is stuck",
      _rg._f(hv, "k8s.gpu.upgrade_stuck") == ["kub-b7"])

fs = _rg.r_gpu_upgrade(hv)
fs = [f for f in fs if f.get("severity") in ("warn", "info") or True]
check("FAILED and STUCK are WARNs, blocked an info with names",
      any(f["id"] == "K8S_GPU_UPGRADE_FAILED:kub-b6"
          and f["severity"] == "warn" for f in fs)
      and any(f["id"] == "K8S_GPU_UPGRADE_STUCK:kub-b7"
              and f["severity"] == "warn" for f in fs)
      and any(f["id"] == "K8S_GPU_UPGRADE_BLOCKED"
              and any("ml/big-job-77" in d for d in f["detail"])
              for f in fs),
      [(f["id"], f["severity"]) for f in fs])
check("blocked age is tracked in the housekeeping state machinery",
      (hv["facts"].get("k8s.gpu.upgrade_blocked_ages") or {}).get("value")
      == {"kub-b5": 0}, hv["facts"].get("k8s.gpu.upgrade_blocked_ages"))

# And the node-versions table annotates the state next to the laggards
fs2 = _rg.r_node_versions(hv)
drv = [r for r in fs2[0]["table"]["rows"] if r[0] == "GPU driver"]
check("node versions annotate the upgrade state",
      drv and "kub-b4 (upgrade-required)" in drv[0][2], drv)


# --------------------------------------------------------------------------
print("\nMIG-only nodes advertise fine; DRA-only allocators are not 'no GPU'")

F = normalize.Facts()
normalize_k8s.p_nodes({"items": [
    # kub-b7: MIG slices only, fully healthy
    node_obj("kub-b7", {"nvidia.com/mig-1g.10gb": "7", "nvidia.com/mig-2g.20gb": "2"},
             {"nvidia.com/mig-1g.10gb": "7", "nvidia.com/mig-2g.20gb": "2"}, GPU_L),
    # kub-b8: MIG slices, one unhealthy
    node_obj("kub-b8", {"nvidia.com/mig-1g.10gb": "7"},
             {"nvidia.com/mig-1g.10gb": "6"}, GPU_L),
    # kub-a7: no nvidia.com extended resources at all (DRA-only allocator)
    node_obj("kub-a7", {}, {}, GPU_L),
    node_obj("cpu-01", {}, {}, {}),
]}, F, "k_nodes")
normalize_k8s.p_resourceslices({"items": [
    {"metadata": {"name": "a7-slice-1"},
     "spec": {"nodeName": "kub-a7", "driver": "gpu.dra.example.com",
              "devices": [{"name": "gpu-0"}, {"name": "gpu-1"}]}},
]}, F, "k_resourceslices")
gn = F.get_value("k8s.node.gpu_nodes", [])
check("MIG-only nodes are GPU nodes", {"kub-b7", "kub-b8"} <= set(gn), gn)
check("a DRA-slice node folds into the GPU node set",
      "kub-a7" in gn, gn)

b = facts({k: v["value"] for k, v in F.items()})
fs = _rg.r_gpu_health(b)
check("MIG-only healthy node is NOT 'not advertised'",
      not any(f["id"] == "K8S_GPU_NOT_ADVERTISED"
              and "kub-b7" in str(f["detail"]) for f in fs), fs)
check("kub-b8's unhealthy MIG slice is named explicitly",
      any(f["id"] == "K8S_GPU_UNHEALTHY"
          and any("nvidia.com/mig-1g.10gb=6/7" in d for d in f["detail"])
          for f in fs),
      [ (f["id"], f.get("detail", [])[:1]) for f in fs ])
check("the DRA-only node is not called dark",
      not any(f["id"] == "K8S_GPU_NOT_ADVERTISED"
              and "kub-a7" in str(f["detail"]) for f in fs), fs)


# --------------------------------------------------------------------------
print("\nGFD crashloop + strategy line -> restart the toolkit pod ON that node")


def gfd(node, name, waiting="CrashLoopBackOff"):
    return {"metadata": {"namespace": "gpu-operator", "name": name,
                         "ownerReferences": [{"kind": "DaemonSet",
                                              "name": "gpu-feature-discovery"}]},
            "spec": {"nodeName": node, "containers": [{"name": "main"}]},
            "status": {"phase": "Pending",
                       "containerStatuses": [
                           {"name": "main", "restartCount": 23,
                            "state": {"waiting": {"reason": waiting}}}]}}


def toolkit(node, name):
    return {"metadata": {"namespace": "gpu-operator", "name": name,
                         "ownerReferences": [{"kind": "DaemonSet",
                                              "name": "nvidia-container-toolkit-daemonset"}]},
            "spec": {"nodeName": node, "containers": [{"name": "main"}]},
            "status": {"phase": "Running",
                       "conditions": [{"type": "Ready", "status": "True"}],
                       "containerStatuses": [
                           {"name": "main", "restartCount": 0,
                            "state": {"running": {}}}]}}


pods = {"items": [
    gfd("gpu-01", "gpu-feature-discovery-b8zbq"),
    toolkit("gpu-01", "nvidia-container-toolkit-daemonset-x9k2p"),
    gfd("gpu-02", "gpu-feature-discovery-t7qmn"),
    toolkit("gpu-02", "nvidia-container-toolkit-daemonset-p2w8z"),
]}
F = normalize.Facts()
normalize_k8s.p_pods(pods, F, "k_pods")
p = F.get_value("k8s.pod.gpu_operator_pods_by_node", {})
check("every gpu-operator pod is listed per node with its exact name",
      [x["pod"] for x in p.get("gpu-01", [])] ==
      ["gpu-feature-discovery-b8zbq",
       "nvidia-container-toolkit-daemonset-x9k2p"], p)

b = facts({k: v["value"] for k, v in F.items()})
check("no log evidence -> no recipe (absent is not zero)",
      rules_gpu.r_gpu_gfd_strategy(b) == [])
b["facts"]["k8s.log.gpu_crash.class.gfd_strategy_auto"] = {
    "value": {"kind": "error", "count": 4,
              "pods": ["gpu-feature-discovery-b8zbq"],
              "nodes": ["gpu-01"]}, "source": "t"}
fs = rules_gpu.r_gpu_gfd_strategy(b)
check("K8S_GPU_GFD_STRATEGY fires with the exact toolkit pod name",
      len(fs) == 1 and fs[0]["id"] == "K8S_GPU_GFD_STRATEGY"
      and "nvidia-container-toolkit-daemonset-x9k2p" in str(fs[0]["detail"])
      and "nvidia-container-toolkit-daemonset-x9k2p"
      in str(fs[0]["remediation"]), fs)
check("the node the log never named gets no recipe",
      "gpu-02" not in str(fs[0]["detail"] + fs[0]["remediation"]),
      fs[0]["detail"])
b["facts"]["k8s.log.gpu_crash.class.gfd_strategy_auto"] = {
    "value": {"kind": "error", "count": 8,
              "pods": ["gpu-feature-discovery-b8zbq",
                       "gpu-feature-discovery-t7qmn"],
              "nodes": ["gpu-01", "gpu-02"]}, "source": "t"}
fs = rules_gpu.r_gpu_gfd_strategy(b)
check("both flagged nodes get their own exact restart command",
      len(fs) == 1
      and all(n in str(fs[0]["remediation"]) for n in
              ("x9k2p", "p2w8z")), fs[0]["remediation"])


finish()
