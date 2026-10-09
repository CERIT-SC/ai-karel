"""
GPU health rules and the Node versions table.

Most GPU health is readable from node objects Karel already collects: GPU
capacity vs allocatable (the device plugin marks unhealthy GPUs by shrinking
allocatable), and the GPU operator's nvidia.com/* labels. The ClusterPolicy
status and crash-log classification are separate collections
(k_clusterpolicy, k_log_gpu_crash).

Threshold: the 25% CRIT line for K8S_GPU_NOT_ADVERTISED lives directly in
r_gpu_health (single use, documented there).
"""

import json
import os
import re as _re

from rules import _finding


def _f(bundle, path, default=None):
    e = bundle["facts"].get(path)
    return e["value"] if e else default


def _targets():
    """KAREL_NODE_TARGETS: JSON of target versions per component. Malformed
    config must not take the report down - majority rule still applies."""
    try:
        v = json.loads(os.environ.get("KAREL_NODE_TARGETS") or "{}")
        return v if isinstance(v, dict) else {}
    except (ValueError, TypeError):
        return {}


_PENDING_STATES = {"upgrade-required", "cordon-required"}
_BLOCKED_STATES = {"wait-for-jobs-required", "pod-deletion-required",
                   "drain-required"}


def _version_parts(v):
    out = []
    for p in str(v or "").replace("-", ".").split("."):
        m = _re.match(r"(\d+)", p)
        out.append(int(m.group(1)) if m else 0)
    return out


def _version_lt(a, b):
    """Dotted-number compare: '570.133.20' < '580.82.07'. A node AHEAD of
    the target is not 'behind' - and must never read as stuck."""
    return _version_parts(a) < _version_parts(b)


def derive(bundle):
    """GPU stack degradation (for the r_workloads fold) and the driver
    upgrade-state classification. The label on the node is the truth;
    'behind the majority version' alone is not - kub-b4 taught us that."""
    facts = bundle.setdefault("facts", {})
    op = _f(bundle, "k8s.pod.gpu_operator_by_node") or {}
    degraded = sorted(n for n, p in op.items()
                      if not p.get("ready") or p.get("waiting_reason"))
    facts["k8s.gpu.degraded_nodes"] = {"value": degraded, "source": "derive"}

    gpu_nodes = _f(bundle, "k8s.node.gpu_nodes", []) or []
    if not gpu_nodes:
        return bundle
    states = _f(bundle, "k8s.node.gpu_upgrade_states", {}) or {}
    drivers = _f(bundle, "k8s.node.gpu_drivers", {}) or {}
    targets = _targets()
    versions = sorted({drivers.get(n) for n in gpu_nodes if drivers.get(n)})
    target = targets.get("gpu_driver") or \
        (sorted(versions)[-1] if versions else None)

    # nvupdater activity: the upgrade controller exists and sees the cluster
    upd = _f(bundle, "k8s.log.gpu_nvupdater.status")
    upd_active = upd == "ok" and \
        (_f(bundle, "k8s.log.gpu_nvupdater.pod_count") or 0) > 0

    classes = {"current": [], "pending": [], "blocked": [], "failed": [],
               "stuck": []}
    for n in gpu_nodes:
        st = states.get(n)
        driver = drivers.get(n)
        behind = bool(target and driver and _version_lt(driver, target))
        if st in ("upgrade-done",) or (not behind and not st):
            classes["current"].append(n)
        elif st in _PENDING_STATES:
            classes["pending"].append(n)
        elif st in _BLOCKED_STATES:
            classes["blocked"].append(n)
        elif st == "upgrade-failed":
            classes["failed"].append(n)
        elif behind and not st and not upd_active:
            classes["stuck"].append(n)
        elif behind and upd_active:
            classes["pending"].append(n)     # controller says it is working
        else:
            classes["current"].append(n)
    for k, v in classes.items():
        facts["k8s.gpu.upgrade_%s" % k] = {"value": sorted(v), "source": "derive"}
    facts["k8s.gpu.upgrade_blocked_nodes"] = {
        "value": sorted(classes["blocked"]), "source": "derive"}
    return bundle


def _crash_causes(bundle):
    cls = {}
    for name in ("driver_mismatch", "nvml_init", "unclassified"):
        d = _f(bundle, "k8s.log.gpu_crash.class.%s" % name)
        if d and d.get("count"):
            cls[name] = d["count"]
    return cls


_CRASH_TEXT = {
    "driver_mismatch": "reboot required to finish driver update "
                       "(driver/library version mismatch)",
    "nvml_init": "NVML failed to initialise - the driver is not loaded "
                 "(module unload blocked, or install incomplete)",
}


def r_gpu_health(bundle):
    out = []
    gpu_nodes = _f(bundle, "k8s.node.gpu_nodes", []) or []
    if not gpu_nodes:
        return out          # most clusters have no GPUs; absent stays absent
    gpu = _f(bundle, "k8s.node.gpu", {}) or {}
    op = _f(bundle, "k8s.pod.gpu_operator_by_node", {}) or {}
    causes = _crash_causes(bundle)

    dra = _f(bundle, "k8s.node.dra_slices", {}) or {}
    unhealthy, not_advertised = [], []
    for n in gpu_nodes:
        res = gpu.get(n) or {}
        # Full GPUs and the MIG slice family share one health model:
        # allocatable < capacity on ANY of them means blocked capacity.
        per_res = []
        cap_total = 0
        for rk, v in sorted(res.items()):
            if rk != "nvidia.com/gpu" and not rk.startswith("nvidia.com/mig-"):
                continue
            cap = (v or {}).get("capacity") or 0
            alloc = (v or {}).get("allocatable") or 0
            cap_total += cap
            if alloc < cap:
                per_res.append("%s=%d/%d" % (rk, alloc, cap))
        if per_res:
            unhealthy.append((n, per_res))
        elif not cap_total and n not in dra:
            not_advertised.append(n)

    if unhealthy:
        blocked = sum(sum(int(p.split("=")[1].split("/")[1])
                          - int(p.split("=")[1].split("/")[0])
                          for p in per_res)
                      for _n, per_res in unhealthy)
        out.append(_finding(
            "K8S_GPU_UNHEALTHY", "warn",
            "%d GPU(s) blocked on %d node(s): allocatable below capacity"
            % (blocked, len(unhealthy)),
            detail=["%s: %s" % (n, ", ".join(per_res))
                    for n, per_res in unhealthy] +
                   ["the device plugin shrinks allocatable when the DCGM "
                    "health checks fail - those pods cannot schedule"],
            evidence=["k_nodes"], metric=float(len(unhealthy)),
            remediation=["check nvidia-dcgm / the device plugin pod on the "
                         "node; XID errors in dmesg name the GPU"]))

    if not_advertised:
        frac = len(not_advertised) / float(len(gpu_nodes))
        sev = "crit" if frac >= 0.25 else "warn"
        out.append(_finding(
            "K8S_GPU_NOT_ADVERTISED", sev,
            "%d of %d GPU node(s) advertise no nvidia.com/gpu or mig-*"
            % (len(not_advertised), len(gpu_nodes)),
            detail=not_advertised +
                   ["the node is labelled or provisioned for GPU but the "
                    "device plugin advertises nothing - the stack on that "
                    "node is down, or the driver never loaded"] +
                   (["(nodes serving GPUs through DRA slices instead: %s)"
                     % ", ".join(sorted(n for n in gpu_nodes if n in dra))]
                    if any(n in dra for n in gpu_nodes) else []),
            evidence=["k_nodes"], metric=float(len(not_advertised)),
            remediation=["without the resource the scheduler sends no GPU "
                         "workload here; the node idles while GPU queues "
                         "wait elsewhere"]))

    degraded = set(_f(bundle, "k8s.gpu.degraded_nodes", []) or [])
    for n in sorted(degraded):
        p = op.get(n) or {}
        cause = next((_CRASH_TEXT[c] for c in
                      ("driver_mismatch", "nvml_init") if causes.get(c)), None)
        detail = ["gpu-operator pod `%s` (owner %s): %s%s"
                  % (p.get("pod"), p.get("owner"),
                     "in %s" % p["waiting_reason"] if p.get("waiting_reason")
                     else "not ready",
                     ", %d restarts" % p["restarts"] if p.get("restarts")
                     else "")]
        if cause:
            detail.insert(0, "crash log says: %s" % cause)
        out.append(_finding(
            "K8S_GPU_STACK_DEGRADED", "warn",
            "GPU stack degraded on %s%s"
            % (n.split(".")[0], " - %s" % cause.split(" (")[0] if cause
               else ""),
            subject=n, detail=detail,
            evidence=["k_pods"] + (["k_log_gpu_crash"] if cause else []),
            remediation=["the matching pod-log and backoff entries are "
                         "folded into this finding - fix THIS node's stack "
                         "and they all clear"]))

    states = _f(bundle, "k8s.gpu.clusterpolicy_states")
    if states:  # absent CRD (or denied) yields no fact: no finding either
        bad = {k: v for k, v in states.items() if v and v != "ready"}
        if bad:
            out.append(_finding(
                "K8S_GPU_OPERATOR_NOT_READY", "warn",
                "GPU operator ClusterPolicy not ready: %s"
                % ", ".join("%s=%s" % kv for kv in sorted(bad.items())),
                evidence=["k_clusterpolicy"],
                remediation=["the operator is mid-rollout or stuck; per-node "
                             "detail is in the GPU-node findings above"]))

    versions = _f(bundle, "k8s.node.gpu_drivers", {}) or {}
    by_drv = {}
    for n, v in versions.items():
        if n in set(gpu_nodes):
            by_drv.setdefault(v, []).append(n)
    if len(by_drv) > 1:
        out.append(_finding(
            "K8S_GPU_DRIVER_SKEW", "info",
            "GPU nodes run %d different driver versions" % len(by_drv),
            detail=["%s: %s" % (v, ", ".join(sorted(ns)))
                    for v, ns in sorted(by_drv.items())],
            evidence=["k_nodes"],
            remediation=["mixed driver versions are how one node fails an "
                         "upgrade invisibly; align them"]))
    return out


def _short(n):
    return str(n).split(".")[0]


def r_gpu_upgrade(bundle):
    """Driver upgrade state: current/pending count only; blocked names the
    node and the GPU pods holding it (with its age in state); failed and
    silent-stuck are WARN."""
    out = []
    if not (_f(bundle, "k8s.node.gpu_nodes") or []):
        return out
    for n in _f(bundle, "k8s.gpu.upgrade_failed", []) or []:
        out.append(_finding(
            "K8S_GPU_UPGRADE_FAILED", "warn",
            "GPU driver upgrade FAILED on %s" % _short(n), subject=n,
            evidence=["k_nodes"],
            remediation=["read the operator's upgrade controller logs for "
                         "the node; a failed upgrade does not retry "
                         "forever"]))
    stuck = _f(bundle, "k8s.gpu.upgrade_stuck", []) or []
    states = _f(bundle, "k8s.node.gpu_upgrade_states", {}) or {}
    blocked = _f(bundle, "k8s.gpu.upgrade_blocked_nodes", []) or []
    ages = _f(bundle, "k8s.gpu.upgrade_blocked_ages", {}) or {}
    users = _f(bundle, "k8s.pod.gpu_users", {}) or {}
    for n in stuck:
        out.append(_finding(
            "K8S_GPU_UPGRADE_STUCK", "warn",
            "%s runs an old driver and NOTHING is upgrading it" % _short(n),
            subject=n,
            detail=["no nvidia.com/gpu-driver-upgrade-state label, and no "
                    "nvupdater activity seen",
                    "'behind the majority' and 'will be upgraded' are "
                    "different states - this one is going nowhere on its own"],
            evidence=["k_nodes", "k_log_nvupdater"],
            remediation=["check the driver upgrade controller: is the node "
                         "excluded, cordoned forever, or the controller "
                         "simply down?"]))
    if blocked:
        detail = []
        for n in blocked:
            pods = sorted(users.get(n) or [])
            age = ages.get(n)
            line = "%s: %sblocked%s" % (
                _short(n),
                states.get(n) or "blocked",
                ", %d days" % age if age else "")
            if pods:
                line += " - held by %s" % ", ".join(pods[:6])
            detail.append(line)
        out.append(_finding(
            "K8S_GPU_UPGRADE_BLOCKED", "info",
            "%d GPU node(s) blocked from a driver upgrade by workloads"
            % len(blocked),
            detail=detail +
                   ["ask the owners of these pods to release the node; an "
                    "idle pod (see the waste tables) is the cheapest "
                    "unblock"],
            evidence=["k_nodes", "k_pods"]))
    pending = _f(bundle, "k8s.gpu.upgrade_pending", []) or []
    current = _f(bundle, "k8s.gpu.upgrade_current", []) or []
    failed_n = _f(bundle, "k8s.gpu.upgrade_failed", []) or []
    if pending or blocked or failed_n or stuck:
        out.append(_finding(
            "K8S_GPU_UPGRADE_SUMMARY", "info",
            "GPU driver upgrades: %d current, %d pending, %d blocked, "
            "%d failed, %d stuck"
            % (len(current), len(pending), len(blocked),
               len(failed_n), len(stuck)),
            evidence=["k_nodes"]))
    return out


# ------------------------------------------------------- node versions table
def _version_map(bundle, nodes, attr, subset=None):
    out = {}
    for n in nodes:
        if subset is not None and n not in subset:
            continue
        v = _f(bundle, "k8s.node.%s.%s" % (n, attr))
        if not v:
            continue
        out.setdefault(str(v), []).append(n)
    return out


def r_node_versions(bundle):
    """One row per component: kernel, kubelet (RKE2), containerd, OS image,
    and GPU driver on GPU nodes. The target is the majority version unless
    KAREL_NODE_TARGETS pins one; the 'behind' column names the laggards."""
    nodes = _f(bundle, "k8s.node.names", []) or []
    if not nodes:
        return []
    gpu_nodes = set(_f(bundle, "k8s.node.gpu_nodes", []) or [])
    targets = _targets()

    rows = []
    comps = [("kernel", "kernel", None),
             ("kubelet (RKE2)", "kubelet_version", None),
             ("containerd", "container_runtime", None),
             ("OS image", "os_image", None),
             ("GPU driver", "gpu_driver", gpu_nodes or set())]
    any_row = False
    for label, attr, subset in comps:
        if subset is not None and not subset:
            continue
        vm = _version_map(bundle, nodes, attr, subset)
        if not vm:
            continue
        any_row = True
        # Majority wins; on a tie the NEWER version is the target, because
        # "target" describes the upgrade direction, not the average.
        by_ver = sorted(vm.items(), key=lambda kv: _version_parts(kv[0]),
                        reverse=True)
        majority = sorted(by_ver, key=lambda kv: -len(kv[1]))[0][0]
        tkey = {"kernel": "kernel", "kubelet_version": "kubelet",
                "container_runtime": "containerd", "os_image": "os_image",
                "gpu_driver": "gpu_driver"}[attr]
        target = targets.get(tkey) or majority
        if attr == "gpu_driver":
            behind = sorted(n for v, ns in vm.items()
                            if _version_lt(v, target) for n in ns)
        else:
            behind = sorted(n for v, ns in vm.items() if v != target
                            for n in ns)
        if attr == "gpu_driver":
            # "behind" is not actionable on its own; the upgrade state is.
            states = _f(bundle, "k8s.node.gpu_upgrade_states", {}) or {}
            blocked = set(_f(bundle, "k8s.gpu.upgrade_blocked_nodes", []) or [])
            shown = ["%s (%s)" % (_short(n), states.get(n)
                                  or ("blocked by workload" if n in blocked
                                      else "?")) for n in behind[:10]]
        else:
            shown = [n.split(".")[0] for n in behind[:10]]
        rows.append([label,
                     ", ".join("%s (%d)" % (v, len(ns))
                               for v, ns in sorted(vm.items(),
                                                   key=lambda kv: -len(kv[1]))),
                     ", ".join(shown) or "-"])
    if not any_row:
        return []

    f = _finding(
        "K8S_NODE_VERSIONS", "info",
        "Node software versions across %d node(s)" % len(nodes),
        evidence=["k_nodes"],
        remediation=["-"])
    f["section"] = "Node versions"
    f["section_order"] = 30
    f["table"] = {
        "headers": ["component", "versions (nodes)", "behind"],
        "align": ["l", "l", "l"],
        "rows": rows,
        "note": "behind = not on the majority version (or the target from "
                "KAREL_NODE_TARGETS). A mixed row mid-upgrade is fine; a "
                "mixed row for weeks is a stuck upgrade.",
    }
    return [f]


def r_kernel_skew(bundle):
    versions = {}
    for n in _f(bundle, "k8s.node.names", []) or []:
        k = _f(bundle, "k8s.node.%s.kernel" % n)
        if k:
            versions[k] = versions.get(k, 0) + 1
    if len(versions) <= 1:
        return []
    return [_finding(
        "K8S_KERNEL_SKEW", "info",
        "Nodes run %d different kernel versions" % len(versions),
        detail=["%s: %d node(s)" % kv for kv in sorted(versions.items())],
        evidence=["k_nodes"], metric=float(len(versions)),
        remediation=["a node that never got its post-upgrade reboot is the "
                     "usual straggler; it also has the old kernel's CVEs"])]


RULES = [
    r_gpu_health,
    r_kernel_skew,
    r_node_versions,
    r_gpu_upgrade,
]
