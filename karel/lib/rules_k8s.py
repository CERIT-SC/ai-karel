"""
Kubernetes / RKE2 rules for Karel.

Bias: the control plane is upstream of everything. A broken API server explains
broken workloads, and the report must rank causes above effects.
"""

import os
import re as _re

from rules import _finding, is_denied, short_error
import scope

K8S_THRESHOLDS = {
    "cert_days_warn": 60,
    "cert_days_crit": 21,
    "etcd_db_pct_warn": 50.0,          # of the 2GiB default quota
    "etcd_db_pct_crit": 75.0,
    "etcd_quota_bytes": 2 * 1024**3,
    "node_cpu_commit_warn": 90.0,
    "node_mem_commit_warn": 90.0,
    "restart_delta_warn": 5,
    "apiserver_5xx_rate_warn": 0.02,   # fraction of requests/day
    "cronjob_stale_days": 2,
    "tenant_event_pattern_namespaces": 10,  # widespread => platform suspicion
    "event_buffer_stale_minutes": 45,
    "image_pattern_namespaces": 5,  # same repo failing across N namespaces
}


def _f(bundle, path, default=None):
    e = bundle["facts"].get(path)
    return e["value"] if e else default


def _human_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0:
            return "%.1f %s" % (n, u)
        n /= 1024.0
    return "%.1f PiB" % n


# ------------------------------------------------------------ collector health
def r_k8s_collection(bundle):
    out = []
    cmds = bundle["collection"]["commands"]
    k8s_cmds = {n: c for n, c in cmds.items() if n.startswith("k_")}

    if not k8s_cmds:
        return [_finding(
            "KAREL_K8S_NOT_COLLECTED", "warn",
            "No Kubernetes data was collected",
            evidence=["index.tsv"],
            remediation=["the collector did not run - check the plan and the "
                         "Job log",
                         "findings below have no cluster context"])]

    ok = sum(1 for c in k8s_cmds.values() if c.get("status") == "ok")
    if ok == 0:
        return [_finding(
            "KAREL_K8S_UNREACHABLE", "crit",
            "Kubernetes API unreachable - no cluster data in this report",
            detail=sorted(set(
                l for c in k8s_cmds.values() for l in (c.get("stderr_head") or [])))[:4],
            evidence=sorted(k8s_cmds),
            remediation=["if you are reading this, Karel's own pod started, so the "
                         "API was reachable at schedule time - suspect RBAC or a "
                         "mid-run apiserver failure",
                         "check the ServiceAccount token and the ClusterRoleBinding"])]

    # Only genuine denials. A command that failed for another reason (the
    # helper script was not found, say) is KAREL_COMMAND_FAILED - calling it
    # an RBAC gap sent people to the ClusterRole for an installation problem.
    denied = [n for n, c in k8s_cmds.items()
              if c.get("status") in ("failed", "eacces") and c.get("expected") == "ok"
              and is_denied(c)]
    if denied:
        out.append(_finding(
            "KAREL_K8S_RBAC_GAP", "warn",
            "%d Kubernetes collector(s) were denied" % len(denied),
            detail=[", ".join(sorted(denied))] +
                   sorted(set(short_error(l) for n in denied
                              for l in (k8s_cmds[n].get("stderr_head") or [])))[:3],
            evidence=sorted(denied),
            remediation=["missing RBAC, or the resource type does not exist on this "
                         "cluster (e.g. helm.cattle.io CRDs outside RKE2)",
                         "set expected_status in k8s-commands.json for the ones that "
                         "are legitimately absent"]))

    if _f(bundle, "k8s.events.buffer_available") is False:
        out.append(_finding(
            "KAREL_EVENT_BUFFER_MISSING", "warn",
            "Event buffer is not running - event coverage is ~1h, not 24h",
            detail=["Kubernetes Events expire after the apiserver event-ttl "
                    "(1h by default)",
                    "OOMKills, evictions and FailedScheduling from overnight are "
                    "invisible to this report"],
            evidence=["k_event_buffer"],
            remediation=["deploy the event-buffer CronJob at */15 * * * *",
                         "or raise --event-ttl on the apiserver (costs etcd memory)"]))
    return out


# ------------------------------------------------------------------ core health
def r_apiserver(bundle):
    out = []

    if _f(bundle, "k8s.apiserver.readyz_ok") is False:
        out.append(_finding(
            "K8S_APISERVER_NOT_READY", "crit",
            "apiserver /readyz is failing",
            detail=_f(bundle, "k8s.apiserver.readyz_failing", []) or [],
            evidence=["k_readyz"],
            remediation=["a failing readyz check names the subsystem - etcd, "
                         "informers, or an admission webhook",
                         "this is upstream of every other finding in this report"]))

    if _f(bundle, "k8s.apiserver.livez_ok") is False:
        out.append(_finding(
            "K8S_APISERVER_NOT_LIVE", "crit",
            "apiserver /livez is failing",
            detail=_f(bundle, "k8s.apiserver.livez_failing", []) or [],
            evidence=["k_livez"]))

    unavail = _f(bundle, "k8s.apiservice.unavailable", []) or []
    if unavail:
        out.append(_finding(
            "K8S_APISERVICE_UNAVAILABLE", "warn",
            "%d aggregated APIService(s) unavailable" % len(unavail),
            detail=unavail[:10], evidence=["k_apiservices"],
            metric=float(len(unavail)),
            remediation=["an unavailable APIService makes `kubectl get` fail for its "
                         "group and can block namespace deletion",
                         "metrics.k8s.io failing also removes kubectl top data"]))

    dep = _f(bundle, "k8s.apiserver.deprecated_apis", {}) or {}
    live = {k: v for k, v in dep.items() if v and k not in ("", "unknown")}
    if live:
        out.append(_finding(
            "K8S_DEPRECATED_API_IN_USE", "warn",
            "Deprecated APIs are actively being called",
            detail=["removal in %s: %s request(s) since apiserver start" % (k, int(v))
                    for k, v in sorted(live.items())],
            evidence=["k_apiserver_metrics"],
            remediation=["this counts ACTUAL calls, not theoretical deprecation",
                         "identify callers before the next minor upgrade"]))

    rej = _f(bundle, "k8s.apiserver.flowcontrol_rejected_total")
    if rej:
        out.append(_finding(
            "K8S_APISERVER_THROTTLING", "warn",
            "APF has rejected %d request(s) since apiserver start" % int(rej),
            evidence=["k_apiserver_metrics"], metric=float(rej),
            remediation=["a client is exceeding its priority level's concurrency share",
                         "the daily delta on this counter is the useful signal"]))
    return out


def r_etcd_snapshot(bundle):
    """RKE2 etcd snapshots: every etcd node cycles a local AND an S3 copy.
    The local one failing is an etcd problem; the S3 one silently stopping
    is the disaster-recovery problem - and only these CR objects tell."""
    out = []
    files = _f(bundle, "k8s.etcd.snapshot_files")
    if not files:
        return out     # CRD absent / no snapshots at all: not observable here
    cadence = _f(bundle, "k8s.etcd.snapshot_cadence_h") or 2.0
    stale_h = cadence + 1.0
    etcd_nodes = _f(bundle, "k8s.controlplane.etcd_nodes") or []
    stale_local, stale_s3 = [], []
    for node in sorted(set(list(files) + [
            n for n in etcd_nodes if n not in files])):
        slot = files.get(node)
        if not slot:
            stale_local.append("%s (no snapshot records at all)" % node)
            stale_s3.append("%s (no snapshot records at all)" % node)
            continue
        la = slot.get("local_newest_age_h")
        sa = slot.get("s3_newest_age_h")
        if la is None:
            stale_local.append("%s (no local record)" % node)
        elif la > stale_h:
            stale_local.append("%s (last local %.1f h ago)" % (node, la))
        if sa is None:
            stale_s3.append("%s (has local copies, never any S3 copy, "
                            "local %.1f h ago)" % (node, la or -1))
        elif sa > stale_h:
            stale_s3.append("%s (last in S3 %.1f h ago)" % (node, sa))

    if stale_s3:
        f = _finding(
            "K8S_ETCD_SNAPSHOT_S3_STALE", "warn",
            "etcd S3 backups stale on %d node(s)" % len(stale_s3),
            detail=sorted(stale_s3) +
                   ["snapshot cadence ~%.1f h; stale beyond %.1f h"
                    % (cadence, stale_h),
                    "S3 rot fails silently: the etcd data is fine, the "
                    "backups are quietly gone when actually needed"],
            evidence=["k_etcd_snapshots"], metric=float(len(stale_s3)),
            remediation=["check the snapshot secret and endpoint: an expired "
                         "credential stops uploads while local copies still "
                         "appear"])
        f["escalate_after_days"] = 2
        out.append(f)
    if stale_local:
        out.append(_finding(
            "K8S_ETCD_SNAPSHOT_STALE", "warn",
            "local etcd snapshots stale on %d node(s)" % len(stale_local),
            detail=sorted(stale_local),
            evidence=["k_etcd_snapshots"], metric=float(len(stale_local)),
            remediation=["rke2-server owns the cron; its log on that node "
                          "names the failure"]))
    if not stale_local and not stale_s3:
        newest = min(v.get("s3_newest_age_h") or v.get("local_newest_age_h")
                     for v in files.values())
        out.append(_finding(
            "K8S_ETCD_SNAPSHOTS_HEALTHY", "info",
            "etcd snapshots fresh on %d node(s), newest %.1f h ago"
            % (len(files), newest or 0),
            evidence=["k_etcd_snapshots"]))
    return out


def r_etcd(bundle):
    out = []
    size = _f(bundle, "k8s.etcd.db_bytes") or _f(bundle, "k8s.etcd.db_bytes_alt")
    if size:
        quota = K8S_THRESHOLDS["etcd_quota_bytes"]
        pct = 100.0 * size / quota
        sev = ("crit" if pct >= K8S_THRESHOLDS["etcd_db_pct_crit"]
               else "warn" if pct >= K8S_THRESHOLDS["etcd_db_pct_warn"] else None)
        if sev:
            out.append(_finding(
                "K8S_ETCD_DB_SIZE", sev,
                "etcd database is %s (%.0f%% of the 2GiB default quota)"
                % (_human_bytes(size), pct),
                detail=["objects: %s" % (_f(bundle, "k8s.etcd.objects_total") or "?")],
                evidence=["k_apiserver_metrics"], metric=pct,
                remediation=["hitting the quota puts etcd into read-only NOSPACE alarm",
                             "check for churn: Events, Leases, and large ConfigMaps",
                             "compaction and defrag reclaim space; defrag briefly "
                             "blocks the member, do one at a time"]))

    if _f(bundle, "k8s.etcd.has_leader") == 0:
        out.append(_finding(
            "K8S_ETCD_NO_LEADER", "crit", "etcd reports no leader",
            evidence=["k_apiserver_metrics"],
            remediation=["the cluster cannot accept writes - treat as an outage"]))

    failed = _f(bundle, "k8s.etcd.proposals_failed_total")
    if failed:
        out.append(_finding(
            "K8S_ETCD_PROPOSALS_FAILED", "warn",
            "etcd has %d failed proposal(s) since start" % int(failed),
            evidence=["k_apiserver_metrics"], metric=float(failed),
            remediation=["failed proposals usually mean leader changes or slow disks",
                         "correlate with the leader_changes counter delta"]))
    return out


def r_nodes(bundle):
    out = []
    not_ready = _f(bundle, "k8s.node.not_ready", []) or []
    total = _f(bundle, "k8s.node.count")

    if not_ready:
        detail = []
        for n in not_ready:
            since = _f(bundle, "k8s.node.%s.not_ready_since" % n)
            detail.append("%s (since %s)" % (n, since or "unknown"))
        out.append(_finding(
            "K8S_NODE_NOT_READY", "crit",
            "%d of %s node(s) NotReady" % (len(not_ready), total),
            detail=detail, evidence=["k_nodes"], metric=float(len(not_ready)),
            remediation=["a NotReady node explains every pod on it at once",
                         "check kubelet on that node before chasing downstream symptoms"]))

    pressure = _f(bundle, "k8s.node.pressure", []) or []
    if pressure:
        out.append(_finding(
            "K8S_NODE_PRESSURE", "warn",
            "%d node pressure condition(s) active" % len(pressure),
            detail=pressure, evidence=["k_nodes"], metric=float(len(pressure)),
            remediation=["DiskPressure triggers image GC and pod eviction",
                         "evicted pods and re-pulled images add load exactly when "
                         "the node is already struggling"]))

    unsched = _f(bundle, "k8s.node.unschedulable", []) or []
    if unsched:
        # A cordon is a maintenance setting: correct when made, a problem only
        # when forgotten. Info on day one, raised on age.
        alloc = _f(bundle, "k8s.node.allocatable_cpu_m", {}) or {}
        tot = sum(alloc.values())
        share = (100.0 * sum(alloc.get(n, 0) for n in unsched) / tot) if tot else None
        f = _finding(
            "K8S_NODE_CORDONED", "info",
            "%d node(s) cordoned%s" % (len(unsched),
                                       " (%.0f%% of cluster CPU)" % share
                                       if share is not None else ""),
            detail=unsched, evidence=["k_nodes"], metric=float(len(unsched)),
            remediation=["cordons set during maintenance are routinely forgotten - "
                         "this is raised to WARN after a week"])
        f["escalate_after_days"] = 7
        out.append(f)

    versions = _f(bundle, "k8s.node.kubelet_versions", {}) or {}
    if len(versions) > 1:
        out.append(_finding(
            "K8S_KUBELET_VERSION_SKEW", "warn",
            "%d distinct kubelet versions across nodes" % len(versions),
            detail=["%s: %d node(s)" % (k, v) for k, v in sorted(versions.items())],
            evidence=["k_nodes"], metric=float(len(versions)),
            remediation=["a partially completed RKE2 upgrade",
                         "mixed versions are supported briefly, not indefinitely"]))

    usage = _f(bundle, "k8s.node.usage", {}) or {}
    hot = ["%s cpu %.0f%% mem %.0f%%" % (n, u.get("cpu_pct", 0), u.get("mem_pct", 0))
           for n, u in usage.items()
           if (u.get("mem_pct") or 0) >= K8S_THRESHOLDS["node_mem_commit_warn"]]
    if hot:
        out.append(_finding(
            "K8S_NODE_MEMORY_HIGH", "warn",
            "%d node(s) above %.0f%% memory" % (len(hot), K8S_THRESHOLDS["node_mem_commit_warn"]),
            detail=hot, evidence=["k_top_nodes"], metric=float(len(hot)),
            remediation=["memory exhaustion triggers the OOM killer, which takes "
                         "pods down and cascades into restarts elsewhere"]))
    return out


def _platform(bundle, path):
    """(platform items, platform count, total count) for a problem list.

    Prefers the facts scope.derive() wrote; recomputes them when a rule is
    called on a bundle that was never derived (tests, old callers).
    """
    items = _f(bundle, path + ".platform")
    count = _f(bundle, path + ".platform_count")
    if items is None:
        raw = _f(bundle, path, []) or []
        items = [i for i in raw if scope.is_platform(scope.item_ns(i))]
        count = len(items)
    return items, count if count is not None else len(items)


def _atleast(bundle, path):
    """'at least ' when the count came from a truncated sample (older bundles)."""
    return "at least " if _f(bundle, path + ".partial") else ""


def _more(items, count, shown=15):
    """Detail lines that say when they are a sample."""
    lines = list(items[:shown])
    if count > len(lines):
        lines.append("... %d more (findings.json)" % (count - len(lines)))
    return lines


def _gpu_fold(bundle, items):
    """Fold GPU-operator problems into K8S_GPU_STACK_DEGRADED.

    When a node's GPU stack is degraded, that node's gpu-operator pods would
    otherwise appear a second and third time here (backoff lists, degraded
    DaemonSets). One problem, one finding; the others just point at it.
    """
    deg = {_short(n) for n in (_f(bundle, "k8s.gpu.degraded_nodes") or [])}
    if not deg:
        return list(items), 0
    kept, dropped = [], 0
    for i in items:
        if not str(i).startswith("gpu-operator/"):
            kept.append(i)
            continue
        m = _re.search(r" on ([\w.\-]+)$", str(i))
        node = _short(m.group(1)) if m else None
        if node and node in deg:
            dropped += 1
        elif not m and any(d in str(i) for d in deg):
            dropped += 1
        else:
            kept.append(i)
    return kept, dropped


def _short(node):
    return str(node).split(".")[0]


def r_workloads(bundle):
    """Platform workloads only. Tenants' workloads go to r_tenant_summary.

    On a shared cluster, "36 containers in backoff" was 34 tenant apps and
    two DaemonSet pods the operators actually own - reported as one CRIT that
    nobody could act on.
    """
    out = []

    for kind, label in (("deployment", "Deployment"), ("statefulset", "StatefulSet"),
                        ("daemonset", "DaemonSet")):
        deg, n = _platform(bundle, "k8s.%s.degraded" % kind)
        deg, dropped = _gpu_fold(bundle, deg)
        n = max(0, n - dropped)
        if deg:
            lines = _more(deg, n)
            if dropped:
                lines.append("(%d gpu-operator entr(ies) folded into "
                             "K8S_GPU_STACK_DEGRADED)" % dropped)
            out.append(_finding(
                "K8S_WORKLOAD_DEGRADED", "warn",
                "%s%d platform %s(s) below desired replicas"
                % (_atleast(bundle, "k8s.%s.degraded" % kind), n, label),
                subject=kind, detail=lines,
                evidence=["k_%ss" % kind], metric=float(n)))

    pending, n = _platform(bundle, "k8s.pod.pending")
    if pending:
        out.append(_finding(
            "K8S_PODS_PENDING", "warn",
            "%s%d platform pod(s) Pending" % (_atleast(bundle, "k8s.pod.pending"), n),
            detail=_more(pending, n), evidence=["k_pods"], metric=float(n),
            remediation=["check FailedScheduling events for the reason - usually "
                         "requests, a nodeSelector or a taint no node satisfies"]))

    backoff, n = _platform(bundle, "k8s.pod.backoff")
    backoff, dropped = _gpu_fold(bundle, backoff)
    n = max(0, n - dropped)
    if backoff:
        pulls = [b for b in backoff if "ImagePull" in b or "ErrImagePull" in b]
        lines = _more(backoff, n)
        if dropped:
            lines.append("(%d gpu-operator entr(ies) folded into "
                         "K8S_GPU_STACK_DEGRADED)" % dropped)
        out.append(_finding(
            "K8S_PODS_BACKOFF", "crit" if n > 3 else "warn",
            "%s%d platform container(s) in a backoff state"
            % (_atleast(bundle, "k8s.pod.backoff"), n),
            detail=lines, evidence=["k_pods"], metric=float(n),
            remediation=["a DaemonSet pod crashlooping on one node usually means "
                         "that node is broken, not the DaemonSet - check it first"] +
                        (["ImagePullBackOff on a platform pod: check the registry "
                          "and pull secret, and whether the tag still exists"]
                         if pulls else [])))

    # OOMKills are listed for EVERY namespace, not platform-only: an OOMKill
    # is a cluster fact (the node adds a counter and a kubelet event) and the
    # tenant table's summary row is no place to hide a nameable pod.
    oom_all = _f(bundle, "k8s.pod.oomkilled", []) or []
    oom_total = _f(bundle, "k8s.pod.oomkilled_count") or len(oom_all)
    if oom_all:
        plat_n = _f(bundle, "k8s.pod.oomkilled.platform_count")
        split_n = (" - %d platform, %d tenant"
                   % (plat_n, max(0, oom_total - plat_n))) \
            if plat_n is not None else ""
        out.append(_finding(
            "K8S_OOMKILLED", "warn",
            "%s%d container(s) show a recent OOMKill%s"
            % (_atleast(bundle, "k8s.pod.oomkilled"), oom_total, split_n),
            detail=_more(oom_all, oom_total, shown=40),
            evidence=["k_pods"], metric=float(oom_total),
            remediation=["raise the memory limit or fix the leak - an OOMKilled "
                         "logging, storage or network agent drops data or I/O on "
                         "that node"]))

    stale, n = _platform(bundle, "k8s.cronjob.stale")
    # Older bundles counted suspended CronJobs as stale.
    suspended = set(_f(bundle, "k8s.cronjob.suspended", []) or [])
    stale = [c for c in stale if c.split(" ", 1)[0] not in suspended]
    if stale:
        out.append(_finding(
            "K8S_CRONJOB_STALE", "warn",
            "%d platform CronJob(s) are overdue" % len(stale),
            detail=_more(stale, len(stale)), evidence=["k_cronjobs"],
            metric=float(len(stale)),
            remediation=["a CronJob that silently stops running is the classic "
                         "backup failure - including Karel's own"]))

    failed_jobs, n = _platform(bundle, "k8s.job.failed")
    if failed_jobs:
        helm = [j for j in failed_jobs if "helm-install" in j or "helm-delete" in j]
        out.append(_finding(
            "K8S_JOBS_FAILED", "warn",
            "%s%d platform Job(s) failed" % (_atleast(bundle, "k8s.job.failed"), n),
            detail=_more(failed_jobs, n), evidence=["k_jobs"], metric=float(n),
            remediation=([ "failed helm-install Jobs in kube-system mean an RKE2 "
                          "packaged component (CNI, CoreDNS, ingress) drifted from "
                          "its intended config and nobody noticed"] if helm else
                         ["review the Job logs before deleting"])))
    return out


def r_tenant_summary(bundle):
    """Tenant namespaces: one summary table, never alarms.

    Mirrors what the old per-namespace analysis delivered - how much, how many
    namespaces, which ones most - without a finding per tenant mistake.
    A condition whose source collected shows a 0 row (a clean check still
    says it ran); only a condition whose source failed is omitted, and it is
    named separately below.
    """
    cmds = (bundle.get("collection") or {}).get("commands") or {}
    rows, union, partial, unobserved = [], set(), False, []
    for path, _count_path, label, src in scope.SPLIT:
        collected = cmds.get(src, {}).get("status", "ok") == "ok"
        n = _f(bundle, path + ".tenant_count")
        if n is None:
            raw = _f(bundle, path)
            if raw is None:
                if not collected:
                    unobserved.append((label, src))
                    continue
                n = 0
            else:
                tenant = [i for i in raw
                          if not scope.is_platform(scope.item_ns(i))]
                n = len(tenant)
                by_ns = {}
                for i in tenant:
                    by_ns[scope.item_ns(i)] = by_ns.get(scope.item_ns(i), 0) + 1
                top = sorted(by_ns.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
                ns_count = len(by_ns)
        else:
            top = _f(bundle, path + ".tenant_top", []) or []
            ns_count = _f(bundle, path + ".tenant_ns_count") or 0
        if path == "k8s.cronjob.stale":
            suspended = set(_f(bundle, "k8s.cronjob.suspended", []) or [])
            raw = _f(bundle, path, []) or []
            dropped = sum(1 for c in raw if c.split(" ", 1)[0] in suspended
                          and not scope.is_platform(scope.item_ns(c)))
            n = max(0, n - dropped)
        if not n:
            clean = _f(bundle, "k8s.tenant.clean_runs.%s"
                       % path.rsplit(".", 1)[-1]) or 0
            cnt = "0 (clean %d runs)" % clean if clean > 0 and collected else 0
            rows.append([label, cnt, 0, "-"])
            continue
        by_ns = _f(bundle, path + "_by_ns")
        if isinstance(by_ns, dict):
            union |= {ns for ns in by_ns if not scope.is_platform(ns)}
        else:
            union |= {scope.item_ns(i) for i in (_f(bundle, path, []) or [])
                      if scope.item_ns(i) and not scope.is_platform(scope.item_ns(i))}
        sampled = bool(_f(bundle, path + ".tenant_partial"))
        partial = partial or sampled
        ge = "≥" if sampled else ""
        if path == "k8s.pod.failed_recent":
            # One runaway Job is one problem: name the owners, not the noise
            # of their pod counts, in the most-affected column.
            groups = _f(bundle, "k8s.pod.failed_recent_groups") or {}
            top_groups = sorted(groups.values(), key=lambda g: -g["count"])[:3]
            most = ", ".join("%s (%d)" % (g["owner"], g["count"])
                             for g in top_groups)
        else:
            most = ", ".join("%s (%s%d)" % (ns, ge, c) for ns, c in top[:3])
        rows.append([label, n, "%s%d" % (ge, ns_count), most])

    # Tenant event patterns below the WARN threshold: counted, not alarmed.
    thr = K8S_THRESHOLDS["tenant_event_pattern_namespaces"]
    for reason, p in sorted((_f(bundle, "k8s.events.patterns") or {}).items()):
        ns_c = p.get("ns_count") or 0
        if not ns_c or ns_c >= thr:
            continue
        union |= {ns for ns, _n in (p.get("top") or [])}
        rows.append(["events: %s" % reason, p.get("count") or 0,
                     str(ns_c),
                     ", ".join("%s (%d)" % (ns, n)
                               for ns, n in (p.get("top") or [])[:3])])

    # ACME solver pods older than an hour: tenant objects, counted not alarmed
    # (the actionable causes are the ACME_* findings above).
    stk = _f(bundle, "k8s.acme.solvers_stale_by_ns") or {}
    if stk:
        union |= set(stk)
        rows.append(["ACME solver pods older than 1h", sum(stk.values()),
                     str(len(stk)),
                     ", ".join("%s (%d)" % kv for kv in
                               sorted(stk.items(), key=lambda kv: -kv[1])[:3])])
    # HTTPRoutes whose parent conditions fail: the Gateway API equivalent of
    # an ingress pointing at a missing Service.
    rb = _f(bundle, "k8s.httproute.bad_parent_by_ns") or {}
    if rb:
        union |= set(rb)
        detail_by_ns = _f(bundle, "k8s.httproute.bad_parent") or []
        rows.append(["HTTPRoutes with a failing parent",
                     sum(rb.values()), str(len(rb)),
                     ", ".join("%s (%s/%s)" % (d["ns"], d["condition"],
                                                d["reason"])
                               for d in detail_by_ns[:3])])
    if not rows:
        return []
    # No grand total: one crashlooping pod is also a degraded Deployment, so a
    # sum across rows counts the same failure several times.
    changes = []
    for path, e in sorted(bundle["facts"].items()):
        if not path.startswith("k8s.tenant.change."):
            continue
        c = e.get("value") or {}
        key = path.rsplit(".", 1)[-1]
        bits = []
        if c.get("delta"):
            bits.append("%+d" % c["delta"])
        if c.get("regress"):
            bits.append("regressed: %s" % ",".join(c["regress"][:3]))
        persist = [(ns, n) for ns, n in (c.get("persist") or []) if n >= 3]
        if persist:
            bits.append("persistent: %s" % ", ".join(
                "%s ×%d" % (ns, n) for ns, n in persist[:3]))
        if bits:
            changes.append("%s: %s (%s)" % (key, c.get("count") or 0,
                                            "; ".join(bits)))
    f = _finding(
        "K8S_TENANT_WORKLOADS", "info",
        "Tenant workloads: issues in %s%d namespace(s)"
        % ("at least " if partial else "", len(union)),
        detail=(["%s: %s in %s namespace(s); most: %s" % tuple(r) for r in rows]
                + changes),
        evidence=["k_pods", "k_deployments", "k_statefulsets", "k_jobs",
                  "k_cronjobs", "k_pvc"],
        metric=float(len(union)))
    f["section"] = "Tenant workloads"
    f["section_order"] = 10
    f["table"] = {"headers": ["condition", "count", "namespaces", "most affected"],
                  "align": ["l", "r", "r", "l"],
                  "rows": rows,
                  "note": ("Tenant namespaces are summarised, not alarmed on: "
                           "these are the tenants' own workloads. Platform "
                           "namespaces are reported individually above. "
                           "Set KAREL_PLATFORM_NAMESPACES to add site-specific "
                           "platform namespaces.") +
                          (" ≥ marks rows built from a sample: this bundle "
                           "recorded only the first entries of that condition."
                           if partial else "")}
    out = [f]
    if unobserved:
        out.append(_finding(
            "KAREL_TENANT_CONDITION_UNOBSERVED", "info",
            "%d tenant condition(s) have no data this run" % len(unobserved),
            detail=["%s (%s)" % (l, s) for l, s in unobserved] +
                   ["their rows are omitted from the tenant table - silence "
                    "here is a collection gap, not a clean bill"],
            evidence=sorted({s for _l, s in unobserved})))
    return out


def r_storage_k8s(bundle):
    out = []

    unbound, n = _platform(bundle, "k8s.pvc.unbound")
    if unbound:
        out.append(_finding(
            "K8S_PVC_UNBOUND", "warn",
            "%s%d platform PVC(s) not Bound" % (_atleast(bundle, "k8s.pvc.unbound"), n),
            detail=_more(unbound, n), evidence=["k_pvc"], metric=float(n),
            remediation=["check the csi-provisioner logs for the storage class "
                         "these request",
                         "a Pending PVC blocks every pod that mounts it"]))

    released = _f(bundle, "k8s.pv.released", []) or []
    if released:
        out.append(_finding(
            "K8S_PV_RELEASED", "info",
            "%d PV(s) in Released state" % len(released),
            detail=released[:10], evidence=["k_pv"], metric=float(len(released)),
            remediation=["Released PVs hold storage that will never be reused",
                         "confirm the data is not needed, then delete"]))

    unattached = _f(bundle, "k8s.volumeattachment.unattached_count")
    if unattached:
        out.append(_finding(
            "K8S_VOLUME_ATTACH_STUCK", "warn",
            "%d VolumeAttachment(s) not attached" % unattached,
            detail=_attach_detail(bundle, unattached),
            evidence=["k_volumeattach"], metric=float(unattached),
            remediation=["stuck attachments block pod startup and node drains",
                         "usually the CSI node plugin on the target node"]))
    return out


def _attach_detail(bundle, count):
    """One readable line per stuck attachment: volume, node, driver, victim.

    The attachment name is an internal CSI handle; on its own it tells an
    operator nothing. The useful question is "which volume on which node is
    holding up which pod", so each line answers that, and says explicitly when
    a join could not be made rather than leaving the reader to guess.

    One line per attachment rather than an indented block: report.collapse()
    groups similar lines to fold repetition, which would pull an indented
    sub-line away from the attachment it belongs to.
    """
    stuck = _f(bundle, "k8s.volumeattachment.unattached", []) or []
    claims = _f(bundle, "k8s.pv.claims", {}) or {}
    users = _f(bundle, "k8s.pvc.pod_users", {}) or {}

    lines = []
    for a in stuck[:10]:
        # Older bundles recorded bare names; keep them readable instead of
        # crashing or printing a dict of nonsense.
        if not isinstance(a, dict):
            lines.append("attachment %s: no further detail in this bundle" % a)
            continue
        pv = a.get("pv") or "?"
        claim = claims.get(pv)
        line = "attachment %s: volume %s" % (a.get("name") or "?", pv)
        if claim:
            line += " (claim %s)" % claim
        line += " -> node %s, driver %s" % (a.get("node") or "?",
                                            a.get("driver") or "?")
        waiters = users.get(claim) if claim else None
        if waiters:
            shown = ", ".join(waiters[:3])
            more = "" if len(waiters) <= 3 else " (+%d more)" % (len(waiters) - 3)
            line += ", blocks %s%s" % (shown, more)
        elif claim:
            line += ", blocks no pod currently mounting this claim"
        else:
            line += (", blocked pod unknown (the PV's claimRef was not recorded)")
        if a.get("error"):
            line += "; attach error: %s" % short_error(a["error"], 140)
        lines.append(line)
    if count > len(stuck[:10]):
        lines.append("... %d more (findings.json)" % (count - len(stuck[:10])))
    return lines


# API groups served by the apiserver itself. A fail-closed webhook on any of
# these with no backend blocks ordinary cluster operations (Pods, Deployments,
# Namespaces); one on a CRD group blocks only that CRD.
BUILTIN_API_GROUPS = {
    "", "*", "apps", "batch", "autoscaling", "policy", "networking.k8s.io",
    "rbac.authorization.k8s.io", "storage.k8s.io", "admissionregistration.k8s.io",
    "apiextensions.k8s.io", "apiregistration.k8s.io", "coordination.k8s.io",
    "discovery.k8s.io", "events.k8s.io", "node.k8s.io", "scheduling.k8s.io",
    "certificates.k8s.io", "flowcontrol.apiserver.k8s.io", "resource.k8s.io",
    "authentication.k8s.io", "authorization.k8s.io", "internal.apiserver.k8s.io",
    "storagemigration.k8s.io",
}


def r_webhooks(bundle):
    """A fail-closed webhook with no backend rejects every write it matches.

    One finding per backing Service: fourteen hooks in two configurations
    pointing at one dead Service are one problem with one fix, and were being
    reported as fourteen CRITs that buried everything else.

    Severity follows what the hooks intercept:
      built-in resources               CRIT  (ordinary operations are blocked)
      CRD groups that are installed    WARN  (only those objects are blocked)
      CRD groups that are not installed INFO (a leftover that matches nothing)
      not recorded (older bundle)      CRIT  (unknown is not safe)
    """
    out = []
    endpoints = _f(bundle, "k8s.service.ready_endpoints", {}) or {}
    if not endpoints:
        return out
    services = _f(bundle, "k8s.service.names")
    services = set(services) if services is not None else None
    crd_groups = _f(bundle, "k8s.crd.groups")
    crd_groups = set(crd_groups) if crd_groups is not None else None

    down = {}
    for kind in ("validating", "mutating"):
        entries = _f(bundle, "k8s.webhook.%s" % kind, {}) or {}
        for key, w in sorted(entries.items()):
            if w.get("failurePolicy") != "Fail":
                continue
            svc = w.get("service")
            if not svc:
                continue                      # URL-based webhook, cannot check here
            if endpoints.get(svc, 0) == 0:
                down.setdefault(svc, []).append((kind, key, w))
                continue
            to = w.get("timeoutSeconds")
            if to and to > 15:
                out.append(_finding(
                    "K8S_WEBHOOK_LONG_TIMEOUT", "info",
                    "Webhook %s has a %ss timeout" % (key, to), subject=key,
                    evidence=["k_%swh" % kind],
                    remediation=["long fail-closed timeouts amplify apiserver latency "
                                 "when the backend is slow"]))

    for svc, hooks in sorted(down.items()):
        configs = sorted({w.get("configuration") or k.split("/", 1)[0]
                          for _, k, w in hooks})
        kinds = sorted({kd for kd, _, _ in hooks})
        known = all("api_groups" in w for _, _, w in hooks)
        groups = set()
        for _, _, w in hooks:
            groups.update(w.get("api_groups") or [])
        narrowed = any(w.get("namespace_selector") or w.get("object_selector")
                       for _, _, w in hooks)

        if services is not None:
            missing = svc not in services
            state = "does not exist" if missing else "has no ready endpoints"
        else:
            # No Service list in this bundle. An EndpointSlice exists for every
            # selector Service, even with zero endpoints - so no slice at all
            # means the Service is most likely gone.
            missing = svc not in endpoints
            state = ("has no EndpointSlice - the Service most likely no longer "
                     "exists" if missing else "has no ready endpoints")

        if not known:
            sev = "crit"
            scope_line = ("intercepted resources: not recorded (older bundle, or "
                          "no rules in the configuration) - treated as "
                          "cluster-wide until known")
        elif groups & BUILTIN_API_GROUPS:
            sev = "crit"
            scope_line = "intercepts built-in resources: %s" % ", ".join(
                sorted({r for _, _, w in hooks for r in (w.get("resources") or [])
                        if r.split("/", 1)[0] in
                        {"core" if g == "" else g for g in BUILTIN_API_GROUPS}})[:8]
                or sorted(groups & BUILTIN_API_GROUPS))
        elif crd_groups is not None and not (groups & crd_groups):
            sev = "info"
            scope_line = ("intercepts only API groups with no CRD installed (%s) - "
                          "nothing can match, so nothing is blocked today"
                          % ", ".join(sorted(groups)))
        else:
            sev = "warn"
            scope_line = "writes to %s are rejected; other API groups are unaffected" \
                % ", ".join(sorted(groups))

        title = ("%d fail-closed %s webhook(s) point at %s, which %s"
                 % (len(hooks), "/".join(kinds), svc,
                    ("does not exist" if services is not None else
                     "has no endpoints (Service likely gone)") if missing
                    else "has no ready endpoints"))
        if sev == "info":
            title = ("Leftover webhook configuration(s) %s point at missing %s"
                     % (", ".join(configs), svc))
        detail = ["service: %s - %s" % (svc, state),
                  "configuration(s): %s" % ", ".join(configs),
                  scope_line]
        if narrowed:
            detail.append("some hooks are narrowed by a namespace/object selector, "
                          "so the real blast radius may be smaller")
        detail += ["hooks:"] + ["  %s" % k for _, k, _ in hooks[:10]]
        if len(hooks) > 10:
            detail.append("  ... %d more" % (len(hooks) - 10))

        rem = (["the Service is gone: if its component was uninstalled or moved, "
                "delete the leftover configuration(s): " +
                "; ".join("`kubectl delete %swebhookconfiguration %s`" % (kd, c)
                          for kd, c in sorted({(kd, w.get("configuration")
                                                 or k.split("/", 1)[0])
                                                for kd, k, w in hooks}))]
               if missing else
               ["restore the backing pods, or temporarily set failurePolicy: "
                "Ignore to unblock writes"])
        out.append(_finding(
            "K8S_WEBHOOK_FAIL_CLOSED_DOWN", sev, title, subject=svc,
            detail=detail,
            evidence=sorted({"k_%swh" % kd for kd in kinds}) + ["k_endpointslices"],
            metric=float(len(hooks)), remediation=rem))
    return out


def r_certs(bundle):
    out = []
    days = _f(bundle, "k8s.cert.apiserver_days_remaining")
    if days is not None:
        sev = ("crit" if days <= K8S_THRESHOLDS["cert_days_crit"]
               else "warn" if days <= K8S_THRESHOLDS["cert_days_warn"] else None)
        if sev:
            out.append(_finding(
                "K8S_APISERVER_CERT_EXPIRY", sev,
                "apiserver serving certificate expires in %d days" % days,
                detail=["not after: %s" % _f(bundle, "k8s.cert.apiserver_not_after")],
                evidence=["k_tls_probe"], metric=float(-days),
                remediation=["RKE2 rotates on restart when within ~90 days",
                             "restarting rke2-server on each node in turn is the "
                             "normal remedy - do one node at a time"]))

    err = _f(bundle, "k8s.cert.apiserver_probe_error")
    if err:
        out.append(_finding(
            "KAREL_CERT_PROBE_FAILED", "warn",
            "Certificate probe failed - expiry is unknown",
            detail=[str(err)[:160]], evidence=["k_tls_probe"],
            remediation=["cert expiry is the classic RKE2 outage; not knowing is bad"]))

    # standing, unresolvable-from-a-pod gap: state it every run, at info level
    out.append(_finding(
        "KAREL_CERT_COVERAGE_GAP", "info",
        "Kubelet and etcd certificate expiry is not visible from inside a pod",
        detail=_f(bundle, "k8s.cert.coverage_gaps", []) or
               ["per-node certs under /var/lib/rancher/rke2 are not readable here"],
        evidence=["k_tls_probe"],
        remediation=["run `rke2 certificate check` on each node, or publish its "
                     "output via a node-level DaemonSet for Karel to read"]))
    return out


_NODE_REASONS = {"NodeNotReady", "OOMKilling", "SystemOOM", "Evicted", "Rebooted",
                 "FailedCreatePodSandBox", "NodeHasDiskPressure",
                 "NodeHasInsufficientMemory", "FreeDiskSpaceFailed",
                 "ImageGCFailed", "ContainerGCFailed"}
_POD_REASONS = {"FailedScheduling", "FailedMount", "FailedAttachVolume",
                "ProvisioningFailed", "ErrImagePull", "ImagePullBackOff", "Unhealthy"}


# ---------------------------------------------------------------- acme/cert
ACME_SOLVER_PORT = 8089


def _netpol_blocks(ns, netpols, ingress_ns):
    """Deliberately narrow: a default-deny ingress policy in the solver's
    namespace, and no rule admitting the solver port from the ingress
    controller's own namespace. Full policy evaluation is out of scope."""
    rules = netpols.get(ns) or []
    default_deny = any(r.get("empty_ingress") or
                       (not r.get("ingress") and "Ingress" in r.get("types", []))
                       for r in rules)
    if not default_deny:
        return False
    for r in rules:
        for ir in r.get("ingress") or []:
            ports = ir.get("ports") or []
            if ports and ACME_SOLVER_PORT not in ports and str(ACME_SOLVER_PORT) not in [str(p) for p in ports]:
                continue
            froms = ir.get("from") or []
            if not froms:
                return False          # open to all: covered
            # any namespaced selector can name the controller ns; selectors
            # are not resolved, so only an EMPTY from or an all-selector pass
            # as clearly admit. Stay conservative: presence of ANY explicit
            # selector means "review", per the spec's narrow contract.
    return True


def r_acme(bundle):
    out = []
    certs_expired = _f(bundle, "k8s.acme.certificates_expired") or []
    certs_expiring = _f(bundle, "k8s.acme.certificates_expiring_not_ready") or []
    if certs_expired or certs_expiring:
        out.append(_finding(
            "ACME_CERT_EXPIRING", "crit",
            "%d certificate(s) expired, %d expiring inside 7 days and not "
            "Ready" % (len(certs_expired), len(certs_expiring)),
            detail=sorted(certs_expired + certs_expiring)[:15] +
                   ["this is the impact signal - the solvers below are only "
                    "the cause"],
            evidence=["k_acme_certificates"],
            remediation=["renew via cert-manager; check the linked "
                         "Challenge for the failing validation"]))
    solvers = _f(bundle, "k8s.acme.solvers_stale", []) or []
    if not solvers:
        return out

    dns = _f(bundle, "k8s.acme.dns", {}) or {}
    expected = _f(bundle, "k8s.acme.dns_expected", []) or []
    challenges = _f(bundle, "k8s.acme.challenges", []) or []
    ch_by_ns = {}
    for c in sorted(challenges, key=lambda c: (c.get("ns"), c.get("dnsName") or "")):
        if c.get("dnsName"):
            ch_by_ns.setdefault(c.get("ns"), []).append(c.get("dnsName"))
    netpols = _f(bundle, "k8s.netpol.by_ns", {}) or {}
    ingress_ns = os.environ.get("KAREL_ACME_INGRESS_NS", "ingress-nginx")

    # Solver and challenge cohabit the namespace; pair them by sorted name
    # (both are numbered per challenge). An ns with more solvers than
    # challenges leaves the extra solvers in the unexplained bucket.
    dns_bad, netpol_bad, stale = [], [], []
    solvers_by_ns = {}
    for s in sorted(solvers, key=lambda s: s["pod"]):
        solvers_by_ns.setdefault(s["ns"], []).append(s)
    for ns, pods in sorted(solvers_by_ns.items()):
        hosts = ch_by_ns.get(ns) or []
        for idx, s in enumerate(pods):
            host = hosts[idx] if idx < len(hosts) else None
            d = dns.get(host) if host else None
            if d and d.get("status") in ("nxdomain", "nodata", "servfail",
                                         "differ", "error"):
                dns_bad.append("%s — %s %s%s" % (
                    s["pod"], host,
                    {"nxdomain": "does not exist (NXDOMAIN)",
                     "nodata": "no records (NODATA/SERVFAIL)",
                     "servfail": "resolver SERVFAIL",
                     "differ": "resolves to %s, expected %s"
                               % (", ".join(d.get("addresses") or []) or "nothing",
                                  ", ".join(expected) or "?"),
                     "error": "dns error"}[d.get("status")],
                    "" if not (s.get("age_h") or 0) else
                    ", solver %.1f h old" % s["age_h"]))
                continue
            if _netpol_blocks(ns, netpols, ingress_ns):
                netpol_bad.append("%s (default-deny ingress in %s, no admit of "
                                  "tcp %d from %s)"
                                  % (s["pod"], ns, ACME_SOLVER_PORT, ingress_ns))
            else:
                stale.append(s["pod"])

    if dns_bad:
        out.append(_finding(
            "ACME_SOLVER_DNS", "warn",
            "%d ACME solver(s) older than 1h have broken DNS" % len(dns_bad),
            detail=sorted(dns_bad)[:15] +
                   ["a certificate cannot validate while its hostname does "
                    "not reach the solver"],
            evidence=["k_acme_solvers", "k_acme_challenges", "k_acme_probe"],
            metric=float(len(dns_bad)),
            remediation=["fix the DNS record or remove the challenge; the "
                         "solver is transient, deleting it just re-creates"]))
    if netpol_bad:
        out.append(_finding(
            "ACME_SOLVER_NETPOL", "warn",
            "%d ACME solver(s) older than 1h are blocked by NetworkPolicy"
            % len(netpol_bad),
            detail=sorted(netpol_bad)[:15] +
                   ["deliberately narrow check: default-deny present, no "
                    "ingress rule matching tcp %d from %s"
                    % (ACME_SOLVER_PORT, ingress_ns)],
            evidence=["k_acme_solvers", "k_networkpolicies"],
            metric=float(len(netpol_bad)),
            remediation=["admit the ingress controller's namespace on the "
                         "solver port, or the http-01 challenge never "
                         "completes"]))
    if stale:
        out.append(_finding(
            "ACME_SOLVER_STALE", "info",
            "%d ACME solver(s) older than 1h - cause not identified"
            % len(stale),
            detail=sorted(stale)[:15] +
                   ["DNS resolves and no blocking NetworkPolicy matched; "
                    "inspect the challenge and the solver pod logs"],
            evidence=["k_acme_solvers"],
            metric=float(len(stale))))
    return out


def r_events(bundle):
    """Node and platform warning events (buffered when the CronJob runs).
    Node-level reasons justify a WARN; pod-level reasons are permanent
    background on a shared cluster and are INFO."""
    out = []
    node_by_reason = _f(bundle, "k8s.events.node_by_reason")
    plat_by_reason = _f(bundle, "k8s.events.platform_by_reason")
    if node_by_reason is None and plat_by_reason is None:
        return out    # not collected (live) and no buffer - nothing to say

    node_keys = _f(bundle, "k8s.events.node_keys") or {}
    plat_keys = _f(bundle, "k8s.events.platform_keys") or {}
    out += r_event_buffer_state(bundle)

    node_by_reason = node_by_reason or {}
    plat_by_reason = plat_by_reason or {}
    node_level = sorted(r for r in node_by_reason if r in _NODE_REASONS)
    pod_level = {r: n for r, n in plat_by_reason.items() if r in _POD_REASONS}

    if node_level or pod_level:
        samples = sorted(node_keys)[:5] + sorted(plat_keys)[:5]
        f = _finding(
            "K8S_EVENT_PATTERN",
            "warn" if node_level else "info",
            ("Node-level events in the collection window: %s"
             % ", ".join(node_level)) if node_level else
            "Pod-level platform warning events present: %s"
            % ", ".join(k for k, _ in
                        sorted(pod_level.items(), key=lambda kv: -kv[1])[:5]),
            detail=["%s x%d" % (k, v) for k, v in
                    sorted(list(node_by_reason.items()) +
                           list(pod_level.items()),
                           key=lambda kv: -kv[1])] +
                   (["", "sample keys:"] +
                    ["%s x%d" % (k, (node_keys.get(k) or plat_keys.get(k)
                                   or {}).get("count") or 0)
                     for k in samples] if samples else []),
            evidence=["k_event_buffer", "k_events"],
            # Deliberately NOT the cumulative count. Event counters only ever
            # rise while a condition persists, so using them as the metric
            # makes the finding escalate on every run for a known problem -
            # which trains people to ignore escalation.
            metric=float(len(node_level) + len(pod_level)),
            remediation=["event counters are cumulative while the condition "
                         "lasts; the key names node or workload and reason"])
        out.append(f)
    return out


# Tenant event bursts with a platform suspect. One tenant's FailedMount is
# their storage class; the same reason in 40 namespaces is the CSI driver.
def r_tenant_event_patterns(bundle):
    out = []
    patterns = _f(bundle, "k8s.events.patterns") or {}
    thr = K8S_THRESHOLDS["tenant_event_pattern_namespaces"]
    for reason, p in sorted(patterns.items()):
        ns_count = p.get("ns_count") or 0
        if ns_count < thr:
            continue          # below threshold: a row in the tenant summary
        out.append(_finding(
            "K8S_TENANT_EVENT_PATTERN", "warn",
            "%s in %d tenant namespaces — %s suspected"
            % (reason, ns_count, p.get("suspect") or "platform component"),
            subject=reason,
            detail=["%d events across %d tenant namespaces in the window"
                    % (p.get("count") or 0, ns_count),
                    "most affected: %s"
                    % (", ".join("%s (%d)" % (ns, n)
                                 for ns, n in (p.get("top") or [])[:5])
                       or "?"),
                    "the same reason at this breadth points at shared "
                    "platform infrastructure, not at any one tenant"],
            evidence=["k_event_buffer", "k_events"], metric=float(ns_count),
            remediation=["check %s before asking tenants to change anything"
                         % (p.get("suspect") or "the platform")]))
    return out


def r_event_buffer_state(bundle):
    """A stopped or partially denied buffer CronJob is a coverage gap, listed
    under What this report cannot see - never a quiet night taken at face
    value."""
    out = []
    buf = _f(bundle, "k8s.events.buffer")
    if not buf:
        return out
    stale_m = K8S_THRESHOLDS["event_buffer_stale_minutes"]
    age = buf.get("last_write_age_m")
    failed = buf.get("failed_requests") or []
    if not buf.get("writes") or (age is not None and age > stale_m) or failed:
        bits = []
        if not buf.get("writes"):
            bits.append("no buffer writes anywhere in the window - the "
                        "buffer CronJob is not running")
        if age is not None and age > stale_m:
            bits.append("last buffer write %.0f min ago (threshold %d)"
                        % (age, stale_m))
        if failed:
            bits.append("failed sub-requests: %s" % ", ".join(failed[:8]))
        out.append(_finding(
            "KAREL_EVENT_BUFFER_STALE", "info",
            "Event buffer is stale or partially failing",
            detail=bits + ["event coverage below may be only part of the "
                           "window - treat silence as unknown, not quiet"],
            evidence=["k_event_buffer"],
            remediation=["check the event-buffer CronJob's logs; a denied "
                         "sub-request usually means RBAC drifted"]))
    return out


def _schedulable(bundle):
    """Nodes that can actually accept a pod right now.

    Cluster-wide capacity ratios that count a NotReady or cordoned node's
    allocatable as available understate pressure - and produce two different
    percentages for the same quantity in one report.
    """
    nodes = _f(bundle, "k8s.node.names", []) or []
    out = set(nodes)
    out -= set(_f(bundle, "k8s.node.not_ready", []) or [])
    out -= set(_f(bundle, "k8s.node.unschedulable", []) or [])
    return out, [n for n in nodes if n not in out]


def r_controlplane_spread(bundle):
    """Which nodes actually run etcd. On a 4-node cluster where 3 are control
    plane, the control plane and the storage quorum fail together."""
    out = []
    etcd = _f(bundle, "k8s.controlplane.etcd_nodes", []) or []
    nodes = _f(bundle, "k8s.node.names", []) or []
    if not etcd:
        return out

    if len(etcd) % 2 == 0:
        out.append(_finding(
            "K8S_ETCD_EVEN_MEMBERS", "warn",
            "etcd has %d members - no more fault tolerance than %d"
            % (len(etcd), len(etcd) - 1),
            detail=["members on: %s" % ", ".join(etcd)],
            evidence=["k_pods"],
            remediation=["an even member count tolerates the same number of "
                         "failures as the odd number below it, with more ways to "
                         "lose quorum"]))

    workers = [n for n in nodes if n not in etcd]
    if workers and len(nodes) > len(etcd):
        out.append(_finding(
            "K8S_CONTROLPLANE_LAYOUT", "info",
            "%d of %d nodes run the control plane" % (len(etcd), len(nodes)),
            detail=["control plane: %s" % ", ".join(sorted(etcd)),
                    "worker only: %s" % ", ".join(sorted(workers)),
                    "losing a control-plane node is strictly worse than losing a "
                    "worker; they are not interchangeable when planning drains"],
            evidence=["k_pods"]))
    return out


def r_node_reservations(bundle):
    """capacity minus allocatable is what the kubelet holds back for itself, the
    container runtime and the OS. Zero means a memory-hungry pod can starve the
    kubelet and take the node NotReady - and that node may also be carrying an
    etcd member."""
    out = []
    reserved = _f(bundle, "k8s.node.reserved_mem_bytes", {}) or {}
    if not reserved:
        return out

    none_reserved = sorted(n for n, v in reserved.items() if not v)
    etcd = set(_f(bundle, "k8s.controlplane.etcd_nodes", []) or [])

    if none_reserved:
        critical = sorted(set(none_reserved) & etcd)
        out.append(_finding(
            "K8S_NO_RESERVED_MEMORY", "crit" if critical else "warn",
            "%d node(s) reserve no memory for the kubelet and OS" % len(none_reserved),
            detail=["nodes: %s" % ", ".join(none_reserved)] +
                   (["of these, %s also run etcd - losing the kubelet there takes "
                     "a quorum member with it" % ", ".join(critical)]
                    if critical else []) +
                   ["allocatable equals capacity, so pods may be scheduled up to "
                    "the last byte of RAM",
                    "under pressure the kubelet, containerd and etcd compete with "
                    "pods for memory, and the OOM killer decides"],
            evidence=["k_nodes"], metric=float(len(none_reserved)),
            remediation=["set kubelet system-reserved and/or kube-reserved memory",
                         "on RKE2: --kubelet-arg system-reserved=memory=<N>Gi",
                         "size it for kubelet + containerd + the static pods that "
                         "node runs, not a round number"]))

    values = sorted(set(reserved.values()))
    if len(values) > 1:
        out.append(_finding(
            "K8S_NODE_RESERVATION_DRIFT", "warn",
            "Nodes disagree on reserved memory",
            detail=["%s: %s reserved" % (n, _human_bytes(v))
                    for n, v in sorted(reserved.items())],
            evidence=["k_nodes"],
            remediation=["a node configured differently from its peers behaves "
                         "differently under pressure, and drain planning that "
                         "assumes uniformity is wrong",
                         "usually one node was provisioned from a newer template"]))
    return out


def r_image_cache(bundle):
    """Nodes whose ephemeral storage is small for the images they run.

    The image total is the sum of sizeBytes over node.status.images. That list
    is capped (50 entries by default) and counts shared layers once per image,
    so it is an order of magnitude, not a disk measurement - it once produced
    "118% of ephemeral storage". What IS reliable is ephemeral capacity itself,
    so the signal is a node far smaller than its peers carrying images of the
    same size: the first candidate for DiskPressure and image-GC churn.
    """
    out = []
    names = _f(bundle, "k8s.node.names", []) or []
    eph = {n: _f(bundle, "k8s.node.%s.ephemeral_alloc_bytes" % n) for n in names}
    eph = {n: v for n, v in eph.items() if v}
    if len(eph) < 3:
        return out
    vals = sorted(eph.values())
    median = vals[len(vals) // 2]
    small = []
    for n, v in sorted(eph.items()):
        img = _f(bundle, "k8s.node.%s.image_cache_bytes" % n)
        if not img:
            continue
        if v < 0.25 * median and img >= 0.5 * v:
            small.append((v, n, img))
    if not small:
        return out
    small.sort()
    v, n, img = small[0]
    out.append(_finding(
        "K8S_EPHEMERAL_STORAGE_OUTLIER", "info",
        "%s has %s of ephemeral storage, ~1/%d of a typical node, for images "
        "of the same size" % (n.split(".")[0], _human_bytes(v),
                              max(2, round(median / v))),
        detail=["%s: ephemeral %s, reported images ~%s"
                % (nn, _human_bytes(vv), _human_bytes(ii)) for vv, nn, ii in small] +
               ["median node: %s" % _human_bytes(median),
                "image sizes are the kubelet's capped list with shared layers "
                "counted per image - an order of magnitude, not disk usage",
                "no DiskPressure is set today; watch for image GC and evictions"],
        evidence=["k_nodes"], metric=float(len(small)),
        remediation=["enlarge the node's kubelet/containerd filesystem, or keep "
                     "image-heavy workloads off it"]))
    return out


def r_resource_waste(bundle):
    """24-hour average usage vs request, from k8s-pod-resource-usage.

    The pool was 90% CPU-requested while nodes sat at 10-40% - the cluster
    only LOOKS full. Tenant workloads, so a summary table section, not
    per-pod findings. "No series" is kept distinct from "measured 0%": the
    first may be broken metrics, the second is an idle card."""
    out = []
    cpu_err = _f(bundle, "k8s.usage.cpu.error") or \
        _f(bundle, "k8s.usage.cpu.parse_error")
    gpu_err = _f(bundle, "k8s.usage.gpu.error") or \
        _f(bundle, "k8s.usage.gpu.parse_error")
    for res, err in (("cpu", cpu_err), ("gpu", gpu_err)):
        if err:
            out.append(_finding(
                "KAREL_USAGE_NOT_COLLECTED", "info",
                "%s usage table not available this run" % res.upper(),
                subject=res,
                detail=[err,
                        "the waste section is absent - that is a coverage "
                        "gap, not proof there is no waste"],
                evidence=["k_top_%s" % res]))
    cpu_total = _f(bundle, "k8s.usage.cpu.total_pods")
    gpu_total = _f(bundle, "k8s.usage.gpu.total_pods")
    if cpu_total is None and gpu_total is None:
        return out

    # pod -> node -> GPU model, for the GPUs an idle pod is attached to
    pod_node = {}
    for node, pods in (_f(bundle, "k8s.node.pod_names", {}) or {}).items():
        for nn in pods:
            pod_node[nn] = node
    gpu_models = _f(bundle, "k8s.node.gpu_labels", {}) or {}

    def _model(nn):
        node = pod_node.get(nn)
        if node:
            return (gpu_models.get(node) or {}).get("nvidia.com/gpu.product") or ""
        return ""

    sections = []
    if cpu_total is not None:
        top = _f(bundle, "k8s.usage.cpu.top", []) or []
        waste = _f(bundle, "k8s.usage.cpu.waste_total") or 0
        young = _f(bundle, "k8s.usage.cpu.excluded_young") or 0
        sections.append(("CPU", "%d pods measured, %.1f cores wasted total"
                         % (cpu_total, waste), top, young))
    if gpu_total is not None:
        topg = _f(bundle, "k8s.usage.gpu.top_gpu", []) or []
        young = _f(bundle, "k8s.usage.gpu.excluded_young") or 0
        ns_n = _f(bundle, "k8s.usage.gpu.no_series") or 0
        waste = _f(bundle, "k8s.usage.gpu.waste_total") or 0
        sections.append(("GPU", "%d pods, %.0f cards wasted, %d with no "
                         "usage series at all" % (gpu_total, waste, ns_n),
                         topg, young))
    if not sections:
        return out

    n_excl = _f(bundle, "k8s.usage.cpu.excluded_namespaces")
    detail = []
    for label, headline, _top, young in sections:
        detail.append("%s: %s%s" % (label, headline,
                      ("; %d pod(s) under 12h excluded" % young) if young
                      else ""))
    f = _finding(
        "K8S_TENANT_RESOURCE_WASTE", "info",
        "Resource waste (24 h average vs request)",
        detail=detail +
               (["excluded namespaces per suppression ledger: %s"
                 % ", ".join(_f(bundle, "k8s.usage.cpu.excluded_namespaces")
                             or [])] if n_excl else []),
        evidence=["k_top_cpu", "k_top_gpu"],
        metric=round(sum(s[1] and _f(bundle, "k8s.usage.cpu.waste_total") or 0
                         for s in sections), 1))
    f["section"] = "Resource waste"
    f["section_order"] = 25

    rows_cpu = []
    rows_gpu = []
    for label, _headline, top, _young in sections:
        if label == "CPU":
            rows_cpu = top
        else:
            rows_gpu = top
    tables = []
    if rows_cpu:
        tables.append({"title": "top 20 CPU waste (cores)",
                       "headers": ["pod", "request", "avg 24h", "waste", "age"],
                       "align": ["l", "r", "r", "r", "r"],
                       "rows": rows_cpu})
    gpu_reqs = _f(bundle, "k8s.pod.gpu_requests", {}) or {}
    if rows_gpu:
        gpu_table_rows = []
        mem_annotated = 0
        for nn, u, r, m, a in rows_gpu:
            br = gpu_reqs.get(nn) or {}
            if not br.get("cards") and not br.get("mig") and \
                    br.get("gpu_mem_gb"):
                # gpu-mem is the JupyterHub shared-memory quota (GiB),
                # silently summed into the card column by the binary.
                r = "%s gpu-mem" % r
                mem_annotated += 1
            gpu_table_rows.append([nn, u, r, m or _model(nn), a])
        tables.append({
            "title": "top 30 GPU rows (no-series first)",
            "headers": ["pod", "usage", "request", "model", "age"],
            "align": ["l", "r", "r", "l", "r"],
            "rows": gpu_table_rows,
            "note": ("request marked 'gpu-mem' is JupyterHub shared-memory "
                     "quota (GiB), not whole GPUs; the binary cannot split "
                     "them out, Karel restores the unit." if mem_annotated
                     else None),
        })
    if len(tables) == 1:
        f["table"] = tables[0]
    else:
        f["tables"] = tables
    out.append(f)
    return out


def r_gateway(bundle):
    """Gateway API: the CRDs may be absent (skip quietly and say so), or the
    plane is healthy (a zero-fault line - a clean check still says it ran),
    or individual objects are broken."""
    out = []
    g_count = _f(bundle, "k8s.gateway.count")
    r_count = _f(bundle, "k8s.httproute.count")
    cmds = bundle["collection"]["commands"]
    missing = [n for n in ("k_gateways", "k_httproutes")
               if cmds.get(n) and cmds[n].get("status") in ("failed", "eacces")
               and cmds[n].get("expected") != "ok"]
    if missing and g_count is None and r_count is None:
        out.append(_finding(
            "KAREL_GATEWAY_CRD_ABSENT", "info",
            "Gateway API CRDs are not installed (or not readable) here",
            detail=["the gateway checks were skipped; ingress checks are "
                    "unaffected"],
            evidence=missing))
        return out
    if g_count is None and r_count is None:
        return out

    for g in _f(bundle, "k8s.gateway.not_ready", []) or []:
        out.append(_finding(
            "K8S_GATEWAY_NOT_READY", "warn",
            "Gateway %s not ready" % g["nn"], subject=g["nn"],
            detail=g.get("issues") or [],
            evidence=["k_gateways"],
            remediation=["the Gateway's own condition names the controller's "
                         "reason - read the gateway controller for it"]))

    bad = _f(bundle, "k8s.httproute.bad_parent") or []
    if not bad and not _f(bundle, "k8s.gateway.not_ready"):
        out.append(_finding(
            "K8S_GATEWAY_HEALTHY", "info",
            "%d Gateways, %d HTTPRoutes, all accepted"
            % (g_count or 0, r_count or 0),
            evidence=["k_gateways", "k_httproutes"]))
    elif (g_count or 0) or (r_count or 0):
        out.append(_finding(
            "K8S_GATEWAY_PARTIAL", "info",
            "%d Gateways, %d HTTPRoutes - %d route(s) failing"
            % (g_count or 0, r_count or 0, len(bad)),
            evidence=["k_gateways", "k_httproutes"]))
    return out


def r_cnpg(bundle):
    """CloudNativePG: per-cluster health from the operator's own status.
    The CRD may be absent (a quiet cannot-see note, like the Gateway CRDs);
    a cluster with no ready instances is a database down (CRIT), anything
    else degraded is WARN; a healthy fleet prints its one line so the check
    is visibly done."""
    cmds = bundle["collection"]["commands"]
    count = _f(bundle, "k8s.cnpg.count")
    c = cmds.get("k_cnpg_clusters")
    if count is None and c and c.get("status") in ("failed", "eacces") \
            and c.get("expected") != "ok":
        return [_finding(
            "KAREL_CNPG_CRD_ABSENT", "info",
            "CloudNativePG CRDs are not installed (or not readable) here",
            detail=["the CNPG cluster checks were skipped"],
            evidence=["k_cnpg_clusters"])]
    if count is None:
        return []

    out = []
    unhealthy = _f(bundle, "k8s.cnpg.unhealthy", []) or []
    for u in unhealthy:
        down = u.get("ready") == 0 and (u.get("instances") or 0) > 0
        ns, _, name = u["nn"].partition("/")
        out.append(_finding(
            "K8S_CNPG_CLUSTER_UNHEALTHY", "crit" if down else "warn",
            "CNPG cluster %s: %s" % (u["nn"], "; ".join(u["issues"])),
            subject=u["nn"], detail=u["issues"],
            evidence=["k_cnpg_clusters"],
            remediation=["`kubectl -n %s describe cluster.postgresql.cnpg.io "
                         "%s` - the operator names the blocker on the "
                         "cluster's conditions" % (ns, name)]))
    if not unhealthy:
        out.append(_finding(
            "K8S_CNPG_HEALTHY", "info",
            "%d CNPG clusters, all healthy" % count,
            evidence=["k_cnpg_clusters"]))
    return out


def r_failure_patterns(bundle):
    """Deterministic root-cause groupings the AI layer names. The same image
    repo failing to pull across many namespaces is ONE announcement; floating
    tags (latest, dev, main, no tag) on failing pods is the other."""
    failing = _f(bundle, "k8s.pod.failing") or []
    if not failing:
        return []
    out = []
    by_repo = {}
    for p in failing:
        img = p.get("image") or {}
        ns = p.get("ns")
        if img.get("repo"):
            by_repo.setdefault(img["repo"], set()).add(ns)
    thr = K8S_THRESHOLDS["image_pattern_namespaces"]
    for repo, nss in sorted(by_repo.items()):
        if len(nss) >= thr and any(
                p.get("wait_reason") and "Pull" in (p.get("wait_reason") or "")
                for p in failing if (p.get("image") or {}).get("repo") == repo):
            # spec: registry path deleted upstream, or the tag vanished
            tags = sorted({(p.get("image") or {}).get("tag")
                           for p in failing
                           if (p.get("image") or {}).get("repo") == repo
                           and (p.get("image") or {}).get("tag")} - {None})
            out.append(_finding(
                "K8S_IMAGE_PULL_PATTERN", "warn",
                "image repo `%s` fails to pull in %d namespaces"
                % (repo, len(nss)), subject=repo,
                detail=["a shared cause (tag removed upstream, registry "
                        "outage, auth rot), not %d tenant mistakes"
                        % len(nss)] +
                       (["tags seen: %s" % ", ".join("`%s`" % t for t in tags)]
                        if tags else []),
                evidence=["k_pods"], metric=float(len(nss)),
                remediation=["check the repo upstream/registry for the tag; "
                             "the model layer does not need to name this one"]))
    floating = {}
    for p in failing:
        img = p.get("image") or {}
        tag = img.get("tag")
        if tag in ("latest", "dev", "main") or (img.get("repo") and tag is None):
            repo = "docker.io/%s" % img["repo"] \
                if img.get("registry") == "docker.io" else \
                "%s/%s" % (img.get("registry"), img.get("repo"))
            floating.setdefault("%s:%s" % (repo, tag or "<none>"), set()).add(p.get("ns"))
    if floating:
        out.append(_finding(
            "K8S_FLOATING_TAGS", "info",
            "%d failing pod(s) run on floating tags (latest/dev/main/untagged)"
            % sum(len(v) for v in floating.values()),
            detail=["%s in %d namespace(s)" % (k, len(v))
                    for k, v in sorted(floating.items(),
                                       key=lambda kv: -len(kv[1]))[:10]] +
                   ["a floating tag means the failure is not reproducible "
                    "against what the tag pointed at when deployed"],
            evidence=["k_pods"],
            metric=float(sum(len(v) for v in floating.values()))))
    return out


def r_jupyterhub_cleanup(bundle):
    """The deterministic read of the JupyterHub slot: expired namespaces
    that still exist in-cluster and how much storage sits in them."""
    count = _f(bundle, "external.jupyterhub.pvc_count")
    if not count:
        return []
    expired_n = _f(bundle, "external.jupyterhub.expired_ns_count") or 0
    present_n = _f(bundle, "external.jupyterhub.still_present_count") or 0
    bytes_n = _f(bundle, "external.jupyterhub.pvc_bytes") or 0
    return [_finding(
        "K8S_JUPYTERHUB_CLEANUP", "info",
        "%d expired JupyterHub namespace(s) still in-cluster hold %d PVC(s) "
        "(%s)" % (present_n, count, _human_bytes(bytes_n)),
        detail=["%d expired namespaces reported by the JupyterHub slot"
                % expired_n,
                "this is the cleanup with the clearest owner: JupyterHub "
                "itself says the namespace is expired"],
        evidence=["derive"],
        remediation=["drop the namespaces via the JupyterHub owner list, "
                      "then the matching pvc_unused entries drop with them"])]


def r_request_vs_usage(bundle):
    """Requests are a scheduling reservation, not consumption. When the two
    diverge hard, "86% committed" and "2% used" are both true, and a reader who
    sees only one of them draws the wrong conclusion."""
    out = []
    usage = _f(bundle, "k8s.node.usage", {}) or {}
    reqs = _f(bundle, "k8s.node.requests", {}) or {}
    alloc = _f(bundle, "k8s.node.allocatable_mem_bytes", {}) or {}
    if not usage or not reqs or not alloc:
        return out

    sched, excluded = _schedulable(bundle)
    keys = [n for n in alloc if not sched or n in sched]
    tot_req = sum((reqs.get(n) or {}).get("mem_bytes") or 0 for n in keys)
    tot_alloc = sum(alloc[n] for n in keys)
    tot_used = 0
    for n, u in usage.items():
        if keys and n not in keys:
            continue
        if u.get("mem_bytes"):
            tot_used += u["mem_bytes"]
        elif u.get("mem_pct") is not None and alloc.get(n):
            tot_used += alloc[n] * u["mem_pct"] / 100.0
    if not (tot_req and tot_alloc and tot_used):
        return out

    req_pct = 100.0 * tot_req / tot_alloc
    use_pct = 100.0 * tot_used / tot_alloc
    if req_pct >= 50 and req_pct > use_pct * 3:
        out.append(_finding(
            "K8S_REQUESTS_OVERSTATED", "info",
            "Memory requests are %.0f%% of the cluster but actual use is %.0f%%"
            % (req_pct, use_pct),
            detail=["requested %s, in use %s, allocatable %s"
                    % (_human_bytes(tot_req), _human_bytes(tot_used),
                       _human_bytes(tot_alloc))] +
                   (["computed over the %d schedulable node(s) only; %s "
                     "excluded as unavailable"
                     % (len(keys), ", ".join(sorted(excluded)))]
                    if excluded else []) + [
                    "requests are a scheduling reservation, not consumption",
                    "consequence: the scheduler will refuse to place new pods "
                    "long before the machines are actually short of memory",
                    "the node-loss headroom figures elsewhere in this report are "
                    "reservation arithmetic, so they describe when scheduling "
                    "fails, not when the cluster runs out of RAM"],
            evidence=["k_nodes", "k_pods", "k_top_nodes"],
            metric=round(req_pct - use_pct, 1),
            remediation=["right-sizing requests would recover most of the "
                         "apparent commitment",
                         "do not read this as spare capacity for a node failure - "
                         "after failover the same reservations must still fit"]))
    return out


def r_resource_hygiene(bundle):
    out = []
    total = _f(bundle, "k8s.pod.containers") or 0
    no_cpu = _f(bundle, "k8s.pod.containers_no_cpu_request") or 0
    no_mem = _f(bundle, "k8s.pod.containers_no_mem_request") or 0
    if total and no_cpu:
        pct = 100.0 * no_cpu / total
        if pct >= 10:
            out.append(_finding(
                "K8S_MISSING_REQUESTS", "info",
                "%d of %d containers (%.0f%%) declare no CPU request"
                % (no_cpu, total, pct),
                detail=["%d declare no memory request" % no_mem,
                        "the scheduler cannot reserve what is not requested, so "
                        "every capacity and node-loss figure in this report is a "
                        "LOWER BOUND",
                        "these pods are also the first evicted under node pressure"],
                evidence=["k_pods"], metric=pct,
                remediation=["requests are what make drain and failover planning "
                             "meaningful; without them the numbers are decorative"]))

    be = _f(bundle, "k8s.pod.besteffort_count") or 0
    pods = _f(bundle, "k8s.pod.count") or 0
    if be and pods and 100.0 * be / pods >= 10:
        out.append(_finding(
            "K8S_BESTEFFORT_PODS", "info",
            "%d of %d pods are BestEffort" % (be, pods),
            detail=(_f(bundle, "k8s.pod.besteffort", []) or [])[:10] +
                   ["BestEffort pods are evicted first under node memory pressure"],
            evidence=["k_pods"], metric=float(be)))
    return out


RULES = [
    r_k8s_collection,
    r_tenant_summary,
    r_controlplane_spread,
    r_node_reservations,
    r_image_cache,
    r_request_vs_usage,
    r_resource_hygiene,
    r_apiserver,
    r_etcd,
    r_etcd_snapshot,
    r_nodes,
    r_workloads,
    r_storage_k8s,
    r_webhooks,
    r_certs,
    r_events,
    r_tenant_event_patterns,
    r_acme,
    r_resource_waste,
    r_gateway,
    r_cnpg,
    r_failure_patterns,
    r_jupyterhub_cleanup,
]
