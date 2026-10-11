"""
Platform vs tenant scope.

On a shared cluster with hundreds of tenant namespaces, "36 containers in
backoff" is mostly tenants' own broken deployments. Ranking that as a CRIT next
to a dead CSI node plugin buries the one thing the operators own.

So every per-object problem list is split here, once, into:

  platform  namespaces the operators run (kube-system, cattle-*, CSI, GPU
            operator, ...). These stay individual findings at their normal
            severity.
  tenant    everything else. Summarised as counts and most-affected
            namespaces - the same shape the old per-namespace analysis
            produced - never as alarms.

KAREL_PLATFORM_NAMESPACES (comma-separated fnmatch globs) EXTENDS the defaults
with site-specific namespaces, e.g. "beegfs,env-injector,clusterwide-*".

This runs as a derivation over the finished bundle, so it behaves identically
on a live run and on a replay of an older bundle.json.
"""

import fnmatch
import os

DEFAULT_PLATFORM_NAMESPACES = (
    "kube-*", "cattle-*", "*-system", "*operator*",
    "calico-*", "tigera-*", "cert-manager", "ingress-nginx", "gpu-operator",
    "csi-*", "metallb*", "kubewarden", "cloudnativepg", "rook-*", "longhorn*",
)


def platform_globs():
    extra = [g.strip() for g in
             os.environ.get("KAREL_PLATFORM_NAMESPACES", "").split(",") if g.strip()]
    return tuple(DEFAULT_PLATFORM_NAMESPACES) + tuple(extra)


def is_platform(ns, globs=None):
    if not ns:
        return False
    for g in globs or platform_globs():
        if fnmatch.fnmatchcase(ns, g):
            return True
    return False


def item_ns(item):
    """Namespace of a 'ns/name...' problem-list entry, or None (cluster-scoped)."""
    s = str(item)
    if "/" not in s:
        return None
    ns = s.split("/", 1)[0]
    return ns if ns and " " not in ns else None


def platform_first(items, globs=None):
    """Order a list so platform entries survive truncation."""
    globs = globs or platform_globs()
    return sorted(items, key=lambda i: (not is_platform(item_ns(i), globs), str(i)))


# (list fact, count fact or None, human label, source command) - the source
# decides "checked, none found" (render a 0 row) from "not checked" (row
# omitted, listed under What this report cannot see).
SPLIT = [
    ("k8s.pod.failed_recent",    "k8s.pod.failed_recent_count",    "pods Failed (last 7 days)",            "k_pods"),
    ("k8s.pod.backoff",          "k8s.pod.backoff_count",          "containers in CrashLoop/ImagePull backoff", "k_pods"),
    ("k8s.pod.oomkilled",        "k8s.pod.oomkilled_count",        "containers with a recent OOMKill",     "k_pods"),
    ("k8s.pod.pending",          "k8s.pod.pending_count",          "pods Pending",                         "k_pods"),
    ("k8s.deployment.degraded",  "k8s.deployment.degraded_count",  "Deployments below desired replicas",   "k_deployments"),
    ("k8s.statefulset.degraded", "k8s.statefulset.degraded_count", "StatefulSets below desired replicas",  "k_statefulsets"),
    ("k8s.daemonset.degraded",   "k8s.daemonset.degraded_count",   "DaemonSets below desired replicas",    "k_daemonsets"),
    ("k8s.job.failed",           "k8s.job.failed_count",           "Jobs failed",                          "k_jobs"),
    ("k8s.cronjob.stale",        "k8s.cronjob.stale_count",        "CronJobs overdue",                     "k_cronjobs"),
    ("k8s.pvc.unbound",          "k8s.pvc.unbound_count",          "PVCs not Bound",                       "k_pvc"),
    ("k8s.deployment.paused",    None,                             "Deployments with rollout paused",      "k_deployments"),
    ("k8s.workload.colocated",   "k8s.workload.colocated_count",   "multi-replica workloads with every replica on one node", "k_pods"),
]

SPLIT_SOURCE = {t[0]: t[3] for t in SPLIT}


def _val(facts, path, default=None):
    e = facts.get(path)
    return e["value"] if e else default


# ------------------------------------------------ day-over-day movement
def _csv_names(v):
    return [s for s in str(v or "").split(",") if s]


def _csv_map(v):
    out = {}
    for part in _csv_names(v):
        if ":" in part:
            k, c = part.rsplit(":", 1)
            try:
                out[k] = int(c)
            except ValueError:
                continue
    return out


def track_ns_movement(put, prev_facts, prefix, key, cur_by_ns, prev_count,
                      cap=300):
    """Per category/condition day-over-day state, stored as scalar snapshot
    facts: current ns set, the ever-union, per-ns run streaks and the top-5
    counts; plus a display fact with the movement for today's report."""
    set_p = "%s.ns_set.%s" % (prefix, key)
    ever_p = "%s.ns_ever.%s" % (prefix, key)
    runs_p = "%s.ns_runs.%s" % (prefix, key)
    top_p = "%s.ns_top.%s" % (prefix, key)

    cur_set = set(cur_by_ns)
    prev_set = set(_csv_names(prev_facts.get(set_p)))
    prev_ever = set(_csv_names(prev_facts.get(ever_p)))
    prev_runs = _csv_map(prev_facts.get(runs_p))
    prev_top = _csv_map(prev_facts.get(top_p))

    runs = {ns: prev_runs.get(ns, 0) + 1 for ns in cur_set}
    ever = prev_ever | cur_set
    if len(ever) > cap:
        ever = set(sorted(ever)[:cap])
    top = sorted(cur_by_ns.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    top_set = {ns for ns, _c in top}
    prev_top_set = set(prev_top)

    put(set_p, ",".join(sorted(cur_set)))
    put(ever_p, ",".join(sorted(ever)))
    put(runs_p, ",".join("%s:%d" % (ns, runs[ns])
                         for ns in sorted(runs, key=lambda i: (-runs[i], i))))
    put(top_p, ",".join("%s:%s" % (ns, c) for ns, c in top))

    change = {
        "count": sum(cur_by_ns.values()),
        "delta": None,
        "enter": sorted(top_set - prev_top_set),
        "leave": sorted(prev_top_set - top_set),
        "regress": sorted(cur_set & (prev_ever - prev_set)),
        "persist": [(ns, runs[ns])
                    for ns in sorted(runs, key=lambda i: (-runs[i], i))
                    if runs[ns] >= 2],
    }
    if prev_count is not None:
        try:
            change["delta"] = int(sum(cur_by_ns.values())) - int(prev_count)
        except (TypeError, ValueError):
            change["delta"] = None
    put("%s.change.%s" % (prefix, key), change)
    return change


def derive(bundle, globs=None, prev_facts=None):
    """Add <list>.platform / .tenant_* facts for every list in SPLIT.

    Exact when the parser recorded <list>_by_ns; otherwise (older bundles) a
    best effort from the possibly-truncated list plus the total count, and the
    result is marked partial rather than presented as exact. Also tracks per
    condition consecutive zero counts (clean runs) for the tenant table.
    """
    globs = globs or platform_globs()
    facts = bundle.setdefault("facts", {})
    prev_facts = prev_facts or {}
    cmds = (bundle.get("collection") or {}).get("commands") or {}

    def put(path, value):
        facts[path] = {"value": value, "source": "derive"}

    for path, count_path, _label, _src in SPLIT:
        items = _val(facts, path)
        if items is None:
            continue                      # ABSENT stays absent
        items = list(items)
        plat = [i for i in items if is_platform(item_ns(i), globs)]
        by_ns = _val(facts, path + "_by_ns")
        total = _val(facts, count_path) if count_path else None
        if total is None:
            total = (sum(by_ns.values()) if isinstance(by_ns, dict) else len(items))

        if isinstance(by_ns, dict):
            tenant = {ns: n for ns, n in by_ns.items() if not is_platform(ns, globs)}
            plat_count = sum(n for ns, n in by_ns.items() if is_platform(ns, globs))
            partial = False
        else:
            tenant = {}
            for i in items:
                ns = item_ns(i)
                if ns and not is_platform(ns, globs):
                    tenant[ns] = tenant.get(ns, 0) + 1
            plat_count = len(plat)
            partial = total > len(items)

        put(path + ".platform", plat)
        put(path + ".platform_count", plat_count)
        put(path + ".tenant_count", max(0, total - plat_count))
        put(path + ".tenant_ns_count", len(tenant))
        put(path + ".tenant_top",
            [[ns, n] for ns, n in sorted(tenant.items(), key=lambda kv: (-kv[1], kv[0]))[:5]])
        if partial:
            # The list is a sample: platform entries may have been cut, and
            # tenant namespace counts are lower bounds.
            put(path + ".partial", True)
            put(path + ".tenant_partial", True)

    # Consecutive clean runs per condition, in the snapshot as scalars. Only
    # a run whose source collected may extend the streak; a blind run ends it.
    for path in SPLIT_SOURCE:
        key = "k8s.tenant.clean_runs.%s" % path.rsplit(".", 1)[-1]
        src = SPLIT_SOURCE[path]
        collected = cmds.get(src, {}).get("status", "ok") == "ok"
        tcount = facts.get(path + ".tenant_count")
        tcount = tcount["value"] if isinstance(tcount, dict) else None
        prev_n = prev_facts.get(key) or 0
        if collected and (tcount or 0) == 0:
            put(key, int(prev_n) + 1)
        else:
            put(key, 0)

    # Day-over-day movement per condition (top5 exchanges, regressions,
    # persistence) - computed from the SAME by_ns data the table shows.
    for path, _count_path, _label, _src in SPLIT:
        by_ns = facts.get(path + "_by_ns")
        by_ns = by_ns["value"] if isinstance(by_ns, dict) else None
        if not isinstance(by_ns, dict):
            raw = facts.get(path)
            if isinstance(raw, dict):
                by_ns = {}
                for item in raw.get("value") or []:
                    ns = item_ns(item)
                    if ns and not is_platform(ns, globs):
                        by_ns[ns] = by_ns.get(ns, 0) + 1
        if not isinstance(by_ns, dict):
            continue
        tenant_ns = {ns: n for ns, n in by_ns.items()
                     if not is_platform(ns, globs)}
        key = path.rsplit(".", 1)[-1]
        prev_count = prev_facts.get(path + ".tenant_count")
        track_ns_movement(put, prev_facts, "k8s.tenant", key, tenant_ns,
                          prev_count)
    return bundle
