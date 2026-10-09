"""
The findings nobody's dashboard shows.

  * node-loss simulation: what actually breaks if one node dies, computed
    across pods, PDBs and local PVs
  * counter deltas: restarts, apiserver errors, etcd growth

Everything here is arithmetic. The LLM layer narrates it; it never computes it.
"""

from rules import _finding

HEADROOM = {
    "pct_after_loss_warn": 100.0,      # survivors cannot hold the requests
    "restart_delta_warn": 5,
}


def _f(bundle, path, default=None):
    e = bundle["facts"].get(path)
    return e["value"] if e else default


def _human_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for u in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024.0:
            return "%.1f %s" % (n, u)
        n /= 1024.0
    return "%.1f EiB" % n


def _sev_rank(s):
    return {"info": 0, "warn": 1, "crit": 2}.get(s, 0)


# ------------------------------------------------------- node-loss simulation
#
# Losing a node degrades the cluster. That is the definition of losing a node,
# and saying so for each of 51 nodes is not information. The simulation only
# speaks when one node's loss would do something WORSE than lose that node's
# share of capacity:
#
#   * the survivors cannot hold the requests at all (the cluster is not N+1)
#   * etcd cannot lose one more member and keep quorum
#   * a workload that was scaled out for availability has every replica on
#     the one node, so its loss is a full outage of something that looks HA
#
# The headroom numbers themselves are always computed and shown in Key
# metrics, so a quiet report still proves the arithmetic was done.
#
# Deliberately NOT here any more: PDBs (a node that dies ignores them - they
# only matter for a planned drain, see r_drain_blockers), single-replica
# workloads (on a shared cluster, most of them, by the tenants' choice), node-
# local PVs and host-pinned pods (tied to the node by design).

def _blocking_taints(bundle, node):
    t = _f(bundle, "k8s.node.%s.taints" % node) or []
    return [k for k in t if k != "node.kubernetes.io/unschedulable"]


def capacity(bundle):
    """Request headroom over the general-purpose pool, now and after losing
    its largest node. None when the inputs are absent.

    The pool is Ready, uncordoned nodes without a NoSchedule/NoExecute taint:
    a cordoned node accepts nothing, and a tainted (control-plane, dedicated
    GPU, ...) node accepts only what tolerates it. Load is what currently runs
    on the pool - pods on excluded nodes stay where they are.

    This is aggregate arithmetic and therefore OPTIMISTIC: it ignores
    fragmentation, affinity and per-node limits. When it says the survivors
    cannot hold the load, they certainly cannot.
    """
    nodes = _f(bundle, "k8s.node.names", []) or []
    alloc_cpu = _f(bundle, "k8s.node.allocatable_cpu_m", {}) or {}
    alloc_mem = _f(bundle, "k8s.node.allocatable_mem_bytes", {}) or {}
    requests = _f(bundle, "k8s.node.requests")
    if not nodes or requests is None or not (alloc_cpu or alloc_mem):
        return None
    not_ready = set(_f(bundle, "k8s.node.not_ready", []) or [])
    cordoned = set(_f(bundle, "k8s.node.unschedulable", []) or [])

    excluded = {"not ready": [], "cordoned": [], "tainted": []}
    pool = []
    for n in nodes:
        if n in not_ready:
            excluded["not ready"].append(n)
        elif n in cordoned:
            excluded["cordoned"].append(n)
        elif _blocking_taints(bundle, n):
            excluded["tainted"].append(n)
        else:
            pool.append(n)
    taint_fallback = False
    if len(pool) < 2:
        # Every node carries some taint: judge the schedulable nodes instead
        # of reporting nothing, and say so.
        pool = [n for n in nodes if n not in not_ready and n not in cordoned]
        excluded["tainted"] = []
        taint_fallback = True
    if len(pool) < 2:
        return None

    res = {"pool": pool, "excluded": excluded, "taint_fallback": taint_fallback}
    for kind, alloc, rkey in (("cpu", alloc_cpu, "cpu_m"), ("mem", alloc_mem, "mem_bytes")):
        cap = sum(alloc.get(n, 0) for n in pool)
        load = sum((requests.get(n) or {}).get(rkey, 0) for n in pool)
        if not cap:
            continue
        worst = max(pool, key=lambda n: (alloc.get(n, 0), n))
        left = cap - alloc.get(worst, 0)
        res[kind] = {
            "cap": cap, "load": load, "pct": 100.0 * load / cap,
            "worst": worst,
            "pct_after": (100.0 * load / left) if left > 0 else None,
            "deficit": max(0, load - left),
        }
    return res


def derive_capacity(bundle):
    """Store the headroom numbers as facts, so Key metrics always shows them
    and tomorrow's snapshot can diff them - a quiet node-loss section still
    proves the arithmetic was done."""
    cap = capacity(bundle)
    if not cap:
        return bundle
    facts = bundle.setdefault("facts", {})
    for k in ("cpu", "mem"):
        c = cap.get(k)
        if not c:
            continue
        facts["k8s.capacity.%s_req_pct" % k] = {"value": round(c["pct"], 1),
                                               "source": "derive"}
        if c["pct_after"] is not None:
            facts["k8s.capacity.%s_req_pct_after_loss" % k] = {
                "value": round(c["pct_after"], 1), "source": "derive"}
        facts["k8s.capacity.%s_largest_node" % k] = {"value": c["worst"],
                                                    "source": "derive"}
    facts["k8s.capacity.pool_nodes"] = {"value": len(cap["pool"]), "source": "derive"}
    return bundle


def _fmt_amount(kind, v):
    return ("%.0f cores" % (v / 1000.0)) if kind == "cpu" else _human_bytes(v)


def r_node_loss(bundle):
    """What would a single node failure break beyond that node's capacity?"""
    out = []

    # --- 1. is the cluster N+1 for requests at all?
    cap = capacity(bundle)
    if cap:
        short = [k for k in ("cpu", "mem")
                 if cap.get(k) and cap[k]["pct_after"] is not None
                 and cap[k]["pct_after"] > HEADROOM["pct_after_loss_warn"]]
        if short:
            label = {"cpu": "CPU", "mem": "memory"}
            detail = []
            for k in short:
                c = cap[k]
                detail.append(
                    "%s: requests are %.0f%% of the pool now; without %s they "
                    "would be %.0f%% - about %s of pods would have nowhere to go"
                    % (label[k], c["pct"], c["worst"], c["pct_after"],
                       _fmt_amount(k, c["deficit"])))
            ex = cap["excluded"]
            detail.append("pool: %d schedulable node(s)%s" % (
                len(cap["pool"]),
                "".join("; %d %s excluded" % (len(v), k) for k, v in ex.items() if v)))
            detail.append("aggregate arithmetic ignores fragmentation and "
                          "affinity, so the real shortfall is larger, not smaller")
            out.append(_finding(
                "K8S_NOT_N_PLUS_ONE", "warn",
                "Cluster cannot absorb the loss of its largest node (%s)"
                % " and ".join(label[k] for k in short),
                detail=detail, evidence=_EV,
                metric=round(max(cap[k]["pct_after"] for k in short), 1),
                remediation=["add capacity, or accept that a node failure leaves "
                             "pods Pending until it returns",
                             "check whether the cordoned nodes are still meant to "
                             "be out of the pool" if ex.get("cordoned") else
                             "reclaim over-stated requests (see "
                             "K8S_REQUESTS_OVERSTATED if present)"]))

    # --- 2. etcd fault tolerance
    etcd = _f(bundle, "k8s.controlplane.etcd_nodes", []) or []
    if etcd:
        not_ready = set(_f(bundle, "k8s.node.not_ready", []) or [])
        total = len(etcd)
        healthy = [n for n in etcd if n not in not_ready]
        need = total // 2 + 1
        tolerance = len(healthy) - need
        if tolerance < 1:
            degraded_now = len(healthy) < total
            out.append(_finding(
                "K8S_ETCD_NO_FAULT_TOLERANCE", "crit" if degraded_now else "warn",
                "etcd cannot lose one more member without losing quorum",
                detail=["members: %d (%s)" % (total, ", ".join(etcd)),
                        "on NotReady nodes: %s" % (
                            ", ".join(sorted(set(etcd) - set(healthy))) or "none"),
                        "quorum needs %d; the next failure of any of %s makes the "
                        "Kubernetes API unavailable for writes" % (
                            need, ", ".join(healthy) or "them")],
                evidence=["k_nodes", "k_pods"],
                remediation=(["restore the NotReady control-plane node first - "
                              "this is the cluster's only margin"]
                             if degraded_now else
                             ["run 3 (or 5) etcd members so that one failure is "
                              "survivable"])))

    # --- 3. redundancy that is not
    colocated = _f(bundle, "k8s.workload.colocated.platform")
    if colocated is None:
        import scope
        colocated = [i for i in (_f(bundle, "k8s.workload.colocated", []) or [])
                     if scope.is_platform(scope.item_ns(i))]
    if colocated:
        out.append(_finding(
            "K8S_REPLICAS_COLOCATED", "warn",
            "%d platform workload(s) have every replica on one node"
            % len(colocated),
            detail=colocated[:15] + ["losing that node is a full outage of each "
                                     "of these, although they look redundant"],
            evidence=["k_pods"], metric=float(len(colocated)),
            remediation=["add podAntiAffinity or a topologySpreadConstraint on "
                         "kubernetes.io/hostname",
                         "`kubectl rollout restart` respreads them today, but "
                         "nothing stops them converging again"]))
    return out


def r_drain_blockers(bundle):
    """PDBs matter for a planned drain, not for a node that dies."""
    blocking = _f(bundle, "k8s.pdb.blocking")
    if not blocking:
        return []
    n = _f(bundle, "k8s.pdb.blocking_count") or len(blocking)
    return [_finding(
        "K8S_PDB_BLOCKS_DRAIN", "info",
        "%d PDB(s) currently allow zero disruptions - a drain of a node "
        "hosting them will stall" % n,
        detail=blocking[:10] + (["... and %d more" % (n - len(blocking[:10]))]
                                if n > 10 else []),
        evidence=["k_pdb"], metric=float(n),
        remediation=["expected for single-instance databases and minAvailable "
                     "equal to replicas; plan drains with "
                     "`kubectl drain --timeout` and handle these by hand"])]


_EV = ["k_nodes", "k_pods"]


# ------------------------------------------------------------- delta rules
def r_deltas(bundle, prev_facts=None):
    """Rules that need yesterday. prev_facts is injected by the pipeline."""
    out = []
    if not prev_facts:
        return out

    def prev(path):
        return prev_facts.get(path)

    # --- restart increases, per owner. Platform workloads only: a tenant's
    # crashlooping app is already counted in the tenant summary.
    import scope
    jumped, tenant_jumped = [], 0
    for path, entry in bundle["facts"].items():
        if not path.startswith("k8s.restarts."):
            continue
        cur = entry["value"]
        old = prev(path)
        if old is None:
            continue
        delta = cur - old
        if delta >= HEADROOM["restart_delta_warn"]:
            owner = path[len("k8s.restarts."):]
            if scope.is_platform(scope.item_ns(owner)):
                jumped.append("%s +%d (now %d)" % (owner, delta, cur))
            else:
                tenant_jumped += 1
    if jumped:
        out.append(_finding(
            "K8S_RESTART_SPIKE", "warn",
            "%d platform workload(s) restarted repeatedly since the last run"
            % len(jumped),
            detail=sorted(jumped)[:15] + (
                ["(%d tenant workload(s) also restarted repeatedly)" % tenant_jumped]
                if tenant_jumped else []),
            evidence=["k_pods"],
            metric=float(len(jumped)),
            remediation=["a rising restart counter is a live problem; a high but "
                         "static one is history"]))

    # --- apiserver counters.
    # /metrics is served by whichever apiserver the service VIP happened to
    # route to. With more than one instance, consecutive runs may scrape
    # different processes, so a delta is meaningless in BOTH directions - a
    # negative one is not evidence of a restart, and a positive one is not a
    # rate. Say so instead of inventing a conclusion.
    n_api = len(_f(bundle, "k8s.controlplane.apiserver_nodes", []) or [])
    start_now = bundle["facts"].get("k8s.apiserver.start_time")
    start_prev = prev("k8s.apiserver.start_time")
    comparable = n_api <= 1

    tot_now, tot_old = bundle["facts"].get("k8s.apiserver.requests_total"), \
        prev("k8s.apiserver.requests_total")
    err_now, err_old = bundle["facts"].get("k8s.apiserver.requests_5xx_total"), \
        prev("k8s.apiserver.requests_5xx_total")

    if not comparable:
        if tot_now and tot_old and tot_now["value"] != tot_old:
            out.append(_finding(
                "KAREL_APISERVER_METRICS_NOT_COMPARABLE", "info",
                "apiserver counter deltas are not usable with %d instances" % n_api,
                detail=["`kubectl get --raw /metrics` is answered by whichever "
                        "apiserver the service VIP selected",
                        "consecutive runs may hit different processes, so the "
                        "request and error counters cannot be differenced",
                        "gauges in this report (etcd db size, deprecated API "
                        "usage) are still meaningful; rates are not"],
                evidence=["k_apiserver_metrics"],
                remediation=["scrape each apiserver pod individually - a "
                             "Prometheus ServiceMonitor does this and gives real "
                             "rates with history",
                             "until then Karel deliberately reports no apiserver "
                             "error rate rather than a fabricated one"]))
    else:
        restarted = (start_now and start_prev is not None
                     and start_now["value"] != start_prev)
        if restarted:
            out.append(_finding(
                "K8S_APISERVER_RESTARTED", "info",
                "apiserver restarted since the last run",
                detail=["process start time changed, so counters reset"],
                evidence=["k_apiserver_metrics"]))
        elif tot_now and tot_old and err_now is not None and err_old is not None:
            dt = tot_now["value"] - tot_old
            de = err_now["value"] - err_old
            if dt > 0 and de >= 0:
                rate = de / dt
                if rate >= 0.01:
                    out.append(_finding(
                        "K8S_APISERVER_ERROR_RATE", "warn",
                        "apiserver 5xx rate was %.2f%% since the last run"
                        % (rate * 100),
                        detail=["%d errors out of %d requests" % (de, dt)],
                        evidence=["k_apiserver_metrics"], metric=rate * 100,
                        remediation=["correlate with etcd latency and webhook "
                                     "timeouts"]))

    # --- etcd growth
    cur_e = bundle["facts"].get("k8s.etcd.db_bytes")
    old = prev("k8s.etcd.db_bytes")
    if cur_e and old:
        growth = cur_e["value"] - old
        if growth > 50 * 1024 * 1024:
            out.append(_finding(
                "K8S_ETCD_GROWTH", "warn",
                "etcd database grew %s in a day" % _human_bytes(growth),
                detail=["now %s" % _human_bytes(cur_e["value"])],
                evidence=["k_apiserver_metrics"], metric=float(growth),
                remediation=["sustained growth points at object churn - Events, "
                             "Leases, or a controller rewriting status in a loop"]))
    return out


RULES = [
    r_node_loss,
    r_drain_blockers,
]

DELTA_RULES = [r_deltas]
