"""
Housekeeping: abandoned objects, as a cleanup list per namespace.

The daily report shows only a backlog line and a per-category summary table;
the full list lands in out/housekeeping.md and out/housekeeping.csv. On
2026-10-07, 508 of 3,108 Services had no ready endpoints - the exclusions
below (ExternalName, pods-behind-but-broken, scaled-to-zero, operator-owned,
young) are what reduce that number to genuinely abandoned objects.

Ages live in a separate ConfigMap (karel-housekeeping-state), keyed by object
UID: a deleted and recreated object starts at age 0. An entry disappears only
when its source command collected successfully this run; otherwise it is
kept - a collection failure must not reset ages.

Every item carries a confidence, a reason and an age. Proposed commands exist
only for `certain` categories; pvc_unused never gets one, because the object
is data.
"""

import base64
import csv
import gzip
import io
import json
import os

from rules import _finding
import logscan
import scope

CATEGORIES = {
    #              confidence  tenant-ready after
    "svc_no_backend":           ("likely", 14),
    "lb_ip_abandoned":          ("likely", 7),
    "ingress_backend_missing":  ("certain", 1),
    "ingress_backend_abandoned": ("likely", 14),
    "hpa_target_missing":       ("certain", 1),
    "failed_pods_old":          ("certain", 0),
    "pvc_unused":               ("ask", 30),
    "pv_released":              ("likely", 7),
    "ns_empty":                 ("likely", 30),
    "ns_stuck_terminating":     ("certain", 0),
    "pod_stuck_terminating":    ("certain", 0),
    "acme_solver_stale":        ("certain", 0),
    "acme_cert_expired":        ("likely", 7),
    "gateway_orphaned_route":   ("likely", 7),
    "demo_workload":            ("likely", 30),
}

DEFAULT_DEMO_IMAGES = "paulbouwer/hello-kubernetes"


def _demo_images():
    v = os.environ.get("KAREL_DEMO_IMAGES")
    return [s.strip() for s in (v if v is not None else DEFAULT_DEMO_IMAGES)
            .split(",") if s.strip()]


def _demo_items(bundle, now, items, stats):
    """hello-kubernetes-style leftovers, detected by IMAGE (names are copied
    and renamed; images are not). The interesting content is the MISMATCH:
    exposed with nothing behind it, or running with nothing exposing it."""
    templates = {}
    templates.update(_f(bundle, "k8s.deployment.templates") or {})
    templates.update(_f(bundle, "k8s.statefulset.templates") or {})
    if not templates:
        return
    images = _demo_images()

    def _is_demo(img):
        if not img:
            return False
        base = img.split("@", 1)[0].rsplit(":", 1)[0]
        return any(base == d or base.endswith("/" + d) for d in images)

    demos = {}
    for key, t in templates.items():
        if any(_is_demo(i) for i in (t.get("images") or [])):
            ns = key.split(":", 1)[1].split("/", 1)[0]
            slot = demos.setdefault(ns, {"ns": ns, "deploy": [],
                                         "created": None})
            slot["deploy"].append(key.split(":", 1)[1])
            if not slot["created"] or \
                    (t.get("created") and t["created"] < slot["created"]):
                slot["created"] = t.get("created")
    svcs, ingresses = {}, {}
    for nn, i in (_f(bundle, "k8s.service.info") or {}).items():
        svcs.setdefault(nn.split("/", 1)[0], []).append(nn.split("/", 1)[-1])
    for nn, i in (_f(bundle, "k8s.ingress.info") or {}).items():
        ingresses.setdefault(nn.split("/", 1)[0], []).append(nn.split("/", 1)[-1])
    # demo namespaces are any with a matching deployment, service or ingress
    for ns in sorted(demos):
        n_svc = len(svcs.get(ns) or [])
        n_ing = len(ingresses.get(ns) or [])
        if not (n_svc or n_ing):
            mismatch = "running, nothing exposes it (no Service/Ingress)"
        else:
            mismatch = "%d Deployment(s), %d Service(s), %d Ingress(es)" \
                       % (len(demos[ns]["deploy"]), n_svc, n_ing)
        items.append({
            "ns": ns, "kind": "App", "name": "demo workload",
            "uid": "demo:%s" % ns, "category": "demo_workload",
            "reason": "demo image (%s): %s"
                      % ("/".join(_demo_images()), mismatch),
            "cost": "", "cost_gb": 0.0,
            "created": (demos.get(ns) or {}).get("created"),
            "keep_reason": None,
        })


# Which collector must succeed for a category's aged entries to be pruned.
CAT_SOURCE = {
    "svc_no_backend": "k_services",
    "lb_ip_abandoned": "k_services",
    "ingress_backend_missing": "k_ingresses",
    "ingress_backend_abandoned": "k_ingresses",
    "hpa_target_missing": "k_hpa",
    "failed_pods_old": "k_pods",
    "pvc_unused": "k_pvc",
    "pv_released": "k_pv",
    "ns_empty": "k_namespaces",
    "ns_stuck_terminating": "k_namespaces",
    "pod_stuck_terminating": "k_pods",
    "acme_solver_stale": "k_acme_solvers",
    "acme_cert_expired": "k_acme_certificates",
    "gateway_orphaned_route": "k_httproutes",
    "demo_workload": "k_deployments",
    "gpu_upgrade_blocked": "k_nodes",
}

_PROPOSED = {
    "svc_no_backend": "kubectl delete svc -n {ns} {name}",
    "lb_ip_abandoned": "kubectl delete svc -n {ns} {name}",
    "ingress_backend_missing": "kubectl delete ingress -n {ns} {name}",
    "hpa_target_missing": "kubectl delete hpa -n {ns} {name}",
    "failed_pods_old": "kubectl delete pods -n {ns} --field-selector=status.phase=Failed",
    "ns_empty": "kubectl delete ns {name}",
    "acme_solver_stale": "kubectl delete pod -n {ns} {name}",
}

# ConfigMap ceiling is 1 MiB; the warn fires at 70% of it, measured on the
# ENCODED size actually written (the plain-JSON size was once above the
# failure point, and nothing warned).
STATE_LIMIT_BYTES = 1024 * 1024
STATE_WARN_BYTES = int(STATE_LIMIT_BYTES * 0.70)


# ------------------------------------------------------------- state codec
# The age state is persisted gzipped and base64-encoded in the ConfigMap's
# binaryData: this JSON is highly repetitive and compresses by an order of
# magnitude, and client-side `apply` (which copies the object into the
# last-applied-configuration annotation, capped at 256 KiB) is not used.
def encode_state(state):
    """state dict -> base64(gzip(json)) str, ready for binaryData."""
    raw = json.dumps(state, separators=(",", ":"), sort_keys=True).encode()
    return base64.b64encode(gzip.compress(raw, 9)).decode()


def decode_state(payload):
    """Accept the encoded form, and plain JSON for states written before the
    switch (migration path is load-once, write-compressed)."""
    if not payload:
        return None
    if isinstance(payload, bytes):
        payload = payload.decode()
    try:
        return json.loads(gzip.decompress(base64.b64decode(payload)))
    except Exception:
        pass
    try:
        return json.loads(payload)
    except Exception:
        return None


def _f(bundle, path, default=None):
    e = bundle["facts"].get(path)
    return e["value"] if e else default


def _days(ts, now):
    dt = logscan.parse_ts(ts)
    if dt is None:
        return None
    return max(0.0, (now - dt).total_seconds()) / 86400.0


# ------------------------------------------------------------- item building
def _service_items(bundle, now, items, stats):
    info = _f(bundle, "k8s.service.info")
    if info is None:
        return
    endpoints = _f(bundle, "k8s.service.endpoints") or {}
    templates = dict(_f(bundle, "k8s.deployment.templates") or {})
    templates.update(_f(bundle, "k8s.statefulset.templates") or {})

    for nn, i in sorted(info.items()):
        if (i.get("type") or "") == "ExternalName":
            continue
        ep = endpoints.get(nn)
        # not-ready endpoints: pods exist but are broken - a workload
        # finding, not housekeeping. ready < total AND any addresses at all.
        if ep and ep.get("total") > 0:
            continue
        sel = i.get("selector") or {}
        if sel:
            idle = any((t.get("replicas") or 0) == 0 and
                       all((t.get("labels") or {}).get(k) == v
                           for k, v in sel.items())
                       for t in templates.values())
            if idle:
                stats["idle_services"] = stats.get("idle_services", 0) + 1
                continue
        if i.get("owner_kinds"):
            continue            # operator-managed (e.g. CNPG -ro/-r)
        age = _days(i.get("created"), now)
        if age is not None and age < 1:
            continue            # younger than 1 day: too young to judge
        ns, name = nn.split("/", 1)
        lb = (i.get("type") or "") == "LoadBalancer"
        cat = "lb_ip_abandoned" if lb else "svc_no_backend"
        ips = ", ".join(i.get("lb_ips") or [])
        items.append({
            "ns": ns, "kind": "Service", "name": name, "uid": i.get("uid"),
            "category": cat,
            "reason": "zero endpoints (no EndpointSlice has any address)"
                      + ("; LoadBalancer IP %s held" % ips if lb and ips else ""),
            "cost": "1 IP" if lb else "",
            "cost_gb": 0.0,
            "created": i.get("created"),
            "keep_reason": i.get("keep"),
        })
        if lb:
            stats["lb_ips"] = stats.get("lb_ips", 0) + len(i.get("lb_ips") or []) or 1


def _ingress_items(bundle, now, items, stats, orphan_svcs):
    info = _f(bundle, "k8s.ingress.info")
    if info is None:
        return
    names = set(_f(bundle, "k8s.service.names") or [])
    for nn, i in sorted(info.items()):
        ns = nn.split("/", 1)[0]
        backends = i.get("backends") or []
        missing = [b for b in backends if "%s/%s" % (ns, b) not in names]
        hosts = ", ".join(i.get("hosts") or []) or "(no hosts)"
        if missing:
            cat, reason = "ingress_backend_missing", \
                "backend Service(s) do not exist: %s" % ", ".join(missing)
        elif backends and all(("%s/%s" % (ns, b)) in orphan_svcs
                              for b in backends):
            cat, reason = "ingress_backend_abandoned", \
                "every backend Service has no endpoints"
        else:
            continue
        items.append({
            "ns": ns, "kind": "Ingress", "name": nn.split("/", 1)[1],
            "uid": i.get("uid"), "category": cat, "reason": reason,
            "cost": hosts, "cost_gb": 0.0, "created": i.get("created"),
            "keep_reason": i.get("keep"),
        })


def _hpa_items(bundle, now, items, stats):
    info = _f(bundle, "k8s.hpa.info")
    if info is None:
        return
    templates = dict(_f(bundle, "k8s.deployment.templates") or {})
    templates.update(_f(bundle, "k8s.statefulset.templates") or {})
    for nn, i in sorted(info.items()):
        ns = nn.split("/", 1)[0]
        reason = None
        if i.get("able_to_scale") is False and \
                i.get("able_reason") == "FailedGetScale":
            reason = "AbleToScale=False with FailedGetScale - cannot read its target"
        tkey = "%s:%s/%s" % (i.get("target_kind"), ns, i.get("target_name"))
        if reason is None and i.get("target_name") and tkey not in templates:
            reason = "scale target %s/%s does not exist" % (
                i.get("target_kind"), i.get("target_name"))
        if not reason:
            continue
        items.append({
            "ns": ns, "kind": "HorizontalPodAutoscaler",
            "name": nn.split("/", 1)[1], "uid": i.get("uid"),
            "category": "hpa_target_missing", "reason": reason, "cost": "",
            "cost_gb": 0.0, "created": i.get("created"),
            "keep_reason": i.get("keep"),
        })


def _failed_pod_items(bundle, now, items, stats):
    failed = _f(bundle, "k8s.pod.failed_pods")
    old_by_ns = _f(bundle, "k8s.pod.failed_old_by_ns")
    if failed is None and old_by_ns is None:
        return
    reasons = {}
    for ns, entries in sorted((failed or {}).items()):
        for e in entries:
            age = _days(e.get("finished_at") or e.get("created"), now)
            if age is not None and age >= 7:
                reasons.setdefault(ns, set()).add(e.get("reason") or "?")
    for ns, n in sorted((old_by_ns or {}).items()):
        if not n:
            continue
        finished = []
        for e in (failed or {}).get(ns) or []:
            age = _days(e.get("finished_at") or e.get("created"), now)
            if age is not None and age >= 7 and e.get("finished_at"):
                finished.append(e.get("finished_at"))
        items.append({
            "ns": ns, "kind": "Pod", "name": "%d failed pods" % n,
            "uid": "%s/failed-pods" % ns, "category": "failed_pods_old",
            "reason": "%d pod(s) in phase Failed for more than 7 days "
                      "(reasons: %s)"
                      % (n, ", ".join(sorted(reasons.get(ns) or {"?"}))[:60]),
            "cost": "%d pods" % n, "cost_gb": 0.0,
            # the oldest completed failure is when the problem STARTED
            "transition_at": min(finished) if finished else None,
            "keep_reason": None,
        })


def _pvc_items(bundle, now, items, stats):
    info = _f(bundle, "k8s.pvc.info")
    if info is None:
        return
    users = _f(bundle, "k8s.pvc.pod_users") or {}
    for nn, i in sorted(info.items()):
        if i.get("phase") != "Bound":
            continue
        if users.get(nn):
            continue                    # some pod still mounts it
        age = _days(i.get("created"), now)
        if age is not None and age < 7:
            continue
        ns, name = nn.split("/", 1)
        gb = round((i.get("size_bytes") or 0) / 1024.0 ** 3, 1)
        items.append({
            "ns": ns, "kind": "PersistentVolumeClaim", "name": name,
            "uid": i.get("uid"),
            "category": "pvc_unused",
            "reason": "Bound, referenced by no pod, older than 7 days",
            "cost": "%.1f GiB" % gb, "cost_gb": gb,
            "created": i.get("created"),
            "keep_reason": i.get("keep"),
        })


def _pv_items(bundle, now, items, stats):
    info = _f(bundle, "k8s.pv.info")
    if info is None:
        return
    for name, i in sorted(info.items()):
        if i.get("phase") != "Released":
            continue
        gb = round((i.get("size_bytes") or 0) / 1024.0 ** 3, 1)
        items.append({
            "ns": "", "kind": "PersistentVolume", "name": name,
            "uid": i.get("uid"), "category": "pv_released",
            "reason": "phase Released - claim satisfied, volume idling",
            "cost": "%.1f GiB" % gb, "cost_gb": gb,
            "created": i.get("created"),
            "transition_at": i.get("last_transition"),
            "keep_reason": i.get("keep"),
        })


def _namespace_items(bundle, now, items, stats):
    info = _f(bundle, "k8s.ns.info")
    if info is None:
        return
    pods = _f(bundle, "k8s.pod.by_ns") or {}
    svcs, pvcs = {}, {}
    for nn in (_f(bundle, "k8s.service.info") or {}):
        svcs[nn.split("/", 1)[0]] = svcs.get(nn.split("/", 1)[0], 0) + 1
    for nn in (_f(bundle, "k8s.pvc.info") or {}):
        pvcs[nn.split("/", 1)[0]] = pvcs.get(nn.split("/", 1)[0], 0) + 1
    for ns, i in sorted(info.items()):
        kept = i.get("keep")
        dt = i.get("deletion_timestamp")
        if dt:
            age_h = (_days(dt, now) or 0) * 24.0
            if age_h >= 1:
                items.append({
                    "ns": ns, "kind": "Namespace", "name": ns, "uid": i.get("uid"),
                    "category": "ns_stuck_terminating",
                    "reason": "deletionTimestamp set %.1f h ago - finalizers "
                              "are not finishing" % age_h,
                    "cost": "", "cost_gb": 0.0, "created": i.get("created"),
                    "keep_reason": kept,
                })
            continue
        age = _days(i.get("created"), now)
        if age is None or age < 30:
            continue
        if pods.get(ns) or svcs.get(ns) or pvcs.get(ns):
            continue
        items.append({
            "ns": ns, "kind": "Namespace", "name": ns, "uid": i.get("uid"),
            "category": "ns_empty",
            "reason": "no pods, PVCs or Services; older than 30 days",
            "cost": "", "cost_gb": 0.0, "created": i.get("created"),
            "keep_reason": kept,
        })


def _terminating_pod_items(bundle, now, items, stats):
    term = _f(bundle, "k8s.pod.terminating_info")
    if term is None:
        return
    for t in term:
        age_h = (_days(t.get("deleted_at"), now) or 0) * 24.0
        if age_h < 1:
            continue
        nn = t.get("pod") or "?/?"
        ns, name = nn.split("/", 1)
        items.append({
            "ns": ns, "kind": "Pod", "name": name,
            "uid": nn, "category": "pod_stuck_terminating",
            "reason": "deleting for %.1f h - inspect finalizers and node %s"
                      % (age_h, (t.get("node") or "?").split(".")[0]),
            "cost": "", "cost_gb": 0.0, "keep_reason": None,
        })


def _acme_solver_items(bundle, now, items, stats):
    solvers = _f(bundle, "k8s.acme.solvers_stale")
    if solvers is None:
        return
    for s in solvers:
        items.append({
            "ns": s["ns"], "kind": "Pod", "name": s["pod"],
            "uid": "acme-solver:%s/%s" % (s["ns"], s["pod"]),
            "category": "acme_solver_stale",
            "reason": "http-01 solver older than 1h (challenge never "
                      "completes; deleting just re-creates it)",
            "cost": "", "cost_gb": 0.0, "created": s.get("created"),
            "keep_reason": None,
        })


def _acme_cert_items(bundle, now, items, stats):
    """Certificates expired longer than the parser's stale boundary: nobody
    renewed them for weeks, so they are abandoned plumbing, not outages -
    the recent ones stay with r_acme as CRIT."""
    stale = _f(bundle, "k8s.acme.certificates_expired_stale")
    if stale is None:
        return
    for e in stale:
        items.append({
            "ns": e.get("ns"), "kind": "Certificate",
            "name": e.get("name"),
            "uid": e.get("uid"),
            "category": "acme_cert_expired",
            "reason": "certificate expired %.0f days ago and was never "
                      "renewed" % (e.get("days") or 0),
            "cost": "", "cost_gb": 0.0, "created": None,
            "keep_reason": e.get("keep"),
        })


def _gateway_items(bundle, now, items, stats):
    orphaned = _f(bundle, "k8s.httproute.orphaned")
    if orphaned is None:
        return
    for r in orphaned:
        items.append({
            "ns": r["ns"], "kind": "HTTPRoute", "name": r["name"],
            "uid": r.get("uid"),
            "category": "gateway_orphaned_route",
            "reason": "attached to no parent Gateway - matches nothing",
            "cost": "", "cost_gb": 0.0,
            "keep_reason": None,
        })


# ------------------------------------------------------------------- derive
def derive(bundle, prev_state=None, now=None, prev_facts=None):
    """Join the collected facts into housekeeping items, merge the age state,
    and emit the summary facts. Returns the NEW state dict for the pipeline
    to persist (out/housekeeping-state.json -> the ConfigMap)."""
    facts = bundle.setdefault("facts", {})
    now = now or logscan.parse_ts(bundle.get("collected_at")) or logscan.utcnow()

    # Any of the extended parsers absent means this bundle predates the
    # feature (replay): do nothing at all rather than list garbage.
    have_sources = any(_f(bundle, p) is not None for p in (
        "k8s.service.info", "k8s.pvc.info", "k8s.ns.info", "k8s.ingress.info",
        "k8s.hpa.info"))
    if not have_sources:
        return {"version": 1, "updated": logscan.iso_z(now), "items":
                dict(((prev_state or {}).get("items") or {}))}

    items, stats = [], {}
    _service_items(bundle, now, items, stats)
    orphan_svcs = {"%s/%s" % (i["ns"], i["name"]) for i in items
                   if i["category"] in ("svc_no_backend", "lb_ip_abandoned")}
    _ingress_items(bundle, now, items, stats, orphan_svcs)
    _hpa_items(bundle, now, items, stats)
    _failed_pod_items(bundle, now, items, stats)
    _pvc_items(bundle, now, items, stats)
    _pv_items(bundle, now, items, stats)
    _namespace_items(bundle, now, items, stats)
    _terminating_pod_items(bundle, now, items, stats)
    _acme_solver_items(bundle, now, items, stats)
    _acme_cert_items(bundle, now, items, stats)
    _gateway_items(bundle, now, items, stats)
    _demo_items(bundle, now, items, stats)

    # namespace-level keep annotation covers the objects inside it
    ns_keep = {ns: (i.get("keep") or None)
               for ns, i in (_f(bundle, "k8s.ns.info") or {}).items() if i}
    for i in items:
        i["platform"] = scope.is_platform(i["ns"]) if i["ns"] else True
        if not i.get("keep_reason") and i["ns"] in ns_keep:
            i["keep_reason"] = ns_keep[i["ns"]]
        cat = CATEGORIES[i["category"]]
        i["confidence"] = cat[0]

    kept = [i for i in items if i.get("keep_reason")]
    items = [i for i in items if not i.get("keep_reason")]

    now_iso = logscan.iso_z(now)
    prev_items = dict(((prev_state or {}).get("items") or {}))

    # A state that was never saved (or lost) while the previous snapshot says
    # items existed: ages silently restarted - that is a finding, not a
    # shrug. The save itself happens after this derive, so only a stale load
    # is detectable here.
    prev_hk_bytes = prev_facts.get("k8s.housekeeping.state_bytes") \
        if prev_facts else None
    if prev_hk_bytes and not prev_items:
        facts["k8s.housekeeping.state_load_failed"] = {
            "value": "previous snapshot had a %.1f KiB state but nothing "
                     "loaded - the last save failed (or the ConfigMap was "
                     "recreated); every age restarted at 0"
                     % (prev_hk_bytes / 1024.0), "source": "derive"}

    new_items = {}
    for i in items:
        uid = i.get("uid") or "%s|%s|%s|%s" % (
            i["kind"], i["ns"] or "-", i["name"], i["category"])
        i["uid"] = uid
        prev = prev_items.get(uid)
        first_seen = prev.get("first_seen") \
            if prev and prev.get("category") == i["category"] else None
        first_seen = first_seen or now_iso
        i["first_seen"] = first_seen
        # Age has three sources; the best available wins. A recorded
        # transition time is exact; Karel's first_seen is a lower bound;
        # creationTimestamp is context only, never tenant-ready.
        transition = i.get("transition_at")
        seen_days = int(_days(first_seen, now) or 0)
        if transition and _days(transition, now) is not None:
            i["age_days"] = int(_days(transition, now))
            i["age_source"] = "transition"
        else:
            i["age_days"] = seen_days
            i["age_source"] = "seen"
        i["tenant_ready"] = i["age_days"] >= CATEGORIES[i["category"]][1]
        if CATEGORIES[i["category"]][0] == "certain" and i["category"] in _PROPOSED:
            i["proposed_command"] = _PROPOSED[i["category"]].format(
                ns=i["ns"], name=i["name"].replace('"', ""))
        # Only what ages need survives; ns/kind/name are recomputed per run.
        new_items[uid] = {"category": i["category"], "first_seen": first_seen}

    # GPU upgrade-blocked nodes carry their ages in the same state, so the
    # report can say "blocked 14 days" rather than only "blocked".
    blocked = facts.get("k8s.gpu.upgrade_blocked_nodes") or {}
    blocked = blocked.get("value", []) if isinstance(blocked, dict) else []
    ages = {}
    for n in blocked:
        uid = "gpu-upgrade-blocked:%s" % n
        prev = prev_items.get(uid)
        fs = prev.get("first_seen") \
            if prev and prev.get("category") == "gpu_upgrade_blocked" else None
        new_items[uid] = {"category": "gpu_upgrade_blocked",
                          "first_seen": fs or now_iso}
        ages[n] = int(_days(new_items[uid]["first_seen"], now) or 0)
    if ages:
        facts["k8s.gpu.upgrade_blocked_ages"] = {"value": ages,
                                                 "source": "derive"}

    # Prune or keep previous entries: only a SUCCESSFUL source collection
    # entitles us to say an object is gone.
    cmds = (bundle.get("collection") or {}).get("commands") or {}
    collected_ok = {n for n, c in cmds.items() if c.get("status") == "ok"}
    for uid, prev in prev_items.items():
        if uid in new_items:
            continue
        src = CAT_SOURCE.get(prev.get("category"))
        if src and src in collected_ok:
            continue                      # really gone
        if src:
            new_items[uid] = prev         # not collected: keep the age

    state = {"version": 2, "updated": now_iso, "items": new_items}
    state_bytes = len(encode_state(state))

    def put(path, value):
        if value is not None:
            facts[path] = {"value": value, "source": "derive"}

    put("k8s.housekeeping.items", items)
    put("k8s.housekeeping.kept", kept)
    put("k8s.housekeeping.total", len(items))
    put("k8s.housekeeping.ns_count", len({i["ns"] for i in items if i["ns"]}))
    put("k8s.housekeeping.kept_count", len(kept))
    put("k8s.housekeeping.idle_services", stats.get("idle_services", 0))
    put("k8s.housekeeping.tenant_ready_total",
        sum(1 for i in items if i.get("tenant_ready")))
    put("k8s.housekeeping.state_bytes", state_bytes)
    by_cat = {}
    for i in items:
        by_cat.setdefault(i["category"], []).append(i)

    # Every category whose source collected prints a row - "checked, none
    # found" differs from "not checked", which is listed as unobserved.
    rows, unobserved = [], []
    for cat in sorted(CATEGORIES):
        src = CAT_SOURCE.get(cat)
        collected = cmds.get(src, {}).get("status", "ok") == "ok"
        if not collected:
            unobserved.append((cat, src))
            continue
        lst = by_cat.get(cat, [])
        clean_key = "k8s.housekeeping.clean_runs.%s" % cat
        prev_clean = 0
        try:
            prev_clean = int((prev_facts or {}).get(clean_key) or 0)
        except (TypeError, ValueError):
            prev_clean = 0
        clean = (prev_clean + 1) if not lst else 0
        put(clean_key, clean)
        put("k8s.housekeeping.count.%s" % cat, len(lst))
        if not lst:
            rows.append([cat,
                         "0 (clean %d runs)" % clean if clean else 0,
                         0, "-", "", 0])
            continue
        nss = {i["ns"] for i in lst if i["ns"]}
        oldest = max(i["age_days"] for i in lst)
        cost_gb = sum(i.get("cost_gb") or 0 for i in lst)
        cost = ("%.1f GiB" % cost_gb) if cost_gb else \
            ("%d IP" % len(lst) if cat == "lb_ip_abandoned" else "")
        rows.append([cat, len(lst), len(nss), "%dd" % oldest, cost,
                     sum(1 for i in lst if i.get("tenant_ready"))])
    put("k8s.housekeeping.table", rows)
    if unobserved:
        put("k8s.housekeeping.unobserved",
            ["%s (%s)" % (c, s) for c, s in unobserved])

    # Day-over-day movement per category, for the "changes since last run".
    for cat in sorted(CATEGORIES):
        lst = by_cat.get(cat, [])
        cur_by_ns = {}
        for i in lst:
            if i.get("ns"):
                cur_by_ns[i["ns"]] = cur_by_ns.get(i["ns"], 0) + 1
        prev_count = (prev_facts or {}).get("k8s.housekeeping.count.%s" % cat)
        scope.track_ns_movement(put, prev_facts or {},
                                "k8s.housekeeping", cat, cur_by_ns,
                                prev_count)
    lb_old = ["%s/%s" % (i["ns"], i["name"]) for i in items
              if i["category"] == "lb_ip_abandoned" and i["age_days"] >= 7]
    put("k8s.housekeeping.lb_old", lb_old)
    ns_stuck = [i["name"] for i in items
                if i["category"] == "ns_stuck_terminating"]
    put("k8s.housekeeping.ns_stuck", ns_stuck)
    pod_stuck = [i for i in items if i["category"] == "pod_stuck_terminating"]
    put("k8s.housekeeping.pod_stuck", [i["name"] for i in pod_stuck])
    return state


# ------------------------------------------------------------------- writers
CSV_COLUMNS = ["namespace", "kind", "name", "uid", "category", "confidence",
               "reason", "cost", "first_seen", "age_days", "tenant_ready",
               "kept_reason", "proposed_command", "age_source", "created"]


def _row(i):
    return [i["ns"], i["kind"], i["name"], i.get("uid") or "", i["category"],
            i.get("confidence") or "", i.get("reason") or "",
            i.get("cost") or "", i.get("first_seen") or "",
            i.get("age_days") if i.get("age_days") is not None else "",
            "yes" if i.get("tenant_ready") else "no",
            i.get("keep_reason") or "", i.get("proposed_command") or "",
            i.get("age_source") or "seen", i.get("created") or ""]


def write_outputs(out_dir, bundle, state):
    """out/housekeeping.md (per namespace, cost then age), out/housekeeping.csv
    (stable diff-friendly sort), and the state file the pipeline persists."""
    items = _f(bundle, "k8s.housekeeping.items", []) or []
    kept = _f(bundle, "k8s.housekeeping.kept", []) or []

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "housekeeping.csv"), "wt",
              newline="") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_COLUMNS)
        for i in sorted(list(items) + list(kept),
                        key=lambda x: (x["ns"], x["kind"], x["name"])):
            w.writerow(_row(i))

    cost_key = {"lb_ip_abandoned": 0, "pvc_unused": 1, "pv_released": 1}
    lines = ["# Housekeeping - abandoned objects", ""]
    by_ns = {}
    for i in items:
        by_ns.setdefault(i["ns"] or "(cluster)", []).append(i)
    for ns in sorted(by_ns):
        lines.append("## %s" % ns)
        lines.append("")
        for i in sorted(by_ns[ns],
                        key=lambda x: (cost_key.get(x["category"], 2),
                                       -(x.get("cost_gb") or 0),
                                       -x.get("age_days", 0))):
            bits = ["- `%s/%s`" % (i["kind"], i["name"]),
                    "%s (%s)" % (i["category"], i.get("confidence")),
                    "age %dd (%s)" % (i.get("age_days", 0),
                                      i.get("age_source") or "seen"),
                    (("created %s" % (i["created"] or "?"))
                     if i.get("created") else "created ?"),
                    i.get("reason") or ""]
            if i.get("cost"):
                bits.append("cost: %s" % i["cost"])
            bits.append("platform" if i.get("platform") else "tenant")
            cmd = i.get("proposed_command")
            if cmd:
                bits.append("`%s`" % cmd)
            lines.append(" — ".join(b for b in bits if b))
        lines.append("")
    if kept:
        lines.append("## Kept (annotated)")
        lines.append("")
        for i in sorted(kept, key=lambda x: (x["ns"], x["kind"], x["name"])):
            lines.append("- `%s/%s` %s/%s — %s"
                         % (i["kind"], i["name"], i["ns"] or "(cluster)",
                            i["category"], i.get("keep_reason")))
        lines.append("")
    with open(os.path.join(out_dir, "housekeeping.md"), "wt") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")

    with open(os.path.join(out_dir, "housekeeping-state.json"), "wt") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)


def render_csv(items, kept):
    """CSV text, for tests."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for i in sorted(list(items) + list(kept),
                    key=lambda x: (x["ns"], x["kind"], x["name"])):
        w.writerow(_row(i))
    return buf.getvalue()


# --------------------------------------------------------------------- rules
def _movement_lines(bundle, prefix):
    """Compact per-category movement lines: count+delta, top5 exchanges,
    regressions, persistence - only the entries that say anything."""
    out = []
    for path, e in sorted(bundle["facts"].items()):
        if not path.startswith(prefix + ".change."):
            continue
        cat = path.rsplit(".", 1)[-1]
        c = e.get("value") or {}
        bits = []
        if c.get("delta"):
            bits.append("%+d" % c["delta"])
        if c.get("enter"):
            bits.append("top5 +%s" % ",".join(c["enter"]))
        if c.get("leave"):
            bits.append("top5 -%s" % ",".join(c["leave"]))
        if c.get("regress"):
            bits.append("regressed: %s" % ",".join(c["regress"][:4]))
        persist = [(ns, n) for ns, n in (c.get("persist") or []) if n >= 3]
        if persist:
            bits.append("persistent: %s" % ", ".join(
                "%s ×%d" % (ns, n) for ns, n in persist[:4]))
        if bits:
            out.append("%s: %d (%s)" % (cat, c.get("count") or 0,
                                        "; ".join(bits)))
    return out


def r_housekeeping(bundle, prev_facts=None):
    prev_facts = prev_facts or {}
    total = _f(bundle, "k8s.housekeeping.total")
    if total is None:
        return []
    out = []
    ns_count = _f(bundle, "k8s.housekeeping.ns_count") or 0
    title = "%d items in %d namespaces" % (total, ns_count)
    prev_total = prev_facts.get("k8s.housekeeping.total")
    if isinstance(prev_total, (int, float)):
        d = int(total - prev_total)
        title += "; %+d since the previous run" % d
    kept_n = _f(bundle, "k8s.housekeeping.kept_count") or 0
    idle_n = _f(bundle, "k8s.housekeeping.idle_services") or 0
    detail = []
    if kept_n:
        detail.append("%d annotated object(s) are kept aside and not counted"
                      % kept_n)
    if idle_n:
        detail.append("%d Service(s) point at workloads scaled to zero "
                      "(idle, not abandoned)" % idle_n)
    for line in _movement_lines(bundle, "k8s.housekeeping"):
        detail.append(line)
    detail.append("full list: out/housekeeping.md and out/housekeeping.csv; "
                  "an object earns its age from first sight - deleting and "
                  "recreating it resets the clock (ages are keyed by UID)")
    f = _finding(
        "K8S_HOUSEKEEPING", "info", title, detail=detail,
        evidence=["k_services", "k_ingresses", "k_hpa", "k_pods", "k_pvc",
                  "k_pv", "k_namespaces"],
        metric=float(total))
    f["section"] = "Housekeeping"
    f["section_order"] = 20
    rows = _f(bundle, "k8s.housekeeping.table") or []
    first_seens = [str(i.get("first_seen"))
                   for i in (_f(bundle, "k8s.housekeeping.items") or [])
                   if i.get("first_seen")]
    since = min(first_seens)[:10] if first_seens else None
    f["table"] = {
        "headers": ["category", "count", "namespaces", "oldest", "cost",
                    "tenant-ready"],
        "align": ["l", "r", "r", "r", "r", "r"],
        "rows": rows,
        "note": "tenant-ready = old enough to hand to the namespace owner "
                "for confirmation. Ages survive runs; `pvc_unused` never "
                "carries a delete command, because the object is data."
                + (" Ages tracked since %s; categories without a recorded "
                   "transition reach tenant-ready 14-30 days after that."
                   % since if since else ""),
    }
    out.append(f)

    lb_old = _f(bundle, "k8s.housekeeping.lb_old") or []
    if lb_old:
        out.append(_finding(
            "K8S_LB_IP_ABANDONED", "warn",
            "%d abandoned LoadBalancer Service(s) holding external IPs"
            % len(lb_old),
            detail=lb_old[:15] +
                   ["each has had zero endpoints for a week or more; the IP "
                    "stays allocated and (on MetalLB/cloud) may cost money"],
            evidence=["k_services"], metric=float(len(lb_old)),
            remediation=["confirm with the namespace owner, then "
                         "kubectl delete svc"]))

    ns_stuck = _f(bundle, "k8s.housekeeping.ns_stuck") or []
    if ns_stuck:
        out.append(_finding(
            "K8S_NAMESPACE_STUCK_TERMINATING", "warn",
            "%d namespace(s) stuck Terminating" % len(ns_stuck),
            detail=ns_stuck[:15] +
                   ["deletionTimestamp older than 1h: finalizers (usually a "
                    "CR or a PVC) are not finishing"],
            evidence=["k_namespaces"], metric=float(len(ns_stuck)),
            remediation=["kubectl get ns <name> -o jsonpath={.spec.finalizers}"
                         " and clear whatever blocks them"]))
    return out


def r_housekeeping_state_size(bundle):
    n = _f(bundle, "k8s.housekeeping.state_bytes")
    if n is None or n <= STATE_WARN_BYTES:
        return []
    return [_finding(
        "KAREL_HOUSEKEEPING_STATE_LARGE", "warn",
        "housekeeping state is %.0f%% of the 1 MiB ConfigMap limit"
        % (100.0 * n / STATE_LIMIT_BYTES),
        detail=["measured on the gzipped, base64-encoded state actually "
                "written (%d KiB of %d KiB); past the limit the save fails "
                "and ages silently restart every run"
                % (n / 1024.0, STATE_LIMIT_BYTES / 1024)],
        evidence=["index.tsv"],
        remediation=["clean part of the backlog (that is what it is for), "
                     "or split the tracking ConfigMap by category"])]


def r_housekeeping_unobserved(bundle):
    unobserved = _f(bundle, "k8s.housekeeping.unobserved")
    if not unobserved:
        return []
    return [_finding(
        "KAREL_HOUSEKEEPING_UNOBSERVED", "info",
        "%d housekeeping categor(ies) have no data this run" % len(unobserved),
        detail=unobserved +
               ["their rows are omitted - a collection gap, not proof the "
                "objects are gone"],
        evidence=["index.tsv"])]


def r_housekeeping_state_save(bundle):
    """The previous save failed: state exists in the last snapshot, not on
    disk now. Ages restarted this run, so nothing can age towards
    tenant-ready."""
    msg = _f(bundle, "k8s.housekeeping.state_load_failed")
    if not msg:
        return []
    return [_finding(
        "KAREL_HOUSEKEEPING_STATE_SAVE_FAILED", "warn", msg,
        detail=["the ConfigMap holds at most 1 MiB, and client-side apply "
                "dies even earlier (its annotation is capped at 256 KiB) - "
                "an oversized state fails exactly this way",
                "check the collector Job log for 'could not update "
                "karel-housekeeping-state'"],
        evidence=["index.tsv"],
        remediation=["free the backlog or accept the reset; if the state is "
                     "broken, delete the ConfigMap and let the ages rebuild"])]


RULES = [
    r_housekeeping_state_size,
    r_housekeeping_state_save,
    r_housekeeping_unobserved,
]

DELTA_RULES = [
    r_housekeeping,
]
