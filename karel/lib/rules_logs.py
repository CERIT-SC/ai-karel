"""
Rules over the log-check facts (k8s.log.*): Fleet SSA conflicts and the
Thanos sidecar / compactor / querier health checks.

The motivating failure: a Thanos upload outage that went unnoticed for about
20 days. Two principles do the work here:

  * Silence is not health. A missing upload heartbeat is "not observable"
    (listed under What this report cannot see), never "fine" - and a stalled
    heartbeat IS a finding on day one, escalated by age, not by count.
  * Absent is not zero. Every fact is read with a None default; a check that
    did not collect produces no findings at all.
"""

import datetime

from rules import _finding
import logscan

THANOS_THRESHOLDS = {
    "stall_margin_h": 1.0,          # stall = block duration + margin
    "block_duration_default_h": 2.0,
    "retention_default_days": 15,
    "sidecar_escalate_days": 2,
    "compactor_escalate_days": 3,
    "data_loss_crit_h": 24.0,       # stall is CRIT at once when loss is near
    "compactor_stale_margin_h": 1.0,
    "compactor_wait_default_h": 1.0,
    "querier_store_hint": "store",  # overridable in config/log-checks.json
}


def _f(bundle, path, default=None):
    e = bundle["facts"].get(path)
    return e["value"] if e else default


def _cls(bundle, check, name, default=None):
    return _f(bundle, "k8s.log.%s.class.%s" % (check, name), default)


def _hours(bundle, iso_a, iso_b):
    a, b = logscan.parse_ts(iso_a), logscan.parse_ts(iso_b)
    if a is None or b is None:
        return None
    return (b - a).total_seconds() / 3600.0


def _parse_duration(s):
    """'720d', '15d12h', '2h' -> seconds."""
    import re
    if not s:
        return None
    total = 0.0
    for n, u in re.findall(r"(\d+(?:\.\d+)?)([smhdwy])", str(s)):
        total += float(n) * {"s": 1, "m": 60, "h": 3600, "d": 86400,
                             "w": 604800, "y": 31536000}[u]
    return total or None


# ------------------------------------------------------------ derived facts
def derive(bundle):
    """Sidecar heartbeat arithmetic, computed once against the collection
    time recorded in the check's own window (never wall clock).
    """
    facts = bundle.setdefault("facts", {})

    def put(path, value):
        if value is not None:
            facts[path] = {"value": value, "source": "derive"}

    check = "thanos_sidecar"
    if _f(bundle, "k8s.log.%s.status" % check) is None:
        return bundle
    b = "k8s.log.%s" % check
    pods = _f(bundle, b + ".pods", []) or []
    now = _f(bundle, b + ".window_to") or bundle.get("collected_at")
    up = _cls(bundle, check, "upload_ok") or {}

    put(b + ".uploads_in_window", up.get("count"))
    last = up.get("last")
    age_h = _hours(bundle, last, now) if last else None
    put(b + ".last_upload_age_h",
        round(age_h, 2) if age_h is not None else None)
    gap_h = (up.get("max_gap_s") or 0) / 3600.0
    put(b + ".max_gap_h", round(gap_h, 2))

    ids = (up.get("extracted") or {}).get("id") or []
    times = [logscan.ulid_time(i) for i in ids]
    times = [t for t in times if t]
    newest = max(times) if times else None
    put(b + ".newest_block_at", logscan.iso_z(newest))

    # Prometheus args from the same pod: retention decides when an unshipped
    # block is LOST; the block duration decides when a gap is a stall.
    pargs = {}
    for p in pods:
        pargs = (p.get("also_args") or {}).get("prometheus") or pargs
    retention_s = _parse_duration(pargs.get("storage.tsdb.retention.time"))
    block_s = (_parse_duration(pargs.get("storage.tsdb.max-block-duration"))
               or _parse_duration(pargs.get("storage.tsdb.min-block-duration")))
    retention_d = (retention_s / 86400.0) if retention_s else \
        THANOS_THRESHOLDS["retention_default_days"]
    block_h = (block_s / 3600.0) if block_s else \
        THANOS_THRESHOLDS["block_duration_default_h"]
    put(b + ".retention_days", retention_d)
    put(b + ".block_duration_h", block_h)
    put(b + ".stall_h", block_h + THANOS_THRESHOLDS["stall_margin_h"])

    stalled = last is None or \
        (age_h is not None and age_h > block_h + THANOS_THRESHOLDS["stall_margin_h"])
    if stalled and last:
        # No failing block's ULID is extracted today, so the conservative
        # estimate: the block that SHOULD have sealed after the last upload.
        unshipped = logscan.parse_ts(last)
        if unshipped is not None:
            unshipped = unshipped + datetime.timedelta(hours=block_h)
            put(b + ".oldest_unshipped_at", logscan.iso_z(unshipped))
            loss = unshipped + datetime.timedelta(days=retention_d)
            put(b + ".data_loss_at", logscan.iso_z(loss))
            h = _hours(bundle, logscan.iso_z(unshipped), now)
            put(b + ".oldest_unshipped_h", round(h, 1) if h is not None else None)
    return bundle


# ------------------------------------------------------- collector coverage
def r_log_check_health(bundle):
    """Zero matching pods or a missing container is itself reported; partial
    coverage is listed under What this report cannot see, never silently."""
    out = []
    checks = _f(bundle, "k8s.log.checks", []) or []
    for name in sorted(checks):
        b = "k8s.log.%s" % name
        ns, sel = (_f(bundle, b + ".namespace") or "?"), \
            (_f(bundle, b + ".selector") or "(none)")
        if _f(bundle, b + ".status") == "no_pods":
            sev = "warn" if _f(bundle, b + ".expect_pods", True) else "info"
            out.append(_finding(
                "KAREL_LOG_NO_PODS", sev,
                "log check '%s' matched no pods" % name, subject=name,
                detail=["namespace `%s`, selector `%s`" % (ns, sel),
                        "either the workload is gone (then this report is "
                        "blind to it) or the selector is wrong"],
                evidence=["k_log_%s" % name],
                remediation=["confirm the workload is running; if it is, fix "
                             "the selector in config/log-checks.json"]))
            continue
        pods = _f(bundle, b + ".pods") or []
        missing = ["%s/%s" % (p.get("pod"), p.get("container"))
                   for p in pods if p.get("container_missing")]
        if missing:
            out.append(_finding(
                "KAREL_LOG_CONTAINER_MISSING", "warn",
                "log check '%s': container not found in %d pod(s)"
                % (name, len(missing)), subject=name,
                detail=missing[:10],
                evidence=["k_log_%s" % name],
                remediation=["the container name in config/log-checks.json "
                             "does not match the pods the selector matched"]))
        cov = _f(bundle, b + ".coverage")
        if cov in ("partial", "none"):
            reasons = sorted({p.get("coverage_reason") for p in pods
                              if p.get("coverage_reason")})
            out.append(_finding(
                "KAREL_LOG_PARTIAL", "info",
                "log check '%s' has %s coverage" % (name, cov), subject=name,
                detail=reasons[:5] +
                       ["error classes are windowed; silence inside this "
                        "check is weaker than usual"],
                evidence=["k_log_%s" % name]))
    return out


# ---------------------------------------------------------------- fleet SSA
_KUBECTL_MANAGERS = {"kubectl-client-side-apply", "kubectl-edit", "kubectl-patch"}


def r_fleet_ssa(bundle):
    """A server-side apply field conflict means Fleet cannot apply part of a
    bundle, so the cluster silently drifts from Git. One finding per
    competing field manager; the metric is distinct (object, field) pairs so
    retries do not escalate it."""
    out = []
    check = "fleet_agent"
    if _f(bundle, "k8s.log.%s.status" % check) is None:
        return out
    ssa = _cls(bundle, check, "ssa_conflict")
    if ssa and ssa.get("count"):
        by_manager = {}
        for e in ssa.get("entries") or []:
            ent = e.get("entry") or {}
            mgr = ent.get("manager") or "unknown"
            slot = by_manager.setdefault(mgr, {})
            key = (ent.get("gvk"), ent.get("path"))
            cur = slot.get(key)
            if cur is None:
                cur = slot[key] = {"count": 0, "last": None,
                                   "gvk": ent.get("gvk"),
                                   "path": ent.get("path")}
            cur["count"] += e.get("count") or 1
            if e.get("last") and (not cur["last"] or e["last"] > cur["last"]):
                cur["last"] = e["last"]
        obj_hint = (ssa.get("extracted") or {})
        objects = (obj_hint.get("object") or []) + (obj_hint.get("object_name") or [])
        for mgr, fields in sorted(by_manager.items()):
            pairs = len(fields)
            detail = []
            for f in sorted(fields.values(),
                            key=lambda x: -(x["count"]))[:15]:
                detail.append("%s — %s — last seen %s"
                              % (", ".join(objects[:5])
                                 if objects else "object name not in log",
                                 f.get("path"), f.get("last") or "?"))
            if mgr in _KUBECTL_MANAGERS:
                rem = ["someone changed a Fleet-managed object by hand: revert "
                       "the manual change, or move it into the Git repo"]
            elif all(f.get("path") == ".spec.replicas"
                     for f in fields.values()):
                rem = ["the chart sets replicas while an HPA scales the "
                       "workload: drop replicas from the chart values, or "
                       "ignore the field with Fleet diff.comparePatches"]
            else:
                rem = ["two controllers own the same field - decide which one "
                       "owns it, and stop the other from writing it"]
            out.append(_finding(
                "K8S_FLEET_SSA_CONFLICT", "warn",
                "Fleet cannot apply %d field(s): owned by `%s`" % (pairs, mgr),
                subject=mgr, detail=detail,
                evidence=["k_log_fleet_agent"], metric=float(pairs),
                remediation=rem))
    unc = _cls(bundle, check, "unclassified")
    if unc and unc.get("count"):
        freq = unc.get("freq") or []
        out.append(_finding(
            "K8S_FLEET_LOG_ERRORS", "info",
            "fleet-agent logged %d unclassified error line(s)"
            % unc["count"],
            detail=["%s (x%d)" % (m, n) for m, n in freq[:5]],
            evidence=["k_log_fleet_agent"], metric=float(unc["count"])))
    return out


# ------------------------------------------------------------------- thanos
def _log_level_over_info(pods, container):
    for p in pods:
        if container and p.get("container") != container:
            continue
        lvl = str((p.get("args") or {}).get("log.level") or "info").lower()
        if lvl not in ("info", "debug"):
            return lvl
    return None


def r_thanos_sidecar(bundle):
    check = "thanos_sidecar"
    out = []
    if _f(bundle, "k8s.log.%s.status" % check) is None:
        return out
    b = "k8s.log.%s" % check
    pods = _f(bundle, b + ".pods") or []
    ev = ["k_log_thanos_sidecar"]
    cov = _f(bundle, b + ".coverage") or "complete"

    disabled = _cls(bundle, check, "uploads_disabled") or {}
    if disabled.get("present"):
        out.append(_finding(
            "THANOS_UPLOADS_DISABLED", "crit",
            "Thanos sidecar says uploads are disabled",
            detail=["the sidecar is running but configured NOT to upload; "
                    "Prometheus blocks never leave the cluster",
                    "last seen: %s" % (disabled.get("last") or "?")] +
                   (disabled.get("samples") or [])[:2],
            evidence=ev,
            remediation=["re-enable upload in the sidecar args / objstore "
                         "config; query history older than the block "
                         "retention is already gone"]))
        return out

    up = _cls(bundle, check, "upload_ok") or {}
    age_h = _f(bundle, b + ".last_upload_age_h")
    stall_h = _f(bundle, b + ".stall_h") or 3.0
    level = _log_level_over_info(pods, "thanos-sidecar")

    if level or (cov != "complete" and not up.get("count")):
        # Asserting "no uploads" from a log that cannot show them is the
        # classic silence-as-health. Report the blind spot instead.
        out.append(_finding(
            "KAREL_LOG_SUCCESS_NOT_OBSERVABLE", "info",
            "thanos_sidecar upload heartbeat is not observable",
            subject=check,
            detail=(["sidecar runs with --log.level=%s: 'upload new block' "
                     "is logged at info and is invisible" % level]
                    if level else
                    ["coverage is %s and no upload line was seen" % cov]),
            evidence=ev,
            remediation=["set --log.level=info (or ship a metrics-based "
                         "check) before trusting upload silence"]))
        return out

    if not up.get("count") or age_h is None or age_h > stall_h:
        if up.get("last"):
            what = "last Thanos block upload %.1f h ago (stall threshold %.0f h)" \
                   % (age_h, stall_h)
        else:
            what = "no Thanos block upload in the whole window"
        detail = [what,
                  "uploads in window: %s" % (up.get("count") or 0),
                  "blocks older than the local retention are gone from "
                  "the cluster - if they never shipped, the long-term data "
                  "has HOLES",
                  "this finding escalates to CRIT after %d days"
                  % THANOS_THRESHOLDS["sidecar_escalate_days"]]
        loss = _f(bundle, b + ".data_loss_at")
        sev = "warn"
        if loss:
            h_left = _hours(bundle,
                            _f(bundle, b + ".window_to")
                            or bundle.get("collected_at"), loss)
            detail.append("oldest unshipped block is deleted locally at %s "
                          "(%.0f h from now)" % (loss, h_left or -1))
            if h_left is not None and \
                    h_left < THANOS_THRESHOLDS["data_loss_crit_h"]:
                sev = "crit"
                detail.insert(0, "DATA LOSS in under %.0f h" %
                              THANOS_THRESHOLDS["data_loss_crit_h"])
        f = _finding(
            "THANOS_UPLOAD_STALLED", sev,
            "Thanos sidecar has not uploaded a block%s" %
            (" in %.1f h" % age_h if up.get("last") else " in the window"),
            detail=detail, evidence=ev,
            metric=round(age_h, 1) if age_h is not None else None,
            remediation=["check thanos-sidecar logs in cattle-monitoring for "
                         "S3 errors (credentials, bucket, network)",
                         "a stopped upload that nobody notices is exactly how "
                         "the 20-day outage happened"])
        f["escalate_after_days"] = THANOS_THRESHOLDS["sidecar_escalate_days"]
        out.append(f)
    elif (up.get("max_gap_s") or 0) / 3600.0 > stall_h:
        out.append(_finding(
            "THANOS_UPLOAD_GAP", "info",
            "Thanos upload gap of %.1f h (now uploading again)"
            % ((up["max_gap_s"]) / 3600.0),
            detail=["largest window gap exceeds the %.0f h stall threshold; "
                    "uploads have since resumed" % stall_h,
                    "verify the gap period's blocks actually shipped - "
                    "Prometheus deletes them after retention"],
            evidence=ev))

    uploads_ok = bool(up.get("count"))
    for cls, data in sorted((c for c in
                             _all_classes(bundle, check)
                             if c[0].startswith("s3_") or c[0] == "block_missing"),
                            key=lambda kv: kv[0]):
        if not data.get("count"):
            continue
        if cls == "block_missing":
            sev, label = "warn", "block vanished before upload (not the "
            "retention race - no upload followed)"
        else:
            sev = logscan.S3_CLASS_SEVERITY.get(cls, "warn")
            if cls == "s3_network" and uploads_ok:
                sev = "info"
            label = logscan.S3_CLASS_LABEL.get(cls, cls)
        out.append(_finding(
            "THANOS_UPLOAD_ERRORS", sev,
            "Thanos sidecar: %d × %s" % (data["count"], label), subject=cls,
            detail=(data.get("samples") or [])[:3] +
                   ["first: %s last: %s" % (data.get("first") or "?",
                                            data.get("last") or "?")],
            evidence=ev, metric=float(data["count"]),
            remediation=["S3/object-store credentials and quotas do not fix "
                         "themselves" if sev == "warn" else
                         "transient network errors are expected; this is "
                         "recorded so a chronic one is visible"]))
    return out


def _all_classes(bundle, check):
    prefix = "k8s.log.%s.class." % check
    for path, e in bundle["facts"].items():
        if path.startswith(prefix):
            yield path[len(prefix):], e["value"]


def r_thanos_compactor(bundle):
    check = "thanos_compactor"
    out = []
    if _f(bundle, "k8s.log.%s.status" % check) is None:
        return out
    b = "k8s.log.%s" % check
    pods = _f(bundle, b + ".pods") or []
    ev = ["k_log_thanos_compactor"]

    halted = _cls(bundle, check, "halted") or {}
    if halted.get("present") and "current" in (halted.get("present_in") or []):
        out.append(_finding(
            "THANOS_COMPACTOR_HALTED", "crit",
            "Thanos compactor logged 'critical error detected; halting'",
            detail=["the compactor is sitting dead in a running container - "
                    "no compaction, retention, or downsampling is happening",
                    "logged once: %s" % (halted.get("last") or "?"),
                    "old blocks accumulate until the bucket hits quota"] +
                   (halted.get("samples") or [])[:2],
            evidence=ev,
            remediation=["read the compaction error in the log (usually S3 "
                         "auth), fix it, then restart the compactor pod"]))
        # FAILING below adds the underlying error detail; do not also alert it
        return out

    ce = _cls(bundle, check, "compaction_exit") or {}
    s3 = {c: d for c, d in _all_classes(bundle, check)
          if c.startswith("s3_") and d.get("count")}
    bad_exit = []
    win_from = _f(bundle, b + ".window_from")
    for p in pods:
        t = p.get("last_termination") or {}
        if t.get("exit_code") in (0, None):
            continue
        age = _hours(bundle, t.get("finished_at"), win_from) if win_from else None
        if age is None or age <= 0:
            # finished at/after the window start: inside the window
            bad_exit.append("%s/%s exited %s at %s (reason: %s)"
                            % (p.get("pod"), p.get("container"),
                               t.get("exit_code"), t.get("finished_at"),
                               t.get("reason") or "?"))
    if ce.get("count") or s3 or bad_exit:
        phases = sorted({(e.get("entry") or {}).get("phase")
                         for e in (ce.get("entries") or [])
                         if (e.get("entry") or {}).get("phase")})
        ph = phases[0] if phases else "iteration"
        s3auth = s3.get("s3_auth")
        if s3auth:
            title = "compactor: %s cannot write to the bucket (Access Denied)" % ph
        elif s3:
            key = sorted(s3)[0]
            title = "compactor: %s failing - %s" % (
                ph, logscan.S3_CLASS_LABEL.get(key, key))
        elif bad_exit:
            title = "compactor exited non-zero (%s)" % ph
        else:
            title = "compactor: %s errors in window" % ph
        detail = []
        if ce.get("count"):
            ops = sorted(set((ce.get("extracted") or {}).get("operation") or []))
            detail += ["%d compaction error(s) in window, phase(s): %s"
                       % (ce["count"], ", ".join(phases) or "?")] + \
                      (ce.get("samples") or [])[:2] + \
                      (["operations: %s" % "; ".join(ops[:3])] if ops else [])
            blocks = (ce.get("extracted") or {}).get("block") or []
            when = sorted(t for t in (logscan.ulid_time(x) for x in blocks) if t)
            if when:
                detail.append("failing block(s) created: %s .. %s"
                              % (logscan.iso_z(when[0]), logscan.iso_z(when[-1])))
        detail += bad_exit[:5]
        detail.append("consequence: old blocks are not deleted and the bucket "
                      "grows until it hits quota")
        f = _finding(
            "THANOS_COMPACTOR_FAILING", "warn", title,
            detail=detail, evidence=ev,
            metric=float((ce.get("count") or 0) + len(bad_exit)),
            remediation=["fixing the S3 write (credentials/bucket) unblocks "
                         "the halted or retrying compactor"])
        f["escalate_after_days"] = THANOS_THRESHOLDS["compactor_escalate_days"]
        out.append(f)

    df = _cls(bundle, check, "disk_full") or {}
    if df.get("count"):
        out.append(_finding(
            "THANOS_COMPACTOR_DISK_FULL", "warn",
            "Thanos compactor ran out of local disk",
            detail=(df.get("samples") or [])[:3],
            evidence=ev,
            remediation=["compaction needs local scratch space roughly the "
                         "size of the largest block group being compacted"]))

    # The iteration heartbeat: with --wait the loop's success line should
    # recur; older than 2 x wait + 1h means the loop is stuck. count==0 with
    # full coverage means the pattern itself may be wrong - silence is not
    # health, it is "not observable".
    it = _cls(bundle, check, "iteration_ok")
    started = [p for p in pods if p.get("started_at")]
    if it is not None and _f(bundle, b + ".status") == "ok" and started:
        wait_h = THANOS_THRESHOLDS["compactor_wait_default_h"]
        args_wait = any((p.get("args") or {}).get("wait") for p in pods)
        since_start_h = min((_hours(bundle, p.get("started_at"),
                                    _f(bundle, b + ".window_to")) or 0)
                            for p in pods if p.get("started_at"))
        stale_h = 2 * wait_h + THANOS_THRESHOLDS["compactor_stale_margin_h"]
        last = it.get("last")
        age = _hours(bundle, last, _f(bundle, b + ".window_to")) if last \
            else None
        if args_wait and last is not None and age is not None \
                and age > stale_h:
            out.append(_finding(
                "THANOS_COMPACTOR_STALE", "warn",
                "compactor's last successful iteration is %.1f h old "
                "(wait interval %s h)" % (age, wait_h),
                detail=["the --wait loop should tick roughly every %s h; "
                        "no success in %.1f h means it is stuck mid-iteration"
                        % (wait_h, age)],
                evidence=ev,
                remediation=["read the compactor log for the in-flight "
                             "iteration's error"]))
        elif not (ce.get("count") or s3 or bad_exit) \
                and (last is None and since_start_h > stale_h) \
                and _f(bundle, b + ".coverage") == "complete":
            out.append(_finding(
                "KAREL_LOG_SUCCESS_NOT_OBSERVABLE", "info",
                "compactor success heartbeat is not observable",
                subject=check,
                detail=["no iteration_ok line was seen, coverage is complete "
                        "and the container outlived 2x the wait interval",
                        "either the success pattern in log-checks.json does "
                        "not match this build, or the compactor runs "
                        "one-shot (--wait unset)"],
                evidence=ev))
    return out


def r_thanos_querier(bundle):
    check = "thanos_querier"
    out = []
    if _f(bundle, "k8s.log.%s.status" % check) is None:
        return out
    b = "k8s.log.%s" % check
    pods = _f(bundle, b + ".pods") or []
    ev = ["k_log_thanos_querier"]

    hint = THANOS_THRESHOLDS["querier_store_hint"]
    store_args = []
    for p in pods:
        for k, v in (p.get("args") or {}).items():
            if not k.startswith(("endpoint", "store")):
                continue
            vals = v if isinstance(v, list) else [v]
            store_args.extend(str(x) for x in vals if hint in str(x))
    if pods and _f(bundle, b + ".status") == "ok" and not store_args:
        out.append(_finding(
            "THANOS_QUERIER_NO_STORE_GATEWAY", "warn",
            "Thanos querier has no store-gateway endpoint configured",
            detail=["no --endpoint/--store arg names a store gateway "
                    "(expected a value containing '%s')" % hint,
                    "bucket data in S3 is not queryable through this "
                    "querier - long-term Grafana panels silently lose "
                    "history beyond the local retention"],
            evidence=ev,
            remediation=["add a store-gateway endpoint to the querier, or "
                         "confirm none exists and suppress this check"]))
    eu = _cls(bundle, check, "endpoint_unhealthy") or {}
    if eu.get("count"):
        eps = (eu.get("extracted") or {}).get("endpoint") or []
        out.append(_finding(
            "THANOS_QUERIER_ENDPOINTS_UNHEALTHY", "warn",
            "Thanos querier cannot reach %d endpoint(s)"
            % (len(eps) or eu["count"]),
            detail=eps[:10] + (eu.get("samples") or [])[:2],
            evidence=ev, metric=float(eu["count"]),
            remediation=["an unreachable store gateway hides bucket data "
                         "from queries"]))
    return out


RULES = [
    r_log_check_health,
    r_fleet_ssa,
    r_thanos_sidecar,
    r_thanos_compactor,
    r_thanos_querier,
]
