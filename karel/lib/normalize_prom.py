"""
Prometheus facts for Karel.

Naming: everything lands under `prom.*` so a rule can always tell whether a
number came from a point-in-time collector or from a time series. That matters
because they answer different questions and fail in different ways.
"""

import json
import os


def load(out_dir):
    path = os.path.join(out_dir, "result.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rt", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def ingest(out_dir, F, collection):
    doc = load(out_dir)
    if doc is None:
        collection["prom"] = {"status": "failed", "tier": 1, "expected": "ok",
                              "stderr_head": ["no result.json - collector did not run"]}
        return

    if not doc.get("reachable"):
        collection["prom"] = {"status": "unreachable", "tier": 1, "expected": "ok",
                              "stderr_head": [str(doc.get("error"))[:160]]}
        F.add("prom.reachable", False, "prom")
        return

    F.add("prom.reachable", True, "prom")
    F.add("prom.url", (doc.get("meta") or {}).get("prom_url"), "prom")
    F.add("prom.elapsed_seconds", doc.get("elapsed_seconds"), "prom")

    queries = doc.get("queries") or {}

    # Retention gates everything. predict_linear over 14 days computed from
    # 30 minutes of history is not a forecast, and a 24h rate from a Prometheus
    # that restarted an hour ago is not a rate. Suppress rather than caveat:
    # a number that looks authoritative and is not is worse than no number.
    ret = (queries.get("prom_retention_days") or {}).get("value")
    F.add("prom.retention_days", ret, "prom")

    ok = no_series = failed = no_match = starved = 0
    legacy = False
    absent_by_job = {}
    job_of = {}
    # record every query's source job FIRST, so the denominator counts all of
    # them rather than only those that got past the suppression checks
    for name, entry in queries.items():
        if entry.get("source_job"):
            job_of[name] = entry["source_job"]

    for name, entry in queries.items():
        st = entry.get("status")
        # Default to 0, not 1. A result written by a collector that predates
        # window annotation cannot tell us what history it needed, and guessing
        # "1 day" suppressed every query including the ones with no window at
        # all. Ungated is the safer failure: report the number and say the
        # gating was unavailable.
        need = entry.get("window_days")
        if need is None:
            legacy = True
            need = 0
        if st == "ok" and ret is not None and need and ret < need:
            starved += 1
            F.add("prom.starved.%s" % name,
                  {"needs_days": need, "have_days": round(ret, 3)}, "prom:" + name)
            collection["prom:" + name] = {
                "status": "insufficient_history", "tier": 2, "expected": "ok",
                "stderr_head": ["needs %sd of history, Prometheus has %.2fd"
                                % (need, ret)]}
            continue
        collection["prom:" + name] = {
            "status": "ok" if st == "ok" else st,
            "tier": 2, "expected": "ok",
            "stderr_head": [entry["error"][:160]] if entry.get("error") else [],
        }
        if st == "ok":
            ok += 1
            F.add("prom.%s" % name, entry.get("value"), "prom:" + name)
            if entry.get("used_fallback"):
                F.add("prom.%s.used_fallback" % name, True, "prom:" + name)
        elif st == "no_match":
            # The query matched nothing, which for a filtering expression is
            # the good outcome. Record it as a real zero.
            no_match += 1
            F.add("prom.%s" % name, 0, "prom:" + name)
        elif st == "no_series":
            no_series += 1
            # Absence of a metric is not a value of zero.
            F.add("prom.missing.%s" % name, True, "prom:" + name)
            if entry.get("source_job"):
                absent_by_job.setdefault(entry["source_job"], []).append(name)
        elif st == "reduce_failed":
            failed += 1
            F.add("prom.reduce_failed.%s" % name, entry.get("error"), "prom:" + name)
        else:
            failed += 1

    F.add("prom.queries_ok", ok, "prom")
    F.add("prom.queries_no_series", no_series, "prom")
    F.add("prom.queries_failed", failed, "prom")
    F.add("prom.queries_no_match", no_match, "prom")
    F.add("prom.queries_insufficient_history", starved, "prom")
    if absent_by_job:
        F.add("prom.absent_by_job",
              {k: sorted(v) for k, v in absent_by_job.items()}, "prom")
    if job_of:
        F.add("prom.query_jobs", job_of, "prom")
    if legacy:
        F.add("prom.legacy_result_format", True, "prom")

    alerts = doc.get("alerts") or {}
    F.add("prom.alerts_available", alerts.get("available"), "prom")
    if alerts.get("available"):
        items = alerts.get("alerts") or []
        F.add("prom.alerts_count", alerts.get("count"), "prom")
        by_sev = {}
        for a in items:
            s = (a.get("severity") or "unknown").lower()
            by_sev[s] = by_sev.get(s, 0) + 1
        F.add("prom.alerts_by_severity", by_sev, "prom")
        F.add("prom.alerts", [
            {"name": a.get("name"), "severity": a.get("severity"),
             "target": a.get("instance") or a.get("namespace"),
             "since": a.get("startsAt"), "summary": a.get("summary")}
            for a in items[:30]], "prom")

    targets = doc.get("targets") or {}
    if targets.get("available"):
        F.add("prom.targets_total", targets.get("total"), "prom")
        F.add("prom.targets_down_count", targets.get("down_count"), "prom")
        F.add("prom.targets_down", targets.get("down"), "prom")
    upby = ((doc.get("queries") or {}).get("prom_up") or {}).get("value")
    if isinstance(upby, dict):
        F.add("prom.up_by_job", upby, "prom")


# ---------------------------------------------------------------------- rules
from rules import _finding  # noqa: E402

PROM_THRESHOLDS = {
    "node_mem_peak_warn": 85.0,
    "apiserver_5xx_warn": 0.01,
    "apiserver_p99_warn": 1.0,
    "etcd_fsync_p99_warn": 0.05,
    "etcd_leader_changes_warn": 3,
    "pvc_used_warn": 85.0,
    "min_retention_days_for_trend": 7.0,
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


def r_prom_health(bundle):
    """Karel reporting on the health of the monitoring system. If Prometheus is
    blind, so is every trend claim in this report."""
    out = []
    if _f(bundle, "prom.reachable") is False:
        return [_finding(
            "KAREL_PROM_UNREACHABLE", "warn",
            "Prometheus unreachable - no history, rates or forecasts in this report",
            detail=["every trend, peak and rate elsewhere is absent, not zero",
                    "point-in-time findings are unaffected"],
            evidence=["prom"],
            remediation=["check the Prometheus pods and the service name in PROM_URL",
                         "an unreachable Prometheus is a monitoring blind spot, not "
                         "a cluster condition"])]
    if _f(bundle, "prom.reachable") is None:
        return out

    down = _f(bundle, "prom.targets_down", []) or []
    if down:
        by_job = {}
        for t in down:
            by_job.setdefault(t.get("job") or "?", []).append(t)
        job_totals = _f(bundle, "prom.up_by_job", {}) or {}

        # A job where EVERY instance is down is almost never N simultaneous
        # failures. It is a ServiceMonitor pointing at something that is not
        # running - often a component the cluster deliberately disabled.
        whole_jobs, partial = [], []
        for job, items in sorted(by_job.items()):
            total = job_totals.get(job)
            if total and len(items) >= total:
                whole_jobs.append((job, len(items), items))
            else:
                partial.append((job, len(items), total, items))

        if whole_jobs:
            det = []
            for job, n, items in whole_jobs:
                err = (items[0].get("error") or "").strip()
                det.append("%s: all %d instance(s) down — %s" % (job, n, err[:80]))
            out.append(_finding(
                "PROM_JOB_ENTIRELY_DOWN", "warn",
                "%d scrape job(s) have every instance down" % len(whole_jobs),
                detail=det + [
                    "every instance of a job failing at once is usually a "
                    "ServiceMonitor aimed at something that is not running, not "
                    "a simultaneous outage",
                    "a component disabled at install time (kube-proxy under "
                    "Cilium, for example) leaves its scrape config behind",
                    "this also fires TargetDown continuously, which is how "
                    "alerting stops being trusted"],
                evidence=["prom"], metric=float(len(whole_jobs)),
                remediation=["confirm the component is meant to be running",
                             "if it was deliberately disabled, remove or disable "
                             "its ServiceMonitor rather than muting the alert"]))

        if partial:
            out.append(_finding(
                "PROM_TARGETS_DOWN", "warn",
                "%d scrape target(s) down across %d job(s)"
                % (sum(n for _, n, _, _ in partial), len(partial)),
                detail=["%s: %d of %s down (%s)"
                        % (j, n, tot or "?",
                           ", ".join(str(x.get("instance")) for x in items[:3]))
                        for j, n, tot, items in partial] +
                       ["a down target is a blind spot; the metrics it would "
                        "provide are missing rather than healthy"],
                evidence=["prom"], metric=float(len(partial)),
                remediation=["if a kube-state-metrics or node-exporter target is "
                             "down, findings here that depend on it are silently "
                             "weaker"]))

    missing = sorted(k[len("prom.missing."):] for k in bundle["facts"]
                     if k.startswith("prom.missing."))
    if missing:
        out.append(_finding(
            "KAREL_PROM_METRICS_ABSENT", "info",
            "%d query(ies) returned no series" % len(missing),
            detail=[", ".join(missing),
                    "the metric is not scraped, or does not exist on this release",
                    "recorded as absent, never as zero"],
            evidence=["prom"],
            remediation=["check whether the exporter's ServiceMonitor is active",
                         "queries that stay absent should be removed from "
                         "prom-queries.json so they stop being reported"]))

    retention = _f(bundle, "prom.retention_days")
    starved = sorted(k[len("prom.starved."):] for k in bundle["facts"]
                     if k.startswith("prom.starved."))
    if starved:
        if retention is not None and retention < 1:
            headline = ("Prometheus has %.0f minutes of history - %d time-window "
                        "finding(s) suppressed" % (retention * 1440, len(starved)))
            sev = "warn"
            extra = ["this normally means Prometheus was restarted or its storage "
                     "was lost; check whether the storage was the cause"]
        else:
            headline = ("Prometheus holds %.1f days of history - %d finding(s) "
                        "suppressed" % (retention or 0, len(starved)))
            sev = "info"
            extra = []
        out.append(_finding(
            "KAREL_PROM_INSUFFICIENT_HISTORY", sev, headline,
            detail=["suppressed: %s" % ", ".join(starved),
                    "a 14-day regression computed from a shorter window is not a "
                    "forecast, and a 24h rate from a Prometheus that restarted an "
                    "hour ago is not a rate",
                    "these are suppressed rather than caveated: a number that "
                    "looks authoritative and is not is worse than no number"] + extra,
            evidence=["prom"], metric=float(len(starved)),
            remediation=["nothing to fix if the restart was deliberate - the "
                         "findings return as history accumulates",
                         "if retention is permanently short, raise it or the "
                         "trend rules will never fire"]))

    if _f(bundle, "prom.legacy_result_format"):
        out.append(_finding(
            "KAREL_PROM_LEGACY_RESULT", "info",
            "Prometheus results predate window/empty annotation",
            detail=["the collector did not record how much history each query "
                    "needs, so short-retention suppression is not applied",
                    "and an empty result cannot be told apart from a metric that "
                    "is simply not scraped",
                    "rebuild the image so bin/prom_query.py and "
                    "config/prom-queries.json are the same generation"],
            evidence=["prom"],
            remediation=["this is a Karel version mismatch, not a cluster "
                         "condition"]))

    reduce_failed = sorted(k[len("prom.reduce_failed."):] for k in bundle["facts"]
                           if k.startswith("prom.reduce_failed."))
    if reduce_failed:
        out.append(_finding(
            "KAREL_PROM_REDUCE_FAILED", "info",
            "%d query(ies) returned series but no usable value" % len(reduce_failed),
            detail=[", ".join(reduce_failed),
                    "the label named in the query's `reduce` is absent from the "
                    "metric on this Prometheus - a Karel manifest bug, not a "
                    "cluster condition"],
            evidence=["prom"],
            remediation=["fix the reduce key in prom-queries.json"]))
    return out


def r_scrape_gap_consequences(bundle):
    """Tie a down scrape target to the findings it actually blinds.

    A report that lists "2 scrape jobs down" in one place and "5 queries
    returned no series" in another leaves the reader to join them. The join is
    deterministic, and the consequence - which findings can no longer fire - is
    the part that matters.
    """
    out = []
    down = _f(bundle, "prom.targets_down", []) or []
    if not down:
        return out
    down_jobs = {t.get("job") for t in down if t.get("job")}
    absent = _f(bundle, "prom.absent_by_job", {}) or {}
    job_of = _f(bundle, "prom.query_jobs", {}) or {}

    # Without source_job tagging the join cannot be made. Say so rather than
    # silently producing nothing, which reads identically to "no gaps".
    if not job_of and (_f(bundle, "prom.queries_no_series") or 0):
        return [_finding(
            "KAREL_PROM_JOB_TAGS_MISSING", "info",
            "Cannot link down scrape targets to the queries they blind",
            detail=["%d query(ies) returned no series and %d target(s) are down, "
                    "but the results carry no source_job tag to join them"
                    % (_f(bundle, "prom.queries_no_series") or 0, len(down)),
                    "the collector predates source_job in prom-queries.json"],
            evidence=["prom"],
            remediation=["rebuild the image so bin/prom_query.py and "
                         "config/prom-queries.json are one generation"])]

    for job, queries in sorted(absent.items()):
        # match loosely: a ServiceMonitor job name and the metric prefix are
        # often not identical
        hit = [dj for dj in down_jobs if job in dj or dj in job
               or job.replace("-", "") in dj.replace("-", "")]
        if not hit:
            continue
        total = sum(1 for j in job_of.values() if j == job)
        blinded = {
            "kube-state-metrics": ["OOMKills over 24h", "restart trends",
                                   "pods pending over time",
                                   "node NotReady history"],
            "node-exporter": ["measured memory peaks"],
            "etcd": ["etcd growth forecasting", "fsync latency",
                     "leader-election churn"],
        }.get(job, [])
        out.append(_finding(
            "PROM_SCRAPE_GAP_BLINDS_FINDINGS", "warn",
            "Scrape job '%s' is down, so %d of Karel's %d queries against it "
            "return nothing" % (", ".join(sorted(hit)), len(queries), total),
            subject=job,
            detail=["absent queries: %s" % ", ".join(queries[:8])] +
                   (["", "findings that cannot fire while this lasts:"] +
                    ["  - %s" % b for b in blinded] if blinded else []) +
                   ["", "these report ABSENT, not healthy - a quiet report on "
                    "this subject means nothing was measured"],
            evidence=["prom"], metric=float(len(queries)),
            remediation=["restore the exporter, or remove its ServiceMonitor if "
                         "the component was deliberately disabled",
                         "until then the point-in-time collectors still cover "
                         "current state; only history and rates are missing"]))
    return out


def r_prom_alerts(bundle):
    """Alertmanager already encodes what this organisation decided matters.
    Re-deriving those judgements would be arrogant; ignoring them, worse."""
    out = []
    if not _f(bundle, "prom.alerts_available"):
        return out
    alerts = _f(bundle, "prom.alerts", []) or []
    # Watchdog fires permanently by design - it certifies that the alerting
    # pipeline works. Reporting it as a finding is exactly the noise this tool
    # is supposed to reduce.
    BY_DESIGN = {"watchdog", "alwaysfiring", "deadmansswitch"}
    alerts = [a for a in alerts
              if (a.get("name") or "").lower().replace("-", "") not in BY_DESIGN]
    if not alerts:
        if _f(bundle, "prom.alerts_count"):
            out.append(_finding(
                "PROM_NO_REAL_ALERTS", "info",
                "Only the always-firing watchdog alert is active",
                detail=["Alertmanager is reachable and its pipeline is proven "
                        "working, with nothing else firing"],
                evidence=["prom"]))
        return out

    by_sev = {}
    for a in alerts:
        k = (a.get("severity") or "unknown").lower()
        by_sev[k] = by_sev.get(k, 0) + 1
    crit = [a for a in alerts if (a.get("severity") or "").lower() == "critical"]
    sev = "crit" if crit else "warn"
    out.append(_finding(
        "PROM_ACTIVE_ALERTS", sev,
        "%d Alertmanager alert(s) firing (%s)"
        % (len(alerts),
           ", ".join("%d %s" % (v, k) for k, v in sorted(by_sev.items()))),
        detail=["[%s] %s — %s (since %s)"
                % ((a.get("severity") or "?").upper(), a.get("name"),
                   a.get("target") or "cluster", (a.get("since") or "?")[:16])
                for a in alerts[:15]],
        evidence=["prom"], metric=float(len(alerts)),
        remediation=["these are your own alerting rules, not Karel's judgement",
                     "an alert firing continuously for days is either a real "
                     "unfixed problem or a rule nobody trusts - both need a "
                     "decision"]))
    return out


def r_prom_transients(bundle):
    """The whole class of event a daily point-in-time report cannot see."""
    out = []

    leader = _f(bundle, "prom.etcd_leader_changes_24h")
    if leader and leader >= PROM_THRESHOLDS["etcd_leader_changes_warn"]:
        out.append(_finding(
            "K8S_ETCD_LEADER_CHURN", "warn",
            "%.0f etcd leader election(s) in the last 24h" % leader,
            detail=["frequent elections usually mean slow disks or network jitter",
                    "each election is a brief write stall for the whole API"],
            evidence=["prom:etcd_leader_changes_24h"], metric=float(leader),
            remediation=["check the fsync p99 below; above ~50ms, etcd will "
                         "elect repeatedly"]))

    notready = _f(bundle, "prom.node_notready_minutes_24h", {}) or {}
    flapped = {k: v for k, v in notready.items() if v and v >= 1}
    if flapped:
        out.append(_finding(
            "K8S_NODE_FLAPPED", "warn",
            "%d node(s) were NotReady at some point in the last 24h" % len(flapped),
            detail=["%s: %.0f minute(s)" % (k, v) for k, v in sorted(flapped.items())] +
                   ["all nodes may be Ready right now and this still happened"],
            evidence=["prom:node_notready_minutes_24h"], metric=float(len(flapped))))

    ooms = _f(bundle, "prom.pod_oomkills_24h", []) or []
    if ooms:
        out.append(_finding(
            "K8S_OOMKILLS_24H", "warn",
            "%d pod(s) were OOMKilled in the last 24h" % len(ooms),
            detail=["%s/%s x%.0f" % (o["labels"].get("namespace"),
                                     o["labels"].get("pod"), o.get("value") or 0)
                    for o in ooms[:15]] +
                   ["this is the signal the 1h event TTL hides"],
            evidence=["prom:pod_oomkills_24h"], metric=float(len(ooms)),
            remediation=["repeated OOMKills on a control-plane or storage pod "
                         "destabilise the cluster"]))
    return out


def r_prom_rates(bundle):
    """Rates that were impossible from a load-balanced /metrics scrape."""
    out = []

    rate = _f(bundle, "prom.apiserver_5xx_rate_24h")
    if rate is not None and rate >= PROM_THRESHOLDS["apiserver_5xx_warn"]:
        out.append(_finding(
            "K8S_APISERVER_ERROR_RATE", "warn",
            "apiserver 5xx rate is %.2f%% over 24h" % (rate * 100),
            detail=["measured per-instance by Prometheus, so this is a real rate"],
            evidence=["prom"], metric=rate * 100,
            remediation=["correlate with etcd fsync latency and webhook timeouts"]))

    p99 = _f(bundle, "prom.apiserver_latency_p99_24h")
    if p99 is not None and p99 >= PROM_THRESHOLDS["apiserver_p99_warn"]:
        out.append(_finding(
            "K8S_APISERVER_SLOW", "warn",
            "apiserver p99 request latency is %.2fs over 24h" % p99,
            detail=["excludes WATCH and CONNECT"],
            evidence=["prom"], metric=p99))

    fsync = _f(bundle, "prom.etcd_fsync_p99_24h")
    if fsync is not None and fsync >= PROM_THRESHOLDS["etcd_fsync_p99_warn"]:
        out.append(_finding(
            "K8S_ETCD_SLOW_DISK", "warn",
            "etcd WAL fsync p99 is %.0fms over 24h" % (fsync * 1000),
            detail=["above roughly 50ms etcd starts electing new leaders",
                    "on these nodes etcd shares disks with the OS - but verify "
                    "that is still true"],
            evidence=["prom"], metric=fsync * 1000,
            remediation=["etcd wants a dedicated low-latency device more than it "
                         "wants a fast one"]))
    return out


def r_prom_peaks(bundle):
    """Measured peaks. The single most useful thing Prometheus adds, because
    node-loss headroom computed from requests describes when SCHEDULING fails,
    not when the machines actually run out."""
    out = []
    # node_exporter series are keyed by instance (ip:port); cAdvisor working-set
    # is keyed by node. Prefer whichever can actually be named, and never print
    # an ip:port where the rest of the report prints node names.
    peaks = _f(bundle, "prom.node_mem_peak_7d", {}) or {}
    alloc = _f(bundle, "k8s.node.allocatable_mem_bytes", {}) or {}
    ws = _f(bundle, "prom.node_mem_working_set_peak_7d", {}) or {}
    if ws and alloc:
        named = {}
        for node, used in ws.items():
            a = alloc.get(node)
            if a:
                named[node] = 100.0 * used / a
        if named:
            peaks = named
    elif peaks and not any(k in alloc for k in peaks):
        out.append(_finding(
            "KAREL_PROM_INSTANCE_LABELS", "info",
            "Node memory peaks are keyed by scrape instance, not node name",
            detail=[", ".join(sorted(peaks)[:4]),
                    "node_exporter labels series with ip:port; without a join "
                    "these cannot be tied to the nodes named elsewhere in this "
                    "report"],
            evidence=["prom"],
            remediation=["kube-prometheus-stack usually provides the "
                         "instance:node_... recording rules; if they are absent "
                         "the container working-set query is the better source"]))
        peaks = {}
    # Memory peaks feed two checks; PVC fullness is a THIRD, independent one.
    # An early return on missing peaks once hid every PVC warning behind
    # missing node-metric data as well.
    if peaks:
        hot = {k: v for k, v in peaks.items()
               if v is not None and v >= PROM_THRESHOLDS["node_mem_peak_warn"]}
        if hot:
            out.append(_finding(
                "K8S_NODE_MEM_PEAK", "warn",
                "%d node(s) peaked above %.0f%% memory in the last 7 days"
                % (len(hot), PROM_THRESHOLDS["node_mem_peak_warn"]),
                detail=["%s: %.0f%%" % (k, v) for k, v in sorted(hot.items())] +
                       ["this is measured, not requested"],
                evidence=["prom"], metric=max(hot.values())))

    # The cross-check that only becomes possible with history.
    reqs = _f(bundle, "k8s.node.requests", {}) or {}
    alloc = _f(bundle, "k8s.node.allocatable_mem_bytes", {}) or {}
    # Only nodes that can accept a pod. Counting a NotReady node's allocatable
    # as available understates commitment, and made this finding quote 59%
    # while the node table showed 79% for the same quantity.
    unavailable = set(_f(bundle, "k8s.node.not_ready", []) or []) | \
        set(_f(bundle, "k8s.node.unschedulable", []) or [])
    keys = [n for n in alloc if n not in unavailable]
    if reqs and alloc and peaks:
        tot_req = sum((reqs.get(n) or {}).get("mem_bytes") or 0 for n in keys)
        tot_alloc = sum(alloc[n] for n in keys) or 1
        req_pct = 100.0 * tot_req / tot_alloc
        peak_pct = max(peaks.values()) if peaks else None
        if peak_pct is not None and req_pct > peak_pct * 2:
            out.append(_finding(
                "K8S_HEADROOM_RECONCILED", "info",
                "Requests reserve %.0f%% of memory; measured 7-day peak is %.0f%%"
                % (req_pct, peak_pct),
                detail=(["computed over the %d schedulable node(s); %s excluded "
                         "as unavailable" % (len(keys), ", ".join(sorted(unavailable)))]
                        if unavailable else []) +
                       ["a node failure is constrained by RESERVATIONS, because "
                        "the scheduler places against requests",
                        "actual memory exhaustion is much further away than the "
                        "reservation figure suggests",
                        "both numbers are real and they fail in different ways: "
                        "reservations block scheduling, usage triggers the OOM "
                        "killer"],
                evidence=["prom", "k_nodes", "k_pods"],
                metric=round(req_pct - peak_pct, 1),
                remediation=["right-sizing requests toward measured peaks would "
                             "recover most of the apparent commitment",
                             "do not right-size to the peak itself - leave margin "
                             "for the failover case"]))

    pvcs = _f(bundle, "prom.pvc_used_pct_max", []) or []
    full = [p for p in pvcs if (p.get("value") or 0) >= PROM_THRESHOLDS["pvc_used_warn"]]

    # nfs-csi* classes are subdirectories of ONE shared volume: every PVC
    # reports (approximately) the VOLUME's fullness, so N rows are one
    # cause - "the storage became full" - not N problems. Collapse them.
    sc_map = _f(bundle, "k8s.pvc.storageclass_map", {}) or {}
    nfs_classes = [s for s in (_f(bundle, "k8s.storageclass.names", []) or [])
                   if str(s).startswith("nfs-csi")]
    shared, singles = [], []
    for p in full:
        nn = "%s/%s" % (p["labels"].get("namespace"),
                        p["labels"].get("persistentvolumeclaim"))
        cls = sc_map.get(nn)
        if cls and cls in nfs_classes:
            shared.append((nn, p.get("value") or 0, cls))
        else:
            singles.append(p)
    if shared:
        vals = [v for _nn, v, _c in shared]
        out.append(_finding(
            "K8S_PVC_NEARFULL", "warn",
            "shared nfs-csi volume at ~%.0f%% (%d PVC(s) report the same "
            "volume over %.0f%%)"
            % (max(vals), len(shared), PROM_THRESHOLDS["pvc_used_warn"]),
            subject="nfs-csi-shared",
            detail=["%s: %.0f%% (%s)" % (nn, v, cls) for nn, v, cls
                    in sorted(shared, key=lambda x: -x[1])[:8]] +
                   ["spread of reported values %.1f%%..%.1f%% - one shared "
                    "backend volume, not %d independent disks"
                    % (min(vals), max(vals), len(shared)),
                    "housekeeping here means shrinking the VOLUME's "
                    "occupants, not reviewing PVCs one by one"] +
                   (["classes: %s" % ", ".join(sorted({c for _n, _v, c
                                                       in shared}))]),
            evidence=["prom", "k_pvc"], metric=float(len(shared)),
            remediation=["the storage backend is the unit: find what grew "
                         "on it (the housekeeping backlog lists its biggest "
                         "idle PVCs)"]))
    if singles:
        out.append(_finding(
            "K8S_PVC_NEARFULL", "warn",
            "%d PVC(s) above %.0f%% full" % (len(singles), PROM_THRESHOLDS["pvc_used_warn"]),
            detail=["%s/%s: %.0f%%" % (p["labels"].get("namespace"),
                                       p["labels"].get("persistentvolumeclaim"),
                                       p.get("value") or 0) for p in singles[:15]] +
                   ["PVC fullness is invisible from the Kubernetes API alone"],
            evidence=["prom"], metric=max(p.get("value") or 0 for p in singles)))
    return out


def r_prom_forecasts(bundle):
    """predict_linear over 14 days, replacing the two-point extrapolation."""
    out = []
    etcd = _f(bundle, "prom.etcd_db_predict_30d")
    if etcd:
        quota = 4 * 1024 ** 3   # this cluster sets quota-backend-bytes=4Gi
        pct = 100.0 * etcd / quota
        if pct >= 60:
            out.append(_finding(
                "K8S_ETCD_FORECAST", "warn" if pct < 90 else "crit",
                "etcd database trending to %s (%.0f%% of the 4GiB quota) in 30 days"
                % (_human_bytes(etcd), pct),
                detail=["regression over 14 days",
                        "hitting the quota puts etcd into a read-only NOSPACE alarm"],
                evidence=["prom:etcd_db_predict_30d"], metric=pct,
                remediation=["find the churn: Events, Leases, or a controller "
                             "rewriting status in a loop",
                             "compaction and defrag reclaim space; defrag blocks "
                             "the member briefly, so do one at a time"]))
    return out


RULES = [
    r_prom_health,
    r_scrape_gap_consequences,
    r_prom_alerts,
    r_prom_transients,
    r_prom_rates,
    r_prom_peaks,
    r_prom_forecasts,
]
