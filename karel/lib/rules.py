"""
Karel deterministic rules: the structural layer shared by every domain.

A finding is:
  id          stable across runs: "CODE" or "CODE:subject"
  severity    crit | warn | info
  title       one line
  detail      list of lines (evidence, human readable)
  evidence    list of command names / fact paths the claim rests on
  remediation list of lines - proposals only, Karel never acts
  metric      optional float, used for escalation detection and trend text
  causes      list of finding ids this one is downstream of (for later correlation)
"""

SEV_ORDER = {"info": 0, "warn": 1, "crit": 2}


def _f(bundle, path, default=None):
    e = bundle["facts"].get(path)
    return e["value"] if e else default


def _finding(code, severity, title, detail=None, evidence=None,
             remediation=None, metric=None, subject=None, causes=None):
    fid = "%s:%s" % (code, subject) if subject else code
    return {
        "id": fid,
        "code": code,
        "subject": subject,
        "severity": severity,
        "title": title,
        "detail": detail or [],
        "evidence": evidence or [],
        "remediation": remediation or [],
        "metric": metric,
        "causes": causes or [],
    }


def _human_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024.0:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f EiB" % n


# ------------------------------------------------------------ command errors
import re as _re

_DENIED_RE = _re.compile(r"forbidden|permission denied|access denied|cannot (list|get) "
                         r"resource|doesn't have a resource type|could not find the "
                         r"requested resource", _re.I)
_LAUNCH_RE = _re.compile(r"No such file or directory|command not found|"
                         r"can't open file|not executable", _re.I)


def _stderr(c):
    return " ".join(c.get("stderr_head") or [])


def is_denied(c):
    """The API refused, or the resource type does not exist here. Distinct
    from a command that failed for any other reason."""
    return c.get("status") == "eacces" or bool(_DENIED_RE.search(_stderr(c)))


def is_launch_failure(c):
    """The command never ran: Karel's installation, not the cluster."""
    return str(c.get("rc")) in ("126", "127") or bool(_LAUNCH_RE.search(_stderr(c)))


def short_error(line, limit=110):
    """Make one stderr line readable. Interpreters prefix messages with their
    own absolute path ('/opt/homebrew/.../Python: can't open file ...'), and
    cutting from the left kept exactly that prefix and dropped the error."""
    line = str(line).strip()
    m = _re.match(r"^(/\S+?):\s+(.*)$", line)
    if m and len(m.group(1)) > 20:
        line = m.group(2)
    if len(line) > limit:
        line = line[:limit].rsplit(" ", 1)[0] + " ..."
    return line


# --------------------------------------------------------------------- rule 0
def r_collection(bundle):
    """Structural: is this report entitled to draw conclusions at all?"""
    out = []
    col = bundle["collection"]
    cmds = col["commands"]

    sources = col.get("sources") or {}
    broken = {k: v for k, v in sources.items() if not v.get("complete")}
    if broken:
        # Name the source. "complete: NO" on its own is unactionable, and was.
        for label, info in sorted(broken.items()):
            reason = info.get("reason") or "unknown"
            if label == "prom":
                sev, extra = "info", [
                    "Prometheus is optional; without it this report has no rates, "
                    "measured peaks, transients or forecasts",
                    "those findings are ABSENT, not negative"]
                rem = ["set PROM_ENABLED=0 to stop expecting it, or fix the "
                       "collector so its absence stops being reported"]
            else:
                sev, extra = "warn", [
                    "findings that depend on this source are based on partial "
                    "data, or missing entirely"]
                rem = ["check the collector's stderr in the Job log",
                       "raise activeDeadlineSeconds or BUDGET if it was killed",
                       "the sentinel is written only after the collector reaches "
                       "the end, so its absence means an early exit"]
            out.append(_finding(
                "KAREL_SOURCE_INCOMPLETE", sev,
                "Collector '%s' did not complete" % label, subject=label,
                detail=["directory: %s" % info.get("dir"),
                        "reason: %s" % reason] + extra,
                evidence=["index.tsv"], remediation=rem))

    bad = [n for n, c in cmds.items()
           if c.get("status") not in ("ok", c.get("expected"))]
    timeouts = [n for n in bad if cmds[n].get("status") == "timeout"]
    if timeouts:
        out.append(_finding(
            "KAREL_COLLECTOR_TIMEOUT", "warn",
            "%d command(s) timed out" % len(timeouts),
            detail=[", ".join(sorted(timeouts))],
            evidence=sorted(timeouts),
            metric=float(len(timeouts)),
            remediation=["command timeouts under load usually mean the API server "
                         "or the collector host is slow"]))

    # Unparseable output only matters when a parser existed to consume it.
    parse_fail = [n for n, c in cmds.items()
                  if c.get("has_parser") and (c.get("parse_ok") is False
                                              or c.get("parse_error"))]
    if parse_fail:
        out.append(_finding(
            "KAREL_PARSE_FAILURE", "warn",
            "%d command(s) returned output their parser could not use"
            % len(parse_fail),
            detail=[", ".join(sorted(parse_fail))] +
                   ["%s: %s" % (n, cmds[n]["parse_error"][:90])
                    for n in sorted(parse_fail) if cmds[n].get("parse_error")],
            evidence=sorted(parse_fail),
            metric=float(len(parse_fail)),
            remediation=["likely a Kubernetes release JSON shape change - update "
                         "the parser, raw output is retained"]))

    # Denials are reported by KAREL_K8S_RBAC_GAP; listing them here as well
    # produced two warnings, with two different explanations, for one fault.
    failed = [n for n, c in cmds.items()
              if c.get("status") == "failed" and c.get("expected") == "ok"
              and not is_denied(c)]
    if failed:
        det = []
        for n in sorted(failed):
            head = (cmds[n].get("stderr_head") or ["(no stderr)"])[0]
            det.append("%s: %s" % (n, short_error(head)))
        launch = [n for n in failed if is_launch_failure(cmds[n])]
        rem = ["a command that fails silently is a hole in every finding "
               "that would have used it"]
        if launch:
            rem.insert(0, "%s could not even start - that is Karel's installation "
                          "(KAREL_HOME, image layout), not the cluster"
                          % ", ".join(sorted(launch)))
        else:
            rem.append("if the failure is expected on this cluster, set "
                       "expected_status in k8s-commands.json so it stops "
                       "being reported as a fault")
        out.append(_finding(
            "KAREL_COMMAND_FAILED", "warn",
            "%d command(s) failed" % len(failed),
            detail=det, evidence=sorted(failed), metric=float(len(failed)),
            remediation=rem))

    # A command that succeeds and returns nothing is not the same as healthy.
    empty = sorted(n for n, c in cmds.items()
                   if c.get("status") == "ok" and c.get("empty")
                   and c.get("has_parser"))
    if empty:
        out.append(_finding(
            "KAREL_COMMAND_EMPTY", "info",
            "%d command(s) succeeded but returned no data" % len(empty),
            detail=[", ".join(empty),
                    "the subsystem returned an empty result: the feature may be "
                    "unused, or something is broken",
                    "any finding that would have come from these is absent, not "
                    "negative"],
            evidence=empty,
            remediation=["if the feature is genuinely unused, drop the command "
                         "from the manifest so the budget goes elsewhere"]))

    unparsed = sorted(n for n, c in cmds.items()
                      if c.get("status") == "ok" and c.get("has_parser") is False)
    if unparsed:
        out.append(_finding(
            "KAREL_COMMAND_UNPARSED", "info",
            "%d collected command(s) have no parser" % len(unparsed),
            detail=[", ".join(unparsed),
                    "collected and retained for forensics, but contributing no "
                    "facts and therefore no findings"],
            evidence=unparsed,
            remediation=["either write a parser or drop them from the manifest",
                         "keeping them costs collection budget and report "
                         "credibility - the collection table counts them as OK"]))

    ok = sum(1 for n, c in cmds.items() if c.get("status") == "ok")
    total = sum(1 for n, c in cmds.items()
                if c.get("status") not in ("skipped_budget",))
    if total and ok < total * 0.5:
        out.append(_finding(
            "KAREL_COLLECTION_DEGRADED", "crit",
            "Only %d of %d collectors succeeded - do not trust a clean report" % (ok, total),
            evidence=["index.tsv"],
            remediation=["treat absence of findings below as unknown, not healthy"]))
    return out


RULES = [
    r_collection,
]


def evaluate(bundle):
    findings, seen = [], set()
    for rule in RULES:
        try:
            produced = rule(bundle) or []
        except Exception as exc:      # a broken rule must not kill the report
            produced = [_finding(
                "KAREL_RULE_ERROR", "warn",
                "Rule %s raised %s" % (rule.__name__, type(exc).__name__),
                subject=rule.__name__, detail=[str(exc)[:200]],
                remediation=["this is a Karel bug, not a cluster condition"])]
        for f in produced:
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            findings.append(f)
    return rank(findings)


# Within a severity, cluster conditions come before Karel's own bookkeeping.
# (This table used to read {"KAREL": 0, "K8S": 1}, which sorts ascending - so
# "3 command(s) failed" was printed above every real cluster warning.)
_DOMAIN_RANK = {"K8S": 0, "THANOS": 0, "PROM": 1, "KAREL": 2}


def _domain(fid):
    return _DOMAIN_RANK.get(fid.split("_")[0].split(":")[0], 1)


def ruleset_fingerprint(modules):
    """Hash the active rule set, INCLUDING each rule's source.

    Hashing only function names was not enough: editing the body of a rule
    makes findings disappear exactly like a fix does, while the name set is
    unchanged. That is how K8S_APISERVER_RESTARTED was once reported as
    resolved when in fact the rule that produced it had been rewritten.

    Falls back to names alone when source is unavailable (frozen/zipped
    deployment); in that case the caveat is under-reported rather than the
    hash being unstable, and the module list still catches added or removed
    rules.
    """
    import hashlib
    import inspect

    parts = []
    for m in list(modules) + [__import__(__name__)]:
        rules = getattr(m, "RULES", []) + getattr(m, "DELTA_RULES", [])
        for r in rules:
            ident = "%s.%s" % (getattr(m, "__name__", "?"), r.__name__)
            try:
                body = inspect.getsource(r)
            except (OSError, TypeError):
                body = ""
            parts.append("%s\x00%s" % (ident, body))

    # thresholds are policy, and changing one silently changes what is reported
    for m in modules:
        for attr in ("THRESHOLDS", "K8S_THRESHOLDS", "THANOS_THRESHOLDS",
                     "HEADROOM", "PROM_THRESHOLDS"):
            v = getattr(m, attr, None)
            if v is not None:
                parts.append("%s.%s=%s" % (getattr(m, "__name__", "?"), attr,
                                           sorted(v) if isinstance(v, (set, frozenset))
                                           else sorted(v.items()) if isinstance(v, dict)
                                           else v))

    return hashlib.sha256("|".join(sorted(parts)).encode()).hexdigest()[:12]


def rank(findings):
    findings.sort(key=lambda f: (-SEV_ORDER.get(f["severity"], 0),
                                 _domain(f["code"]), f["id"]))
    return findings


def annotate_evidence(findings, bundle):
    """Drop evidence for commands that were never collected, and say so.

    A finding that cites `k_pods` when `k_pods` did not run was computed from
    partial data while implying otherwise - the reader looks for it in the
    collection table and finds nothing. Worse, the numbers in that finding are
    quietly weaker than they appear.

    Generic on purpose: every rule would otherwise have to remember to filter
    its own evidence, and one that forgets fails silently.
    """
    collected = set((bundle.get("collection") or {}).get("commands") or {})
    pseudo = {"index.tsv", "prom", "derive", "karel-suppressions", "_probe"}
    for f in findings:
        ev = f.get("evidence") or []
        if not ev:
            continue
        have = [e for e in ev
                if e in collected or e in pseudo or e.split(":")[0] in collected]
        missing = [e for e in ev if e not in have]
        if not missing:
            continue
        f["evidence"] = have
        f["evidence_missing"] = missing
        f["detail"] = list(f.get("detail") or []) + [
            "", "computed WITHOUT: %s - that source did not collect, so this "
                "finding rests on less than it normally would"
            % ", ".join(sorted(missing))]
    return findings


def evaluate_module(bundle, rule_list, seen_ids, extra_arg=None):
    """Run an additional rule module, skipping ids already produced."""
    out = []
    for rule in rule_list:
        try:
            produced = (rule(bundle, extra_arg) if extra_arg is not None
                        else rule(bundle)) or []
        except Exception as exc:
            produced = [_finding(
                "KAREL_RULE_ERROR", "warn",
                "Rule %s raised %s" % (rule.__name__, type(exc).__name__),
                subject=rule.__name__, detail=[str(exc)[:200]],
                remediation=["this is a Karel bug, not a cluster condition"])]
        for f in produced:
            if f["id"] in seen_ids:
                continue
            seen_ids.add(f["id"])
            out.append(f)
    return out


# ------------------------------------------------------------------- lifecycle
# Evidence names that are not collected commands. They are derived from the
# run itself, so they are ALWAYS observable whenever the pipeline executes.
# Omitting them meant any finding citing only pseudo-evidence could never be
# judged observable, and was carried forward as "not observable" forever -
# including findings whose rule had since been deleted.
PSEUDO_EVIDENCE = {"index.tsv", "derive", "karel-suppressions"}


def observability(bundle):
    """Which evidence sources produced usable data this run.

    A finding can only be declared RESOLVED if the source that would have
    detected it actually produced data. Otherwise 'gone' just means 'blind'.
    """
    # The collectors are independent: Kubernetes and Prometheus findings are
    # judged separately. The per-command statuses already encode which sources
    # produced data.
    col = bundle.get("collection", {})
    seen = {name for name, c in (col.get("commands") or {}).items()
            if c.get("status") == "ok" and c.get("parse_ok") is not False}
    seen |= set(PSEUDO_EVIDENCE)
    # `prom` stands for the Prometheus collector as a whole; it is observable
    # when that collector produced a result, reachable or not.
    if bundle["facts"].get("prom.reachable") is not None:
        seen.add("prom")
    return seen


def apply_lifecycle(findings, prev_findings, now_iso, observed=None,
                    ruleset_changed=False):
    """Assign new / open / escalating, compute days_open.

    Returns (findings, resolved, carried_forward).
      resolved        - gone AND we could see well enough to say so
      carried_forward - gone but unobservable; state is preserved, not cleared
    """
    prev = prev_findings or {}
    for f in findings:
        p = prev.get(f["id"])
        if not p:
            f["state"] = "new"
            f["first_seen"] = now_iso
            f["days_open"] = 0
        else:
            f["first_seen"] = p.get("first_seen", now_iso)
            f["days_open"] = _days_between(f["first_seen"], now_iso)
            old_sev = SEV_ORDER.get(p.get("severity", "info"), 0)
            new_sev = SEV_ORDER.get(f["severity"], 0)
            old_metric, new_metric = p.get("metric"), f.get("metric")
            worse_metric = (old_metric is not None and new_metric is not None
                            and new_metric > old_metric and not ruleset_changed)
            f["state"] = "escalating" if (new_sev > old_sev or worse_metric) else "open"

            # Age escalation. Some conditions are correct when made and become
            # dangerous only through time - a maintenance flag is the archetype.
            # Severity has to be a function of age, not of the setting.
            limit = f.get("escalate_after_days")
            if limit is not None and f["days_open"] > limit \
                    and SEV_ORDER.get(f["severity"], 0) < 2:
                f["aged_from"] = f["severity"]
                f["severity"] = "crit" if f["severity"] == "warn" else "warn"
                f["state"] = "escalating"
                f["detail"] = list(f.get("detail") or []) + [
                    "", "This has been in place for %d days (threshold %d). "
                        "Severity raised on age, not on any change in the "
                        "cluster." % (f["days_open"], limit)]
            # A metric is only comparable across runs if it still means the
            # same thing. When the rule set changed, a metric may have been
            # redefined - which produced a "-85487" change for a finding whose
            # metric went from a cumulative event count to a count of reasons.
            if old_metric is not None and new_metric is not None \
                    and not ruleset_changed:
                f["metric_delta"] = round(new_metric - old_metric, 3)
            f["prev_severity"] = p.get("severity")

    current_ids = {f["id"] for f in findings}
    gone = {fid: meta for fid, meta in prev.items() if fid not in current_ids}

    resolved, carried = [], []
    for fid, meta in gone.items():
        needed = meta.get("evidence") or []
        # KAREL_* findings describe Karel's own run: whether a command timed
        # out, returned nothing, or failed to parse. That is bookkeeping, not
        # observation, and is known on every run regardless of what the cluster
        # did. Without this they can never resolve.
        if fid.split(":")[0].startswith("KAREL_"):
            resolved.append({"id": fid, **meta})
            continue
        if observed is None:
            visible = True
        elif not needed:
            # unknown provenance: only trust disappearance if collection was broadly ok
            visible = len(observed) > 0
        else:
            visible = all(e in observed for e in needed)
        (resolved if visible else carried).append({"id": fid, **meta})

    return findings, resolved, carried


def _days_between(a, b):
    import datetime
    try:
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        da = datetime.datetime.strptime(a, fmt)
        db = datetime.datetime.strptime(b, fmt)
        return max(0, (db - da).days)
    except Exception:
        return 0


def findings_for_snapshot(findings, carried_forward=None):
    """Carried-forward findings MUST stay in the snapshot - dropping them would
    make them look brand new the moment collection recovers."""
    snap = {f["id"]: {
        "first_seen": f.get("first_seen"),
        "severity": f["severity"],
        "metric": f.get("metric"),
        "evidence": f.get("evidence", []),
    } for f in findings}
    for c in carried_forward or []:
        snap.setdefault(c["id"], {k: v for k, v in c.items() if k != "id"})
    return snap
