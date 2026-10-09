#!/usr/bin/env python3
"""
Karel pipeline: raw collector output -> bundle -> findings -> report text.

  pipeline.py --out /tmp/out --prom-out /tmp/out-prom --prev /tmp/prev.json \
              --bundle /tmp/out/bundle.json \
              --snapshot /tmp/out/snapshot.json \
              --report /tmp/out/report.md

Exit codes:
  0  report written (regardless of what it says about the cluster)
  2  could not write the report at all - this is a Karel failure, alarm on it
"""

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import normalize          # noqa: E402
import rules              # noqa: E402
import report as report_mod   # noqa: E402
import normalize_k8s          # noqa: E402
import rules_k8s              # noqa: E402
import rules_headroom         # noqa: E402
import rules_maintenance      # noqa: E402
import rules_logs             # noqa: E402
import rules_gpu              # noqa: E402
import housekeeping           # noqa: E402
import normalize_prom         # noqa: E402
import suppress               # noqa: E402
import scope                  # noqa: E402


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path, default):
    if not path or not os.path.exists(path):
        return default
    try:
        with open(path, "rt", errors="replace") as fh:
            text = fh.read().strip()
        return json.loads(text) if text else default
    except Exception as exc:
        print("pipeline: could not read %s (%s), continuing without it"
              % (path, exc), file=sys.stderr)
        return default


def build_snapshot(bundle, findings, carried=None, fingerprint=None):
    """Tier-A state: small enough for a ConfigMap, enough for tomorrow's deltas."""
    scalars = {}
    for path, entry in bundle["facts"].items():
        v = entry["value"]
        if isinstance(v, bool) or isinstance(v, (int, float, str)):
            scalars[path] = v

    return {
        "schema_version": normalize.SCHEMA_VERSION,
        "run_id": bundle.get("run_id"),
        "collected_at": bundle.get("collected_at"),
        "ruleset": fingerprint,
        "facts": scalars,
        "findings": rules.findings_for_snapshot(findings, carried),
    }


def _ingest_external(bundle, external_dir, prev_facts):
    """Each *.json in the external dir becomes bundle['external'][<name>]
    plus deterministic summary facts. Failures of one slot never cost the
    others (or the report)."""
    facts = bundle.setdefault("facts", {})
    ext = {}
    if external_dir and os.path.isdir(external_dir):
        for name in sorted(os.listdir(external_dir)):
            if not name.endswith(".json"):
                continue
            stem = name[:-5]
            doc = _load_json(os.path.join(external_dir, name), None)
            if isinstance(doc, dict) or isinstance(doc, list):
                ext[stem] = doc

                def put(path, value):
                    if value is not None:
                        facts[path] = {"value": value, "source": "derive"}
                put("external.%s.present" % stem, True)
                if isinstance(doc, dict) and doc.get("captured_at"):
                    put("external.%s.captured_at" % stem, doc["captured_at"])
    if ext:
        bundle["external"] = ext

    # RT: ticket count, oldest ticket age, days since the last requester
    # message - computed, so the narrative quotes verifiable numbers.
    rt = ext.get("rt")
    if isinstance(rt, dict):
        tickets = rt.get("tickets") or []

        def put(path, value):
            if value is not None:
                facts[path] = {"value": value, "source": "derive"}
        put("external.rt.count", len(tickets))
        ages = [t.get("age_days") for t in tickets
                if isinstance(t.get("age_days"), (int, float))]
        put("external.rt.oldest_age_d", max(ages) if ages else None)
        since = [t.get("last_requester_days") for t in tickets
                 if isinstance(t.get("last_requester_days"), (int, float))]
        put("external.rt.since_requester_d", min(since) if since else None)

    # JupyterHub expired-namespace join against in-cluster state: how much
    # of the 1.7 PB of unused PVC sits in namespaces JupyterHub says expired.
    jh = ext.get("jupyterhub") or {}
    expired = set(jh.get("expired_namespaces") or [])
    if expired:

        def fv(path, default=None):
            e = facts.get(path)
            return e["value"] if e else default
        ns_info = fv("k8s.ns.info", {}) or {}
        pvc_info = fv("k8s.pvc.info", {}) or {}
        present = sorted(ns for ns in expired if ns in ns_info)
        pvc_n, pvc_b = 0, 0
        for nn, i in pvc_info.items():
            ns = nn.split("/", 1)[0]
            if ns in expired:
                pvc_n += 1
                pvc_b += i.get("size_bytes") or 0

        def put(path, value):
            facts[path] = {"value": value, "source": "derive"}
        put("external.jupyterhub.expired_ns_count", len(expired))
        put("external.jupyterhub.still_present_count", len(present))
        put("external.jupyterhub.pvc_count", pvc_n)
        put("external.jupyterhub.pvc_bytes", pvc_b)


def _normalize(out, prom_out, now):
    try:
        return normalize.build_bundle([
            {"label": "k8s", "dir": out,
             "parsers": normalize_k8s.PARSERS,
             "text": normalize_k8s.TEXT_COMMANDS},
            {"label": "prom", "dir": prom_out, "parsers": "prom"},
        ])
    except Exception as exc:
        print("pipeline: normalize failed hard: %s" % exc, file=sys.stderr)
        return {
            "schema_version": normalize.SCHEMA_VERSION,
            "run_id": None, "collected_at": now,
            "collection": {"complete": False, "sources": {}, "commands": {}},
            "facts": {},
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/out", help="k8s collector output dir")
    ap.add_argument("--prom-out", default="/tmp/out-prom", help="prometheus output dir")
    ap.add_argument("--prev", default="/tmp/prev.json", help="yesterday's snapshot")
    ap.add_argument("--bundle", default=None)
    ap.add_argument("--snapshot", default=None)
    ap.add_argument("--report", default=None)
    ap.add_argument("--suppressions", default="/tmp/suppressions.json")
    ap.add_argument("--housekeeping-state", default=None,
                    help="previous housekeeping age state (from the "
                         "karel-housekeeping-state ConfigMap)")
    ap.add_argument("--external-dir", default=None,
                    help="directory of captured external tool outputs "
                         "(rt.json, jupyterhub.json); they land in the "
                         "bundle BEFORE any narrative is generated")
    ap.add_argument("--from-bundle", default=None,
                    help="replay: evaluate and render a saved bundle.json instead "
                         "of normalizing collector output (for iterating on rules "
                         "against real data without re-collecting)")
    args = ap.parse_args()

    out = args.out
    bundle_path = args.bundle or os.path.join(out, "bundle.json")
    snap_path = args.snapshot or os.path.join(out, "snapshot.json")
    report_path = args.report or os.path.join(out, "report.md")
    external_dir = args.external_dir or os.path.join(out, "external")

    now = _now()

    # ------------------------------------------------------------- normalize
    if args.from_bundle:
        bundle = _load_json(args.from_bundle, None)
        if not bundle or "facts" not in bundle:
            print("pipeline: %s is not a bundle" % args.from_bundle, file=sys.stderr)
            return 2
        # drop facts an earlier derivation wrote; they are recomputed below
        bundle["facts"] = {k: v for k, v in bundle["facts"].items()
                           if v.get("source") != "derive"}
    else:
        bundle = _normalize(out, args.prom_out, now)
    if not bundle.get("collected_at"):
        bundle["collected_at"] = now

    # ------------------------------------------------------------- derive
    # The previous snapshot feeds three derivations (clean-run counters,
    # day-over-day movement, the save-failed probe), so it loads first.
    prev = _load_json(args.prev, {}) or {}
    prev_facts = prev.get("facts", {}) or {}

    # Derive steps run on live and replayed bundles alike; a failure costs
    # the derived facts, never the report. scope needs prev_facts for the
    # clean-run counters.
    for step in (scope.derive, rules_headroom.derive_capacity,
                 rules_logs.derive, rules_gpu.derive):
        try:
            if step is scope.derive:
                step(bundle, prev_facts=prev_facts)
            else:
                step(bundle)
        except Exception as exc:
            print("pipeline: derive step %s failed: %s" % (step.__name__, exc),
                  file=sys.stderr)

    # Housekeeping carries its own age state (keyed by object UID), passed in
    # from the previous run's ConfigMap.
    hk_state = {"version": 2, "items": {}}
    try:
        hk_state = housekeeping.derive(
            bundle, _load_json(args.housekeeping_state, None),
            prev_facts=prev_facts)
    except Exception as exc:
        print("pipeline: housekeeping derive failed: %s" % exc,
              file=sys.stderr)

    # External tool captures (RT, JupyterHub, ...): each <name>.json becomes a
    # bundle slot plus a few deterministic facts. Written to the bundle BEFORE
    # any narrative, so every number the AI quotes already has a lifecycle.
    _ingest_external(bundle, external_dir, prev_facts)

    # ------------------------------------------------------------- rules
    findings = rules.evaluate(bundle)
    findings += rules.evaluate_module(bundle, rules_k8s.RULES,
                                      {f["id"] for f in findings})
    findings += rules.evaluate_module(bundle, rules_headroom.RULES,
                                      {f["id"] for f in findings})
    findings += rules.evaluate_module(bundle, rules_maintenance.RULES,
                                      {f["id"] for f in findings})
    findings += rules.evaluate_module(bundle, rules_logs.RULES,
                                      {f["id"] for f in findings})
    findings += rules.evaluate_module(bundle, rules_gpu.RULES,
                                      {f["id"] for f in findings})
    findings += rules.evaluate_module(bundle, housekeeping.RULES,
                                      {f["id"] for f in findings})
    findings += rules.evaluate_module(bundle, normalize_prom.RULES,
                                      {f["id"] for f in findings})
    for _mod in (rules_headroom, housekeeping):
        findings += rules.evaluate_module(bundle, _mod.DELTA_RULES,
                                          {f["id"] for f in findings},
                                          extra_arg=prev_facts)
    findings = rules.rank(rules.annotate_evidence(findings, bundle))

    fingerprint = rules.ruleset_fingerprint(
        [rules_k8s, rules_headroom, rules_maintenance, rules_logs, rules_gpu,
         housekeeping, normalize_prom])
    # A snapshot with no fingerprint predates this mechanism: we cannot know
    # whether the rule set changed, so assume it did rather than claim credit.
    ruleset_changed = bool(prev) and prev.get("ruleset") != fingerprint

    observed = rules.observability(bundle)
    findings, resolved, carried = rules.apply_lifecycle(
        findings, prev.get("findings", {}), bundle["collected_at"], observed,
        ruleset_changed=ruleset_changed)

    # Suppression is applied AFTER lifecycle so a suppressed finding keeps its
    # first_seen and days_open - unsuppressing it must not make it look new.
    ledger = suppress.load(_load_json(args.suppressions, None))
    findings, suppressed, meta = suppress.apply(findings, ledger)
    if meta:
        findings = rules.rank(findings + meta)

    # ------------------------------------------------------------- render
    text = report_mod.render(bundle, findings, resolved, prev,
                             carried=carried, suppressed=suppressed,
                             ruleset_changed=ruleset_changed)

    # ------------------------------------------------------------- persist
    try:
        with open(bundle_path, "wt") as fh:
            json.dump(bundle, fh, indent=1, sort_keys=True)
        with open(snap_path, "wt") as fh:
            json.dump(build_snapshot(bundle, findings + suppressed, carried,
                                     fingerprint), fh, sort_keys=True)
        with open(os.path.join(out, "findings.json"), "wt") as fh:
            json.dump(findings + suppressed, fh, indent=1, sort_keys=True)
    except Exception as exc:
        print("pipeline: could not persist state: %s" % exc, file=sys.stderr)

    try:
        housekeeping.write_outputs(out, bundle, hk_state)
    except Exception as exc:
        print("pipeline: housekeeping outputs failed: %s" % exc,
              file=sys.stderr)

    try:
        with open(report_path, "wt") as fh:
            fh.write(text)
    except Exception as exc:
        print("pipeline: could not write report: %s" % exc, file=sys.stderr)
        sys.stdout.write(text)
        return 2

    sys.stdout.write(text)

    # machine-readable summary for the wrapper / dead-man's switch. Counted
    # the way the report headline counts them (grouped), so the two agree.
    shown = report_mod._collapse_groups(
        [f for f in findings if f["severity"] in ("crit", "warn")])
    counts = {"crit": 0, "warn": 0, "info": 0}
    for f in shown + [f for f in findings if f["severity"] == "info"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    with open(os.path.join(out, "summary.json"), "wt") as fh:
        json.dump({
            "run_id": bundle.get("run_id"),
            "collected_at": bundle["collected_at"],
            "complete": bundle["collection"].get("complete", False),
            "counts": counts,
            "suppressed": len(suppressed),
            "top": [f["id"] for f in findings if f["severity"] == "crit"][:5],
        }, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
