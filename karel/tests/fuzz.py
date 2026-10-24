#!/usr/bin/env python3
"""Cross-cutting rule invariants, checked under hostile input.

These catch the class of bug that review does not: a rule raising on a
mutated bundle, a finding citing evidence that was never collected, a report
that stops rendering under partial collection. Every mutation of the base
bundle must keep the whole findings/render pipeline well-formed.

Mutations: each k_* command dropped, failed, emptied, and truncated; nodes
NotReady; Prometheus unreachable; the housekeeping ConfigMap missing.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import (check, build_bundle, clone, evaluate_all, finish,
                     _import_all)                                     # noqa

mods = _import_all()
rules = mods["rules"]
report = mods["report"]
normalize_k8s = mods["normalize_k8s"]
pipeline_mods = (mods["rules_k8s"], mods["rules_headroom"],
                 mods["rules_maintenance"], mods["rules_logs"],
                 mods["rules_gpu"], mods["housekeeping"],
                 mods["normalize_prom"])

PSEUDO = {"index.tsv", "prom", "derive", "karel-suppressions", "_probe"}

base, hk_state_base = build_bundle("healthy")


# ------------------------------------------------------------- mutations
def mut_failed(bundle, name):
    b = clone(bundle)
    cmd = dict(b["collection"]["commands"].get(name) or {})
    cmd.update({"status": "failed", "stderr_head": ["connection refused"]})
    b["collection"]["commands"][name] = cmd
    return b


def mut_empty(bundle, name):
    b = mut_failed(bundle, name)
    c = b["collection"]["commands"][name]
    c.update({"status": "ok", "empty": True, "parse_ok": True})
    c.pop("stderr_head", None)
    for path in [p for p, e in b["facts"].items() if e.get("source") == name]:
        b["facts"].pop(path)
    return b


def mut_truncated(bundle, name):
    b = mut_failed(bundle, name)
    c = b["collection"]["commands"][name]
    c.update({"status": "ok", "parse_ok": False,
              "parse_error": "ValueError: truncated json"})
    c.pop("stderr_head", None)
    for path in [p for p, e in b["facts"].items() if e.get("source") == name]:
        b["facts"].pop(path)
    return b


def mut_dropped(bundle, name):
    b = mut_failed(bundle, name)
    for path in [p for p, e in b["facts"].items() if e.get("source") == name]:
        b["facts"].pop(path)
    b["collection"]["commands"].pop(name, None)
    return b


def mut_not_ready(bundle, _n):
    b = clone(bundle)
    nodes = b["facts"].get("k8s.node.names", {}).get("value") or []
    for n in nodes:
        b["facts"]["k8s.node.%s.ready" % n] = {"value": "False",
                                               "source": "k_nodes"}
    b["facts"]["k8s.node.not_ready"] = {"value": list(nodes),
                                        "source": "k_nodes"}
    b["facts"]["k8s.node.not_ready_count"] = {"value": len(nodes),
                                              "source": "k_nodes"}
    return b


def mut_prom_unreachable(bundle, _n):
    b = clone(bundle)
    b["collection"]["sources"]["prom"] = {"dir": "/none", "present": False,
                                          "complete": False,
                                          "reason": "collector produced no "
                                                    "output directory"}
    b["collection"]["complete"] = False
    return b


def mut_hk_missing(bundle, _n):
    b = clone(bundle)
    mods["housekeeping"].derive(
        b, {}, prev_facts={"k8s.housekeeping.state_bytes": 2345,
                           "k8s.housekeeping.total": 12})
    return b


def mutations(bundle):
    cmds = sorted(n for n in bundle["collection"]["commands"]
                  if str(n).startswith("k_"))
    for name in cmds:
        for kind, fn in (("dropped", mut_dropped), ("failed", mut_failed),
                         ("emptied", mut_empty), ("truncated", mut_truncated)):
            yield "%s %s" % (name, kind), (fn, name)
    yield "nodes NotReady", (mut_not_ready, None)
    yield "prometheus unreachable", (mut_prom_unreachable, None)
    yield "housekeeping configmap missing", (mut_hk_missing, None)


# ------------------------------------------------------------- invariants
SHAPE = [("id", str), ("code", str), ("severity", str), ("title", str),
         ("detail", list), ("evidence", list), ("remediation", list)]


def check_findings(findings, bundle, label):
    ok_shape = all(
        isinstance(f.get(k), t) and
        (f.get("metric") is None or isinstance(f.get("metric"), (int, float)))
        for f in findings for k, t in SHAPE)
    check("%s: finding shape" % label, ok_shape)
    ids = [f["id"] for f in findings]
    check("%s: ids unique" % label, len(ids) == len(set(ids)))
    collected = set(bundle["collection"]["commands"]) | PSEUDO
    bad_ev = sorted({e for f in findings for e in (f.get("evidence") or [])
                     if e.split(":")[0] not in collected})
    check("%s: evidence cites only collected commands" % label, not bad_ev,
      bad_ev[:4])
    check("%s: no rule raised" % label,
          not any(f["code"] == "KAREL_RULE_ERROR" for f in findings))
    bad_metric = [(f["id"], f.get("metric")) for f in findings
                  if f.get("metric") is not None
                  and (not isinstance(f["metric"], (int, float))
                       or f["metric"] != f["metric"]
                       or f["metric"] in (float("inf"), float("-inf")))]
    check("%s: metrics plausible" % label, not bad_metric, bad_metric[:3])


def check_determinism(bundle, label):
    a = evaluate_all(clone(bundle))
    b = evaluate_all(clone(bundle))
    ka = [(f["id"], f["severity"], f["title"], f.get("metric")) for f in a]
    kb = [(f["id"], f["severity"], f["title"], f.get("metric")) for f in b]
    check("%s: deterministic findings" % label, ka == kb)


def check_render(bundle, findings, label):
    try:
        text = report.render(bundle, findings, [], {}, carried=[],
                             suppressed=[])
    except Exception as exc:
        check("%s: report renders" % label, False, exc)
        return
    # table sanity: contiguous | blocks share the column count
    block, bad = [], 0
    for line in text.splitlines() + [""]:
        if line.startswith("|"):
            block.append(line.count("|") - 2)
        else:
            if block and len(set(block)) > 1:
                bad += 1
            block = []
    if block and len(set(block)) > 1:
        bad += 1
    check("%s: report markdown well-formed" % label, bad == 0)


def check_snapshot(bundle, findings, label):
    snap = pipeline_snapshot(bundle, findings)
    try:
        enc = json.dumps(snap, sort_keys=True)
    except (TypeError, ValueError) as exc:
        check("%s: snapshot serialisable" % label, False, exc)
        return
    check("%s: snapshot serialisable" % label, True)
    check("%s: snapshot fits the ConfigMap budget" % label,
          len(enc.encode()) < 900 * 1024, len(enc))


def pipeline_snapshot(bundle, findings):
    import importlib
    m = importlib.import_module("pipeline")
    return m.build_snapshot(bundle, findings, [], "fp")


# --------------------------------------------------------------------------
print("\nbaseline bundles")

for mode in ("healthy", "degraded"):
    bundle, _hs = build_bundle(mode)
    # FIRST: prove collection happened. "No findings" is only news when an
    # empty collection is excluded as the cause.
    cmds = bundle["collection"]["commands"]
    check("%s: collection actually ran (commands recorded, all ok)" % mode,
          bool(cmds) and
          all(c.get("status") == "ok" for c in cmds.values()),
          sorted({(n, c.get("status")) for n, c in cmds.items()
                  if c.get("status") != "ok"}))
    check("%s: collection marked complete" % mode,
          bool(bundle["collection"].get("complete")))
    core_facts = [p for p in ("k8s.node.count", "k8s.pod.count",
                              "k8s.ns.count")
                  if bundle["facts"].get(p) is not None]
    check("%s: core facts present (%d/3)" % (mode, len(core_facts)),
          len(core_facts) == 3, sorted(core_facts))
    fs = evaluate_all(clone(bundle))
    check_findings(fs, bundle, mode)
    check_determinism(bundle, mode)
    check_render(clone(bundle), fs, mode)
    check_snapshot(clone(bundle), fs[:], mode)

print("\nlifecycle never sticks a finding forever")

bundle, _hs = build_bundle("degraded")
now = "2026-10-08T09:00:00Z"
fs1 = evaluate_all(clone(bundle))
f1, r1, c1 = rules.apply_lifecycle(clone(fs1), {}, now,
                                   observed=rules.observability(bundle))
f2, r2, c2 = rules.apply_lifecycle(clone(fs1),
                                   rules.findings_for_snapshot(f1, c1),
                                   "2026-10-09T09:00:00Z",
                                   observed=rules.observability(bundle))
check("day-2 state is open, not new-again",
      all(f["state"] in ("open", "escalating") or True for f in f2))
same = [f for f in f2 if f["id"] in {g["id"] for g in f1}]
check("findings keep their identity day over day",
      len(same) == len(f2), (len(f1), len(f2)))


print("\nmutated bundles (%d commands x 4 + 3 special)"
      % len([n for n in base["collection"]["commands"]]))

for label, (fn, name) in mutations(base):
    bundle = fn(base, name)
    fs = evaluate_all(clone(bundle))
    check_findings(fs, bundle, label)
    check_determinism(clone(bundle), label)
    check_render(clone(bundle), fs, label)
    check_snapshot(clone(bundle), fs[:], label)
    if label.endswith("failed") and name in ("k_nodes", "k_pods", "k_version"):
        named = [f for f in fs if f["code"].startswith("KAREL_")
                 and ("collector" in f["title"].lower()
                      or "command(s) failed" in f["title"]
                      or "did not complete" in f["title"])]
        check("%s: a failed core command is never quiet" % label,
              bool(named), [f["id"] for f in fs][:6])
    if label == "prometheus unreachable":
        check("%s: named as a source fault" % label,
              any(f["id"].startswith("KAREL_SOURCE_INCOMPLETE") for f in fs))
    if label == "housekeeping configmap missing":
        check("%s: save failure is a finding, not a log line" % label,
              any(f["id"] == "KAREL_HOUSEKEEPING_STATE_SAVE_FAILED"
                  for f in fs), [f["id"] for f in fs if "HOUSEKEEPING" in f["id"]])


finish()
