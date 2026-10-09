"""Shared test helpers: the check()/facts() pattern from test_regressions.py,
moved out so every test file can use it. Each test is named for the false
positive or blind spot it prevents."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
sys.path.insert(0, os.path.join(ROOT, "bin"))

FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print("  PASS  %s" % name)
    else:
        print("  FAIL  %s %s" % (name, detail))
        FAILURES.append(name)


def facts(pairs):
    return {"facts": {k: {"value": v, "source": "t"} for k, v in pairs.items()},
            "collection": {"commands": {}, "complete": True, "sources": {}}}


def _import_all():
    import importlib
    return {n: importlib.import_module(n)
            for n in ("normalize", "normalize_k8s", "scope", "rules",
                      "rules_k8s", "rules_headroom", "rules_maintenance",
                      "rules_logs", "rules_gpu", "housekeeping",
                      "normalize_prom", "report")}


# --------------------------------------------------------------------------
# Full-pipeline helpers for fuzz/consistency suites: fixture -> bundle ->
# derived -> findings, exactly the way lib/pipeline.py does it.
def build_bundle(mode="healthy", extra_paths=None):
    import shutil
    import subprocess
    import tempfile

    mods = _import_all()
    d = tempfile.mkdtemp(prefix="karel-fixture.")
    subprocess.run([sys.executable,
                    os.path.join(ROOT, "tests", "make_k8s_fixture.py"),
                    d, mode], check=True, capture_output=True)
    bundle = mods["normalize"].build_bundle([
        {"label": "k8s", "dir": d,
         "parsers": mods["normalize_k8s"].PARSERS,
         "text": mods["normalize_k8s"].TEXT_COMMANDS}])
    try:
        if not bundle.get("collected_at"):
            bundle["collected_at"] = "2026-10-08T09:00:00Z"
    except AttributeError:
        pass
    for path, val in (extra_paths or {}).items():
        bundle["facts"][path] = {"value": val, "source": "t"}
    for step in (mods["scope"].derive, mods["rules_headroom"].derive_capacity,
                 mods["rules_logs"].derive, mods["rules_gpu"].derive):
        step(bundle)
    import logscan
    hk_state = mods["housekeeping"].derive(
        bundle, {}, now=logscan.parse_ts(bundle["collected_at"]))
    assert isinstance(hk_state, dict)
    shutil.rmtree(d, ignore_errors=True)
    return bundle, hk_state


def evaluate_all(bundle, prev_facts=None):
    mods = _import_all()
    rules = mods["rules"]
    findings = rules.evaluate(bundle)
    for m in (mods["rules_k8s"], mods["rules_headroom"],
              mods["rules_maintenance"], mods["rules_logs"], mods["rules_gpu"],
              mods["housekeeping"], mods["normalize_prom"]):
        findings += rules.evaluate_module(bundle, m.RULES,
                                          {f["id"] for f in findings})
    for m in (mods["rules_headroom"], mods["housekeeping"]):
        findings += rules.evaluate_module(bundle, m.DELTA_RULES,
                                          {f["id"] for f in findings},
                                          extra_arg=prev_facts or {})
    return rules.rank(rules.annotate_evidence(findings, bundle))


def clone(bundle):
    import json
    return json.loads(json.dumps(bundle))


def finish():
    print("\n%s" % ("-" * 60))
    if FAILURES:
        print("%d FAILURE(S): %s" % (len(FAILURES), ", ".join(FAILURES)))
        sys.exit(1)
    print("all tests pass")
