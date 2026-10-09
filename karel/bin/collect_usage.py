#!/usr/bin/env python3
"""Run k8s-pod-resource-usage for one resource and pass its CSV through.

The tool itself takes a long time (up to ~30 min against a busy Prometheus),
so its timeouts are generous and its failure modes are explicit:

  * exit status comes from THE BINARY, not from a pipeline consumer - the
    old wrapper's `echo "Done $?"` after a pipe reported grep's status, so a
    partial failure once read as success
  * partial output (binary started writing and then died) is a FAILED
    collection, never a table that looks complete
  * when the binary is absent or Prometheus is unreachable, the error goes
    into the document and the run exits 0 - a coverage gap named under
    What this report cannot see, not a collector crash

Namespace exclusions used to be a silent `grep -v '^vllm-ns,'`; they now live
in the suppression ledger next to the other reviewable decisions:

  {"suppressions": [...],
   "usage_exclude": [{"pattern": "vllm-ns", "reason": "GPU playground",
                      "by": "ops@cerit-sc.cz"}]}

Exclusions are reported in the output document (kept_vs_excluded), never
silently dropped.
"""

import json
import os
import subprocess
import sys

BINARY = os.environ.get("KAREL_USAGE_BIN", "k8s-pod-resource-usage")
TIMEOUT_CPU = int(os.environ.get("KAREL_USAGE_TIMEOUT_CPU", "1200"))
TIMEOUT_GPU = int(os.environ.get("KAREL_USAGE_TIMEOUT_GPU", "600"))

# The usage binary reads Prometheus itself and insists on
# PROMETHEUS_URL (env or --prometheus-url). The old report's failure mode
# was exactly this missing export: binary present, dead on arrival.
PROMETHEUS_URL = os.environ.get(
    "PROMETHEUS_URL") or os.environ.get(
    "PROM_URL") or "http://rancher-monitoring-prometheus.cattle-monitoring-system.svc.cluster.local:9090"


def _load_exclusions(path):
    try:
        doc = json.load(open(path))
    except Exception:
        return []
    if isinstance(doc, dict):
        ex = doc.get("usage_exclude") or []
    else:
        ex = []
    return [e for e in ex if isinstance(e, dict) and e.get("pattern")]


def _excluded(line, pats):
    import fnmatch
    ns = line.split(",", 1)[0].strip()
    return any(fnmatch.fnmatchcase(ns, p.get("pattern", "")) for p in pats)


def main():
    resource = (sys.argv[1] if len(sys.argv) > 1 else "cpu").lower()
    if resource not in ("cpu", "gpu"):
        json.dump({"error": "usage: collect_usage.py cpu|gpu"}, sys.stdout)
        return 0
    sup_path = os.environ.get("SUPPRESSIONS_FILE", "/tmp/suppressions.json")
    exclusions = _load_exclusions(sup_path)

    argv = [BINARY, "-aggregation", "avg", "-duration", "24h",
            "-resource", resource]
    timeout = TIMEOUT_CPU if resource == "cpu" else TIMEOUT_GPU
    env = dict(os.environ, PROMETHEUS_URL=PROMETHEUS_URL)
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, env=env)
    except FileNotFoundError:
        json.dump({"resource": resource,
                   "error": "binary not found: %s" % BINARY}, sys.stdout)
        return 0
    except subprocess.TimeoutExpired:
        json.dump({"resource": resource,
                   "error": "timeout after %ds" % timeout}, sys.stdout)
        return 0
    if r.returncode != 0:
        # Partial output is a failed collection; do not pass it on.
        json.dump({"resource": resource,
                   "error": "exit %s: %s"
                            % (r.returncode, (r.stderr or "").strip()[:200])},
                  sys.stdout)
        return 0

    lines = [l for l in (r.stdout or "").splitlines() if l.strip()]
    if len(lines) < 2:
        json.dump({"resource": resource,
                   "error": "empty or header-only output"}, sys.stdout)
        return 0

    kept = [lines[0]]
    excluded_rows = []
    for line in lines[1:]:
        if _excluded(line, exclusions):
            excluded_rows.append(line.split(",", 1)[0].strip())
        else:
            kept.append(line)

    json.dump({
        "resource": resource,
        "csv": "\n".join(kept) + "\n",
        "excluded": sorted(set(excluded_rows)),
        "excluded_reasons": ["%s (%s)" % (p.get("pattern"),
                                          p.get("reason") or "no reason")
                             for p in exclusions if exclusions],
        "rows": len(kept) - 1,
    }, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
