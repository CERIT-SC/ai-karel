#!/usr/bin/env python3
"""End-to-end: bin/run.sh against the scenario-driven fake kubectl.

Two scenarios: a healthy cluster (nothing from the new checks) and a degraded
one (stalled sidecar, halted compactor, unhealthy GPU, SSA conflict, event
burst). Each run must still write COMPLETE and summary.json.
"""

import datetime
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import ROOT, check, finish                     # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)


def _ts(hours_ago):
    return (NOW - datetime.timedelta(hours=hours_ago)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _logline(hours_ago, rest):
    ts = _ts(hours_ago)[:-1] if _ts(hours_ago).endswith("Z") else _ts(hours_ago)
    return '%s.000000000Z %s' % (ts, rest)


def sidecar_healthy():
    lines = []
    for h in (25.5, 23.5, 21.5, 19.5, 17.5, 15.5, 13.5, 11.5, 9.5, 7.5, 5.5,
              3.5, 1.5, 0.2):
        lines.append(_logline(h, 'level=info ts=x caller=shipper.go:402 '
                                 'msg="upload new block" '
                                 'id=01JACMDM603N438RXDYAKRKN83'))
    return "\n".join(lines) + "\n"


def sidecar_stalled():
    lines = [_logline(40, 'level=info ts=x caller=shipper.go:402 '
                          'msg="upload new block" id=01JACMDM603N438RXDYAKRKN83'),
             _logline(22, 'level=info ts=x caller=shipper.go:402 '
                          'msg="upload new block" id=01JACMDM603N438RXDYAKRKN83')]
    return "\n".join(lines) + "\n"


def compactor_halted():
    return (_logline(10, 'level=info ts=x caller=main.go msg="starting"') + "\n" +
            _logline(9, 'level=error ts=x caller=main.go '
                        'msg="critical error detected; halting"') + "\n")


def fleet_ssa():
    return (_logline(5, 'level=error ts=x caller=apply.go:182 '
                        'msg="Apply failed with 1 conflicts: conflict with '
                        '\\"kubectl-client-side-apply\\" using apps/v1: '
                        '.spec.replicas"') + "\n")


def dcgm_crash():
    return (_logline(11, "Failed to initialize NVML: Driver/library version "
                         "mismatch") + "\n")


def _prom_pods(with_healthy_nodes=True):
    return {"items": [{
        "metadata": {"name": "prom-0", "namespace": "cattle-monitoring-system"},
        "spec": {"nodeName": "kub-a9", "containers": [
            {"name": "prometheus",
             "args": ["--storage.tsdb.retention.time=720d"]},
            {"name": "thanos-sidecar", "args": ["--log.level=info"]}]},
        "status": {"containerStatuses": [
            {"name": "prometheus", "restartCount": 0,
             "state": {"running": {"startedAt": _ts(400)}}},
            {"name": "thanos-sidecar", "restartCount": 0,
             "state": {"running": {"startedAt": _ts(400)}}}]}}]}


def _compactor_pods():
    return {"items": [{
        "metadata": {"name": "cmp-0", "namespace": "cattle-monitoring-system"},
        "spec": {"nodeName": "kub-a9",
                 "containers": [{"name": "thanos-compactor", "args": ["--wait"]}]},
        "status": {"containerStatuses": [
            {"name": "thanos-compactor", "restartCount": 0,
             "state": {"running": {"startedAt": _ts(400)}}}]}}]}


def _fleet_pods():
    return {"items": [{
        "metadata": {"name": "fleet-agent-0", "namespace": "cattle-fleet-system"},
        "spec": {"nodeName": "kub-a9",
                 "containers": [{"name": "fleet-agent", "args": []}]},
        "status": {"containerStatuses": [
            {"name": "fleet-agent", "restartCount": 0,
             "state": {"running": {"startedAt": _ts(400)}}}]}}]}


def _gpu_nodes():
    return {"items": [{
        "metadata": {"name": "gpu-01", "labels": {
            "nvidia.com/gpu.present": "true",
            "nvidia.com/gpu.product": "NVIDIA-H100",
            "nvidia.com/cuda.driver-version.full": "550.90.07"}},
        "status": {
            "capacity": {"cpu": "8", "memory": "64Gi", "nvidia.com/gpu": "8"},
            "allocatable": {"cpu": "7800m", "memory": "60Gi",
                            "nvidia.com/gpu": "7"},
            "conditions": [{"type": "Ready", "status": "True"}],
            "nodeInfo": {"kubeletVersion": "v1.35.6+rke2r1",
                         "osImage": "Ubuntu 24.04.2 LTS",
                         "kernelVersion": "6.8.0-51-generic",
                         "containerRuntimeVersion": "containerd://2.0.5"}}}]}


def _gpu_pods():
    return {"items": [{
        "metadata": {"namespace": "gpu-operator",
                     "name": "nvidia-dcgm-exporter-abcde",
                     "ownerReferences": [{"kind": "DaemonSet",
                                          "name": "nvidia-dcgm-exporter"}]},
        "spec": {"nodeName": "gpu-01",
                 "containers": [{"name": "dcgm", "resources": {}}]},
        "status": {"phase": "Running",
                   "conditions": [{"type": "Ready", "status": "False"}],
                   "containerStatuses": [
                       {"name": "dcgm", "restartCount": 14,
                        "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}}]}


def _burst_patterns():
    items = []
    for i in range(40):
        items.append({"metadata": {"uid": "b%d" % i, "name": "b%d" % i,
                                   "namespace": "tenant-%d" % i,
                                   "creationTimestamp": _ts(3)},
                      "involvedObject": {"kind": "Pod",
                                         "namespace": "tenant-%d" % i,
                                         "name": "web-%d" % i},
                      "reason": "FailedCreatePodSandBox", "type": "Warning",
                      "count": 3, "lastTimestamp": _ts(1)})
    return {"items": items}


def run_scenario(name, extra_calls, log_files, state_d=None):
    """extra_calls: scenario 'calls' entries; log_files: {fname: content}."""
    d = state_d or tempfile.mkdtemp(prefix="karel-run-%s." % name)
    for fname, content in log_files.items():
        with open(os.path.join(d, fname), "wt") as fh:
            fh.write(content)
    calls = [
        {"argv_contains": ["version", "-o", "json"],
         "stdout": json.dumps({"serverVersion": {"gitVersion": "v1.35.6+rke2r1"}})},
        {"argv_contains": ["get", "--raw"], "stdout": "ok"},
        {"argv_contains": ["top", "nodes"], "stdout": ""},
    ] + extra_calls
    scenario = os.path.join(d, "scenario.json")
    with open(scenario, "wt") as fh:
        json.dump({"calls": calls}, fh)

    env = dict(os.environ)
    env["PATH"] = os.path.join(ROOT, "tests", "fakebin") + ":" + env["PATH"]
    env.update({
        "FAKE_KUBECTL_SCENARIO": scenario,
        "HOME": d, "WORK": os.path.join(d, "work"),
        "OUT": os.path.join(d, "out"), "OUT_PROM": os.path.join(d, "out-prom"),
        "KAREL_NS": "ai-karel-ns", "PROM_ENABLED": "0", "BUDGET": "300",
        "KAREL_STATE_DIR": os.path.join(d, "state"),
    })
    for sub in ("work", "out", "out-prom"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    timeout = 240 if sys.platform == "darwin" else 300
    r = subprocess.run(["bash", os.path.join(ROOT, "bin", "run.sh")],
                       capture_output=True, text=True, env=env, timeout=timeout)
    return d, r


def findings(out):
    path = os.path.join(out, "findings.json")
    if not os.path.exists(path):
        return []
    try:
        return json.load(open(path))
    except Exception:
        return []


def ids(fs):
    return {f["id"] for f in fs}


NEW_CHECK_PREFIXES = ("THANOS_", "K8S_GPU_", "K8S_FLEET_",
                      "K8S_TENANT_EVENT_PATTERN", "K8S_LB_IP_ABANDONED",
                      "K8S_NAMESPACE_STUCK_TERMINATING")


# --------------------------------------------------------------------------
print("\nrun.sh, scenario healthy")

calls = [
    {"argv_contains": ["get", "pods", "-A", "-o", "json"],
     "stdout": json.dumps(_prom_pods())},
    {"argv_contains": ["prometheus=rancher-monitoring-prometheus"], "stdout": json.dumps(_prom_pods())},
    {"argv_contains": ["get", "nodes"], "stdout": json.dumps({"items": [
        {"metadata": {"name": "kub-a9", "labels": {}},
         "status": {"capacity": {"cpu": "8", "memory": "64Gi"},
                    "allocatable": {"cpu": "7800m", "memory": "60Gi"},
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "nodeInfo": {"kubeletVersion": "v1.35.6+rke2r1",
                                 "osImage": "Ubuntu 24.04.2 LTS",
                                 "kernelVersion": "6.8.0-51-generic",
                                 "containerRuntimeVersion": "containerd://2.0.5"}}}]})},
    {"argv_contains": ["logs", "prom-0"],
     "stdout_file": "healthy-sidecar.log"},
]
d, r = run_scenario("healthy", calls,
                    {"healthy-sidecar.log": sidecar_healthy()})
check("run.sh exits 0 on a healthy cluster", r.returncode == 0,
      (r.stderr or "")[-300:])
check("COMPLETE sentinel written", os.path.exists(os.path.join(d, "out", "COMPLETE")))
check("summary.json written", os.path.exists(os.path.join(d, "out", "summary.json")))
sd = os.path.join(d, "state")
check("snapshot state persisted as a file (not a ConfigMap)",
      os.path.exists(os.path.join(sd, "snapshot.json")))
check("housekeeping state persisted as a file",
      os.path.exists(os.path.join(sd, "housekeeping-state.json")))
check("a dated archive copy exists",
      any(f.startswith("karel-state-") for f in os.listdir(os.path.join(sd, "archive")))
      if os.path.isdir(os.path.join(sd, "archive")) else False)
check("no state-write WARNINGS in the log",
      "could not update karel-" not in r.stderr and "could not write" not in (r.stderr or ""))
fs = findings(os.path.join(d, "out"))
bad = [i for i in ids(fs)
       if i.split(":")[0].startswith(NEW_CHECK_PREFIXES)
       and any(f["severity"] in ("crit", "warn") for f in fs if f["id"] == i)]
check("no WARN/CRIT from the new checks", bad == [], bad)
check("report mentions the upload heartbeat",
      os.path.exists(os.path.join(d, "out", "report.md")) and
      "upload(s) in window" in open(os.path.join(d, "out", "report.md")).read())

print("\nsecond run loads the file baseline, never a ConfigMap")
d2, r2 = run_scenario("healthy", calls,
                      {"healthy-sidecar.log": sidecar_healthy()}, state_d=d)
check("run 2 exits 0", r2.returncode == 0, (r2.stderr or "")[-200:])
check("baseline came from the file, not a ConfigMap",
      "bytes, file)" in (r2.stderr or "") and "legacy ConfigMap" not in (r2.stderr or ""))
check("housekeeping ages carried across runs (first_seen persists)",
      "housekeeping state loaded" in (r2.stderr or "")
      and ", file)" in (r2.stderr or ""))


# --------------------------------------------------------------------------
print("\nrun.sh, scenario degraded")

def _all_pods():
    items = (_prom_pods()["items"] + _compactor_pods()["items"]
             + _fleet_pods()["items"] + _gpu_pods()["items"])
    return {"items": items}


calls = [
    {"argv_contains": ["get", "pods", "-A", "-o", "json"],
     "stdout": json.dumps(_all_pods())},
    {"argv_contains": ["get", "nodes", "-o", "json"],
     "stdout": json.dumps(_gpu_nodes())},
    {"argv_contains": ["prometheus=rancher-monitoring-prometheus"], "stdout": json.dumps(_prom_pods())},
    {"argv_contains": ["app=thanos-compactor"], "stdout": json.dumps(_compactor_pods())},
    {"argv_contains": ["cattle-fleet-system"], "stdout": json.dumps(_fleet_pods())},
    {"argv_contains": ["gpu-operator"], "stdout": json.dumps(_gpu_pods())},
    {"argv_contains": ["reason=FailedCreatePodSandBox"],
     "stdout": json.dumps(_burst_patterns())},
    {"argv_contains": ["logs", "prom-0", "-n", "cattle-monitoring-system"],
     "stdout_file": "stalled-sidecar.log"},
    {"argv_contains": ["logs", "cmp-0"], "stdout_file": "halted-compactor.log"},
    {"argv_contains": ["logs", "fleet-agent-0"], "stdout_file": "fleet-ssa.log"},
    {"argv_contains": ["logs", "nvidia-dcgm-exporter-abcde", "--previous"],
     "stdout_file": "dcgm-crash.log"},
]
d, r = run_scenario("degraded", calls, {
    "stalled-sidecar.log": sidecar_stalled(),
    "halted-compactor.log": compactor_halted(),
    "fleet-ssa.log": fleet_ssa(),
    "dcgm-crash.log": dcgm_crash(),
})
check("run.sh exits 0 on a degraded cluster", r.returncode == 0,
      (r.stderr or "")[-300:])
fs = findings(os.path.join(d, "out"))
got = ids(fs)
expect = {
    "THANOS_UPLOAD_STALLED",
    "THANOS_COMPACTOR_HALTED",
    "K8S_GPU_UNHEALTHY",
    "K8S_GPU_STACK_DEGRADED:gpu-01",
    "K8S_FLEET_SSA_CONFLICT:kubectl-client-side-apply",
    "K8S_TENANT_EVENT_PATTERN:FailedCreatePodSandBox",
}
missing = expect - got
check("exactly the expected new findings appear", not missing,
      "missing: %s; have: %s" % (missing, sorted(got)))
check("the dcgm crashloop is folded, not a second backoff finding",
      "K8S_PODS_BACKOFF" not in got, sorted(got))
check("no THANOS_UPLOADS_DISABLED false positive",
      "THANOS_UPLOADS_DISABLED" not in got)
hk = os.path.join(d, "out", "housekeeping-state.json")
check("housekeeping state file written for the next run", os.path.exists(hk))


finish()
