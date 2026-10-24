#!/usr/bin/env python3
"""Jupyter notebook collector: who holds a GPU, and is the notebook alive.

Pods named jupyter-* are notebook servers. Two questions a daily report can
answer honestly:

  * GPU over the last 24h - from DCGM_FI_DEV_GPU_UTIL, which carries the pod
    name. This ONLY works for pods that requested nvidia.com/gpu: the on-cluster
    dcgm-exporter does not export per-pod series for nvidia.com/mig-* slices
    (no GPU_I_ID/GPU_I_PROFILE series exist at all) and nvidia.com/gpu-mem is a
    memory quota on a shared card that no exporter attributes to a pod. Those
    pods are reported as "no per-pod GPU metrics", never as "GPU idle" - the
    first is a blind spot, the second is a finding.
  * CPU over the last 72h - a notebook whose GPU never fires can still be
    used (kernels crunching on CPU). A peak far above the trailing average
    means someone ran something recently. container_cpu_usage_seconds_total
    is scraped by cadvisor for every pod, so this has no blind spots.

Failure contract (same as the rest of Karel): kubectl or Prometheus trouble
is recorded in the document and the exit status stays 0 - a broken collector
must look exactly like itself, not like a healthy cluster.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROM_URL = os.environ.get(
    "PROM_URL") or os.environ.get(
    "PROMETHEUS_URL") or "http://rancher-monitoring-prometheus.cattle-monitoring-system.svc.cluster.local:9090"

KUBECTL_TIMEOUT = int(os.environ.get("KAREL_JUPYTER_KUBECTL_TIMEOUT", "60"))
PROM_TIMEOUT = int(os.environ.get("KAREL_JUPYTER_PROM_TIMEOUT", "60"))

# A 72h CPU peak at or above this many cores counts as "someone used it".
CPU_PEAK_CORES = float(os.environ.get("KAREL_JUPYTER_CPU_PEAK_CORES", "0.5"))
# A full-GPU pod whose 24h MAX utilisation stays below this percent never
# touched its card.
GPU_IDLE_MAX_PCT = float(os.environ.get("KAREL_JUPYTER_GPU_IDLE_MAX_PCT", "10"))

_QUANTITY_RE = re.compile(
    r"^\s*([+-]?[0-9.]+)\s*(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|M|G|T|P|E|)\s*$")
_MULT = {
    "": 1.0, "n": 1e-9, "u": 1e-6, "m": 1e-3,
    "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
    "Ki": 2 ** 10, "Mi": 2 ** 20, "Gi": 2 ** 30,
    "Ti": 2 ** 40, "Pi": 2 ** 50, "Ei": 2 ** 60,
}


def quantity(v):
    m = _QUANTITY_RE.match(str(v or ""))
    if not m:
        return None
    try:
        return float(m.group(1)) * _MULT[m.group(2)]
    except ValueError:
        return None


def prom_query(expr):
    """Instant query. Returns (status, result-or-error); never raises."""
    url = "%s/api/v1/query?%s" % (
        PROM_URL.rstrip("/"), urllib.parse.urlencode({"query": expr}))
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=PROM_TIMEOUT) as r:
            doc = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return "failed", "HTTP %s" % e.code
    except Exception as exc:
        return "unreachable", "%s: %s" % (type(exc).__name__, str(exc)[:120])
    if doc.get("status") != "success":
        return "failed", str(doc.get("error"))[:160]
    return "ok", (doc.get("data") or {}).get("result") or []


def by_pod(result):
    """Prom vector -> {(namespace, pod): float}; series without a value vanish."""
    out = {}
    for s in result:
        m = s.get("metric") or {}
        try:
            v = float(s.get("value", [None, None])[1])
        except (TypeError, ValueError):
            continue
        if v != v:  # NaN is "unknown", not a number
            continue
        if m.get("namespace") and m.get("pod"):
            out[(m["namespace"], m["pod"])] = v
    return out


def list_jupyter_pods():
    """kubectl get pods -A -o json, filtered to jupyter-*. Returns (pods, err)."""
    try:
        r = subprocess.run(
            ["kubectl", "get", "pods", "-A", "-o", "json"],
            capture_output=True, text=True, timeout=KUBECTL_TIMEOUT)
    except Exception as exc:
        return None, "%s: %s" % (type(exc).__name__, str(exc)[:120])
    if r.returncode != 0:
        return None, (r.stderr or "").strip()[:200]
    try:
        doc = json.loads(r.stdout)
    except ValueError:
        return None, "kubectl output was not JSON"
    return [p for p in doc.get("items", [])
            if p.get("metadata", {}).get("name", "").startswith("jupyter-")], None


def gpu_kind(limits):
    """Classify the GPU request. Returns (kind, request_text).

    kind: full | mig | gpu-mem | none. A pod with both nvidia.com/gpu and a
    quota is full - the card is what the metrics describe.
    """
    cards = limits.get("nvidia.com/gpu")
    if cards:
        return "full", "%s gpu" % cards
    migs = ["%s=%s" % (k, v) for k, v in sorted(limits.items())
            if k.startswith("nvidia.com/mig-")]
    if migs:
        return "mig", " ".join(migs)
    mem = limits.get("nvidia.com/gpu-mem")
    if mem:
        return "gpu-mem", "%s gpu-mem" % mem
    return "none", ""


def main():
    pods_raw, err = list_jupyter_pods()
    if err or pods_raw is None:
        json.dump({"resource": "jupyter", "error": "kubectl: %s" % err},
                  sys.stdout)
        return 0

    now = time.time()
    pods = []
    for p in pods_raw:
        meta = p.get("metadata") or {}
        spec = p.get("spec") or {}
        status = p.get("status") or {}
        limits = {}
        cpu_req = 0.0
        cpu_req_seen = False
        restarts = 0
        for cs in status.get("containerStatuses") or []:
            restarts += int(cs.get("restartCount") or 0)
        for c in spec.get("containers") or []:
            c_lim = (c.get("resources") or {}).get("limits") or {}
            c_req = (c.get("resources") or {}).get("requests") or {}
            q = quantity(c_req.get("cpu"))
            if q is not None:
                cpu_req += q
                cpu_req_seen = True
            for k, v in c_req.items():
                if k == "cpu" or k.startswith("nvidia.com/"):
                    continue
                q = quantity(v)
                if q is not None:
                    limits[k] = limits.get(k, 0.0) + q
            # GPU types are extended resources: they only validly appear in
            # limits; requests mirror them, but read limits to be explicit.
            for k, v in c_lim.items():
                if not k.startswith("nvidia.com/"):
                    continue
                q = quantity(v)
                limits[k] = (limits.get(k, 0.0) + q) if q is not None \
                    else limits.get(k, 0.0)
        kind, req_text = gpu_kind({k: v for k, v in limits.items()
                                   if k.startswith("nvidia.com/")})
        started = (status.get("startTime")
                   or (meta.get("creationTimestamp") or ""))
        age_h = None
        try:
            ts = time.mktime(time.strptime(started[:19], "%Y-%m-%dT%H:%M:%S"))
            # startTime is UTC; mktime assumes local - correct by timezone
            age_h = (now - ts + time.timezone) / 3600.0
        except (ValueError, OverflowError):
            pass
        pods.append({
            "nn": "%s/%s" % (meta.get("namespace"), meta.get("name")),
            "namespace": meta.get("namespace"),
            "pod": meta.get("name"),
            "node": spec.get("nodeName") or "",
            "phase": status.get("phase") or "?",
            "age_h": round(age_h, 1) if age_h is not None else None,
            "restarts": restarts,
            "gpu_kind": kind,
            "gpu_request": req_text,
            "cpu_request_cores": round(cpu_req, 3) if cpu_req_seen else None,
        })

    # Prometheus: GPU 24h (full-GPU pods only have series - verified live:
    # DCGM_FI_DEV_GPU_UTIL has no GPU_I_PROFILE series at all on this cluster,
    # and gpu-mem pods have no series whatsoever) and CPU 72h for everyone.
    prom = {"url": PROM_URL, "reachable": False, "queries": {}}
    queries = {
        "gpu_avg_24h": 'avg by (namespace,pod)(avg_over_time('
                       'DCGM_FI_DEV_GPU_UTIL{pod=~"jupyter-.*"}[24h]))',
        "gpu_max_24h": 'max by (namespace,pod)(max_over_time('
                       'DCGM_FI_DEV_GPU_UTIL{pod=~"jupyter-.*"}[24h]))',
        "cpu_avg_72h": 'avg_over_time(sum by (namespace,pod)('
                       'rate(container_cpu_usage_seconds_total'
                       '{pod=~"jupyter-.*",container!=""}[5m]))[72h:5m])',
        "cpu_max_72h": 'max_over_time(sum by (namespace,pod)('
                       'rate(container_cpu_usage_seconds_total'
                       '{pod=~"jupyter-.*",container!=""}[15m]))[72h:15m])',
        "cpu_max_24h": 'max_over_time(sum by (namespace,pod)('
                       'rate(container_cpu_usage_seconds_total'
                       '{pod=~"jupyter-.*",container!=""}[15m]))[24h:15m])',
    }
    metrics = {}
    st, res = prom_query("vector(1)")
    if st != "ok":
        prom["error"] = res
    else:
        prom["reachable"] = True
        for name, expr in queries.items():
            st, res = prom_query(expr)
            prom["queries"][name] = {"status": st}
            if st != "ok":
                prom["queries"][name]["error"] = res
                continue
            vals = by_pod(res)
            prom["queries"][name]["series"] = len(res)
            metrics[name] = vals

    live = {(p["namespace"], p["pod"]) for p in pods}
    for name, vals in metrics.items():
        prom["queries"][name]["matched_live_pods"] = \
            sum(1 for k in vals if k in live)

    for p in pods:
        key = (p["namespace"], p["pod"])
        g_avg = metrics.get("gpu_avg_24h", {}).get(key)
        g_max = metrics.get("gpu_max_24h", {}).get(key)
        if g_avg is not None:
            p["gpu_avg_24h_pct"] = round(g_avg, 1)
            p["gpu_max_24h_pct"] = round(g_max, 1) if g_max is not None else None
        if prom["reachable"] and p["gpu_kind"] == "full":
            if g_avg is None:
                p["gpu_verdict"] = "no series (pod newer than 24h or not scraped)"
            elif g_max is not None and g_max < GPU_IDLE_MAX_PCT:
                p["gpu_verdict"] = "idle (max %.1f%% < %.0f%% over 24h)" \
                                   % (g_max, GPU_IDLE_MAX_PCT)
            else:
                p["gpu_verdict"] = "used"
        c_avg = metrics.get("cpu_avg_72h", {}).get(key)
        c_max = metrics.get("cpu_max_72h", {}).get(key)
        c_max24 = metrics.get("cpu_max_24h", {}).get(key)
        if c_avg is not None:
            p["cpu_avg_72h_cores"] = round(c_avg, 3)
        if c_max is not None:
            p["cpu_max_72h_cores"] = round(c_max, 3)
        if c_max24 is not None:
            p["cpu_max_24h_cores"] = round(c_max24, 3)
        if c_max is not None:
            p["cpu_active_72h"] = c_max >= CPU_PEAK_CORES

    kinds = {}
    for p in pods:
        kinds[p["gpu_kind"]] = kinds.get(p["gpu_kind"], 0) + 1

    json.dump({
        "resource": "jupyter",
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "counts": {"pods": len(pods), "by_gpu_kind": kinds},
        "thresholds": {"cpu_peak_cores": CPU_PEAK_CORES,
                       "gpu_idle_max_pct": GPU_IDLE_MAX_PCT},
        "prom": prom,
        "pods": sorted(pods, key=lambda p: p["nn"]),
    }, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
