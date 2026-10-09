#!/usr/bin/env python3
"""CPU/GPU waste: wrapper exit-status handling, parse rules, the section."""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import ROOT, check, facts, finish                # noqa: E402

import normalize        # noqa: E402
import normalize_k8s    # noqa: E402
import rules_k8s        # noqa: E402

CSV_CPU = (
    # the real binary's header (captured 2026-10-08)
    "namespace,pod,prometheus_usage,k8s_requests,age\n"
    "shop,web-1,0.4,2.0,4d\n"
    "shop,web-2,0.05,1.0,2d\n"
    "ml,train-a,7.5,8.0,3d\n"
    "ml,idle-b,n/a,4.0,8.3d\n"
    "lab,young-c,0.01,3.0,4h\n"
)
CSV_GPU = (
    # its GPU sibling: usage is a % of requested cards; model_name column
    "namespace,pod,prometheus_usage,k8s_requests,age,model_name\n"
    "ml,train-a,95.0%,4,3d,NVIDIA A100\n"
    "ml,idle-b,n/a,2,8.3d,NVIDIA A100\n"
    "ml,idle-c,0.0%,1,4d,NVIDIA A40\n"
    "lab,young-g,5.0%,2,2h,NVIDIA H100\n"
)


# --------------------------------------------------------------------------
print("\nparsing rules: n/a vs 0, young pods excluded, waste arithmetic")

F = normalize.Facts()
normalize_k8s.p_usage({"resource": "cpu", "csv": CSV_CPU, "rows": 5},
                      F, "k_top_cpu")
check("real header parses; all pods counted",
      F.get_value("k8s.usage.cpu.total_pods") == 5,
      F.get_value("k8s.usage.cpu.parse_error"))
check("one under-12h pod is excluded and counted",
      F.get_value("k8s.usage.cpu.excluded_young") == 1, F.get_value("k8s.usage.cpu.top"))
check("young pods are not in the waste table",
      not any("young-c" in str(r) for r in F.get_value("k8s.usage.cpu.top")))
check("no-series counted, and distinct from zero",
      F.get_value("k8s.usage.cpu.no_series") == 1)
waste = F.get_value("k8s.usage.cpu.waste_total")
check("waste = sum(request - avg) over the rest (1.6 + 0.95 + 0.5)",
      abs((waste or 0) - 3.05) < 0.01, waste)
top = F.get_value("k8s.usage.cpu.top")
check("ranked by waste, web-1 first",
      top and top[0][0] == "shop/web-1" and abs(top[0][3] - 1.6) < 0.01, top)
check("no parse error recorded for the real header",
      F.get_value("k8s.usage.cpu.parse_error") is None)

F = normalize.Facts()
normalize_k8s.p_usage({"resource": "gpu", "csv": CSV_GPU, "rows": 4}, F, "k_top_gpu")
topg = F.get_value("k8s.usage.gpu.top_gpu")
check("GPU rows rank no-series first, then usage ascending",
      [r[0] for r in topg] == ["ml/idle-b", "ml/idle-c", "ml/train-a"], topg)
check("GPU young pods excluded",
      F.get_value("k8s.usage.gpu.excluded_young") == 1)
check("GPU percent means share of REQUESTED cards (95% of 4 wastes 0.2, "
      "0% of 1 wastes 1.0)",
      abs((F.get_value("k8s.usage.gpu.waste_total") or 0) - 1.2) < 0.01,
      F.get_value("k8s.usage.gpu.waste_total"))
check("GPU rows keep the model name",
      topg[0][3] == "NVIDIA A100" and topg[2][3] == "NVIDIA A100", topg)


# --------------------------------------------------------------------------
print("\nwrapper: binary status, ledger exclusions, missing binary")

WRAP = os.path.join(ROOT, "bin", "collect_usage.py")
fakebin = tempfile.mkdtemp(prefix="karel-usage-bin.")
script = os.path.join(fakebin, "k8s-pod-resource-usage")


def run_wrapper(script_body):
    with open(script, "wt") as fh:
        fh.write(script_body)
    os.chmod(script, 0o755)
    env = dict(os.environ)
    env["PATH"] = fakebin + ":" + env["PATH"]
    r = subprocess.run([sys.executable, WRAP, "cpu"], capture_output=True,
                       text=True, env=env, timeout=30)
    return json.loads(r.stdout)


out = run_wrapper("#!/bin/sh\nprintf '%s\n' 'namespace,pod,request,usage,age_h'\nprintf 'a,b,1,0.5,99\n'\nexit 3\n")
check("nonzero binary means failed collection, not a table",
      "error" in out and "csv" not in out, out)
out = run_wrapper("#!/bin/sh\nprintf '%s\n' 'namespace,pod,request,usage,age_h'\nprintf 'a,b,1,0.5,99\n'\n")
check("clean pass-through keeps the CSV",
      out.get("rows") == 1 and "a,b,1,0.5,99" in out.get("csv", ""), out)


env_scenario = tempfile.mkdtemp()
sup_path = os.path.join(env_scenario, "suppressions.json")
with open(sup_path, "wt") as fh:
    json.dump({"suppressions": [],
               "usage_exclude": [{"pattern": "vllm-ns",
                                  "reason": "GPU playground",
                                  "by": "ops@x"}]}, fh)
with open(script, "wt") as fh:
    fh.write("#!/bin/sh\nprintf 'namespace,pod,request,usage,age_h\n'\n"
             "printf 'vllm-ns,nope,1,0.1,50\n'\nprintf 'ok-ns,real,2,0.2,55\n'\n")
os.chmod(script, 0o755)
env = dict(os.environ)
env["PATH"] = fakebin + ":" + env["PATH"]
env["SUPPRESSIONS_FILE"] = sup_path
r = subprocess.run([sys.executable, WRAP, "cpu"], capture_output=True,
                   text=True, env=env, timeout=30)
out = json.loads(r.stdout)
check("ledger exclusion drops the row, with the reason recorded",
      out.get("excluded") == ["vllm-ns"] and "ok-ns" in out.get("csv", "")
      and "vllm-ns/nope" not in out.get("csv", ""), out)

env = dict(os.environ)
env["KAREL_USAGE_BIN"] = "definitely-not-a-real-binary-xyz"
r = subprocess.run([sys.executable, WRAP, "gpu"], capture_output=True,
                   text=True, env=env, timeout=30)
out = json.loads(r.stdout)
check("missing binary is an error document, not a crash",
      "not found" in (out.get("error") or ""), out)


# --------------------------------------------------------------------------
print("\nsection: two tables with the join to the GPU model")

F = normalize.Facts()
normalize_k8s.p_usage({"resource": "cpu", "csv": CSV_CPU, "rows": 4}, F, "k_top_cpu")
normalize_k8s.p_usage({"resource": "gpu", "csv": CSV_GPU, "rows": 3}, F, "k_top_gpu")
pairs = {k: v["value"] for k, v in F.items()}
pairs["k8s.node.pod_names"] = {"gpu-node-1": ["ml/train-a", "ml/idle-b"]}
pairs["k8s.node.gpu_labels"] = {"gpu-node-1": {"nvidia.com/gpu.product": "NVIDIA-H100"}}
b = facts(pairs)
fs = rules_k8s.r_resource_waste(b)
check("one section with two tables",
      len(fs) == 1 and fs[0].get("section") == "Resource waste"
      and len(fs[0].get("tables", [])) == 2, fs[0]["id"] if fs else None)
check("tables carry titles",
      fs and "cpu" in fs[0]["tables"][0]["title"].lower())

b2 = facts({"k8s.usage.cpu.error": "binary not found: k8s-pod-resource-usage"})
fs2 = rules_k8s.r_resource_waste(b2)
check("a failed collection is named under cannot-see",
      any(f["id"] == "KAREL_USAGE_NOT_COLLECTED:cpu"
          and f["severity"] == "info" for f in fs2), fs2)


# --------------------------------------------------------------------------
print("\nthe rendered report actually shows the section (both resources)")

import report as _report    # noqa: E402
text = _report.render(b, fs, [], {}, carried=[], suppressed=[])
check("a two-resource section renders its heading",
      "## Resource waste" in text)
check("both tables render with their titles",
      text.count("top 2") >= 0 and "top 30 GPU rows" in text
      and "top 20 CPU waste" in text, [l for l in text.splitlines()
                                       if "waste" in l][:4])
check("GPU rows keep the usage/model cells",
      "NVIDIA A40" in text or "NVIDIA A100" in text)


# --------------------------------------------------------------------------
print("\ngpu-mem quota never masquerades as a whole card count")

pods_gm = {"items": [{
    "metadata": {"namespace": "vo", "name": "jupyter-perrine",
                 "ownerReferences": [{"kind": "ReplicaSet", "name": "x-abc1"}]},
    "spec": {"nodeName": "kub-b7",
             "containers": [{"name": "notebook", "resources": {
                 "requests": {"nvidia.com/gpu-mem": "60", "cpu": "10"}}}]},
    "status": {"phase": "Running"}}]}
F = normalize.Facts()
normalize_k8s.p_pods(pods_gm, F, "k_pods")
check("gpu-mem-only pod recorded with the breakdown, not as a card pod",
      F.get_value("k8s.pod.gpu_requests", {}).get("vo/jupyter-perrine")
      == {"cards": 0, "mig": 0, "gpu_mem_gb": 60}, F.get_value("k8s.pod.gpu_requests"))
check("and it is NOT a card-holding user for upgrade/drain joins",
      "kub-b7" not in (F.get_value("k8s.pod.gpu_users") or {}))

pairs2 = {"k8s.usage.gpu.total_pods": 2, "k8s.usage.gpu.waste_total": 0.0,
          "k8s.usage.gpu.top_gpu": [["vo/jupyter-perrine", "n/a", 60.0, "", "2000 h"],
                                    ["vo/yolo1", "n/a", 1.0, "NVIDIA A100", "1500 h"]],
          "k8s.pod.gpu_requests": {"vo/jupyter-perrine": {"cards": 0, "mig": 0,
                                                          "gpu_mem_gb": 60}}}
fs = rules_k8s.r_resource_waste(facts(pairs2))
_t = fs[0].get("table") or fs[0]["tables"][0]
row = _t["rows"][0]
check("the table annotates the unit instead of saying '60 GPUs'",
      row[2] == "60.0 gpu-mem" and "gpu-mem" in (_t.get("note") or ""), row)


finish()
