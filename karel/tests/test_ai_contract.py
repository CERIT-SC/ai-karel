#!/usr/bin/env python3
"""The P2 contract: external slots, failing-pod facts, deterministic
pattern groups, redaction, the narrative number validator."""

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


# --------------------------------------------------------------------------
print("\nimage splitting for grouping and narrative")

split = normalize_k8s._image_split
check("registry/repo/tag split",
      split("reg.example.com/team/app:1.2")
      == {"registry": "reg.example.com", "repo": "team/app", "tag": "1.2"})
check("docker.io namespace is not a registry",
      split("bitnami/redis:7")
      == {"registry": "docker.io", "repo": "bitnami/redis", "tag": "7"})
check("tagless image",
      split("quay.io/x/app") == {"registry": "quay.io", "repo": "x/app",
                                 "tag": None})


# --------------------------------------------------------------------------
print("\nfailing-pod facts: clean, bounded, redacted")

pods = {"items": [
    {"metadata": {"namespace": "shop", "name": "web-1",
                  "ownerReferences": [{"kind": "ReplicaSet",
                                       "name": "web-abc123"}]},
     "spec": {"containers": [{"name": "web",
                              "image": "reg.example.com/shop/web:latest"}]},
     "status": {"phase": "Running",
                "containerStatuses": [{
                    "name": "web", "image": "reg.example.com/shop/web:latest",
                    "state": {"waiting": {
                        "reason": "ImagePullBackOff",
                        "message": "pull from https://user:secretpw@reg.example.com/shop/web failed"}},
                    "restartCount": 3}]}},
    {"metadata": {"namespace": "ml", "name": "train-1",
                  "ownerReferences": [{"kind": "Job", "name": "train-77"}]},
     "spec": {"containers": [{"name": "c",
                              "image": "docker.io/library/python:3.12"}]},
     "status": {"phase": "Failed",
                "containerStatuses": [{
                    "name": "c", "image": "docker.io/library/python:3.12",
                    "state": {"terminated": {"reason": "Error",
                                             "exitCode": 137,
                                             "finishedAt": "2026-10-08T01:00:00Z"}}}]}},
]}
F = normalize.Facts()
normalize_k8s.p_pods(pods, F, "k_pods")
failing = F.get_value("k8s.pod.failing") or []
check("two failing pods recorded with owners",
      len(failing) == 2 and failing[0]["owner"] and "web" in failing[0]["owner"], failing)
check("URL credentials are stripped from messages",
      "secretpw" not in json.dumps(failing), failing[0].get("message"))
check("image split present", failing[0]["image"]["repo"] == "shop/web")


# --------------------------------------------------------------------------
print("\ndeterministic pattern groups")

pods2 = {"items": [
    {"metadata": {"namespace": "ns%d" % i, "name": "p%d" % i,
                  "ownerReferences": [{"kind": "ReplicaSet", "name": "x-abc"}]},
     "spec": {"containers": [{"name": "c", "image": "docker.io/bitnami/nginx:dev"}]},
     "status": {"phase": "Running",
                "containerStatuses": [{
                    "name": "c", "image": "docker.io/bitnami/nginx:dev",
                    "state": {"waiting": {"reason": "ImagePullBackOff",
                                          "message": "tag not found"}}}]}}
    for i in range(6)]}
F2 = normalize.Facts()
normalize_k8s.p_pods(pods2, F2, "k_pods")
b2 = facts({k: v["value"] for k, v in F2.items()})
fs = rules_k8s.r_failure_patterns(b2)
ids = [(f["id"], f["severity"]) for f in fs]
check("one repo in six namespaces is one WARN, not six",
      any(i == "K8S_IMAGE_PULL_PATTERN:bitnami/nginx" and s == "warn"
          for i, s in ids), ids)
check("floating tag pattern listed",
      any(i == "K8S_FLOATING_TAGS" for i, s in ids), ids)


# --------------------------------------------------------------------------
print("\nnarrative number validator")

bundle = {"facts": {
    "k8s.pod.failed_recent_count": {"value": 704},
    "k8s.housekeeping.count.svc_no_backend": {"value": 412},
    "k8s.clean_runs": {"value": 26},
}}
bf = tempfile.mktemp(suffix=".json")
with open(bf, "wt") as fh:
    json.dump(bundle, fh)
VAL = os.path.join(ROOT, "bin", "validate_narrative.py")
r = subprocess.run([sys.executable, VAL, "-", bf],
                   input="704 pods failed last week; 412 services have no backend.",
                   capture_output=True, text=True)
check("verifiable narrative passes", r.returncode == 0,
      (r.stdout, r.stderr))
r = subprocess.run([sys.executable, VAL, "-", bf],
                   input="913 tickets are waiting.",
                   capture_output=True, text=True)
check("an invented number is flagged with its line", r.returncode == 1
      and "913" in (r.stdout + r.stderr), (r.stdout, r.stderr))


finish()
