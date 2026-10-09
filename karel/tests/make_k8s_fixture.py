#!/usr/bin/env python3
"""Synthetic Kubernetes collector output. Usage: make_k8s_fixture.py <dir> [healthy|degraded]"""
import gzip
import json
import os
import sys
import datetime

out = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "healthy"
deg = mode == "degraded"
os.makedirs(os.path.join(out, "raw"), exist_ok=True)

now = datetime.datetime.now(datetime.timezone.utc)
iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")

NODES = ["node-01", "node-02", "node-03", "node-04"]
down_node = "node-03" if deg else None


def node(name):
    ready = "False" if name == down_node else "True"
    conds = [{"type": "Ready", "status": ready,
              "lastTransitionTime": iso(now - datetime.timedelta(hours=3))}]
    if deg and name == "node-04":
        conds.append({"type": "DiskPressure", "status": "True",
                      "lastTransitionTime": iso(now - datetime.timedelta(hours=1))})
    else:
        conds.append({"type": "DiskPressure", "status": "False"})
    # node-04 lags the fleet on all three: an older Kubernetes patch, an
    # older RKE2 release, and a kernel that has not had its security reboot.
    kv = "v1.35.6+rke2r1"
    kern = "6.8.0-51-generic"
    if deg and name == "node-04":
        kv = "v1.35.4+rke2r0"
        kern = "6.8.0-49-generic"
    roles = ({"node-role.kubernetes.io/control-plane": "true",
              "node-role.kubernetes.io/etcd": "true"} if name != "node-04" else
             {"node-role.kubernetes.io/worker": "true"})
    if name != "node-04":
        conds.append({"type": "EtcdIsVoter", "status": "True",
                      "message": "Node is a voting member of the etcd cluster"})
    return {
        "metadata": {"name": name, "labels": roles},
        "spec": {"unschedulable": True if (deg and name == "node-02") else False},
        "status": {
            "conditions": conds,
            "allocatable": {"cpu": "15500m", "memory": "65011712Ki",
                            "ephemeral-storage": "92871219742", "pods": "110"},
            "capacity": {"cpu": "16", "memory": "67108864Ki",
                         "ephemeral-storage": "95467948Ki", "pods": "110"},
            "nodeInfo": {"kubeletVersion": kv, "osImage": "Ubuntu 24.04.2 LTS",
                         "kernelVersion": kern,
                         "containerRuntimeVersion": "containerd://2.0.5"},
            "images": [{"names": ["x"], "sizeBytes": 1} for _ in range(40)],
        },
    }


def pod(ns, name, node_name, owner_kind=None, owner_name=None, phase="Running",
        ready=True, restarts=0, oom=False, waiting=None, cpu="200m", mem="512Mi",
        selector=False, app=None, claim=None):
    md = {"namespace": ns, "name": name}
    if app:
        md["labels"] = {"app": app}
    if owner_kind:
        md["ownerReferences"] = [{"kind": owner_kind, "name": owner_name}]
    cs = {"name": "main", "restartCount": restarts, "state": {}}
    if oom:
        cs["lastState"] = {"terminated": {"reason": "OOMKilled", "exitCode": 137}}
    if waiting:
        cs["state"] = {"waiting": {"reason": waiting}}
    spec = {"nodeName": node_name,
            "containers": [{"name": "main",
                            "resources": {"requests": {"cpu": cpu, "memory": mem}}}]}
    if claim:
        spec["volumes"] = [{"name": "data",
                            "persistentVolumeClaim": {"claimName": claim}}]
    if selector:
        spec["nodeSelector"] = {"kubernetes.io/hostname": node_name}
    return {
        "metadata": md, "spec": spec,
        "status": {"phase": phase,
                   "conditions": [{"type": "Ready",
                                   "status": "True" if ready else "False"}],
                   "containerStatuses": [cs]},
    }


pods = []
for i, n in enumerate(NODES):
    for j in range(3):
        pods.append(pod("storage", "storage-worker-%d-%d" % (i * 3 + j, j), n,
                        "ReplicaSet", "storage-worker-%d-7d9c8f" % (i * 3 + j),
                        phase="Failed" if (deg and n == down_node) else "Running",
                        ready=not (deg and n == down_node),
                        cpu="1000m", mem="4Gi", selector=True, app="storage-worker"))
    pods.append(pod("storage", "node-agent-%s-6" % n, n,
                    "ReplicaSet", "cc-%s" % n, selector=True, app="node-agent"))
    pods.append(pod("storage", "node-exporter-%s-7" % n, n,
                    "ReplicaSet", "ex-%s" % n, selector=True, app="node-exporter"))
    if i < 3:
        pods.append(pod("storage", "quorum-%s-xyz" % "abc"[i], n,
                        "ReplicaSet", "quorum-%s-1a2b3c" % "abc"[i],
                        cpu="500m", mem="2Gi", selector=True, app="quorum"))
pods.append(pod("storage", "storage-operator-5f6g7h-qq", "node-01",
                "ReplicaSet", "storage-operator-5f6g7h", restarts=8 if deg else 1))
pods.append(pod("storage", "storage-manager-a-11", "node-01",
                "ReplicaSet", "storage-manager-a-9a8b7c", cpu="500m", mem="2Gi"))
pods.append(pod("kube-system", "rke2-coredns-autoscaler-1", "node-02",
                "ReplicaSet", "rke2-coredns-autoscaler-4d5e6f"))
pods.append(pod("app", "api-7d9c8f-abcde", "node-01", "ReplicaSet", "api-7d9c8f",
                restarts=14 if deg else 2, oom=deg, cpu="2000m", mem="8Gi"))
pods.append(pod("app", "api-7d9c8f-fghij", "node-02", "ReplicaSet", "api-7d9c8f",
                restarts=11 if deg else 2, cpu="2000m", mem="8Gi"))
pods.append(pod("app", "worker-0", "node-03", "StatefulSet", "worker",
                phase="Pending" if deg else "Running", ready=not deg,
                waiting="ImagePullBackOff" if deg else None,
                cpu="4000m", mem="16Gi", selector=True, claim="data-worker-0"))
pods.append(pod("ai-karel-ns", "karel-29001-zz", "node-04", "Job",
                "karel-29001234", phase="Succeeded"))

wh_svc_ready = 0 if deg else 2
validating = {"items": [{
    "metadata": {"name": "app-webhook"},
    "webhooks": [{"name": "resources.example.io", "failurePolicy": "Fail",
                  "timeoutSeconds": 30 if deg else 5,
                  "clientConfig": {"service": {"namespace": "app",
                                               "name": "app-admission-controller"}}}],
}]}

endpointslices = {"items": [
    {"metadata": {"namespace": "app",
                  "labels": {"kubernetes.io/service-name": "app-admission-controller"}},
     "endpoints": ([{"addresses": ["10.42.0.5"], "conditions": {"ready": True}},
                    {"addresses": ["10.42.1.5"], "conditions": {"ready": True}}]
                   if wh_svc_ready else [])},
]}

metrics = {
    "metrics": {
        "k8s.etcd.db_bytes": 1_400_000_000 if deg else 780_000_000,
        "k8s.etcd.has_leader": 1,
        "k8s.etcd.leader_changes_total": 9 if deg else 2,
        "k8s.etcd.proposals_failed_total": 4 if deg else 0,
        "k8s.etcd.objects_total": 41_233,
        "k8s.apiserver.requests_total": 9_400_000 if deg else 8_900_000,
        "k8s.apiserver.requests_5xx_total": 12_400 if deg else 300,
        "k8s.apiserver.requests_429_total": 40,
        "k8s.apiserver.flowcontrol_rejected_total": 17 if deg else 0,
        "k8s.apiserver.inflight": 12,
        "k8s.apiserver.deprecated_apis": {"1.36": 4210} if deg else {},
        "k8s.apiserver.rss_bytes": 2_100_000_000,
    },
    "families_seen": 12,
}

tls = {
    "apiserver": {"endpoint": "10.43.0.1:443",
                  "not_after": iso(now + datetime.timedelta(days=18 if deg else 300)),
                  "days_remaining": 18 if deg else 300,
                  "subject": "CN=kube-apiserver"},
    "ca_bundle": {"path": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
                  "certificates": 1},
    "coverage_gaps": ["kubelet client certificates (per-node) are NOT visible from a pod"],
}

events_buf = {"available": True, "source_days": ["2026-08-22", "2026-08-23"],
              "coverage": "buffered", "key_count": 3,
              "events": ({
                  "app|Pod|api-7d9c8f-abcde|OOMKilling|Warning":
                      {"count": 6, "first": "x", "last": "y"},
                  "app|Pod|worker-0|FailedScheduling|Warning":
                      {"count": 31, "first": "x", "last": "y"},
                  "storage|Pod|storage-worker-9-0|Unhealthy|Warning":
                      {"count": 12, "first": "x", "last": "y"},
              } if deg else {})}

pdb = {"items": [{
    "metadata": {"namespace": "storage", "name": "storage-worker"},
    "status": {"disruptionsAllowed": 0 if deg else 1,
               "currentHealthy": 9 if deg else 12, "desiredHealthy": 10},
}]}

pv = {"items": [
    {"metadata": {"name": "pvc-aaa"}, "status": {"phase": "Bound"},
     "spec": {"csi": {"driver": "example.csi.driver"},
              "claimRef": {"namespace": "app", "name": "data-worker-0"}}},
    {"metadata": {"name": "local-registry"}, "status": {"phase": "Bound"},
     "spec": {"local": {"path": "/srv/registry"},
              "nodeAffinity": {"required": {"nodeSelectorTerms": [
                  {"matchExpressions": [{"key": "kubernetes.io/hostname",
                                         "operator": "In", "values": ["node-03"]}]}]}}}},
    {"metadata": {"name": "pvc-old"}, "status": {"phase": "Released"},
     "spec": {"csi": {"driver": "example.csi.driver"}}},
]}

pvc = {"items": [
    {"metadata": {"namespace": "app", "name": "data-worker-0"},
     "spec": {"storageClassName": "fast-storage"},
     "status": {"phase": "Pending" if deg else "Bound"}},
    {"metadata": {"namespace": "app", "name": "cache"},
     "spec": {"storageClassName": "fast-storage"}, "status": {"phase": "Bound"}},
]}

files = {
    "k_version": {"clientVersion": {"gitVersion": "v1.35.6"},
                  "serverVersion": {"gitVersion": "v1.35.6+rke2r1"}},
    "k_nodes": {"items": [node(n) for n in NODES]},
    "k_pods": {"items": pods},
    "k_pvc": pvc,
    "k_pv": pv,
    "k_volumeattach": {"items": [
        {"metadata": {"name": "csi-abc"},
         "spec": {"attacher": "example.csi.driver", "nodeName": down_node or "node-01",
                  "source": {"persistentVolumeName": "pvc-aaa"}},
         "status": ({"attached": False,
                     "attachError": {"message": "rpc error: code = DeadlineExceeded "
                                                "desc = context deadline exceeded"}}
                    if deg else {"attached": True})}]},
    "k_pdb": pdb,
    "k_validatingwh": validating,
    "k_mutatingwh": {"items": []},
    "k_endpointslices": endpointslices,
    "k_deployments": {"items": [
        {"metadata": {"namespace": "app", "name": "api"},
         "spec": {"replicas": 3, "paused": True if deg else False},
         "status": {"readyReplicas": 2 if deg else 3}}]},
    "k_statefulsets": {"items": [
        {"metadata": {"namespace": "app", "name": "worker"},
         "spec": {"replicas": 1}, "status": {"readyReplicas": 0 if deg else 1}}]},
    "k_daemonsets": {"items": [
        {"metadata": {"namespace": "kube-system", "name": "rke2-canal"},
         "status": {"desiredNumberScheduled": 4,
                    "numberReady": 3 if deg else 4}}]},
    "k_jobs": {"items": ([
        {"metadata": {"namespace": "kube-system", "name": "helm-install-rke2-coredns"},
         "status": {"failed": 3}}] if deg else [])},
    "k_cronjobs": {"items": [
        {"metadata": {"namespace": "ai-karel-ns", "name": "karel"},
         "spec": {}, "status": {"lastScheduleTime": iso(now)}},
        {"metadata": {"namespace": "backup", "name": "nightly"},
         "spec": {}, "status": {"lastScheduleTime": iso(
             now - datetime.timedelta(days=6 if deg else 0.5))}}]},
    "k_helmcharts": {"items": [
        {"metadata": {"namespace": "kube-system", "name": "rke2-coredns"},
         "spec": {"chart": "rke2-coredns", "version": "1.42.0"}}]},
    "k_helmchartcfg": {"items": []},
    "k_apiservices": {"items": [
        {"metadata": {"name": "v1beta1.metrics.k8s.io"},
         "status": {"conditions": [{"type": "Available",
                                    "status": "False" if deg else "True",
                                    "reason": "FailedDiscoveryCheck"}]}}]},
    "k_leases": {"items": [
        {"metadata": {"namespace": "kube-system", "name": "kube-scheduler"},
         "spec": {"holderIdentity": "node-01"}}]},
    "k_events": {"items": []},
    "k_event_buffer": events_buf,
    "k_storageclass": {"items": [
        {"metadata": {"name": "fast-storage",
                      "annotations": {"storageclass.kubernetes.io/is-default-class": "true"}}}]},
    "k_csr": {"items": []},
    "k_apiserver_metrics": metrics,
    "k_tls_probe": tls,
    "k_namespaces": {"items": [{"metadata": {"name": n}} for n in
                               ("default", "kube-system", "storage", "app", "ai-karel-ns")]},
}

text_files = {
    "k_readyz": "[+]ping ok\n[+]etcd ok\nreadyz check passed" if not deg else
                "[+]ping ok\n[-]etcd failed: reason withheld\nreadyz check failed",
    "k_livez": "livez check passed",
    "k_top_nodes": "\n".join(
        "%s  %sm  %s%%  %sMi  %s%%" % (
            n, 4200 + i * 300, 27 + i * 2, 38000 + i * 4000, 62 + i * (11 if deg else 3))
        for i, n in enumerate(NODES)),
}

index_rows = []
tier1 = {"k_version", "k_readyz", "k_livez", "k_nodes"}

for name, obj in files.items():
    with open(os.path.join(out, "raw", "%s.stdout" % name), "wt") as fh:
        json.dump(obj, fh)
    open(os.path.join(out, "raw", "%s.stderr" % name), "w").close()
    index_rows.append((name, "0", "1", "1" if name in tier1 else "2", "ok",
                       str(os.path.getsize(os.path.join(out, "raw", "%s.stdout" % name)))))

for name, text in text_files.items():
    with open(os.path.join(out, "raw", "%s.stdout" % name), "wt") as fh:
        fh.write(text)
    open(os.path.join(out, "raw", "%s.stderr" % name), "w").close()
    index_rows.append((name, "0", "1", "1" if name in tier1 else "2", "ok",
                       str(len(text))))

with open(os.path.join(out, "index.tsv"), "wt") as fh:
    for r in index_rows:
        fh.write("\t".join(r) + "\n")
with open(os.path.join(out, "expected_status.json"), "wt") as fh:
    json.dump({}, fh)
open(os.path.join(out, "COMPLETE"), "w").close()

for f in os.listdir(os.path.join(out, "raw")):
    p = os.path.join(out, "raw", f)
    with open(p, "rb") as s_, gzip.open(p + ".gz", "wb") as d_:
        d_.write(s_.read())
    os.remove(p)

print("k8s fixture written to %s (%s)" % (out, mode))
