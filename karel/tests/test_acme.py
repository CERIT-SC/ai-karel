#!/usr/bin/env python3
"""ACME solver + certificate health: the 2026-09/10 persistent problem
shape — 25 solvers, 23 DNS-broken, 2 policy-blocked."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import rules_k8s        # noqa: E402
import housekeeping     # noqa: E402
import logscan          # noqa: E402


def solver_pod(ns, i):
    return {"metadata": {"namespace": ns, "name": "cm-acme-http-solver-%d" % i,
                         "creationTimestamp": "2026-10-08T02:00:00Z"},
            "spec": {"nodeName": "kub-a9"},
            "status": {"phase": "Running"}}


# 25 solvers across 11 namespaces; challenges carry the dnsNames
pods = {"items": []}
challenges = {"items": []}
dns = {}
netted = {}
expect = ["10.0.0.5"]
for i in range(25):
    ns = "tenant-%02d" % (i % 11)
    pods["items"].append(solver_pod(ns, i))
    host = "svc-%02d.example.com" % i
    challenges["items"].append({
        "metadata": {"namespace": ns, "name": "ch-%02d" % i},
        "spec": {"dnsName": host},
        "status": {"state": "pending", "reason": "http-01 self check failed"}})
    if i < 23:
        # 23 broken: 12 NXDOMAIN, 8 resolve to the wrong address, 3 SERVFAIL
        dns[host] = ({"status": "nxdomain", "addresses": []} if i < 12 else
                     {"status": "differ", "addresses": ["10.0.0.99"]} if i < 20 else
                     {"status": "servfail", "addresses": []})
    else:
        dns[host] = {"status": "ok", "addresses": ["10.0.0.5"]}
        if i == 23:
            netted[ns] = [{"name": "deny-all", "empty_ingress": True,
                           "types": ["Ingress"], "ingress": []}]
        else:
            netted[ns] = [{"name": "deny-all-open", "empty_ingress": True,
                           "types": ["Ingress"], "ingress": []}]


def acme_bundle():
    return facts({
        "k8s.acme.solvers": [
            {"ns": (p["metadata"]["namespace"]), "pod": p["metadata"]["name"],
             "node": "kub-a9", "created": "2026-10-08T02:00:00Z",
             "age_h": 5.2, "phase": "Running"}
            for p in pods["items"]],
        "k8s.acme.solvers_stale": [
            {"ns": (p["metadata"]["namespace"]), "pod": p["metadata"]["name"],
             "node": "kub-a9", "created": "2026-10-08T02:00:00Z",
             "age_h": 5.2, "phase": "Running"}
            for p in pods["items"]],
        "k8s.acme.solvers_stale_count": 25,
        "k8s.acme.solvers_stale_by_ns": dict(
            (ns, sum(1 for p in pods["items"]
                     if p["metadata"]["namespace"] == ns))
            for ns in {p["metadata"]["namespace"] for p in pods["items"]}),
        "k8s.acme.challenges": [
            {"ns": c["metadata"]["namespace"], "name": c["metadata"]["name"],
             "dnsName": c["spec"]["dnsName"], "state": "pending",
             "reason": "http-01 self check failed"}
            for c in challenges["items"]],
        "k8s.acme.dns": dns,
        "k8s.acme.dns_expected": expect,
        "k8s.netpol.by_ns": netted,
        "k8s.acme.certificates_expired": [],
        "k8s.acme.certificates_expiring_not_ready": [],
    })


b = acme_bundle()
fs = rules_k8s.r_acme(b)
codes = {}
for f in fs:
    codes.setdefault(f["code"], []).append(f)

check("the 23 DNS-broken solvers are one WARN detailing each",
      len(codes.get("ACME_SOLVER_DNS", [])) == 1
      and codes["ACME_SOLVER_DNS"][0]["metric"] == 23, list(codes))
check("NXDOMAIN and wrong-answer are distinguished",
      codes and any("NXDOMAIN" in d for d in codes["ACME_SOLVER_DNS"][0]["detail"])
      and any("10.0.0.99" in d for d in codes["ACME_SOLVER_DNS"][0]["detail"]),
      codes["ACME_SOLVER_DNS"][0]["detail"][:5])
check("the 2 policy-blocked solvers are one WARN naming namespaces",
      len(codes.get("ACME_SOLVER_NETPOL", [])) == 1
      and codes["ACME_SOLVER_NETPOL"][0]["metric"] == 2)
check("no stale-cause info when every solver is explained",
      not codes.get("ACME_SOLVER_STALE"))

b2 = dict(b)
b2["facts"] = dict(b["facts"])
b2["facts"]["k8s.acme.certificates_expiring_not_ready"] = {
    "value": ["shop/tls-cert (3 days left, not Ready)"], "source": "t"}
fs2 = rules_k8s.r_acme(facts({k: v["value"] for k, v in b2["facts"].items()}))
check("not-ready certificate inside 7 days is CRIT",
      any(f["id"] == "ACME_CERT_EXPIRING" and f["severity"] == "crit"
          for f in fs2))


# --------------------------------------------------------------------------
print("\nsolvers land in the tenant table and in housekeeping")

fs3 = rules_k8s.r_tenant_summary(b)
rows = fs3[0]["table"]["rows"] if fs3 else []
check("tenant table has an ACME row with the count",
      any(r[0] == "ACME solver pods older than 1h" and r[1] == 25
          for r in rows), rows)

hb = facts({k: v["value"] for k, v in b["facts"].items()})
hb["facts"]["k8s.ns.info"] = {"value": {}, "source": "t"}
hb["collected_at"] = "2026-10-08T09:00:00Z"
housekeeping.derive(hb, {}, now=logscan.parse_ts("2026-10-08T09:00:00Z"))
slv = [i for i in hb["facts"]["k8s.housekeeping.items"]["value"]
       if i["category"] == "acme_solver_stale"]
check("stale solvers are housekeeping items with delete proposals",
      len(slv) == 25 and all(i.get("proposed_command") for i in slv),
      len(slv))


# --------------------------------------------------------------------------
print("\nDNS probe: NXDOMAIN vs SERVFAIL vs NODATA vs wrong address")

import socket
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "bin"))
import probe_acme     # noqa: E402


class _FakeGai:
    def __init__(self, mapping):
        self.mapping = mapping

    def __call__(self, host, port, proto=None):
        v = self.mapping.get(host)
        if v == "nx":
            raise socket.gaierror(socket.EAI_NONAME, "nxdomain")
        if v == "servfail":
            raise socket.gaierror(socket.EAI_AGAIN, "temp")
        if v == "nodata":
            return []
        return [(socket.AF_INET, None, None, "", (a, 0)) for a in (v or [])]


mapping = {"good.example.com": ["10.0.0.5"], "nx.example.com": "nx",
           "empty.example.com": "nodata", "flaky.example.com": "servfail"}
_orig_gai = probe_acme.socket.getaddrinfo
probe_acme.socket.getaddrinfo = _FakeGai(mapping)
try:
    sts = {h: probe_acme.dns_lookup(h) for h in mapping}
finally:
    probe_acme.socket.getaddrinfo = _orig_gai
check("NXDOMAIN distinct", sts["nx.example.com"][0] == "nxdomain", sts)
check("ok answers resolve", sts["good.example.com"] == ("ok", ["10.0.0.5"]))
check("NODATA distinct", sts["empty.example.com"][0] == "nodata", sts)
check("SERVFAIL distinct", sts["flaky.example.com"][0] == "servfail", sts)


finish()
