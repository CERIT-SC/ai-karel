#!/usr/bin/env python3
"""Gateway API status checks."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import check, facts, finish                     # noqa: E402

import normalize        # noqa: E402
import normalize_k8s    # noqa: E402
import rules_k8s        # noqa: E402
import housekeeping     # noqa: E402
import logscan          # noqa: E402

GWS = {"items": [
    {"metadata": {"namespace": "apps", "name": "gw-ok"},
     "status": {"conditions": [
         {"type": "Accepted", "status": "True", "reason": "Accepted"},
         {"type": "Programmed", "status": "True", "reason": "Programmed"}]}},
    {"metadata": {"namespace": "apps", "name": "gw-bad"},
     "status": {"conditions": [
         {"type": "Accepted", "status": "True", "reason": "Accepted"},
         {"type": "Programmed", "status": "False", "reason": "AddressNotAssigned"}]}},
]}

ROUTES = {"items": [
    {"metadata": {"namespace": "apps", "name": "rt-ok", "uid": "r1"},
     "spec": {"parentRefs": [{"name": "gw-ok"}]},
     "status": {"parents": [{"parentRef": {"name": "gw-ok"}, "conditions": [
         {"type": "Accepted", "status": "True"},
         {"type": "ResolvedRefs", "status": "True"}]}]}},
    {"metadata": {"namespace": "apps", "name": "rt-broken", "uid": "r2"},
     "spec": {"parentRefs": [{"name": "gw-ok"}]},
     "status": {"parents": [{"parentRef": {"name": "gw-ok"}, "conditions": [
         {"type": "Accepted", "status": "True"},
         {"type": "ResolvedRefs", "status": "False", "reason": "BackendNotFound"}]}]}},
    {"metadata": {"namespace": "apps", "name": "rt-orphan", "uid": "r3",
                  "creationTimestamp": "2026-01-01T00:00:00Z"},
     "spec": {"parentRefs": []},
     "status": {"parents": []}},
]}

F = normalize.Facts()
normalize_k8s.p_gateways(GWS, F, "k_gateways")
normalize_k8s.p_httproutes(ROUTES, F, "k_httproutes")
pairs = {k: v["value"] for k, v in F.items()}
b = facts(pairs)
b["collection"]["commands"] = {
    "k_gateways": {"status": "ok"}, "k_httproutes": {"status": "ok"}}

fs = rules_k8s.r_gateway(b)
ids = [(f["id"], f["severity"]) for f in fs]
check("not-ready gateway is WARN naming the reason",
      any(f["id"] == "K8S_GATEWAY_NOT_READY:apps/gw-bad"
          and any("AddressNotAssigned" in d for d in f["detail"])
          for f in fs), ids)
check("healthy gateway does not alarm", not any(
    f["id"] == "K8S_GATEWAY_NOT_READY:apps/gw-ok" for f in fs))
check("route failure breaks the healthy line",
      any(f["id"] == "K8S_GATEWAY_PARTIAL" for f in fs), ids)

fs = rules_k8s.r_tenant_summary(b)
rows = fs[0]["table"]["rows"] if fs else []
check("ResolvedRefs=False produces one tenant row",
      any(r[0] == "HTTPRoutes with a failing parent" and r[1] == 1
          for r in rows), rows)

hb = facts(pairs)
hb["facts"]["k8s.ns.info"] = {"value": {}, "source": "t"}
hb["collected_at"] = "2026-10-08T09:00:00Z"
housekeeping.derive(hb, {}, now=logscan.parse_ts("2026-10-08T09:00:00Z"))
orphans = [i for i in hb["facts"]["k8s.housekeeping.items"]["value"]
           if i["category"] == "gateway_orphaned_route"]
check("route with no parent is a housekeeping item",
      orphans and orphans[0]["name"] == "rt-orphan", orphans)

print("\nall healthy gives the one-liner; absent CRDs are a cannot-see note")

GWS2 = {"items": [GWS["items"][0]]}
R2 = {"items": [ROUTES["items"][0]]}
F2 = normalize.Facts()
normalize_k8s.p_gateways(GWS2, F2, "k_gateways")
normalize_k8s.p_httproutes(R2, F2, "k_httproutes")
b2 = facts({k: v["value"] for k, v in F2.items()})
b2["collection"]["commands"] = {"k_gateways": {"status": "ok"},
                                "k_httproutes": {"status": "ok"}}
fs2 = rules_k8s.r_gateway(b2)
check("healthy one-liner",
      any(f["id"] == "K8S_GATEWAY_HEALTHY"
          and f["title"] == "1 Gateways, 1 HTTPRoutes, all accepted"
          for f in fs2), fs2)

b3 = facts({})
b3["collection"]["commands"] = {
    "k_gateways": {"status": "eacces", "expected": "eacces"},
    "k_httproutes": {"status": "eacces", "expected": "eacces"}}
fs3 = rules_k8s.r_gateway(b3)
check("absent CRDs are a quiet cannot-see note, not a WARN",
      fs3 and fs3[0]["id"] == "KAREL_GATEWAY_CRD_ABSENT"
      and fs3[0]["severity"] == "info", fs3)


finish()
