#!/usr/bin/env python3
"""ACME DNS probe: do the ACME challenges' hostnames resolve somewhere the
http-01 solver can actually be reached?

Reads challenges via kubectl, resolves each dnsName with the LOCAL resolver
(cluster DNS - see the open question about split-horizon in the spec), and
compares against the expected targets (the ingress controller's LoadBalancer
addresses, overridable with KAREL_ACME_EXPECTED_TARGETS).

Output: {"dns": {"<host>": {"status": ..., "addresses": [...]}},
         "expected": [...]}
Status: ok | differ | nodata | servfail | nxdomain | error
Distinguishing NXDOMAIN from "answers but the wrong address" is the whole
point: they have different owners (DNS record missing vs pointing elsewhere).

Never exits non-zero: an unreachable API is an error field, not a crash.
"""

import json
import os
import socket
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "lib"))

import logscan            # noqa: E402

INGRESS_SVC_HINTS = ("ingress", "traefik", "istio-ingress", "nginx")
SOLVER_PORT = 8089


def dns_lookup(name):
    """-> (status, addresses). NXDOMAIN vs SERVFAIL vs NODATA are different
    failure owners, so they stay separate."""
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        addrs = sorted({i[4][0] for i in infos})
        return ("ok" if addrs else "nodata", addrs)
    except socket.gaierror as exc:
        code = exc.args[0]
        if code == socket.EAI_NONAME:
            return "nxdomain", []
        if code == socket.EAI_AGAIN:
            return "servfail", []
        if code == getattr(socket, "EAI_NODATA", -999):
            return "nodata", []
        return "error", []
    except Exception:
        return "error", []


def _kubectl_json(argv, timeout=45):
    try:
        r = subprocess.run(["kubectl"] + argv, capture_output=True, text=True,
                           timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return None, str(exc)
    if r.returncode != 0:
        return None, (r.stderr or "").strip()[:200]
    try:
        return json.loads(r.stdout or "{}"), None
    except ValueError:
        return None, "unparseable output"


def expected_targets():
    """Ingress controller LoadBalancer addresses; env override wins."""
    env = os.environ.get("KAREL_ACME_EXPECTED_TARGETS")
    if env:
        return sorted(e.strip() for e in env.split(",") if e.strip())
    doc, err = _kubectl_json(["get", "services", "-A", "-o", "json"])
    if err or not doc:
        return []
    out = []
    for svc in doc.get("items") or []:
        spec = svc.get("spec") or {}
        name = (svc.get("metadata") or {}).get("name") or ""
        if spec.get("type") != "LoadBalancer":
            continue
        if not any(h in name.lower() for h in INGRESS_SVC_HINTS):
            continue
        for ing in (svc.get("status") or {}).get("loadBalancer", {}) \
                                        .get("ingress") or []:
            if ing.get("ip"):
                out.append(ing["ip"])
            elif ing.get("hostname"):
                out.append(ing["hostname"])
    return sorted(set(out))


def main():
    doc, err = _kubectl_json(["get", "challenges.acme.cert-manager.io",
                              "-A", "-o", "json"])
    expected = expected_targets()
    if err:
        json.dump({"error": err, "expected": expected, "dns": {}}, sys.stdout)
        return 0

    dns = {}
    for ch in doc.get("items") or []:
        spec = ch.get("spec") or {}
        host = spec.get("dnsName")
        if not host:
            continue
        status, addrs = dns_lookup(host)
        if status == "ok" and expected and \
                not set(addrs) & set(expected):
            status = "differ"
        dns[host] = {"status": status, "addresses": addrs[:5]}

    json.dump({"expected": expected, "dns": dns,
             "captured_at": logscan.iso_z(logscan.utcnow())}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
