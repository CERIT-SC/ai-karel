#!/usr/bin/env python3
"""
Certificate expiry probe.

What this CAN see, from inside a pod:
  * the apiserver serving certificate (TLS handshake to kubernetes.default)
  * the cluster CA bundle mounted into the pod
  * CA bundles embedded in webhook configurations (via kubectl, done elsewhere)

What this CANNOT see, and you must not pretend otherwise:
  * per-node kubelet client certs under /var/lib/rancher/rke2/agent/
  * etcd peer/server certs
RKE2 rotates on restart when a cert is within ~90 days, so the classic RKE2
outage is a node that has not restarted in a year. Covering that needs a
node-level DaemonSet or systemd timer publishing `rke2 certificate check`.
This probe reports the gap explicitly so it stays visible.
"""

import datetime
import json
import os
import socket
import ssl
import sys

CA_PATHS = [
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/etc/kubernetes/pki/ca.crt",
]


def _parse_asn1(s):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            continue
    return None


def probe_apiserver():
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS") or \
        os.environ.get("KUBERNETES_SERVICE_PORT") or "443"
    if not host:
        return {"error": "KUBERNETES_SERVICE_HOST not set"}

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # we want the cert, not trust validation
    try:
        with socket.create_connection((host, int(port)), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname="kubernetes.default.svc") as tls:
                der = tls.getpeercert(binary_form=True)
                cert = tls.getpeercert()
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}

    result = {"endpoint": "%s:%s" % (host, port)}
    # getpeercert() returns {} with CERT_NONE on some builds; fall back to DER text
    not_after = (cert or {}).get("notAfter")
    if not not_after and der:
        try:
            pem = ssl.DER_cert_to_PEM_cert(der)
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            # _ssl has no pure-stdlib parser; record that we could not read it
            result["note"] = "peer cert retrieved but notAfter unavailable on this build"
            result["pem_bytes"] = len(pem)
        except Exception:
            pass
    if not_after:
        exp = _parse_asn1(not_after)
        if exp:
            days = (exp - datetime.datetime.utcnow()).days
            result["not_after"] = exp.strftime("%Y-%m-%dT%H:%M:%SZ")
            result["days_remaining"] = days
        result["subject"] = str((cert or {}).get("subject"))
    return result


def probe_ca():
    for path in CA_PATHS:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            return {"path": path, "bytes": len(data),
                    "certificates": data.count(b"BEGIN CERTIFICATE")}
        except Exception as exc:
            return {"path": path, "error": str(exc)}
    return {"error": "no CA bundle found"}


def main():
    out = {
        "apiserver": probe_apiserver(),
        "ca_bundle": probe_ca(),
        "coverage_gaps": [
            "kubelet client certificates (per-node, /var/lib/rancher/rke2/agent) "
            "are NOT visible from a pod",
            "etcd peer and server certificates are NOT visible from a pod",
            "RKE2 rotates certs on restart within ~90 days of expiry; a node that "
            "has not restarted in a year is the classic failure",
        ],
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
