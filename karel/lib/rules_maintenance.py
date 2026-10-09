"""
Things a human switched off and forgot.

This class of finding shares one property: the setting was correct when it was
made, and becomes dangerous only through time. Severity therefore has to be a
function of age, not of the setting itself.
"""

from rules import _finding


def _f(bundle, path, default=None):
    e = bundle["facts"].get(path)
    return e["value"] if e else default


def r_k8s_paused(bundle):
    out = []
    # Platform only: a tenant pausing their own rollout is their business, and
    # the age escalation below would otherwise turn it into an operator CRIT.
    # Tenant paused Deployments are counted in the tenant summary.
    import scope
    paused = _f(bundle, "k8s.deployment.paused.platform")
    if paused is None:
        paused = [d for d in (_f(bundle, "k8s.deployment.paused", []) or [])
                  if scope.is_platform(scope.item_ns(d))]
    if paused:
        out.append(_finding(
            "K8S_DEPLOYMENT_PAUSED", "warn",
            "%d platform Deployment(s) have rollout paused" % len(paused),
            detail=paused[:15], evidence=["k_deployments"], metric=float(len(paused)),
            remediation=["a paused rollout silently ignores every subsequent change "
                         "to the Deployment"]))
        out[-1]["escalate_after_days"] = 3

    zeroed = _f(bundle, "k8s.workload.scaled_to_zero", []) or []
    if zeroed:
        out.append(_finding(
            "K8S_SCALED_TO_ZERO", "info",
            "%d workload(s) are scaled to zero" % len(zeroed),
            detail=zeroed[:15], evidence=["k_deployments", "k_statefulsets"],
            metric=float(len(zeroed)),
            remediation=["often deliberate; listed because a workload scaled down "
                         "for maintenance and forgotten looks identical to one that "
                         "is intentionally idle"]))
    return out


RULES = [
    r_k8s_paused,
]
