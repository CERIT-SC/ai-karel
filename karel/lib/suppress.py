"""
Suppression ledger.

The answer to "this is intentional for now" is NOT to have a model decide what
to hide. Filtering is a policy decision with real consequences: a suppressed
finding is one nobody will see again. That belongs in a reviewable file with an
author, a reason, and an expiry date - not in a prompt.

Design rules:
  * Suppressed findings are DOWNGRADED and LISTED, never deleted. The report
    always shows what it is not telling you.
  * Every suppression expires. A permanent one must say so explicitly, and is
    reported as such every run so it cannot rot invisibly.
  * An expired suppression is itself a finding - it forces a decision instead
    of silently re-alarming.
  * Suppressions that no longer match anything are reported too, because a
    stale ledger entry usually means the underlying thing changed.

Ledger format (ConfigMap `karel-suppressions`, key `suppressions`):

{
  "suppressions": [
    {
      "id": "K8S_DEPLOYMENT_PAUSED:app/api",
      "until": "2026-12-31",
      "reason": "rollout paused deliberately during a migration",
      "by": "ops@example.org"
    },
    {
      "pattern": "K8S_SCALED_TO_ZERO:*",
      "until": "permanent",
      "reason": "these workloads are intentionally idle",
      "by": "platform-team"
    }
  ]
}
"""

import datetime
import fnmatch

from rules import _finding


def _today():
    return datetime.datetime.now(datetime.timezone.utc).date()


def _parse_date(v):
    if not v or str(v).lower() == "permanent":
        return None
    try:
        return datetime.datetime.strptime(str(v)[:10], "%Y-%m-%d").date()
    except ValueError:
        return False          # distinguishable from "permanent"


def load(raw):
    """Accept the ConfigMap payload; tolerate an empty or broken ledger."""
    if not raw:
        return []
    entries = raw.get("suppressions") if isinstance(raw, dict) else raw
    return entries if isinstance(entries, list) else []


def apply(findings, ledger):
    """Returns (visible, suppressed, meta_findings)."""
    entries = [e for e in ledger if isinstance(e, dict)]
    today = _today()

    visible, suppressed, meta = [], [], []
    used = set()

    malformed = [e for e in entries
                 if not (e.get("id") or e.get("pattern"))
                 or _parse_date(e.get("until")) is False]
    if malformed:
        meta.append(_finding(
            "KAREL_SUPPRESSION_MALFORMED", "warn",
            "%d suppression entry(ies) are malformed and were ignored" % len(malformed),
            detail=[str(e)[:120] for e in malformed[:5]],
            evidence=["karel-suppressions"],
            remediation=["each entry needs `id` or `pattern`, plus `until` as "
                         "YYYY-MM-DD or the literal string permanent",
                         "a malformed entry suppresses nothing - the finding it was "
                         "meant to hide is shown above"]))

    expired = []
    for e in entries:
        if e in malformed:
            continue
        until = _parse_date(e.get("until"))
        if until is not None and until < today:
            expired.append(e)

    for f in findings:
        match = None
        for e in entries:
            if e in malformed or e in expired:
                continue
            key = e.get("id")
            pat = e.get("pattern")
            if key and f["id"] == key:
                match = e
            elif pat and fnmatch.fnmatch(f["id"], pat):
                match = e
            if match:
                break
        if match:
            f = dict(f)
            f["suppressed_by"] = match
            suppressed.append(f)
            used.add(id(match))
        else:
            visible.append(f)

    if expired:
        meta.append(_finding(
            "KAREL_SUPPRESSION_EXPIRED", "warn",
            "%d suppression(s) have expired" % len(expired),
            detail=["%s — expired %s — %s"
                    % (e.get("id") or e.get("pattern"), e.get("until"),
                       e.get("reason") or "no reason recorded")
                    for e in expired[:10]],
            evidence=["karel-suppressions"],
            remediation=["the findings they covered are visible again above",
                         "either renew the suppression with a new date or fix the "
                         "underlying condition - the expiry exists to force that "
                         "choice"]))

    unused = [e for e in entries
              if e not in malformed and e not in expired and id(e) not in used]
    if unused:
        meta.append(_finding(
            "KAREL_SUPPRESSION_UNUSED", "info",
            "%d suppression(s) matched nothing this run" % len(unused),
            detail=["%s — %s" % (e.get("id") or e.get("pattern"),
                                 e.get("reason") or "no reason recorded")
                    for e in unused[:10]],
            evidence=["karel-suppressions"],
            remediation=["either the condition was fixed (remove the entry) or the "
                         "finding id changed (the entry is now silently useless)"]))

    permanent = [e for e in entries
                 if e not in malformed
                 and str(e.get("until", "")).lower() == "permanent"]
    if permanent:
        meta.append(_finding(
            "KAREL_SUPPRESSION_PERMANENT", "info",
            "%d finding(s) are permanently suppressed" % len(permanent),
            detail=["%s — %s (by %s)"
                    % (e.get("id") or e.get("pattern"),
                       e.get("reason") or "no reason recorded",
                       e.get("by") or "unknown")
                    for e in permanent[:10]],
            evidence=["karel-suppressions"],
            remediation=["listed every run on purpose: a permanent suppression "
                         "that nobody re-reads is how a real problem disappears"]))

    return visible, suppressed, meta
