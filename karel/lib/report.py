"""
Karel Markdown report renderer.

Two constraints shape this file:

1. Cluster output is full of markdown metacharacters. `kube-system`, `node-03`,
   `kubectl get`, `<flag>`, `--connect-timeout` would all be mangled by a naive
   renderer, and escaping every one with backslashes turns the raw text into
   unreadable soup. So: technical tokens are wrapped in backticks (which
   disables markdown inside them), and only the remainder is escaped. Machine
   output that came straight from a command goes in a fenced block, where
   nothing needs escaping at all.

2. The report is emailed. Many clients show it as plain text, so tables are
   column-padded to stay readable unrendered.

Deterministic facts first. When the LLM layer lands it appends a clearly
labelled section at the end and never edits anything above it.
"""

import re

SEV_LABEL = {"crit": "CRIT", "warn": "WARN", "info": "INFO"}
STATE_LABEL = {"new": "new", "open": "open", "escalating": "**escalating**"}

MAX_EXPANDED = 18
SUMMARY_THRESHOLD = 8

KEY_METRICS = [
    ("k8s.node.count",                 "nodes",                    "int"),
    ("k8s.node.not_ready_count",       "nodes NotReady",           "int"),
    ("k8s.pod.count",                  "pods",                     "int"),
    ("k8s.pod.not_ready_count",        "pods not ready",           "int"),
    ("k8s.pod.pending_count",          "pods pending",             "int"),
    ("k8s.pod.restarts_total",         "container restarts (cum.)", "int"),
    ("k8s.pvc.unbound_count",          "PVCs unbound",             "int"),
    ("k8s.capacity.cpu_req_pct",       "CPU requested (pool)",     "pct"),
    ("k8s.capacity.cpu_req_pct_after_loss", "… after losing largest node", "pct"),
    ("k8s.capacity.mem_req_pct",       "memory requested (pool)",  "pct"),
    ("k8s.capacity.mem_req_pct_after_loss", "… after losing largest node", "pct"),
    ("k8s.etcd.db_bytes",              "etcd db size",             "bytes"),
    ("k8s.etcd.objects_total",         "etcd objects",             "int"),
    ("k8s.cert.apiserver_days_remaining", "apiserver cert (days)", "int"),
]


# --------------------------------------------------------------- md escaping
_ESCAPE = str.maketrans({
    "\\": "\\\\", "`": "\\`", "*": "\\*", "_": "\\_",
    "[": "\\[", "]": "\\]", "<": "&lt;", ">": "&gt;", "|": "\\|",
})

_TRAILING = ".,;:!?)'\""
_LEADING = "('\""


def _is_technical(tok, quoted=False):
    """Tokens that should be code-spanned rather than escaped."""
    if not tok or " " in tok:
        return False
    if quoted:
        # rules quote cluster object names deliberately: 'replicapool', 'node-03'
        return bool(re.match(r"^[A-Za-z0-9][\w.\-/:]*$", tok))
    if tok.startswith("-") and len(tok) > 1 and not tok.startswith("- "):
        return True                      # --connect-timeout, -f
    if "_" in tok and re.match(r"^[A-Za-z0-9][\w.\-/]*$", tok):
        return True                      # kube_public_service, MEMORY_PRESSURE
    if "=" in tok and " " not in tok:
        return True                      # kubelet=true, app=karel
    if "/" in tok and not tok.startswith("//") and len(tok) > 2 \
            and not re.match(r"^[\d.]+/[\d.]+$", tok) \
            and (tok.startswith("/") or re.search(r"[-._]", tok)):
        return True                      # kube-system/coredns, /readyz
                                         # but NOT 9/10 or pts/day
    if re.match(r"^<[a-z-]+>$", tok):
        return True                      # <flag>, <id>
    if re.match(r"^[a-z][a-z0-9]*(\.[a-z0-9-]+){2,}$", tok):
        return True                      # metrics.k8s.io
    return False


_SPAN_RE = re.compile(r"`[^`\n]+`")


def md(text):
    """Inline markdown for text that may contain cluster output.

    Code spans the caller already wrote are protected first, including
    multi-word ones like `kubectl get` that token-level handling cannot see.
    """
    if text is None:
        return ""
    text = str(text)
    spans = []

    def _stash(m):
        spans.append(m.group(0))
        return "\x00%d\x00" % (len(spans) - 1)

    text = _SPAN_RE.sub(_stash, text)
    out = []
    for tok in text.split(" "):
        if not tok:
            out.append(tok)
            continue
        head = ""
        while tok and tok[0] in _LEADING:
            head, tok = head + tok[0], tok[1:]
        tail = ""
        while tok and tok[-1] in _TRAILING:
            tail, tok = tok[-1] + tail, tok[:-1]
        # A token the rule already code-spanned must pass through untouched,
        # or it becomes \`noout\` in the rendered output.
        if len(tok) > 2 and tok.startswith("`") and tok.endswith("`") \
                and "`" not in tok[1:-1]:
            out.append(head.translate(_ESCAPE) + tok + tail.translate(_ESCAPE))
            continue
        quoted = bool(head) and head[-1] in "'\"" and bool(tail) and tail[0] in "'\""
        if quoted:
            head, tail = head[:-1], tail[1:]
        if _is_technical(tok, quoted):
            piece = "`%s`" % tok.replace("`", "")
        else:
            piece = tok.translate(_ESCAPE)
        out.append(head.translate(_ESCAPE) + piece + tail.translate(_ESCAPE))
    joined = " ".join(out)
    for i, span in enumerate(spans):
        joined = joined.replace("\x00%d\x00" % i, span)
    return joined


def cell(text):
    """Table cell. md() already escapes '|' via _ESCAPE, and technical tokens
    are code-spanned - a second replace would double-escape the backslash."""
    return md(text)


def fence(lines):
    """Machine output goes in a fenced block - no escaping needed at all."""
    body = [str(l) for l in lines]
    marker = "```"
    while any(marker in l for l in body):
        marker += "`"
    return [marker] + body + [marker]


# ------------------------------------------------------------------- tables
def table(headers, rows, align=None):
    """Column-padded markdown table: renders well, and reads well unrendered."""
    if not rows:
        return []
    cols = len(headers)
    align = align or ["l"] * cols
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(r[i]) if i < len(r) else ""))

    def fmt(vals):
        parts = []
        for i in range(cols):
            v = str(vals[i]) if i < len(vals) else ""
            parts.append(v.rjust(widths[i]) if align[i] == "r" else v.ljust(widths[i]))
        return "| " + " | ".join(parts) + " |"

    sep = []
    for i in range(cols):
        if align[i] == "r":
            sep.append("-" * (widths[i] - 1) + ":")
        else:
            sep.append("-" * widths[i])
    return [fmt(headers), "| " + " | ".join(sep) + " |"] + [fmt(r) for r in rows]


# ------------------------------------------------------------- formatting
def _human_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024.0:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f EiB" % n


def _fmt(value, kind):
    if value is None:
        return "-"
    if kind == "pct":
        return "%.1f%%" % float(value)
    if kind == "bytes":
        return _human_bytes(value)
    if kind == "num":
        return "%.2f" % float(value)
    if kind == "int":
        return str(int(value))
    return str(value)


def _delta(cur, prev, kind):
    if prev is None or cur is None:
        return ""
    if kind == "str":
        return "" if cur == prev else "was %s" % prev
    try:
        d = float(cur) - float(prev)
    except (TypeError, ValueError):
        return ""
    if abs(d) < 1e-9:
        return ""
    sign = "+" if d > 0 else ""
    if kind == "bytes":
        return "%s%s" % (sign, _human_bytes(d))
    if kind == "pct":
        return "%s%.1f pts" % (sign, d)
    if kind == "int":
        return "%s%d" % (sign, int(d))
    return "%s%.2f" % (sign, d)



_SPAN = {}


def _elapsed_label(prev_snapshot, bundle):
    """Human span between the baseline and this run."""
    import datetime
    a = (prev_snapshot or {}).get("collected_at")
    b = bundle.get("collected_at")
    if not a or not b:
        return "vs baseline"
    try:
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        d = datetime.datetime.strptime(b, fmt) - datetime.datetime.strptime(a, fmt)
    except (ValueError, TypeError):
        return "vs baseline"
    secs = d.total_seconds()
    if secs < 0:
        return "vs baseline"
    if secs < 3600:
        return "%dm" % (secs // 60)
    if secs < 172800:
        return "%dh" % (secs // 3600)
    return "%dd" % (secs // 86400)


_NOISE = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?"), "<ts>"),
    # generated pod-name suffixes: ten fluent-bit pods of one DaemonSet are
    # one line of information, not ten
    (re.compile(r"-[a-z0-9]{5}(?=[:\s]|$)"), "-<pod>"),
    (re.compile(r"-[a-f0-9]{8,10}-(?=<pod>)"), "-<rs>-"),
    (re.compile(r" on [\w.-]+$"), " on <node>"),
    (re.compile(r"\b[0-9a-f]{8,}\b"), "<hex>"),
    (re.compile(r"\b\d+\b"), "<n>"),
]


def _squash_blanks(lines):
    out = []
    for l in lines:
        if str(l).strip() == "" and out and str(out[-1]).strip() == "":
            continue
        out.append(l)
    while out and str(out[-1]).strip() == "":
        out.pop()
    return out


def collapse(lines, keep=4):
    """Fold repeated detail lines that differ only in timestamps or ids.

    1317 near-identical crash lines are not 1317 pieces of information; showing
    ten of them buries the one thing that matters (that it is happening a lot).
    """
    groups, order = {}, []
    for l in lines:
        key = str(l)
        for rx, rep in _NOISE:
            key = rx.sub(rep, key)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(l)
    out = []
    for key in order:
        members = groups[key]
        if len(members) <= keep:
            out.extend(members)
        else:
            out.extend(members[:keep])
            out.append("... and %d more of the same kind"
                       % (len(members) - keep))
    return out



def _collapse_groups(findings):
    """Fold findings that carry the same `group_key` into one for display.

    Identity stays per-subject so lifecycle is stable; only the rendering is
    collapsed. Severity of the group is the worst member's.
    """
    seen, out = {}, []
    for f in findings:
        gk = f.get("group_key")
        if not gk:
            out.append(f)
            continue
        if gk not in seen:
            g = dict(f)
            g["_members"] = [f]
            seen[gk] = g
            out.append(g)
        else:
            seen[gk]["_members"].append(f)
            if SEV_ORDER.get(f["severity"], 0) > SEV_ORDER.get(seen[gk]["severity"], 0):
                seen[gk]["severity"] = f["severity"]

    for g in out:
        members = g.get("_members") or []
        if len(members) <= 1:
            g.pop("_members", None)
            continue
        subs = [m.get("subject") or m["id"] for m in members]
        g["title"] = "%s — and %d more with identical impact" % (
            g["title"], len(members) - 1)
        g["detail"] = _squash_blanks(list(g.get("detail") or [])) + [
            "-" * 8,
            "identical impact for: %s" % ", ".join(subs),
            "shown for %s" % (g.get("subject") or "?"),
            "each is tracked separately: %s" % ", ".join(m["id"] for m in members[:4]),
        ]
        g.pop("_members", None)
    return out


SEV_ORDER = {"info": 0, "warn": 1, "crit": 2}


# --------------------------------------------------------------------- render
def render(bundle, findings, resolved, prev_snapshot, carried=None,
           suppressed=None, ruleset_changed=False, thresholds=None):
    _SPAN["label"] = _elapsed_label(prev_snapshot, bundle)
    L = []
    facts = bundle["facts"]
    prev_facts = (prev_snapshot or {}).get("facts", {}) or {}

    def fv(path, default=None):
        e = facts.get(path)
        return e["value"] if e else default

    crit = [f for f in findings if f["severity"] == "crit"]
    warn = [f for f in findings if f["severity"] == "warn"]
    info = [f for f in findings if f["severity"] == "info"]
    actionable = _collapse_groups(crit + warn)
    crit = [f for f in actionable if f["severity"] == "crit"]
    warn = [f for f in actionable if f["severity"] == "warn"]

    if crit:
        verdict = "ACTION REQUIRED"
    elif warn:
        verdict = "ATTENTION"
    else:
        verdict = "NOMINAL"

    # ------------------------------------------------------------------ header
    L.append("# Karel — daily cluster report")
    L.append("")
    L.append("**%s** — %d critical, %d warning, %d informational"
             % (verdict, len(crit), len(warn), len(info)))
    L.append("")

    meta_rows = [
        ["Run", "`%s`" % (bundle.get("run_id") or "?")],
        ["Generated", md(bundle.get("collected_at") or "?")],
        ["Kubernetes", md(fv("k8s.version.server") or "unknown")],
        ["Baseline", md((prev_snapshot or {}).get("collected_at")
                        or "none — first run, no deltas available")],
    ]
    L += table(["", ""], meta_rows)
    L.append("")

    # -------------------------------------------------------------- collection
    L.append("## Collection")
    L.append("")
    allc = dict(bundle["collection"]["commands"])
    rows = []
    for label, pred in (("Kubernetes", lambda n: n.startswith("k_")),
                        ("Prometheus", lambda n: n.startswith("prom"))):
        sub = {k: v for k, v in allc.items() if pred(k)}
        if not sub:
            src = (bundle["collection"].get("sources") or {}).get(
                {"Kubernetes": "k8s", "Prometheus": "prom"}[label])
            note = "_not collected_"
            if src and src.get("reason"):
                note = "_%s_" % src["reason"]
            rows.append([label, note, "0"])
            continue
        by_status = {}
        for c in sub.values():
            by_status[c.get("status", "?")] = by_status.get(c.get("status", "?"), 0) + 1
        rows.append([label,
                     ", ".join("%d %s" % (v, k) for k, v in sorted(by_status.items())),
                     str(len(sub))])
    L += table(["source", "outcome", "planned"], rows, ["l", "l", "r"])
    L.append("")

    srcs = bundle["collection"].get("sources") or {}
    broken = sorted(k for k, v in srcs.items() if not v.get("complete"))
    bits = ["complete: **%s**" % ("yes" if not broken else
                                  "NO — " + ", ".join(broken)),
            "duration: %ss" % (bundle.get("budget_used_seconds") or "?"),
            "manifest: `%s`" % ((bundle.get("manifest_sha256") or "?")[:12])]
    L.append(" · ".join(bits))
    L.append("")
    for label in broken:
        L.append("> `%s` collector: %s" % (label, md(srcs[label].get("reason")
                                                     or "did not complete")))
    if broken:
        L.append("")

    # One coverage line per log check and one for the event stream. Silence
    # is not health: the reader sees exactly how far each check could look.
    log_checks = fv("k8s.log.checks", []) or []
    for name in sorted(log_checks):
        b = "k8s.log.%s" % name
        st = fv(b + ".status") or "?"
        if st == "no_pods":
            line = "log `%s`: **no pods matched** (selector `%s`)" \
                % (name, fv(b + ".selector") or "?")
        else:
            cov = fv(b + ".coverage") or "?"
            up = (fv("%s.class.upload_ok" % b) or {}).get("count")
            line = "log `%s`: %s, coverage %s" % (name, st, cov)
            if up is not None:
                line += ", %d upload(s) in window" % up
        L.append("- %s" % md(line))
    if log_checks:
        L.append("")

    if fv("k8s.events.mode") is not None:
        buf = fv("k8s.events.buffer")
        if fv("k8s.events.mode") == "buffered" and buf:
            line = "events: buffered, %s of %s writes (last %.0f min ago)" \
                % (buf.get("ok_writes") if buf.get("ok_writes") is not None
                   else "?",
                   buf.get("expected_writes") or "?",
                   buf.get("last_write_age_m") or 0)
            if buf.get("failed_requests"):
                line += ", **failed: %s**" % ", ".join(buf["failed_requests"][:5])
        else:
            line = ("events: live TTL window only (~1 h; buffer CronJob not "
                    "running)")
        L.append("- %s" % md(line))
        L.append("")

    # ---------------------------------------------------------------- findings
    L.append("## Findings")
    L.append("")

    if not actionable:
        L.append("No critical or warning findings.")
        if not bundle["collection"].get("complete"):
            L.append("")
            L.append("> Collection was incomplete — absence of findings is not "
                     "evidence of health.")
        L.append("")
    else:
        if len(actionable) > SUMMARY_THRESHOLD:
            L.append("### Summary")
            L.append("")
            rows = []
            for f in actionable:
                state = f.get("state", "new")
                mark = {"new": "new", "escalating": "worse", "open": ""}.get(state, "")
                if state in ("open", "escalating") and f.get("days_open"):
                    mark = ("%s, %dd" % (mark, f["days_open"])).strip(", ")
                rows.append([SEV_LABEL.get(f["severity"], ""),
                             cell(f["title"]),
                             "`%s`" % f["id"],
                             mark])
            L += table(["", "finding", "id", "state"], rows)
            L.append("")

        shown = crit[:MAX_EXPANDED]
        shown += warn[: max(0, MAX_EXPANDED - len(shown))]
        deferred = [f for f in actionable if f not in shown]

        L.append("### Detail")
        L.append("")
        for f in shown:
            L += _render_finding(f)

        if deferred:
            L.append("### Not expanded")
            L.append("")
            L.append("%d further finding(s); full detail is in `findings.json`."
                     % len(deferred))
            L.append("")
            L += table(["", "id", "finding"],
                       [[SEV_LABEL.get(f["severity"], ""), "`%s`" % f["id"],
                         cell(f["title"])] for f in deferred])
            L.append("")

    # Info findings that carry their own table(s) get their own section.
    sectioned = [f for f in info if f.get("section")
                 and (f.get("table") or f.get("tables"))]
    info_plain = [f for f in info if f not in sectioned]

    if info_plain:
        # Separate what Karel FOUND from what Karel CANNOT SEE. Mixing them
        # makes a reader sort tool limitations out of cluster facts by hand.
        cluster = [f for f in info_plain if not f["code"].startswith("KAREL_")]
        limits = [f for f in info_plain if f["code"].startswith("KAREL_")]

        if cluster:
            L.append("### Informational")
            L.append("")
            for f in cluster:
                new = " *(new)*" if f.get("state") == "new" else ""
                L.append("- %s%s" % (md(f["title"]), new))
            L.append("")

        if limits:
            L.append("### What this report cannot see")
            L.append("")
            L.append("Karel's own coverage gaps, not cluster conditions. They are "
                     "listed every run so that absence of a finding is never "
                     "mistaken for absence of a problem.")
            L.append("")
            for f in limits:
                new = " *(new)*" if f.get("state") == "new" else ""
                L.append("- %s%s" % (md(f["title"]), new))
            L.append("")

    # Sections have a reading order (tenant workloads before housekeeping
    # before node versions); plain info lists keep severity ranking.
    for f in sorted(sectioned,
                    key=lambda f: (f.get("section_order", 50), f["id"])):
        tables = f.get("tables") or ([f["table"]] if f.get("table") else [])
        if not tables:
            continue
        L.append("## %s" % f["section"])
        L.append("")
        L.append(md(f["title"]))
        L.append("")
        for t in tables:
            if t.get("title"):
                L.append("**%s**" % md(t["title"]))
                L.append("")
            L += table(t["headers"],
                       [[cell(c) if isinstance(c, str) else str(c) for c in r]
                        for r in t["rows"]],
                       t.get("align"))
            L.append("")
            if t.get("note"):
                L.append("*%s*" % md(t["note"]))
                L.append("")

    # ------------------------------------------------------------- suppressed
    if suppressed:
        L.append("## Suppressed")
        L.append("")
        L.append("%d finding(s) matched an entry in the suppression ledger. They "
                 "are listed, never hidden — a report that silently omits things "
                 "cannot be trusted." % len(suppressed))
        L.append("")
        rows = []
        for f in suppressed:
            e = f.get("suppressed_by") or {}
            rows.append([SEV_LABEL.get(f["severity"], ""),
                         cell(f["title"]),
                         "`%s`" % f["id"],
                         cell(e.get("reason") or "—"),
                         md(str(e.get("until") or "—"))])
        L += table(["", "finding", "id", "reason", "until"], rows)
        L.append("")

    # -------------------------------------------------------- carried forward
    if carried:
        L.append("## Not observable this run")
        L.append("")
        L.append("These were open at the last run. The collectors that would "
                 "detect them did not return usable data, so their status is "
                 "**unknown** — do not read their absence above as a fix.")
        L.append("")
        L += table(["", "id"],
                   [[SEV_LABEL.get(c.get("severity", "info"), "INFO"),
                     "`%s`" % c["id"]] for c in carried])
        L.append("")

    # ---------------------------------------------------------------- resolved
    if resolved:
        if ruleset_changed:
            # README: when the rules changed, a disappearance is NOT reported as
            # a fix. It is listed, grouped by code, under its real name.
            L.append("## No longer reported")
            L.append("")
            L.append("> Karel's rule set changed since the previous run, so these "
                     "may have disappeared because a rule was altered or removed, "
                     "not because the condition was fixed. "
                     "**\"We stopped looking\" is not \"it was fixed\".**")
        else:
            L.append("## Resolved since last run")
        L.append("")
        L += table(["", "finding", "count", "ids"], _group_resolved(resolved),
                   ["l", "l", "r", "l"])
        L.append("")

    # ------------------------------------------------------------- key metrics
    L.append("## Key metrics")
    L.append("")
    rows = []
    for path, label, kind in KEY_METRICS:
        cur = fv(path)
        if cur is None:
            continue
        rows.append([md(label), _fmt(cur, kind),
                     _delta(cur, prev_facts.get(path), kind)])
    if rows:
        # The baseline is whatever the previous run was - not necessarily 24h ago.
        # Labelling a 3-minute delta "24h" is a lie the reader cannot detect.
        span = _elapsed_label(prev_snapshot, bundle)
        L += table(["metric", "value", "Δ %s" % span], rows, ["l", "r", "r"])
    else:
        L.append("_No metrics collected._")
    L.append("")

    # ------------------------------------------------------------------ nodes
    knodes = fv("k8s.node.names", []) or []
    if knodes:
        L.append("## Kubernetes nodes")
        L.append("")
        usage = fv("k8s.node.usage", {}) or {}
        reqs = fv("k8s.node.requests", {}) or {}
        pods_by_node = fv("k8s.pod.by_node", {}) or {}
        alloc = fv("k8s.node.allocatable_cpu_m", {}) or {}
        rows = []
        for n in knodes:
            b = "k8s.node.%s" % n
            ac = alloc.get(n) or 0
            am = (fv("k8s.node.allocatable_mem_bytes", {}) or {}).get(n) or 0
            rc = (reqs.get(n) or {}).get("cpu_m") or 0
            rm = (reqs.get(n) or {}).get("mem_bytes") or 0
            u = usage.get(n) or {}
            flags = []
            if fv(b + ".unschedulable"):
                flags.append("cordoned")
            for c in ("MemoryPressure", "DiskPressure", "PIDPressure"):
                if fv(b + ".condition.%s" % c):
                    flags.append(c)
            rel = fv(b + ".rke2_release")
            kern = fv(b + ".kernel")
            rows.append([
                "`%s`" % n,
                "yes" if fv(b + ".ready") == "True" else "**NO**",
                str(pods_by_node.get(n, 0)),
                "`%s`" % rel if rel else "-",
                "`%s`" % kern if kern else "-",
                ("%.0f%%" % (100.0 * rc / ac)) if ac else "-",
                ("%.0f%%" % u["cpu_pct"]) if u.get("cpu_pct") is not None else "-",
                ("%.0f%%" % (100.0 * rm / am)) if am else "-",
                ("%.0f%%" % u["mem_pct"]) if u.get("mem_pct") is not None else "-",
                md(", ".join(flags)) if flags else "",
            ])
        L += table(["node", "ready", "pods", "rke2", "kernel", "cpu req",
                    "cpu use", "mem req", "mem use", "flags"],
                   rows, ["l", "l", "r", "l", "l", "r", "r", "r", "r", "l"])
        L.append("")
        L.append("*req = reserved by the scheduler; use = actually consumed. "
                 "The scheduler places pods against `req`, so that is the column "
                 "that runs out first.*")
        L.append("")

    # ----------------------------------------------------------------- footer
    L.append("---")
    L.append("")
    L.append("*Karel is read-only. Nothing in this report has been acted upon. "
             "Every proposed fix requires a human to review, decide, and execute.*")
    L.append("")

    return "\n".join(L).rstrip() + "\n"


def _group_resolved(resolved, sample=2):
    """One row per finding code. A rule rewrite can retire fifty per-node ids
    at once; a fifty-row table of them says nothing the code does not."""
    groups = {}
    for r in resolved:
        code = r["id"].split(":", 1)[0]
        groups.setdefault(code, []).append(r)
    rows = []
    for code, rs in sorted(groups.items(),
                           key=lambda kv: (-max(SEV_ORDER.get(r.get("severity"), 0)
                                                for r in kv[1]), kv[0])):
        sev = max((r.get("severity", "info") for r in rs),
                  key=lambda x: SEV_ORDER.get(x, 0))
        subs = [r["id"].split(":", 1)[1] for r in rs if ":" in r["id"]]
        subs = [x if len(x) <= 32 else x[:31] + "…" for x in subs]
        ids = ", ".join("`%s`" % x for x in subs[:sample])
        if len(subs) > sample:
            ids += " … +%d" % (len(subs) - sample)
        rows.append([SEV_LABEL.get(sev, "INFO"), "`%s`" % code, str(len(rs)), ids])
    return rows


def _render_finding(f):
    L = []
    state = f.get("state", "new")
    label = STATE_LABEL.get(state, state)
    if state in ("open", "escalating") and f.get("days_open"):
        label = ("open %dd" % f["days_open"] if state == "open"
                 else "%s, open %dd" % (label, f["days_open"]))
    if f.get("aged_from"):
        label += " — raised on age"
    elif state == "escalating" and f.get("prev_severity") \
            and f["prev_severity"] != f["severity"]:
        label += " (was %s)" % SEV_LABEL.get(f["prev_severity"], f["prev_severity"])

    L.append("#### %s — %s" % (SEV_LABEL.get(f["severity"], "INFO"), md(f["title"])))
    L.append("")

    meta = ["`%s`" % f["id"], label]
    if f.get("metric_delta"):
        d = f["metric_delta"]
        meta.append("change over %s: **%s**"
                    % (_SPAN.get("label") or "the interval",
                       ("%+d" % d) if float(d).is_integer() else ("%+.2f" % d)))
    L.append(" · ".join(m for m in meta if m))
    L.append("")

    if f.get("detail"):
        L += fence(_squash_blanks(collapse(_squash_blanks(f["detail"]))))
        L.append("")

    if f.get("remediation"):
        L.append("**Proposed**")
        L.append("")
        for r in f["remediation"]:
            L.append("- %s" % md(r))
        L.append("")

    if f.get("evidence"):
        L.append("*Evidence: %s*" % ", ".join("`%s`" % e for e in f["evidence"]))
        L.append("")
    return L
