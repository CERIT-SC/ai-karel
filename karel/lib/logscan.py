"""
Shared log classification for Karel's log checks (bin/collect_logs.py).

Pure logic, no cluster I/O: the collector script talks to kubectl and feeds
lines here. Aggregation happens in the collector for the same reason
apiserver_metrics.py aggregates there - raw log lines must never reach disk,
the bundle, or the emailed report. What survives is counts, first/last
timestamps, distinct extracted objects, and at most SAMPLE_LIMIT redacted
samples per class.

Line shape handled (see tests):
  kubectl --timestamps : "<RFC3339Nano> <rest of line>"
  CRI log file         : "<RFC3339 with offset> stderr F <rest>"
The rest parses as logfmt when it has key=value tokens, else as JSON, else as
plain text keyed under "msg".
"""

import datetime
import json
import re

SAMPLE_LIMIT = 3
SAMPLE_CHARS = 300
EXTRACT_LIMIT = 50
FREQ_LIMIT = 5
# Per-class pod/node attribution is capped the same way: the gpu-operator
# checks run over one DaemonSet family per node, so 50 covers any cluster.
WHERE_LIMIT = 50


# ---------------------------------------------------------------- timestamps
# Three real prefixes: kubectl --timestamps in Z form, the offset form some
# clusters return ("...+02:00 line"), and the CRI file form
# ("... stderr F line"). All three must yield the same UTC instant.
_KUBE_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(.*)$", re.S)
_CRI_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?:stdin|stdout|stderr)\s+[FP]\s+(.*)$", re.S)


def parse_ts(s):
    """ISO/RFC3339 string -> aware datetime in UTC, or None."""
    if not s:
        return None
    s = str(s).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def iso_z(dt):
    if dt is None:
        return None
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def split_timestamp(line):
    """(datetime|None, rest). Tolerates the kubectl prefix and the CRI one,
    so log files copied off a node classify exactly like live kubectl output."""
    m = _CRI_TS_RE.match(line) or _KUBE_TS_RE.match(line)
    if not m:
        return None, line
    return parse_ts(m.group(1)), m.group(2)


# ------------------------------------------------------------- line parsing
_LOGFMT_TOKEN = re.compile(r"([A-Za-z_][\w.\-]*)=(\"(?:[^\"\\]|\\.)*\"|\S+)")


def _unquote(v):
    if len(v) >= 2 and v.startswith('"') and v.endswith('"'):
        body = v[1:-1]
        # targeted unescape only - a blanket unicode_escape mangles non-ASCII
        return (body.replace('\\"', '"').replace("\\n", "\n")
                    .replace("\\t", "\t").replace("\\\\", "\\"))
    return v


def parse_logfmt(rest):
    """key=value tokens -> dict. None when the line has no such tokens.
    Values may be quoted and contain '=' and ':' (a Minio error body does)."""
    fields = {}
    for m in _LOGFMT_TOKEN.finditer(rest):
        fields[m.group(1)] = _unquote(m.group(2))
    return fields or None


_LOGFMT_KNOWN_KEYS = {"level", "severity", "ts", "time", "msg", "err",
                      "caller", "name", "component", "module", "log"}


def parse_line(rest):
    """-> (fields dict, was_plain_text). JSON objects and logfmt lines become
    field dicts; anything else is {"msg": rest}.

    A prose line that merely CONTAINS 'a=b' (an S3 URL in an error, say) is
    not logfmt: at least one well-known key must be present."""
    rest = rest.rstrip("\n")
    if rest.startswith("{"):
        try:
            obj = json.loads(rest)
            if isinstance(obj, dict):
                return ({k: (v if isinstance(v, str) else json.dumps(v))
                         for k, v in obj.items()}, False)
        except (ValueError, TypeError):
            pass
    f = parse_logfmt(rest)
    if f and f.keys() & _LOGFMT_KNOWN_KEYS:
        return f, False
    return {"msg": rest}, True


# ---------------------------------------------------------------------- ULID
ULID_ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ULID_RE = re.compile(r"\b[0-7][0-9A-HJKMNP-TV-Z]{25}\b")


def ulid_time(ulid):
    """Creation time encoded in a ULID's first 10 chars: the 48-bit
    millisecond epoch, base32 (Crockford). 10 chars cover 50 bits, so the
    value is taken as-is (verified against ulid-py: 01KYNCB25N... is
    2026-07-28T22:08:23Z)."""
    if not ulid:
        return None
    v = 0
    for ch in str(ulid)[:10].upper():
        i = ULID_ALPHA.find(ch)
        if i < 0:
            return None
        v = v * 32 + i
    try:
        return datetime.datetime.fromtimestamp(v / 1000.0,
                                               datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# ------------------------------------------------------------------ redaction
_REDACT_RES = [
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<aws-key-id>"),
    (re.compile(r"(X-Amz-Credential=)[^&\s]+", re.I), r"\1<redacted>"),
    (re.compile(r"(X-Amz-Signature=)[0-9a-f]+", re.I), r"\1<redacted>"),
    (re.compile(r"(://)[^:/@\s]+:[^@\s]+@"), r"\1<creds>@"),
    (re.compile(r"(bearer\s+)[A-Za-z0-9._\-]+", re.I), r"\1<token>"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<hex>"),
    (re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}={0,2}\b"), "<b64>"),
]


def redact(text, limit=SAMPLE_CHARS):
    """Mask the credential shapes that end up in S3 and apiserver logs, then
    truncate. Samples from here are what the report and the bundle may show."""
    s = str(text)
    for rx, rep in _REDACT_RES:
        s = rx.sub(rep, s)
    if len(s) > limit:
        s = s[:limit] + " ..."
    return s


# ------------------------------------------------------------ S3 classifier
# NoSuchKey during deletion-mark handling is normal and is NOT an error.
_S3_IGNORE = re.compile(r"NoSuchKey", re.I)
_S3_RULES = [
    ("s3_auth", re.compile(
        r"AccessDenied|Access Denied|InvalidAccessKeyId|SignatureDoesNotMatch|"
        r"403 Forbidden", re.I)),
    ("s3_quota", re.compile(r"QuotaExceeded|XMinioStorageFull|"
                            r"insufficient storage", re.I)),
    ("s3_clock", re.compile(r"RequestTimeTooSkewed", re.I)),
    ("s3_bucket", re.compile(r"NoSuchBucket", re.I)),
    ("s3_tls", re.compile(r"x509:", re.I)),
    ("s3_network", re.compile(
        r"i/o timeout|connection reset|connection refused|no such host|"
        r"context deadline exceeded|SlowDown|ServiceUnavailable", re.I)),
    ("s3_other", re.compile(r"bucket|s3|objstore|upload", re.I)),
]


def s3_classify(text):
    """Map S3/objstore error text to a class, or None (including NoSuchKey)."""
    if not text or _S3_IGNORE.search(str(text)):
        return None
    for cls, rx in _S3_RULES:
        if rx.search(str(text)):
            return cls
    return None


def s3_benign(text):
    """True when the only S3 signal is a benign one (NoSuchKey during
    deletion-mark handling). These must not reach the unclassified catch-all
    either: normal noise is not an error just because it sits in `err`."""
    if not text:
        return False
    return bool(_S3_IGNORE.search(str(text))) and s3_classify(text) is None


S3_CLASS_SEVERITY = {"s3_auth": "warn", "s3_quota": "warn", "s3_clock": "warn",
                     "s3_bucket": "warn", "s3_tls": "warn",
                     "s3_network": "info", "s3_other": "warn"}

S3_CLASS_LABEL = {"s3_auth": "Access Denied", "s3_quota": "storage quota full",
                  "s3_clock": "clock skew", "s3_bucket": "bucket missing",
                  "s3_tls": "TLS failure", "s3_network": "network errors",
                  "s3_other": "object storage errors"}


# --------------------------------------------------------------------- rules
def compile_rule(spec):
    """Pre-compile one config rule. Shapes:

      {"class": n, "kind": success|state|error|ignore, "field": msg|err|line,
       "regex": "...", "ignore_case": bool,
       "extract": {"id": "field:id" | {"field": "...", "regex": "...with (?P<id>..)"}},
       "extract_many": {"field": "line", "regex": "...", "groups": [...]},
       "require_followed_by": {"class": c, "within_s": 300, "else_class": c2}}
      {"classifier": "s3", "field": "err"}
    """
    r = dict(spec)
    if "classifier" not in r and r.get("regex"):
        flags = re.I if r.get("ignore_case") else 0
        r["_re"] = re.compile(r["regex"], flags)
    ex = r.get("extract") or {}
    r["_extract"] = {}
    for name, es in ex.items():
        if isinstance(es, str):
            r["_extract"][name] = {"field": es.split(":", 1)[1]
                                   if es.startswith("field:") else es,
                                   "regex": None}
        else:
            e = dict(es)
            if e.get("regex"):
                e["_re"] = re.compile(e["regex"])
            r["_extract"][name] = e
    em = r.get("extract_many")
    if isinstance(em, dict):
        em = [em]
    r["_extract_many"] = []
    for spec in em or []:
        if not spec.get("regex"):
            continue
        e = dict(spec)
        e["_re"] = re.compile(e["regex"])
        r["_extract_many"].append(e)
    return r


def match_line(fields, line, rules):
    """First rule wins. Returns (rule, effective_class) or (None, None)."""
    for r in rules:
        if "classifier" in r:
            field = r.get("field", "err")
            text = line if field == "line" else fields.get(field)
            if text is None:
                continue
            cls = s3_classify(text)
            if cls:
                return r, cls
            continue
        rx = r.get("_re")
        if rx is None:
            continue
        field = r.get("field", "msg")
        text = line if field == "line" else fields.get(field)
        if text is None:
            continue
        if rx.search(str(text)):
            return r, r.get("class")
    return None, None


def is_errorish(fields):
    """The catch-all: an err field at ANY level counts, or level=error. The
    2026-10-02 compactor failure was logged at info with the error only in
    err - matching level=error alone would have missed the outage."""
    level = str(fields.get("level") or fields.get("severity") or "").lower()
    return bool(fields.get("err")) or level in ("error", "fatal", "critical")


_NORM_RES = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d+:?\d+)?"),
     "<ts>"),
    (re.compile(r"\b[0-7][0-9A-HJKMNP-TV-Z]{25}\b"), "<ulid>"),
    (re.compile(r"\b[0-9a-f]{8,}\b", re.I), "<hex>"),
    (re.compile(r"\b\d+\b"), "<n>"),
]


def normalize_message(text, limit=80):
    s = str(text)
    for rx, rep in _NORM_RES:
        s = rx.sub(rep, s)
    return " ".join(s.split())[:limit]


# --------------------------------------------------------------- aggregation
class ClassAgg(object):
    def __init__(self, kind):
        self.kind = kind
        self.count = 0
        self.first = None
        self.last = None
        self.times = []              # success: for the gap calculation
        self.present = False         # state
        self.present_in = set()      # state: {"current", "previous"}
        self.extracted = {}
        self.entries = {}            # key -> {"entry","count","first","last"}
        self.samples = []
        self.freq = {}
        self.pods = set()            # attribution: which pods hit this class
        self.nodes = set()

    def note_ts(self, ts):
        if ts is None:
            return
        if self.first is None or ts < self.first:
            self.first = ts
        if self.last is None or ts > self.last:
            self.last = ts

    def add_where(self, pod=None, node=None):
        """Which pod (on which node) produced this class. Without it, a class
        matched by a DaemonSet pod on one node is indistinguishable from the
        same pod on another node - and the fix is per node."""
        if pod and len(self.pods) < WHERE_LIMIT:
            self.pods.add(str(pod))
        if node and len(self.nodes) < WHERE_LIMIT:
            self.nodes.add(str(node))

    def add_extract(self, name, value):
        if value is None:
            return
        s = self.extracted.setdefault(name, set())
        if len(s) < EXTRACT_LIMIT:
            s.add(str(value))

    def add_entry(self, entry, ts):
        key = json.dumps(entry, sort_keys=True)
        cur = self.entries.get(key)
        if cur is None:
            if len(self.entries) >= EXTRACT_LIMIT:
                return
            cur = self.entries[key] = {"entry": entry, "count": 0,
                                       "first": ts, "last": ts}
        cur["count"] += 1
        if ts is not None:
            if cur["first"] is None or ts < cur["first"]:
                cur["first"] = ts
            if cur["last"] is None or ts > cur["last"]:
                cur["last"] = ts

    def add_sample(self, text):
        if len(self.samples) < SAMPLE_LIMIT:
            self.samples.append(redact(text))

    def add_freq(self, text):
        key = normalize_message(text)
        self.freq[key] = self.freq.get(key, 0) + 1

    def to_json(self, now=None):
        out = {"kind": self.kind, "count": self.count}
        if self.kind == "state":
            out["present"] = self.present
            if self.present_in:
                out["present_in"] = sorted(self.present_in)
        if self.first:
            out["first"] = iso_z(self.first)
        if self.last:
            out["last"] = iso_z(self.last)
        if self.kind == "success":
            ts = sorted(self.times)
            gaps = [int((b - a).total_seconds()) for a, b in zip(ts, ts[1:])]
            if ts and now is not None and now > ts[-1]:
                gaps.append(int((now - ts[-1]).total_seconds()))
            out["max_gap_s"] = max(gaps) if gaps else 0
        if self.extracted:
            out["extracted"] = {k: sorted(v) for k, v in
                                sorted(self.extracted.items())}
        if self.entries:
            out["entries"] = [
                {"entry": e["entry"], "count": e["count"],
                 "first": iso_z(e["first"]), "last": iso_z(e["last"])}
                for e in sorted(self.entries.values(),
                                key=lambda e: (-e["count"],
                                               json.dumps(e["entry"],
                                                          sort_keys=True)))]
        if self.samples:
            out["samples"] = self.samples
        if self.freq:
            out["freq"] = [[k, v] for k, v in
                           sorted(self.freq.items(),
                                  key=lambda kv: (-kv[1], kv[0]))[:FREQ_LIMIT]]
        if self.pods:
            out["pods"] = sorted(self.pods)
        if self.nodes:
            out["nodes"] = sorted(self.nodes)
        return out


class Aggregator(object):
    """Feed log lines; get the check's class aggregates plus ignored counts.

    Window semantics: error and success classes count only lines stamped in
    [since, now]; state classes look at the WHOLE fetched log (a halt line is
    logged once and may predate the window). Lines without a parseable
    timestamp are counted as in-window for errors (loud is safer) but carry
    no gap/first/last information.
    """

    def __init__(self, check_cfg, since=None, now=None):
        self.cfg = check_cfg or {}
        self.rules = [compile_rule(r) for r in self.cfg.get("rules") or []]
        self.since = since
        self.now = now or utcnow()
        self.classes = {}
        self.ignored = {}
        self._pending = []           # ignore rules awaiting require_followed_by
        self.lines = 0

    def _agg(self, name, kind):
        a = self.classes.get(name)
        if a is None:
            a = self.classes[name] = ClassAgg(kind)
        return a

    def feed(self, line, source="current", pod=None, node=None):
        self.lines += 1
        ts, rest = split_timestamp(line)
        fields, _plain = parse_line(rest)
        fields["_line"] = rest
        rule, cls = match_line(fields, rest, self.rules)

        if rule is None and is_errorish(fields) \
                and not s3_benign(fields.get("err")):
            cls, kind = "unclassified", "error"
            self._record_error("unclassified", kind, fields, ts, source,
                               freq=True, pod=pod, node=node)
            return cls

        if rule is None:
            return None

        kind = rule.get("kind", "error")

        if kind == "ignore":
            guard = rule.get("require_followed_by")
            if guard:
                self._pending.append({
                    "class": cls, "ts": ts, "fields": fields, "line": rest,
                    "within_s": guard.get("within_s", 300),
                    "follow": guard.get("class"),
                    "else_class": guard.get("else_class") or "unclassified",
                    "source": source, "followed": False,
                })
            else:
                self.ignored[cls] = self.ignored.get(cls, 0) + 1
            return cls

        # a resolved pending guard depends on seeing its success/error class
        self._resolve_pending(cls, ts)

        if kind == "state":
            a = self._agg(cls, "state")
            a.present = True
            a.present_in.add(source)
            a.count += 1
            a.note_ts(ts)
            a.add_where(pod, node)
            self._extract(rule, a, fields, rest, ts)
        elif kind == "success":
            if self._in_window(ts):
                a = self._agg(cls, "success")
                a.count += 1
                a.note_ts(ts)
                if ts is not None:
                    a.times.append(ts)
                self._extract(rule, a, fields, rest, ts)
        else:
            self._record_error(cls, kind, fields, ts, source,
                               rule=rule, line=rest, pod=pod, node=node)
            # A matched error rule wins the primary class, but an S3-shaped
            # err gets its shared class too ("error executing compaction" +
            # "Access Denied" is compaction_exit AND s3_auth; the rule title
            # is built from the pair).
            if "classifier" not in rule:
                extra = s3_classify(fields.get("err"))
                if extra and extra != cls:
                    self._record_error(extra, "error", fields, ts, source,
                                       line=rest, pod=pod, node=node)
        return cls

    def _record_error(self, cls, kind, fields, ts, source, rule=None,
                      line=None, freq=False, pod=None, node=None):
        if not self._in_window(ts):
            return
        a = self._agg(cls, "error")
        a.count += 1
        a.note_ts(ts)
        a.add_where(pod, node)
        if rule is not None:
            self._extract(rule, a, fields, line, ts)
        a.add_sample(line if line is not None else fields.get("_line", ""))
        a.add_freq(fields.get("msg") or line or "")

    def _in_window(self, ts):
        # Unknown timestamp: errors stay loud; callers that need strict
        # windowing (gap math) skip those lines themselves.
        if ts is None:
            return True
        if self.since is not None and ts < self.since:
            return False
        return ts <= self.now

    def _extract(self, rule, agg, fields, line, ts):
        for name, es in (rule.get("_extract") or {}).items():
            field = es.get("field", "line")
            text = line if field == "line" else fields.get(field)
            if text is None:
                continue
            text = str(text)
            rx = es.get("_re")
            if rx is None:
                agg.add_extract(name, text)
                continue
            for m in rx.finditer(text):
                v = None
                try:
                    v = m.group(name)
                except IndexError:
                    pass
                if v is None and m.groups():
                    v = m.group(1)
                if v is not None:
                    agg.add_extract(name, v)
        for em in rule.get("_extract_many") or []:
            field = em.get("field", "line")
            text = line if field == "line" else fields.get(field)
            if text is None:
                continue
            groups = em.get("groups") or []
            for m in em["_re"].finditer(str(text)):
                entry = {}
                for g in groups:
                    try:
                        entry[g] = m.group(g)
                    except IndexError:
                        continue
                if entry:
                    agg.add_entry(entry, ts)

    def _resolve_pending(self, cls, ts):
        for p in self._pending:
            if p["followed"] or cls != p["follow"]:
                continue
            if ts is None or p["ts"] is None:
                continue
            dt = (ts - p["ts"]).total_seconds()
            if 0 <= dt <= p["within_s"]:
                p["followed"] = True

    def finalize(self):
        """Settle pending ignore-guards, then render the class aggregates."""
        for p in self._pending:
            if p["followed"]:
                self.ignored[p["class"]] = self.ignored.get(p["class"], 0) + 1
                continue
            # Within the last within_s before collection the verdict is still
            # open: not an error, not ignored - simply undecided.
            if p["ts"] is not None and \
                    (self.now - p["ts"]).total_seconds() < p["within_s"]:
                continue
            self._record_error(p["else_class"], "error", p["fields"],
                               p["ts"], p["source"], line=p["line"])
        classes = {name: a.to_json(now=self.now)
                   for name, a in self.classes.items()}
        return classes, dict(sorted(self.ignored.items()))
