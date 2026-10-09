"""
Karel collector normalizer: raw collector output -> flat fact bundle.

Design rules (do not break these):
  * A parse failure NEVER kills the run. Record parse_ok=False and continue.
  * A missing fact is ABSENT, not zero. Never invent values.
  * Facts are flat dotted paths so rules are one-liners and diffing is trivial.
  * All collector-release-specific JSON shape knowledge lives in the per-source
    parser modules (normalize_k8s.py, normalize_prom.py) and nowhere else.
"""

import gzip
import json
import os

SCHEMA_VERSION = 1


# --------------------------------------------------------------------------- io
def _read_raw(out_dir, name, stream="stdout"):
    base = os.path.join(out_dir, "raw", "%s.%s" % (name, stream))
    for path, opener in ((base + ".gz", gzip.open), (base, open)):
        if os.path.exists(path):
            try:
                with opener(path, "rt", errors="replace") as fh:
                    return fh.read()
            except Exception:
                return None
    return None


def load_index(out_dir):
    """index.tsv -> {name: {rc, duration_s, tier, status, bytes}}"""
    idx = {}
    path = os.path.join(out_dir, "index.tsv")
    if not os.path.exists(path):
        return idx
    with open(path, "rt", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                continue
            name, rc, dur, tier, status, size = parts[:6]
            idx[name] = {
                "rc": rc,
                "duration_s": _int(dur),
                "tier": _int(tier),
                "status": status,
                "bytes": _int(size),
                # 7th field added later; absent from older collector output
                "timeout": _int(parts[6]) if len(parts) > 6 else None,
            }
    return idx


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _json(text):
    if not text:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        # some tools emit a banner line before the JSON body
        for cut in ("{", "["):
            i = text.find(cut)
            if i > 0:
                try:
                    return json.loads(text[i:])
                except Exception:
                    pass
        return None


# ------------------------------------------------------------------------ facts
class Facts(dict):
    def add(self, path, value, source):
        if value is None:
            return
        if isinstance(value, float):
            value = round(value, 4)
        self[path] = {"value": value, "source": source}

    def get_value(self, path, default=None):
        e = self.get(path)
        return e["value"] if e else default


# ----------------------------------------------------------------------- bundle
def _read_file(path):
    try:
        with open(path, "rt", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


def _read_meta(out_dir):
    return _read_file(os.path.join(out_dir, "meta.json"))


def _ingest(out_dir, parsers, text_cmds, F, collection):
    # A partial upgrade once passed a string instead of a parser dict here and
    # silently produced an empty bundle. Fail loudly instead.
    if not isinstance(parsers, dict):
        raise TypeError(
            "_ingest() got parsers=%r for %s - this module is older than the "
            "caller. Rebuild the image so lib/ is one generation."
            % (parsers, out_dir))

    index = load_index(out_dir)
    expected = _json(_read_file(os.path.join(out_dir, "expected_status.json"))) or {}
    # Commands the manifest declares as returning plain text.
    declared = _json(_read_file(os.path.join(out_dir, "text_commands.json")))
    if isinstance(declared, list):
        text_cmds = set(text_cmds) | set(declared)

    for name, info in index.items():
        entry = dict(info)
        entry["expected"] = expected.get(name, "ok")
        entry["parse_ok"] = None
        if info["status"] == "ok":
            raw = _read_raw(out_dir, name)
            is_text = name in text_cmds
            obj = raw if is_text else _json(raw)
            if obj is None and not is_text and raw and raw.strip():
                # Succeeded, produced output, but it is not JSON. Only a real
                # problem if something was going to parse it - otherwise the
                # command simply returns plain text and nothing depends on it.
                if name in parsers:
                    obj = raw
                    entry["parsed_as_text"] = True
                else:
                    entry["non_json_output"] = True
            entry["parse_ok"] = obj is not None and obj != ""
            # An empty list/dict from a successful command means the subsystem
            # returned no data - the feature is unused, or something is broken.
            if isinstance(obj, (list, dict)) and len(obj) == 0:
                entry["empty"] = True
            entry["has_parser"] = name in parsers
            if obj is not None and name in parsers:
                try:
                    parsers[name](obj, F, name)
                except Exception as exc:          # never let a parser kill the run
                    entry["parse_error"] = "%s: %s" % (type(exc).__name__, exc)
                    entry["parse_ok"] = False
        else:
            err = _read_raw(out_dir, name, "stderr") or ""
            entry["stderr_head"] = err.strip().splitlines()[:2]
        collection[name] = entry


def build_bundle(sources):
    """Merge collector outputs into one bundle.

    `sources` is an ordered list of dicts; the FIRST source provides the run
    metadata (meta.json):

        {"label": "k8s",  "dir": "/tmp/out",      "parsers": k8s.PARSERS,
         "text": k8s.TEXT_COMMANDS}
        {"label": "prom", "dir": "/tmp/out-prom", "parsers": "prom"}

    Completeness is tracked PER SOURCE. A bare "complete: NO" tells a reader
    that something is wrong and nothing about what, which is unactionable.
    """
    sources = list(sources or [])
    first_dir = sources[0]["dir"] if sources else ""
    meta = _json(_read_meta(first_dir)) or {}

    F = Facts()
    collection = {}
    sources_meta = {}

    for src in sources:
        label = src.get("label") or src.get("dir")
        d = src["dir"]
        parsers = src.get("parsers")
        present = os.path.isdir(d)
        entry = {"dir": d, "present": present, "complete": None}
        sources_meta[label] = entry

        if not present:
            # Silence is not health. An expected source that produced no
            # directory at all is recorded, not skipped.
            entry["complete"] = False
            entry["reason"] = "collector produced no output directory"
            continue

        if parsers == "prom":
            import normalize_prom
            normalize_prom.ingest(d, F, collection)
            doc_ok = os.path.exists(os.path.join(d, "result.json"))
            entry["complete"] = doc_ok
            if not doc_ok:
                entry["reason"] = "no result.json"
            continue

        _ingest(d, parsers, src.get("text") or set(), F, collection)
        done = os.path.exists(os.path.join(d, "COMPLETE"))
        entry["complete"] = done
        if not done:
            entry["reason"] = ("COMPLETE sentinel missing - the collector did "
                               "not reach the end of its run")

    complete = all(v.get("complete") for v in sources_meta.values())

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": meta.get("run_id"),
        "collected_at": meta.get("started"),
        "finished_at": meta.get("finished"),
        "manifest_sha256": meta.get("manifest_sha256"),
        "budget_used_seconds": meta.get("budget_used_seconds"),
        "collection": {
            "complete": complete,
            "sources": sources_meta,
            "commands": collection,
        },
        "facts": dict(F),
    }
