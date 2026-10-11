#!/usr/bin/env python3
"""Run one log check from config/log-checks.json and print one JSON document.

Aggregation happens HERE, not in the pipeline: raw log lines never reach
disk, the bundle, or the report - only counts, timestamps, distinct objects
and redacted samples do (the same contract apiserver_metrics.py follows).

  collect_logs.py --check thanos_sidecar      # against the cluster
  collect_logs.py --check thanos_sidecar --from-file sidecar.log   # tuning/tests

Window start comes from KAREL_SINCE (exported by run.sh from the previous
snapshot, default now-26h, capped at 48h). Per-container log size is bounded
by KAREL_LOG_LIMIT_BYTES (default 20 MiB). Exit 0 even when no pods match -
that is data ("status": "no_pods"), not a failure. Non-zero only when the
collector itself fails (bad config, kubectl unusable).
"""

import argparse
import datetime
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "lib"))

import logscan            # noqa: E402

DEFAULT_LIMIT_BYTES = 20 * 1024 * 1024
GET_TIMEOUT = 30
LOG_TIMEOUT = 45


def _run(args, timeout):
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=timeout)


def _kubectl(args, timeout):
    try:
        return _run(["kubectl"] + args, timeout)
    except subprocess.TimeoutExpired:
        class R(object):
            returncode = 124
            stdout = ""
            stderr = "kubectl timed out"
        return R()
    except OSError as exc:
        class R(object):
            returncode = 127
            stdout = ""
            stderr = str(exc)
        return R()


def load_config(path):
    with open(path, "rt") as fh:
        doc = json.load(fh)
    return doc.get("checks") or {}


def parse_args_list(argv):
    """CLI args -> {'log.level': 'info', 'flag': True}.

    Handles all three real forms: --k=v, --k v, and bare flags. A repeated
    key (thanos querier's --endpoint) becomes a list, never clobbered.
    """
    out = {}
    argv = [str(a) for a in argv or []]
    i = 0
    while i < len(argv):
        a = argv[i]
        i += 1
        if not a.startswith("--"):
            continue
        a = a[2:]
        if "=" in a:
            key, v = a.split("=", 1)
        elif i < len(argv) and not argv[i].startswith("--"):
            key, v = a, argv[i]
            i += 1
        else:
            key, v = a, True
        if key in out:
            if isinstance(out[key], list):
                out[key].append(v)
            else:
                out[key] = [out[key], v]
        else:
            out[key] = v
    return out


def container_status(pod, name):
    for cs in (pod.get("status") or {}).get("containerStatuses") or []:
        if cs.get("name") == name:
            return cs
    return None


def spec_container(pod, name):
    for c in (pod.get("spec") or {}).get("containers") or []:
        if c.get("name") == name:
            return c
    return None


def last_termination(cs):
    t = ((cs or {}).get("lastState") or {}).get("terminated")
    if not t:
        return None
    return {"reason": t.get("reason"), "exit_code": t.get("exitCode"),
            "finished_at": t.get("finishedAt")}


def started_at(cs):
    return (((cs or {}).get("state") or {}).get("running") or {}).get("startedAt")


def fetch_log(pod, ns, container, limit, previous=False):
    args = ["logs", pod, "-n", ns, "-c", container,
            "--timestamps", "--limit-bytes=%d" % limit]
    if previous:
        args.append("--previous")
    r = _kubectl(args, LOG_TIMEOUT)
    if r.returncode != 0:
        return None, (r.stderr or "").strip()[:160]
    return r.stdout, None


def run_check(name, check, since, now, limit, max_pods):
    ns = check.get("namespace")
    selector = check.get("selector") or ""
    want_container = check.get("container")
    only_restarted = bool(check.get("only_restarted"))
    previous_only = bool(check.get("previous_only"))
    also_args_from = check.get("also_args_from")

    argv = ["get", "pods"]
    if ns:
        argv += ["-n", ns]
    else:
        argv.append("-A")
    if selector:
        argv += ["-l", selector]
    argv += ["-o", "json"]
    r = _kubectl(argv, GET_TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError("kubectl get pods failed: %s"
                           % ((r.stderr or "").strip()[:200]))
    pods = (json.loads(r.stdout) if r.stdout.strip() else {}).get("items") or []

    agg = logscan.Aggregator(check, since=since, now=now)
    entries = []

    # Prefer the noisy pods when there are more than the cap: a restarted
    # container is exactly what the previous-log path exists for.
    def _restart_total(p):
        return sum((cs.get("restartCount") or 0)
                   for cs in (p.get("status") or {}).get("containerStatuses") or [])

    pods = sorted(pods, key=lambda p: (-_restart_total(p),
                                       (p.get("metadata") or {}).get("name") or ""))
    pod_overflow = max(0, len(pods) - max_pods)
    pods = pods[:max_pods]

    for pod in pods:
        md = pod.get("metadata") or {}
        spec = pod.get("spec") or {}
        pname = md.get("name")
        node = spec.get("nodeName")
        names = ([c.get("name") for c in spec.get("containers") or []]
                 if want_container in (None, "*") else [want_container])
        for cname in names:
            cs = container_status(pod, cname)
            sc = spec_container(pod, cname)
            entry = {"pod": pname, "node": node, "container": cname}
            if sc is None and cs is None:
                entry.update({"container_missing": True, "coverage": "none",
                              "coverage_reason": "no such container in pod"})
                entries.append(entry)
                continue
            restarts = (cs.get("restartCount") or 0) if cs else 0
            if only_restarted and not restarts:
                continue
            started = started_at(cs)
            entry.update({
                "started_at": started,
                "restart_count": restarts,
                "last_termination": last_termination(cs),
                "args": parse_args_list((sc or {}).get("args")),
                "coverage": "complete", "truncated": False,
            })
            if also_args_from:
                other = spec_container(pod, also_args_from)
                if other is not None:
                    entry["also_args"] = {also_args_from:
                                          parse_args_list(other.get("args"))}

            coverage_reasons = []
            fetched = 0
            for previous in ([True] if previous_only else [False] +
                             ([True] if restarts else [])):
                text, err = fetch_log(pname, ns, cname, limit,
                                      previous=previous)
                src = "previous" if previous else "current"
                if text is None:
                    if previous:
                        coverage_reasons.append(
                            "previous container's log is missing (%s)"
                            % (err or "unavailable"))
                    else:
                        entry["coverage"] = "none"
                        coverage_reasons.append(
                            "log fetch failed: %s" % (err or "unknown"))
                    continue
                fetched += 1
                if len(text.encode()) >= limit:
                    entry["truncated"] = True
                    coverage_reasons.append(
                        "--limit-bytes=%d truncated the log" % limit)
                for line in text.splitlines():
                    if line.strip():
                        agg.feed(line, source=src, pod=pname, node=node)

            st = logscan.parse_ts(started)
            if st is not None and since is not None and st > since:
                coverage_reasons.append("container started inside the window")
            if not fetched and entry["coverage"] != "none":
                entry["coverage"] = "none"
                coverage_reasons.append("no log content fetched")
            if coverage_reasons and entry["coverage"] == "complete":
                entry["coverage"] = "partial"
            if coverage_reasons:
                entry["coverage_reason"] = "; ".join(coverage_reasons)
            entries.append(entry)

    classes, ignored = agg.finalize()
    classes = _with_configured_zeros(check, classes, now)
    status = "ok" if entries else "no_pods"
    doc = {
        "check": name,
        "status": status,
        "namespace": ns,
        "selector": selector,
        "container": want_container,
        "expect_pods": bool(check.get("expect_pods", True)),
        "window": {"from": logscan.iso_z(since), "to": logscan.iso_z(now)},
        "pods": entries,
        "pod_overflow": pod_overflow,
        "lines": agg.lines,
        "classes": classes,
        "ignored": ignored,
    }
    return doc


def _with_configured_zeros(check, classes, now):
    """Classes that matched nothing still appear (count 0). A rule cannot
    tell 'pattern configured, zero hits' from 'check not run' otherwise -
    and silence must stay distinguishable from health being asserted."""
    for spec in check.get("rules") or []:
        cls = spec.get("class")
        kind = spec.get("kind", "error")
        if "classifier" in spec:
            continue
        if cls and cls not in classes:
            classes[cls] = logscan.ClassAgg(kind).to_json(now=now)
    return classes


def run_from_file(name, check, path, since, now):
    agg = logscan.Aggregator(check, since=since, now=now)
    opener = open
    if path.endswith(".gz"):
        import gzip
        opener = gzip.open
    with opener(path, "rt", errors="replace") as fh:
        for line in fh:
            if line.strip():
                agg.feed(line)
    classes, ignored = agg.finalize()
    classes = _with_configured_zeros(check, classes, now)
    return {
        "check": name, "status": "ok", "source": "file:%s" % path,
        "namespace": check.get("namespace"),
        "selector": check.get("selector"), "container": check.get("container"),
        "expect_pods": bool(check.get("expect_pods", True)),
        "window": {"from": logscan.iso_z(since), "to": logscan.iso_z(now)},
        "pods": [{"pod": "(file)", "container": check.get("container"),
                  "coverage": "complete", "truncated": False,
                  "restart_count": 0}],
        "lines": agg.lines, "classes": classes, "ignored": ignored,
    }


def default_since(now):
    env = os.environ.get("KAREL_SINCE")
    if env:
        s = logscan.parse_ts(env)
        if s is not None:
            # capped at 48h: an old baseline must not make the log fetch huge
            cap = now - datetime.timedelta(hours=48)
            return max(s, cap)
    return now - datetime.timedelta(hours=26)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", required=True)
    ap.add_argument("--from-file", default=None)
    ap.add_argument("--config", default=os.environ.get(
        "KAREL_LOG_CHECKS") or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "config", "log-checks.json"))
    ap.add_argument("--since", default=None)
    ap.add_argument("--now", default=None)
    ap.add_argument("--limit-bytes", type=int,
                    default=int(os.environ.get("KAREL_LOG_LIMIT_BYTES")
                              or DEFAULT_LIMIT_BYTES))
    ap.add_argument("--max-pods", type=int, default=10)
    args = ap.parse_args()

    try:
        checks = load_config(args.config)
    except Exception as exc:
        print("collect_logs: cannot load %s: %s" % (args.config, exc),
              file=sys.stderr)
        return 1

    check = checks.get(args.check)
    if check is None:
        print("collect_logs: no check '%s' in %s (have: %s)"
              % (args.check, args.config, ", ".join(sorted(checks))),
              file=sys.stderr)
        return 1

    now = logscan.parse_ts(args.now) if args.now else logscan.utcnow()
    since = logscan.parse_ts(args.since) if args.since \
        else default_since(now)
    max_pods = int(check.get("max_pods") or args.max_pods)

    try:
        if args.from_file:
            doc = run_from_file(args.check, check, args.from_file, since, now)
        else:
            doc = run_check(args.check, check, since, now,
                            args.limit_bytes, max_pods)
    except Exception as exc:
        print("collect_logs: %s failed: %s" % (args.check, exc),
              file=sys.stderr)
        return 1

    json.dump(doc, sys.stdout, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
