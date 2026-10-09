#!/usr/bin/env python3
"""Tests for the log collector (bin/collect_logs.py, lib/logscan.py) and the
Fleet/Thanos rules (lib/rules_logs.py). Real samples are the fixtures; a
scriptable fake kubectl covers collection without a cluster."""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import ROOT, check, facts, finish              # noqa: E402

import logscan          # noqa: E402
import rules            # noqa: E402
import rules_logs       # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures", "logs")
SINCE = logscan.parse_ts("2026-10-06T19:20:00Z")
NOW = logscan.parse_ts("2026-10-07T19:20:00Z")


def classify(check_name, path, since=SINCE, now=NOW):
    cfg = json.load(open(os.path.join(ROOT, "config", "log-checks.json")))
    agg = logscan.Aggregator(cfg["checks"][check_name], since=since, now=now)
    with open(os.path.join(FIX, path), errors="replace") as fh:
        for line in fh:
            if line.strip():
                agg.feed(line)
    return agg.finalize()


# --------------------------------------------------------------------------
print("\nlogfmt with escaped quotes and colons parses into fields")

f, plain = logscan.parse_line(
    'level=warn ts=2026-10-07T06:58:00.1Z caller=shipper.go:418 '
    'msg="upload failed; will be retried" '
    'err="stat block 01JACMDM603N438RXDYAKRKN83: no such '
    'file or directory"')
check("err with colons and spaces is one field",
      f.get("err") == "stat block 01JACMDM603N438RXDYAKRKN83: "
      "no such file or directory", f.get("err"))
check("quoted msg with a semicolon is one field",
      f.get("msg") == "upload failed; will be retried")
check("not mistaken for plain text", plain is False)

f2, _ = logscan.parse_line('msg="a \\"quoted\\" word" x=1')
check("escaped quotes inside a quoted value", f2.get("msg") == 'a "quoted" word')


# --------------------------------------------------------------------------
print("\nkubectl --timestamps and CRI prefixes give the same UTC time")

a_ts, a_rest = logscan.split_timestamp(
    "2026-10-07T19:02:51.123456789Z level=info msg=\"upload new block\"")
b_ts, b_rest = logscan.split_timestamp(
    "2026-10-07T21:02:51.123456789+02:00 stderr F "
    "level=info msg=\"upload new block\"")
check("CRI +02:00 equals the kubectl Z time", a_ts == b_ts,
      "%s vs %s" % (a_ts, b_ts))
check("both strip the prefix from the payload",
      a_rest == b_rest and a_rest.startswith("level=info"))


# --------------------------------------------------------------------------
print("\nthe 2026-10-02 compactor line (level=info, error in `err`)")

classes, ignored = classify("thanos_compactor",
                            "thanos_compactor_2026-10-02.log",
                            since=logscan.parse_ts("2026-10-02T00:00:00Z"),
                            now=logscan.parse_ts("2026-10-02T23:59:59Z"))
ce = classes.get("compaction_exit") or {}
check("logged at info with err= still becomes compaction_exit",
      ce.get("count") == 1, classes)
phases = [e["entry"].get("phase") for e in ce.get("entries") or []]
check("phase is retention", phases == ["retention"], phases)
check("S3 class of the same line is s3_auth",
      (classes.get("s3_auth") or {}).get("count") == 1)
op = sorted((ce.get("extracted") or {}).get("operation") or [])
check("operation is 'upload deletion-mark.json'",
      op == ["upload deletion-mark.json"], op)
block = (ce.get("extracted") or {}).get("block", ["?"])[0]
check("failing block created 2026-07-28 22:08 UTC",
      logscan.iso_z(logscan.ulid_time(block)) == "2026-07-28T22:08:20Z")


# --------------------------------------------------------------------------
print("\nstat race: ignored when an upload follows within 300 s")

classes, ignored = classify("thanos_sidecar", "thanos_sidecar_2026-10-07.log")
check("both stat races are ignored", ignored.get("stat_block_race") == 2,
      ignored)
check("no block_missing is raised", "block_missing" not in classes
      or not classes["block_missing"].get("count"))

ag = logscan.Aggregator(
    {"rules": [{"class": "upload_ok", "kind": "success", "field": "msg",
                "regex": "^upload new block$"},
               {"class": "stat_block_race", "kind": "ignore", "field": "err",
                "regex": "stat block",
                "require_followed_by": {"class": "upload_ok", "within_s": 300,
                                        "else_class": "block_missing"}}]},
    since=SINCE, now=NOW)
ag.feed("2026-10-07T10:00:00.000000000Z level=warn ts=x "
        "err=\"stat block 01J: no such file or directory\"")
cl, ig = ag.finalize()
check("no following upload at all -> block_missing",
      (cl.get("block_missing") or {}).get("count") == 1 and not ig)

NOW2 = logscan.parse_ts("2026-10-07T10:02:00Z")
ag = logscan.Aggregator(
    {"rules": [{"class": "upload_ok", "kind": "success", "field": "msg",
                "regex": "^upload new block$"},
               {"class": "stat_block_race", "kind": "ignore", "field": "err",
                "regex": "stat block",
                "require_followed_by": {"class": "upload_ok", "within_s": 300,
                                        "else_class": "block_missing"}}]},
    since=SINCE, now=NOW2)
ag.feed("2026-10-07T10:00:00.000000000Z level=warn ts=x "
        "err=\"stat block 01J: no such file or directory\"")
cl, ig = ag.finalize()
check("within 300 s before collection: undecided, not an error",
      not (cl.get("block_missing") or {}).get("count")
      and not ig.get("stat_block_race"))


# --------------------------------------------------------------------------
print("\nthe 2026-10-07 sidecar sample: heartbeat arithmetic")

up = classes.get("upload_ok") or {}
check("8 uploads in the window", up.get("count") == 8, up)
check("max gap is 7262 s (about 2 h 01 min)", up.get("max_gap_s") == 7262,
      up.get("max_gap_s"))
check("last upload 19:02:51", up.get("last") == "2026-10-07T19:02:51Z")
check("NoSuchKey never becomes an error",
      "unclassified" not in classes or
      not classes["unclassified"].get("count"))


# --------------------------------------------------------------------------
print("\nstalled sidecar: WARN at 4 h, CRIT with a 3-day-old baseline")


def sidecar_bundle(upload_ok_last, window_to="2026-10-07T19:20:00Z",
                   args_lvl=None, retention=None):
    pargs = {"log.level": args_lvl} if args_lvl else {}
    prom = {}
    if retention:
        prom = {"storage.tsdb.retention.time": retention}
    pod = {"pod": "prom-0", "node": "kub-a9", "container": "thanos-sidecar",
           "started_at": "2026-09-30T08:11:02Z", "restart_count": 0,
           "last_termination": None, "args": pargs, "coverage": "complete",
           "truncated": False}
    if retention:
        pod["also_args"] = {"prometheus": prom}
    up = {"kind": "success", "count": 4, "max_gap_s": 7200}
    if upload_ok_last:
        up["last"] = upload_ok_last
    else:
        up["count"] = 0
    return facts({
        "k8s.log.thanos_sidecar.status": "ok",
        "k8s.log.thanos_sidecar.pods": [pod],
        "k8s.log.thanos_sidecar.window_from": "2026-10-06T19:20:00Z",
        "k8s.log.thanos_sidecar.window_to": window_to,
        "k8s.log.thanos_sidecar.coverage": "complete",
        "k8s.log.thanos_sidecar.class.upload_ok": up,
        "k8s.log.thanos_sidecar.class.uploads_disabled":
            {"kind": "state", "present": False},
    })


b = sidecar_bundle("2026-10-07T15:20:00Z")   # 4 h ago
rules_logs.derive(b)
fs = rules_logs.r_thanos_sidecar(b)
stalled = [f for f in fs if f["id"] == "THANOS_UPLOAD_STALLED"]
check("4 h without upload -> THANOS_UPLOAD_STALLED", len(stalled) == 1, fs)
check("stall is a WARN on day one", stalled[0]["severity"] == "warn")
check("it escalates after 2 days",
      stalled[0].get("escalate_after_days") == 2)

now_iso = "2026-10-07T19:20:00Z"
prev = {"THANOS_UPLOAD_STALLED": {"first_seen": "2026-10-04T19:20:00Z",
                                  "severity": "warn", "metric": 4.0,
                                  "evidence": ["k_log_thanos_sidecar"]}}
findings, resolved, carried = rules.apply_lifecycle(
    list(stalled), prev, now_iso, observed={"k_log_thanos_sidecar"})
check("first_seen 3 days old with a 2-day limit -> CRIT",
      findings[0]["severity"] == "crit" and findings[0]["state"] == "escalating",
      (findings[0]["severity"], findings[0]["state"]))


# --------------------------------------------------------------------------
print("\ndata loss under 24 h away -> CRIT immediately")

b = sidecar_bundle("2026-10-07T15:20:00Z", retention="24h")
rules_logs.derive(b)
check("short retention parsed from the prometheus args",
      b["facts"]["k8s.log.thanos_sidecar.retention_days"]["value"] == 1.0)
fs = rules_logs.r_thanos_sidecar(b)
stalled = [f for f in fs if f["id"] == "THANOS_UPLOAD_STALLED"]
check("stalled with data loss inside 24 h -> CRIT at once",
      stalled and stalled[0]["severity"] == "crit",
      [f["severity"] for f in stalled])


# --------------------------------------------------------------------------
print("\n--log.level=warn says 'not observable', not 'stalled'")

b = sidecar_bundle(None, args_lvl="warn")
rules_logs.derive(b)
fs = rules_logs.r_thanos_sidecar(b)
check("heartbeat invisible at warn level -> cannot-see item",
      any(f["id"] == "KAREL_LOG_SUCCESS_NOT_OBSERVABLE:thanos_sidecar"
          for f in fs), [f["id"] for f in fs])
check("no false stall alarm from an invisible heartbeat",
      not any(f["id"] == "THANOS_UPLOAD_STALLED" for f in fs))


# --------------------------------------------------------------------------
print("\na halt line logged 3 days before the window halts the compactor NOW")

cfg = json.load(open(os.path.join(ROOT, "config", "log-checks.json")))
ag = logscan.Aggregator(cfg["checks"]["thanos_compactor"],
                        since=NOW, now=NOW)      # window excludes the line
ag.feed("2026-10-04T05:00:00.000000000Z level=info ts=x caller=main.go "
        "msg=\"critical error detected; halting\"")
classes, _ig = ag.finalize()
h = classes.get("halted") or {}
check("state rules see the whole log, window or not", h.get("present") is True)

b = facts({
    "k8s.log.thanos_compactor.status": "ok",
    "k8s.log.thanos_compactor.pods":
        [{"pod": "cmp-0", "container": "thanos-compactor",
          "coverage": "complete", "restart_count": 0, "args": {}}],
    "k8s.log.thanos_compactor.window_from": "2026-10-06T00:00:00Z",
    "k8s.log.thanos_compactor.window_to": "2026-10-07T19:20:00Z",
    "k8s.log.thanos_compactor.class.halted":
        {"kind": "state", "present": True, "present_in": ["current"],
         "last": "2026-10-04T05:00:00Z"},
})
fs = rules_logs.r_thanos_compactor(b)
check("THANOS_COMPACTOR_HALTED is CRIT for a current container",
      any(f["id"] == "THANOS_COMPACTOR_HALTED" and f["severity"] == "crit"
          for f in fs), [(f["id"], f["severity"]) for f in fs])


# --------------------------------------------------------------------------
print("\ncompactor: stale loop detected, silence is 'not observable'")


def compactor_bundle(iter_last, args_wait=True, started="2026-09-30T08:00:00Z"):
    cls = {"kind": "success", "count": 4 if iter_last else 0}
    if iter_last:
        cls["last"] = iter_last
    return facts({
        "k8s.log.thanos_compactor.status": "ok",
        "k8s.log.thanos_compactor.coverage": "complete",
        "k8s.log.thanos_compactor.window_to": "2026-10-07T19:20:00Z",
        "k8s.log.thanos_compactor.pods":
            [{"pod": "cmp-0", "container": "thanos-compactor",
              "coverage": "complete", "restart_count": 0,
              "started_at": started,
              "args": {"wait": True} if args_wait else {}}],
        "k8s.log.thanos_compactor.class.iteration_ok": cls,
        "k8s.log.thanos_compactor.class.halted": {"kind": "state",
                                                  "present": False},
    })


b = compactor_bundle("2026-10-07T14:20:00Z")   # 5 h old, wait 1 h -> stale
fs = rules_logs.r_thanos_compactor(b)
check("last iteration 5 h old with 1 h wait -> THANOS_COMPACTOR_STALE",
      any(f["id"] == "THANOS_COMPACTOR_STALE" for f in fs), fs)

b = compactor_bundle("2026-10-07T18:20:00Z")   # fresh heartbeat
fs = rules_logs.r_thanos_compactor(b)
check("a fresh heartbeat is silent",
      not any(f["id"] == "THANOS_COMPACTOR_STALE" for f in fs))

b = compactor_bundle(None)                     # no success line ever
fs = rules_logs.r_thanos_compactor(b)
check("no success line, complete coverage -> success not observable",
      any(f["id"] == "KAREL_LOG_SUCCESS_NOT_OBSERVABLE:thanos_compactor"
          for f in fs), fs)


# --------------------------------------------------------------------------
print("\nULID creation times (spec vectors)")

check("01KYNCB25N is 2026-07-28 22:08:20 UTC",
      logscan.iso_z(logscan.ulid_time("01KYNCB25N0000000000000000"))
      == "2026-07-28T22:08:20Z")
check("01JACMDMPS is 2024-10-17 07:00:08 UTC",
      logscan.iso_z(logscan.ulid_time("01JACMDMPS0000000000000000"))
      == "2024-10-17T07:00:08Z")


# --------------------------------------------------------------------------
print("\ncoverage: partial start, truncation, no pods, missing container")

COLLECT = os.path.join(ROOT, "bin", "collect_logs.py")
FAKE = os.path.join(ROOT, "tests", "fixtures", "fake_kubectl_pods.json")
calls_log = os.path.join(os.path.dirname(FIX), "kubectl-calls.jsonl")


def run_collect(scenario, *extra):
    env = dict(os.environ)
    env["PATH"] = os.path.join(ROOT, "tests", "fakebin") + ":" + env["PATH"]
    env["FAKE_KUBECTL_SCENARIO"] = scenario
    env["FAKE_KUBECTL_CALLS"] = calls_log
    if os.path.exists(calls_log):
        os.unlink(calls_log)
    r = subprocess.run([sys.executable, COLLECT, "--check", "thanos_sidecar",
                        "--since", "2026-10-06T19:20:00Z",
                        "--now", "2026-10-07T19:20:00Z",
                        "--limit-bytes", "400"] + list(extra),
                       capture_output=True, text=True, env=env, timeout=60)
    return r


POD = {"items": [{
    "metadata": {"name": "prom-0", "namespace": "cattle-monitoring-system"},
    "spec": {"nodeName": "kub-a9", "containers": [
        {"name": "prometheus", "args": ["--storage.tsdb.retention.time=720d"]},
        {"name": "thanos-sidecar", "args": ["--log.level=info"]}]},
    "status": {"containerStatuses": [
        {"name": "prometheus", "restartCount": 0,
         "state": {"running": {"startedAt": "2026-10-06T08:00:00Z"}}},
        {"name": "thanos-sidecar", "restartCount": 0,
         "state": {"running": {"startedAt": "2026-10-07T12:00:00Z"}}}]}}]}


def scenario(pods, log_file=None, log_rc=0, log_stderr=""):
    sc = {"calls": [{"argv_contains": ["get", "pods"],
                     "stdout": json.dumps(pods)}]}
    if log_file is not None:
        sc["calls"].append({"argv_contains": ["logs"],
                            "stdout_file": log_file,
                            "stderr": log_stderr, "rc": log_rc})
    d = os.path.dirname(FIX)
    path = os.path.join(d, "scenario.json")
    with open(path, "wt") as fh:
        json.dump(sc, fh)
    return path


sid = scenario(POD, os.path.join(FIX, "thanos_sidecar_2026-10-07.log"))
r = run_collect(sid)
doc = json.loads(r.stdout)
pods = doc["pods"]
check("container started inside the window -> coverage partial",
      pods[0].get("coverage") == "partial" and
      "started inside" in (pods[0].get("coverage_reason") or ""), pods)
big_log = "x" * 900 + "\nlevel=info msg=\"upload new block\" id=01J\n"
lp = os.path.join(os.path.dirname(FIX), "biglog.txt")
with open(lp, "wt") as fh:
    fh.write(big_log * 30)
sid = scenario(POD, lp)
r = run_collect(sid)
pod = json.loads(r.stdout)["pods"][0]
check("--limit-bytes hit -> truncated", pod.get("truncated") is True,
      pod.get("coverage_reason"))

sid = scenario({"items": []})
r = run_collect(sid)
doc = json.loads(r.stdout)
check("zero matching pods is status no_pods, exit 0",
      doc["status"] == "no_pods" and r.returncode == 0)
b = facts({"k8s.log.checks": ["thanos_sidecar"],
           "k8s.log.thanos_sidecar.status": "no_pods",
           "k8s.log.thanos_sidecar.expect_pods": True,
           "k8s.log.thanos_sidecar.namespace": "cattle-monitoring-system",
           "k8s.log.thanos_sidecar.selector": "app=prometheus"})
fs = rules_logs.r_log_check_health(b)
check("no_pods with expect_pods -> KAREL_LOG_NO_PODS warn",
      any(f["id"] == "KAREL_LOG_NO_PODS:thanos_sidecar"
          and f["severity"] == "warn" for f in fs), fs)

POD_NO_SC = {"items": [dict(POD["items"][0])]}
POD_NO_SC["items"][0] = json.loads(json.dumps(POD["items"][0]))
del POD_NO_SC["items"][0]["spec"]["containers"][1]
del POD_NO_SC["items"][0]["status"]["containerStatuses"][1]
sid = scenario(POD_NO_SC)
r = run_collect(sid)
doc = json.loads(r.stdout)
check("missing container is reported, not silent",
      any(p.get("container_missing") for p in doc["pods"]), doc["pods"])
b = facts({"k8s.log.checks": ["thanos_sidecar"],
           "k8s.log.thanos_sidecar.status": "ok",
           "k8s.log.thanos_sidecar.namespace": "cattle-monitoring-system",
           "k8s.log.thanos_sidecar.selector": "x",
           "k8s.log.thanos_sidecar.pods":
               [{"pod": "prom-0", "container": "thanos-sidecar",
                 "container_missing": True, "coverage": "none"}]})
fs = rules_logs.r_log_check_health(b)
check("missing container -> KAREL_LOG_CONTAINER_MISSING warn",
      any(f["id"] == "KAREL_LOG_CONTAINER_MISSING:thanos_sidecar"
          for f in fs), fs)


# --------------------------------------------------------------------------
print("\ncredentials are masked in samples")

s = logscan.redact('Put "https://minio/b?X-Amz-Credential=AKIAIOSFODNN7EXAM'
                   'PLE%2F20261007&X-Amz-Signature=1a2b3c4d5e6f7a8b9c0d1e2f'
                   '3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f" '
                   'Authorization: Bearer abcdef0123456789xyz '
                   's3://user:secretpw@host/bucket')
for needle in ("AKIAIOSFODNN7EXAMPLE", "1a2b3c4d", "abcdef0123456789xyz",
               "secretpw", "3a4b5c6d"):
    check("masked %s" % needle[:12], needle not in s, s)


# --------------------------------------------------------------------------
print("\nFleet SSA conflicts: manager + path extracted, 409 ignored, "
      "repetition counts once")

classes, ignored = classify("fleet_agent", "fleet_agent_ssa.log",
                            since=logscan.parse_ts("2026-10-06T00:00:00Z"), now=NOW)
ssa = classes.get("ssa_conflict") or {}
check("conflict lines classified (logfmt AND zap JSON)",
      ssa.get("count") == 2, classes)
check("the resourceVersion race is just counted",
      ignored.get("conflict_retry") == 1, ignored)
mgrs = {(e["entry"] or {}).get("manager") for e in ssa.get("entries") or []}
check("field managers extracted from both log formats",
      mgrs == {"kubectl-client-side-apply", "agent"}, mgrs)
paths = {((e["entry"] or {}).get("path") or "") for e in ssa.get("entries") or []}
check("field paths extracted",
      {".spec.replicas", ".spec.template.metadata.labels",
       ".spec.template.spec.containers[name=\"sglang\"].command"} == paths, paths)
check("no path bleeds across the ' && ' conflict boundary",
      not any("&&" in p for p in paths), paths)
objs = sorted((ssa.get("extracted") or {}).get("object") or [])
check("conflicted objects named from 'applying object ns/name'",
      objs == ["vllm-ns/qwen3-embedding-4b-vllm",
               "vllm-ns/qwen3-reranker-4b-vllm"], objs)

line = open(os.path.join(FIX, "fleet_agent_ssa.log")).readline()
cfg = json.load(open(os.path.join(ROOT, "config", "log-checks.json")))
ag = logscan.Aggregator(cfg["checks"]["fleet_agent"],
                        since=logscan.parse_ts("2026-10-07T00:00:00Z"), now=NOW)
for _i in range(100):
    ag.feed(line)
classes, _ig = ag.finalize()
n_entries = len((classes.get("ssa_conflict") or {}).get("entries") or [])
check("the same conflict 100 times is 1-2 distinct pairs, not 100",
      n_entries <= 2, n_entries)


# --------------------------------------------------------------------------
print("\nfake kubectl: the collector asks for exactly the right logs")

POD_RT = json.loads(json.dumps(POD))
POD_RT["items"][0]["status"]["containerStatuses"][1]["restartCount"] = 2
POD_RT["items"][0]["status"]["containerStatuses"][1]["lastState"] = {
    "terminated": {"reason": "Error", "exitCode": 1,
                   "finishedAt": "2026-10-07T11:59:00Z"}}
sid = scenario(POD_RT, os.path.join(FIX, "thanos_sidecar_2026-10-07.log"))
r = run_collect(sid)
doc = json.loads(r.stdout)
calls = [json.loads(l) for l in open(calls_log)]
log_calls = [c for c in calls if c and c[0] == "logs"]
check("logs fetched with --timestamps",
      all("--timestamps" in c for c in log_calls), log_calls)
check("logs fetched with --limit-bytes",
      all(any(a.startswith("--limit-bytes=") for a in c) for c in log_calls))
check("logs fetched per-container",
      any("thanos-sidecar" in c for c in log_calls), log_calls)
check("--previous fetched when restart count > 0",
      any("--previous" in c for c in log_calls), log_calls)
check("last termination is in the pod entry",
      (doc["pods"][0].get("last_termination") or {}).get("exit_code") == 1,
      doc["pods"])

sid = scenario(POD, os.path.join(FIX, "thanos_sidecar_2026-10-07.log"))
r = run_collect(sid)
calls = [json.loads(l) for l in open(calls_log)]
check("no --previous when the container never restarted",
      not any("--previous" in c for c in calls if c and c[0] == "logs"))


# --------------------------------------------------------------------------
print("\nquerier store-gateway detection across arg forms")

import collect_logs    # noqa: E402

check("--k=v, --k v and repeated flags all parse",
      collect_logs.parse_args_list([
          "--http-address=0.0.0.0:19191",
          "--endpoint", "prometheus-operated:10901",
          "--log.level=info", "--wait",
          "--endpoint", "thanos-store:10901"]) == {
          "http-address": "0.0.0.0:19191",
          "endpoint": ["prometheus-operated:10901", "thanos-store:10901"],
          "log.level": "info", "wait": True})


def querier_bundle(args):
    return facts({
        "k8s.log.thanos_querier.status": "ok",
        "k8s.log.thanos_querier.window_from": "2026-10-07T00:00:00Z",
        "k8s.log.thanos_querier.window_to": "2026-10-08T00:00:00Z",
        "k8s.log.thanos_querier.pods":
            [{"pod": "q-1", "container": "thanos-querier",
              "coverage": "complete", "restart_count": 0, "args": args}],
    })


b = querier_bundle({"endpoint": ["prometheus-operated:10901",
                                 "thanos-store:10901"]})
check("store gateway present -> no NO_STORE_GATEWAY finding",
      not any(f["id"] == "THANOS_QUERIER_NO_STORE_GATEWAY"
              for f in rules_logs.r_thanos_querier(b)))
b = querier_bundle({"endpoint": "prometheus-operated:10901"})
check("only the sidecar endpoint -> the finding fires",
      any(f["id"] == "THANOS_QUERIER_NO_STORE_GATEWAY" for f in
          rules_logs.r_thanos_querier(b)))


finish()
