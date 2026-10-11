# Karel — a daily Kubernetes cluster report

Karel collects a fixed set of facts from the Kubernetes API (and optionally from
Prometheus), evaluates a deterministic rule set against them, and writes a
Markdown report that is meant to be emailed. It is read-only and never acts on
the cluster. There is no LLM in the deterministic layer: every claim in the
report is arithmetic over collected facts.

The report has one job: make a reader notice, in a two-minute skim, the handful
of things that actually need a human today — and make it impossible to mistake
"I could not see" for "nothing was wrong".

## Layout in the image

```
/opt/karel/
├── bin/
│   ├── run.sh                 top-level runner (plan → collect → analyse → persist)
│   ├── run-plan.sh            execute plan.tsv, record per-command status
│   ├── apiserver_metrics.py   whitelist a few dozen numbers from /metrics
│   ├── probe_tls.py           apiserver serving-cert expiry probe
│   ├── probe_acme.py          resolve ACME challenge dnsNames vs ingress targets
│   ├── collect_logs.py        run one log check; aggregate in the collector
│   ├── collect_events.py      one filtered, bounded events pass (daily k_events)
│   ├── collect_usage.py       k8s-pod-resource-usage wrapper (CPU/GPU waste)
│   ├── event_buffer.py        CronJob: accumulate filtered events per day
│   ├── fetch_event_buffer.py  read today's + yesterday's event buffers
│   ├── prom_query.py          Prometheus/Alertmanager collector
│   ├── validate_narrative.py  flag narrative numbers with no fact path
│   └── karel-ack.sh           manage the suppression ledger
├── lib/
│   ├── pipeline.py            bundle → findings → report; the CLI entry point
│   ├── normalize.py           generic raw-collector-output → flat fact bundle
│   ├── normalize_k8s.py       Kubernetes parsers (the only shape knowledge)
│   ├── normalize_prom.py      Prometheus facts + rules
│   ├── logscan.py             log line parsing, classification, redaction, ULIDs
│   ├── events_collect.py      server-side filtered event requests + aggregation
│   ├── rules.py               structural rules + finding lifecycle/ranking
│   ├── rules_k8s.py           Kubernetes control-plane/workload/storage rules
│   ├── rules_logs.py          Fleet SSA + Thanos sidecar/compactor/querier rules
│   ├── rules_gpu.py           GPU health + upgrade state + node-versions table
│   ├── housekeeping.py        abandoned objects: derive, rules, md/csv writers
│   ├── rules_headroom.py      node-loss simulation + counter deltas
│   ├── rules_maintenance.py   settings a human switched off and forgot
│   ├── report.py              Markdown renderer
│   └── suppress.py            suppression ledger
├── config/
│   ├── k8s-commands.json      the collectable commands and their tiers
│   ├── log-checks.json        one log check per workload: patterns and kinds
│   └── prom-queries.json      the PromQL queries and their windows
└── deploy/event-buffer.yaml   RBAC + CronJob for the event buffer
```

## Environment

| variable | default | meaning |
| --- | --- | --- |
| `KAREL_HOME` | directory above `bin/run.sh` | image root (`/opt/karel` in the image, the checkout when run by hand); substituted for `${KAREL_HOME}` in manifest argv |
| `WORK` | `/tmp` | scratch space |
| `OUT` | `/tmp/out` | collector output **and** report directory |
| `OUT_PROM` | `/tmp/out-prom` | Prometheus collector output |
| `KAREL_NS` | `ai-karel-ns` | namespace holding the suppression ledger and event-buffer ConfigMaps |
| `KAREL_STATE_DIR` | `/home/ubuntu-persistent/new-reports/state` | where the snapshot and housekeeping state live as plain-JSON files (archives under `archive/`) |
| `STATE_CM` | `karel-state-latest` | legacy snapshot ConfigMap, read once for migration only |
| `SUPPRESS_CM` | `karel-suppressions` | suppression ledger (also `usage_exclude` rows, see below) |
| `K8S_MANIFEST` | `/etc/karel/k8s-commands.json`, else `$KAREL_HOME/config/` | command manifest |
| `BUDGET` | `600` | collection budget, seconds, main pass |
| `USAGE_BUDGET` | `1800` | budget for the parallel usage pass (tier ≥ 8) |
| `KAREL_ACME_EXPECTED_TARGETS` | ingress LB addresses | comma-separated override for the ACME DNS probe targets |
| `KAREL_ACME_INGRESS_NS` | `ingress-nginx` | namespace the NetworkPolicy check must admit |
| `KAREL_DEMO_IMAGES` | `paulbouwer/hello-kubernetes` | comma-separated demo images for `demo_workload` |
| `KAREL_USAGE_BIN` | `k8s-pod-resource-usage` | binary for the usage pass |
| `KAREL_USAGE_TIMEOUT_CPU/GPU` | `1200`/`600` | per-resource timeouts for the usage pass |
| `SUPPRESSIONS_FILE` | `/tmp/suppressions.json` | ledger file the usage wrapper reads for `usage_exclude` |
| `PROM_ENABLED` | `1` | set `0` to skip Prometheus entirely |
| `PROM_URL` | rancher-monitoring service | Prometheus base URL |
| `ALERTMANAGER_URL` | rancher-monitoring service | Alertmanager base URL |
| `KAREL_NODE_SCOPED_APPS` | empty | comma-separated apps that live on one node by design |
| `KAREL_PLATFORM_NAMESPACES` | empty | comma-separated globs ADDED to the built-in platform namespaces (see below); for CERIT e.g. `beegfs,env-injector,clusterwide-*` |
| `KAREL_SINCE` | set by `run.sh` | start of the log/event window: the previous snapshot's `collected_at`, else now−26h, capped at 48h |
| `KAREL_LOG_LIMIT_BYTES` | `20971520` (20 MiB) | per-container log fetch limit for `collect_logs.py` |
| `KAREL_LOG_CHECKS` | `$KAREL_HOME/config/log-checks.json` | where the log-check patterns live |
| `KAREL_NODE_TARGETS` | empty | JSON of target versions per component (`{"gpu_driver": "550.90.07"}`); majority rules when unset |
| `KAREL_KEEP_ANNOTATION` | `karel.cerit-sc.cz/keep` | annotation that marks an object (or whole namespace) as deliberately kept |
| `KAREL_HOUSEKEEPING_STATE_CM` | `karel-housekeeping-state` | legacy ConfigMap for the age tracking (read once for migration; the live store is `$KAREL_STATE_DIR/housekeeping-state.json`) |

## RBAC needed beyond the `view` binding

* `pods/log` — only if you collect log-derived facts (the stock `view`
  ClusterRole grants this).
* `nodes` — already in `view`.
* Ingresses and HPAs (`networking.k8s.io`, `autoscaling`) — `view` covers both.
* `clusterpolicies.nvidia.com` may NOT aggregate into `view`: the manifest
  marks `k_clusterpolicy` `expected_status: eacces`, so a denied or missing
  CRD is not a fault. If you want the GPU-operator rollcall, add a
  ClusterRole rule for it and remove the `expected_status`.
* ConfigMap `get`/`create`/`update` in `KAREL_NS` for state, suppressions and
  the housekeeping age tracking.

The event buffer runs under its own ServiceAccount (see
`deploy/event-buffer.yaml`) because it writes and should not inherit Karel's
cluster-wide read. It additionally needs `namespaces` `list` (platform
namespace discovery) — the bundled ClusterRole has it.

## CronJob notes

Run Karel once a day from a plain CronJob. Three things matter:

* `activeDeadlineSeconds` must exceed `BUDGET`.
* `restartPolicy: Never`, `backoffLimit: 0` — a retry storm against a sick
  apiserver is exactly what you do not want.
* Keep `concurrencyPolicy: Forbid`: two runs writing the same state ConfigMap
  will lose one of them.

## Exit codes

* `0` — a report was written, whatever it says.
* `2` — no report could be written at all. This is a Karel failure and is the
  one thing you should alert on.

## Testing without a cluster

`tests/make_k8s_fixture.py <dir> [healthy|degraded]` writes a synthetic
collector output directory. Then:

```sh
python3 lib/pipeline.py --out /tmp/out --prom-out /tmp/out-prom \
    --prev /dev/null --suppressions /dev/null --report /tmp/report.md
```

To iterate on rules against REAL data without re-collecting, replay a saved
`bundle.json` (every run writes one):

```sh
python3 lib/pipeline.py --from-bundle out/bundle.json --out /tmp/replay \
    --prev /dev/null --suppressions /dev/null \
    --bundle /tmp/replay/bundle.json --snapshot /tmp/replay/snapshot.json \
    --report /tmp/replay/report.md
```

Derived facts (platform/tenant split, headroom) are recomputed on replay. Facts
a newer parser would record are simply absent from an older bundle, and the
rules treat them as unknown, not as zero.

Everything runs through `tests/run_all.py` (or file by file):

```sh
python3 tests/run_all.py            # all suites + --from-bundle replay + pyflakes
python3 tests/test_regressions.py   # the original false-positive suite
python3 tests/test_logs.py          # log collector + Fleet/Thanos rules
python3 tests/test_events.py        # filtered events, burst survival, patterns
python3 tests/test_gpu.py           # GPU health + upgrade state + node versions
python3 tests/test_housekeeping.py  # exclusions, state, keep annotation, csv, ages
python3 tests/test_acme.py          # ACME solver + certificate checks
python3 tests/test_usage.py         # waste wrapper + parse rules + section
python3 tests/test_gateway.py       # Gateway API checks
python3 tests/test_failed_recent.py # recent Failed pods tenant row
python3 tests/test_ai_contract.py   # external slots, failing pods, validator
python3 tests/fuzz.py               # rule invariants under mutated bundles
python3 tests/consistency.py        # encoded state size, tenant arithmetic, determinism
```

`fuzz.py` mutates every `k_*` command (dropped/failed/emptied/truncated),
takes nodes NotReady, makes Prometheus unreachable and deletes the
housekeeping ConfigMap, and re-checks the invariants on each: no rule
raises, findings keep shape, evidence cites only collected commands, the
report renders rectangular, snapshots serialise, evaluations are
deterministic, and a dead source is never quiet. Real log samples are
fixtures under `tests/fixtures/logs/`; collector behaviour against a cluster
is faked by `tests/fakebin/kubectl`, a scenario-driven stand-in that also
records every call for assertions.

## Invariants that must not be broken

1. **A missing fact is ABSENT, not zero.** Rules read facts with a default of
   `None`; they never coerce a missing value to `0`.
2. **A parse failure never kills the run.** `_ingest` records
   `parse_ok=False` and moves on.
3. **Silence is not health.** Every collector records its own completeness, and
   a source that produced no output directory is recorded, not skipped.
4. **Karel never acts.** Remediation text is a proposal for a human.
5. **Absence of a finding is not evidence of health** when collection was
   incomplete; the report says so explicitly.

## Collection

Karel runs two collectors:

* **Kubernetes** (`config/k8s-commands.json`) — one `kubectl` invocation per
  command, each with a tier and a timeout. Tier 1 commands are the
  degraded-mode evidence that must survive a broken cluster; tier 3 is bulk
  (CRDs, large dumps). A command's exit status is recorded per command, and
  an optional `expected_status` stops a legitimately-denied resource being
  reported as a fault.
* **Prometheus** (`config/prom-queries.json`) — instant PromQL queries whose
  time-window work is pushed into PromQL (`max_over_time`, `predict_linear`,
  `increase`, `changes`) so the collector stays trivial. Each query declares
  the history it needs (`window_days`); if Prometheus retention is shorter the
  result is *suppressed*, not caveated.

Both collectors are independent. A broken Prometheus does not make Kubernetes
findings unresolvable, and vice versa.

### `index.tsv` and completeness

`run-plan.sh` writes one `index.tsv` row per command: name, return code,
duration, tier, status, size, timeout. It writes a `COMPLETE` sentinel only
after reaching the end of the plan, so a missing sentinel means an early exit —
which the report names as a failing source rather than silently accepting.

## Report format

### Escaping

Cluster output is full of Markdown metacharacters: `kube-system`, `kubectl get`,
`--connect-timeout`, `<flag>`. Technical tokens are wrapped in backticks (which
disables Markdown inside them); only the remainder is escaped. Machine output
is put in a fenced block, where nothing needs escaping at all.

### Tables

The report is emailed and often read as plain text, so tables are column-padded
to stay readable unrendered.

### Grouping

Findings that carry the same `group_key` are folded at render time into one
entry that names the peers. Identity stays per-subject so day-over-day
lifecycle is stable — only the presentation collapses. Detail lines that differ
only in generated pod-name suffixes or node names (ten pods of one DaemonSet)
are folded too.

When findings disappear after the rule set changed, they are listed under
**No longer reported**, grouped by code — never under "Resolved".

## Suppression ledger

The answer to "this is intentional for now" is not to hide it. Karel keeps a
reviewable ledger (ConfigMap `karel-suppressions`) where every entry has a
reason, an author and an expiry:

```json
{"suppressions": [
  {"id": "K8S_DEPLOYMENT_PAUSED:app/api", "until": "2026-12-31",
   "reason": "rollout paused deliberately during a migration", "by": "ops"},
  {"pattern": "K8S_SCALED_TO_ZERO:*", "until": "permanent",
   "reason": "these workloads are intentionally idle", "by": "platform"}
]}
```

Suppressed findings are **listed, never deleted**. Expired, malformed,
unused and permanent entries are each reported every run, because a suppression
nobody re-reads is how a real problem disappears.

`bin/karel-ack.sh {list|add|rm}` manages the ledger.

## Lifecycle and the ruleset fingerprint

A finding's identity is its `id` (`CODE` or `CODE:subject`). Each run assigns
`new`, `open` or `escalating`, computes `days_open`, and detects a rising metric.
Two details worth knowing:

* A finding is only declared **resolved** if the evidence source that would have
  detected it actually produced data this run. Otherwise it is carried forward
  as "not observable" — absence is not a fix.
* Karel hashes the **body** of every active rule, not just its name, into a
  `ruleset` fingerprint stored in the snapshot. If the rule set changed between
  runs, findings that disappeared are not reported as resolved: *"we stopped
  looking" is not "it was fixed".*

## Log checks

`bin/collect_logs.py --check <name>` runs one entry from
`config/log-checks.json`: resolve the workload's pods by namespace + label
selector (never by pod name — a StatefulSet and a Deployment select the same
way), fetch each container's current log (plus `--previous` after restarts),
classify every line in order (explicit rules first, then a catch-all for
`level=error` or any `err` field), and aggregate **in the collector**. Raw
log lines never reach disk, the bundle or the report: what crosses the wire is
counts, first/last timestamps, distinct extracted objects and at most three
redacted samples per class. Rules live in the config file so ops can tune
patterns without a code change.

Three kinds guard meaning, not just pattern matching:

* **success** — a heartbeat counted in the window (`upload new block`). Its
  absence is never silently read as health: it becomes "not observable"
  (listed under *What this report cannot see*) when the log level or coverage
  can explain the silence, and a stall finding otherwise.
* **state** — presence over the whole fetched log, because
  `critical error detected; halting` is logged once and may predate the
  window.
* **ignore** with `require_followed_by` — the retention stat race
  (`stat block … no such file`) is dropped only when an upload follows within
  300 s; otherwise it reclassifies as `block_missing`.

Window starts come from `KAREL_SINCE` (previous snapshot, default now−26h,
capped at 48h); per-container logs are bounded by `KAREL_LOG_LIMIT_BYTES`.
Coverage (`complete` / `partial` / `none`, with the reason) is reported per
container and folded into the Collection section.

Today the checks are: Fleet agent SSA conflicts (`K8S_FLEET_SSA_CONFLICT`,
one finding per competing field manager), Thanos sidecar/compactor/querier
(`THANOS_*` — see below) and the GPU crash classes. Selectors and message
texts that could not be confirmed against a real cluster sample are marked
`_note: CONFIRM` in `log-checks.json`; the catch-all (`unclassified`) keeps
them loud until a real sample tunes the pattern.

### Thanos: the 20-day outage detector

The sidecar upload heartbeat is the core check. Derived per day: uploads in
the window, last-upload age, largest gap, newest shipped block (decoded from
its ULID), retention and block duration from the Prometheus container's args,
and the local data-loss deadline (`oldest unshipped block + retention`).

* no upload beyond `block duration + 1h` → `THANOS_UPLOAD_STALLED` (WARN on
  day one, CRIT after 2 days, CRIT at once when the data-loss deadline is
  under 24h away);
* `uploads_disabled` in the log → CRIT;
* S3 errors are classed (`auth`, `quota`, `clock`, `bucket`, `tls`,
  `network`, `other`) — WARN except transient `network` while uploads
  continue (`NoSuchKey` during deletion-mark cleanup is normal and never
  counted);
* compactor: `critical error detected; halting` → CRIT; a compaction/S3
  error or a non-zero exit → WARN escalating after 3 days (the title names
  the parsed chain, e.g. "compactor: retention cannot write to the bucket
  (Access Denied)").

## Events

Kubernetes Events expire after the apiserver `--event-ttl` (1h by default), so
a naive daily `kubectl get events -A` sees the last hour of a 24-hour window —
and on a burst day it sees 32,000 objects (17 s, 2026-10-07). Collection is
therefore split into a few **server-side filtered** requests, shared by the
15-minute buffer CronJob and the daily run (`lib/events_collect.py`):

1. **node events** — `involvedObject.kind=Node`, all types (`NodeNotReady`
   is a Normal event; filtering Warning would lose the most important ones).
   Node keys are never truncated.
2. **platform warnings** — `type=Warning`, one request per platform
   namespace; pod names collapse to owner names (ReplicaSet hash and pod
   suffix go, StatefulSet ordinals stay), keys capped at 600 with the drop
   recorded.
3. **tenant patterns** — `reason=<R>,type=Warning` for a fixed suspect list
   (`FailedCreatePodSandBox` → CNI, `FailedMount`/`FailedAttachVolume` → CSI,
   `ProvisioningFailed` → provisioner, `FailedScheduling` → capacity,
   `Evicted` → node pressure), aggregated to counts and namespaces, platform
   namespaces excluded so nothing counts twice.

A pattern reason in ≥ 10 tenant namespaces is `K8S_TENANT_EVENT_PATTERN`
("FailedCreatePodSandBox in 40 tenant namespaces — CNI suspected"); below the
threshold it is a row in the tenant summary, never an alarm. Aggregation is
per event object (max of its cumulative count), then summed per key — event
counters only rise while a condition lasts, so findings key on distinct
reasons, not totals.

The buffer CronJob merges each pass into a per-day ConfigMap with a `_meta`
block per write (written-at, per-request status, dropped counts). A stopped
or partially denied CronJob is `KAREL_EVENT_BUFFER_STALE` under *What this
report cannot see*, and the Collection section carries one line: "events:
buffered, 96 of 96 writes" vs "events: live TTL window only". Output is meant
to survive a 30,000-event tenant burst within the CronJob's memory limit —
items are streamed off the wire text, not parsed wholesale (test asserts
peak RSS below 128 MiB).

## GPU health and node versions

Most GPU health needs no new collection: the device plugin shrinks
allocatable below capacity for unhealthy GPUs (`K8S_GPU_UNHEALTHY`), and the
operator's `nvidia.com/*` labels identify GPU nodes before any resource is
advertised (`K8S_GPU_NOT_ADVERTISED`; CRIT once a quarter of GPU nodes are
dark). Both checks treat **full GPUs and MIG slices** (`nvidia.com/mig-*`)
as one health model — a 7-of-6 MIG slice is named explicitly — and a node
serving GPUs **only through DRA** is detected via its ResourceSlices
(`k_resourceslices`) rather than wrongly called dark. The GPU operator's
pods are tracked per node, so a node with a broken stack is one
`K8S_GPU_STACK_DEGRADED` finding — the matching pod-backoff and
DaemonSet entries are folded into it (a crashlog line like `Driver/library
version mismatch` becomes "reboot required to finish driver update"; one
problem is never reported three times). `k_clusterpolicy` adds the operator's
own rollcall when the CRD is readable; driver skew across nodes is
`K8S_GPU_DRIVER_SKEW`.

`K8S_GPU_GFD_STRATEGY` is the one recipe the report can hand out exactly: when
a `gpu-feature-discovery` pod CrashLoopBackOffs and its previous log says
`failed to create resource manager: unsupported strategy auto`, the
nvidia-container-toolkit on **that node** is the broken part, and the finding
names the exact pods to delete (`kubectl -n gpu-operator delete pod
nvidia-container-toolkit-daemonset-…` — GFD then follows on its own). Log
checks attribute every matched error class to the pods and nodes that
produced it, so a node whose GFD fails for a different reason gets no bogus
recipe.

The **Node versions** table (kernel, kubelet/RKE2, containerd, OS image, GPU
driver on GPU nodes) shows each version with its node count, majority first,
and names the laggards: the target is the majority version unless
`KAREL_NODE_TARGETS` pins one. Mid-upgrade mixing is normal; weeks of mixing
means a stuck upgrade (old kernels also carry the old kernel's CVEs —
`K8S_KERNEL_SKEW`).

## Housekeeping: abandoned objects

The cleanup list joins Services, EndpointSlices, workload templates, pods,
PVCs, PVs, namespaces, Ingresses and HPAs into categories — `svc_no_backend`,
`lb_ip_abandoned`, `ingress_backend_missing`, `hpa_target_missing`,
`pvc_unused`, `pv_released`, `ns_empty`, `ns_stuck_terminating`,
`failed_pods_old`, `pod_stuck_terminating`. When 508 of 3,108 Services have
no ready endpoints the exclusions matter more than the join: ExternalName,
services whose pods exist but are broken (a workload finding, not
housekeeping), selectors matching something scaled to zero (counted as idle,
not listed), operator-owned objects, and anything younger than a day.

Every item carries a **confidence** (`certain` / `likely` / `ask`), a reason
and an age; only `certain` items ever get a proposed `kubectl delete` line,
and `pvc_unused` never does, because the object is data. Ages live in the
`karel-housekeeping-state` ConfigMap **keyed by object UID** — a deleted and
recreated object starts at age 0, and an entry is removed only when the
source command collected successfully that run (a collection failure never
resets ages). `karel.cerit-sc.cz/keep: "<reason>"` on an object or its
namespace pulls it into the kept list, out of the backlog count.

The daily report shows the backlog line with the since-last-run delta
("412 items in 97 namespaces; −23 since last week") and one row per category;
the per-item list with costs and ages lands in `out/housekeeping.md` and a
stable-sorted `out/housekeeping.csv`. WARN is reserved for shared impact:
abandoned LoadBalancer IPs holding quota (`K8S_LB_IP_ABANDONED`) and
namespaces stuck Terminating on finalizers
(`K8S_NAMESPACE_STUCK_TERMINATING`).

State lives as **plain JSON files** under `KAREL_STATE_DIR`
(`snapshot.json`, `housekeeping-state.json`, dated copies in `archive/`):
atomic tmp+rename writes, readable with any editor, and a ConfigMap payload
is read once only as the migration path (an oversized ConfigMap write once
failed silently for weeks, and nobody could inspect it; files you can read
back). The save-failure rule (`KAREL_HOUSEKEEPING_STATE_SAVE_FAILED`,
snapshot says items exist, storage file is empty) still fires on a failed
filesystem write; the 70%-of-1-MiB warn on the encoded size remains as the
upstream guard against recreating the oversized object anywhere.
The housekeeping state itself is keyed by object UID and holds only
`{category, first_seen}` per entry — reason, cost and commands are
recomputed every run.

Age has three sources per item: a **recorded transition time** when
Kubernetes has one (`status.lastPhaseTransitionTime` for Released PVs, the
container's `finishedAt` for Failed pods) which is exact and drives
tenant-ready from day one; Karel's own `first_seen`, a lower bound used when
no transition exists; and `creationTimestamp`, context only — an object can
be created years before it becomes orphaned, so creation never decides
tenant-ready. The section footer states the warm-up date; entries show seen
and created side by side.

### Clean checks say they ran; movement is per category

Every housekeeping category and every tenant condition whose source
collected prints a row, even `0 (clean 26 runs)` — "checked, none found" and
"not checked" render differently. Only a source that failed omits the row,
and it is named under *What this report cannot see*. The snapshot tracks
consecutive clean runs, per-category namespace sets, top-5 exchanges,
regressions (a namespace back after disappearing) and persistence
(streaks), rendered per category under the table.

## ACME (cert-manager http-01)

`k_acme_solvers` (solver pods by label), `k_acme_challenges`,
`k_acme_certificates` and `bin/probe_acme.py` (resolves each challenge's
dnsName: NXDOMAIN ≠ SERVFAIL/NODATA ≠ resolves-to-wrong-address, compared
against the ingress LoadBalancer or `KAREL_ACME_EXPECTED_TARGETS`). Findings
in impact order: `ACME_CERT_EXPIRING` (CRIT — expired, or <7 days and not
Ready; solvers are the cause, certificates are the impact), `ACME_SOLVER_DNS`,
`ACME_SOLVER_NETPOL` (deliberately narrow: default-deny with no admit of tcp
8089 from `KAREL_ACME_INGRESS_NS`), `ACME_SOLVER_STALE` (INFO). Solvers are
tenant objects: they also land in the tenant table and housekeeping
(`acme_solver_stale`) with ages.

## Resource waste (CPU and GPU)

`bin/collect_usage.py` wraps `k8s-pod-resource-usage` for `cpu` and `gpu`
(24 h average): the binary's own exit status decides success (a pipe's last
stage once masked a partial failure), partial output is a failed collection,
and the errors are named under *What this report cannot see*. Rows younger
than 12 hours are excluded and counted; "no series" stays distinct from a
measured 0%; GPU rows join to the node's `nvidia.com/gpu.product` label when
the CSV carries no model. Namespace exclusions live in the suppression
ledger (`usage_exclude` entries with author and reason), not in a `grep -v`.
The tier ≥ 8 pass runs
**in parallel** with the k8s pass under `USAGE_BUDGET`, because 1200 s + 600 s
does not fit the main budget. Output: top-20 CPU and top-30 GPU tables as
tenants, never per-pod findings.

One unit trap worth knowing: JupyterHub's gpushare pods request
`nvidia.com/gpu-mem` (GiB of shared GPU *memory*), not whole cards, and the
binary sums that limit into the card column. Karel restores the unit from
the pod spec (`k8s.pod.gpu_requests` breakdown of cards/MIG/gpu-mem GiB) —
a table cell reads `60.0 gpu-mem`, never "60 GPUs".

## Gateway API

`k_gateways` / `k_httproutes`, skipped quietly (and said under *cannot see*)
when the CRDs are absent. `K8S_GATEWAY_NOT_READY` WARNs name the condition
reason; HTTPRoute `Accepted`/`ResolvedRefs=False` parents land in the tenant
table; a route attached to no parent goes to housekeeping
(`gateway_orphaned_route`). A fully healthy plane prints its one line:
`8 Gateways, 45 HTTPRoutes, all accepted`.

## GPU driver upgrade state

"Behind the majority version" and "will be upgraded" are different states.
Classification per GPU node, from the `nvidia.com/gpu-driver-upgrade-state`
label first, the nvupdater log check second: `upgrade-done`/current and
`upgrade-required`/`cordon-required` are counts; `wait-for-jobs-required`,
`pod-deletion-required` and `drain-required` are **blocked** — the nodes AND
the GPU pods holding them are named (`k8s.pod.gpu_users`), with time-in-state
tracked in the housekeeping state ("blocked 14 days"). `upgrade-failed` is
`K8S_GPU_UPGRADE_FAILED` WARN; behind with no state and no updater activity
is `K8S_GPU_UPGRADE_STUCK` WARN.

## The AI contract (P2)

The AI layer narrates; it never sources a number. Karel hands it:

* **External slots**: any `*.json` in `$OUT/external/` (RT, JupyterHub) is
  ingested into `bundle.external` **before** any narrative, with a few
  deterministic facts computed (`external.rt.count`, `...oldest_age_d`,
  `since_requester_d`; the JupyterHub expired-namespace join to present
  namespaces, PVC counts and bytes → `K8S_JUPYTERHUB_CLEANUP` info).
* **Failing-pod facts** (`k8s.pod.failing`): namespace, owner, image split
  registry/repo/tag, waiting and termination reasons, exit code, and the
  message redacted (URL credentials stripped) and truncated to 300 chars.
* **Deterministic pattern groups** that need no model: one image repo
  failing to pull across N namespaces (`K8S_IMAGE_PULL_PATTERN`), floating
  tags on failing pods (`K8S_FLOATING_TAGS`).
* **A validator**: `bin/validate_narrative.py narrative.md bundle.json`
  flags any number in an AI narrative that matches no fact path in the
  bundle, with the line number.

## Prometheus

Prometheus changes what Karel can honestly claim. Without it Karel sees one
instant per day and any trend statement is a two-point extrapolation. With it:

* rates are real (per-instance scraping makes counters comparable);
* peaks are measured (`node_mem_peak_7d`), not inferred from requests;
* transients are visible (a node NotReady at 03:00 and recovered leaves no
  trace in a point-in-time report);
* etcd growth uses `predict_linear` over two weeks.

Two hard rules:

1. Prometheus may be down exactly when its history is wanted. Unreachable is a
   **finding**, never a crash and never silence.
2. **Absence of a metric is not zero.** A query that returns no series means
   "not scraped" or "does not exist on this release", which is different from
   "the value is zero". `empty_means: none` in the manifest marks filtering
   expressions where an empty result is genuinely good news.

Shared-storage note on `K8S_PVC_NEARFULL`: `nfs-csi*` classes are
subdirectories of ONE volume, so every NFS PVC reports (approximately) the
volume's fullness. N identical rows are not N findings - they collapse into
one "shared nfs-csi volume at ~X", with the per-PVC list kept for local
classes (`zfs-csi`, `beegfs-csi`). The housekeeping backlog is where the
occupants to shrink are ranked.

Retention gates everything: `predict_linear` over 14 days computed from 30
minutes of history is not a forecast, and a suppressed number is safer than one
that looks authoritative and is not.

### Linking a blind spot to its consequences

When a scrape job is down, Karel joins it to the queries that depend on it
(`source_job` in the manifest) and names the findings that can no longer fire.
A report that lists "1 job down" in one place and "3 queries returned no series"
in another leaves the reader to do the join by hand.

## Node analysis

Nodes are where capacity planning, drain safety and control-plane risk meet.
Karel records, per node: readiness and pressure conditions, whether it is
cordoned, allocatable vs capacity (so *reserved* memory is explicit), kubelet
version, RKE2 release, kernel version, container runtime, ephemeral-storage
use, and image-cache size. The node table shows the RKE2 release and kernel
version per node, so a fleet that is only partly upgraded is visible at a
glance rather than needing one `kubectl` call per node.

RKE2 embeds its release in the kubelet version: `v1.35.6+rke2r1` is release
`r1` wrapping Kubernetes `1.35.6`, and the whole string is the RKE2 version as
the RKE2 project tags its releases. SemVer treats the `+` suffix as build
metadata and therefore ignores it. The node table shows the full RKE2 version
per node because the two parts move independently: a node can be on the
current RKE2 release and still lag a Kubernetes patch, or match on Kubernetes
and have missed the RKE2 bump.

The two facts that most often surprise people:

* **Requests are not usage.** `K8S_REQUESTS_OVERSTATED` fires when memory
  requests are a large share of the cluster but actual use is a small one. Both
  numbers are true and they fail in different ways: requests block *scheduling*,
  usage triggers the OOM killer.
* **Zero node reservation is dangerous.** When `allocatable == capacity` the
  kubelet has held nothing back; under pressure the kubelet, the runtime and
  everything else compete with pods and the OOM killer decides. On a node that
  also runs an etcd member this is CRIT.

### Node-loss simulation

Losing a node degrades the cluster - that is what losing a node means, and
saying so once per node is not information. `r_node_loss` therefore reports
only what a single node failure would do *beyond* removing that node's
capacity:

* **The cluster is not N+1** (`K8S_NOT_N_PLUS_ONE`): requests on the
  general-purpose pool would exceed what remains after losing its largest
  node. The pool is Ready, uncordoned, untainted nodes; load is what already
  runs there. This is aggregate arithmetic, so it is optimistic - when it
  fires, pods certainly cannot all be rescheduled. One finding, not one per node.
* **etcd has no fault tolerance left** (`K8S_ETCD_NO_FAULT_TOLERANCE`): one
  more member failure loses quorum. WARN when that is the design (1-2
  members), CRIT when a member is already down. A healthy 3-member etcd is
  silent.
* **Redundancy that is not** (`K8S_REPLICAS_COLOCATED`): a platform workload
  with two or more replicas, all on one node.

The headroom numbers are always computed and shown in **Key metrics** (CPU and
memory requested, now and after losing the largest node), so a quiet report
still shows the arithmetic was done.

Deliberately *not* node-loss findings: PDBs (a dying node ignores them; they
matter for a planned drain, reported once as info by `K8S_PDB_BLOCKS_DRAIN`),
single-replica workloads, node-local PVs and host-pinned pods (tied to their
node by choice).

## Platform vs tenant namespaces

On a shared cluster most broken pods belong to tenants. Every per-object
problem list (backoff, OOMKill, Pending, degraded workloads, failed Jobs,
overdue CronJobs, unbound PVCs, paused rollouts, co-located replicas) is split
by namespace:

* **platform** - `kube-*`, `cattle-*`, `*-system`, `*operator*`, `calico-*`,
  `tigera-*`, `cert-manager`, `ingress-nginx`, `gpu-operator`, `csi-*`,
  `metallb*`, `kubewarden`, `cloudnativepg`, `rook-*`, `longhorn*`, plus
  `KAREL_PLATFORM_NAMESPACES`. These are individual findings at normal severity.
* **tenant** - everything else, summarised in one **Tenant workloads** table:
  count, number of namespaces, most affected namespaces. Never an alarm.

Parsers record exact per-namespace counts (`<list>_by_ns`) and truncate the
sample lists platform-first, so a platform entry is never cut in favour of
forty tenant ones. Counts always come from the full total, never from the
length of a sample.

## Webhooks

Fail-closed webhooks whose backend has no ready endpoints are grouped **per
backing Service** - fourteen hooks pointing at one dead Service are one problem
with one fix. Severity follows what the hooks intercept: built-in resources →
CRIT; only installed CRD groups → WARN; only groups with no CRD installed →
INFO (a leftover that matches nothing); not recorded → CRIT, because unknown
is not safe. A Service that does not exist at all gets a `kubectl delete
...webhookconfiguration` proposal instead of "restore the pods".

## Pod and workload analysis

Per-pod detail would explode the snapshot and make day-over-day diffing
useless (pod names change on every redeploy), so restarts are keyed by owner
(Deployment/StatefulSet/DaemonSet/Job), which is stable across redeploys.
Karel surfaces Pending pods, CrashLoop/ImagePull backoff, recent OOMKills,
CronJobs that stopped running, failed Jobs, PVCs that are not Bound, stuck
VolumeAttachments, and fail-closed webhooks whose backing Service has no ready
endpoints (a cluster-wide write outage). A "recent" OOMKill is one whose
`lastState.terminated.finishedAt` is inside the last 48h — every one of them
is listed by name, in all namespaces (platform and tenant), with the kill's
age next to the entry (`killed 9h ago`); a chronically-OOMing container is
followed by the restart counter and K8S_RESTART_SPIKE rather than by a finding
that never clears.

A stuck VolumeAttachment is reported with its volume, target node, CSI driver
and the pod waiting on that claim, not just the attachment's internal CSI
handle — the handle identifies nothing on its own, and the pod is the reason
the attachment matters. The PV→claim and claim→pod joins are made during
normalization; when a bundle predates them, or the PV carries no `claimRef`,
the report says the pod is unknown rather than omitting it.

Real pins matter for drain planning; DaemonSet pods, podAntiAffinity, one-shot
Job pods and static control-plane pods are deliberately *not* counted as pins.

## Findings vs. blind spots

Informational findings are split into two sections:

* **Informational** — things Karel found in the cluster.
* **What this report cannot see** — Karel's own coverage gaps (certs not
  visible from a pod, commands with no parser, a collector that did not
  complete). They are listed every run so that absence of a finding is never
  mistaken for absence of a problem.

## Severity discipline

* `crit` — a real, current outage or an unrecoverable-on-its-own condition.
* `warn` — degraded, or a risk that needs a decision.
* `info` — a fact worth stating, including Karel's own limitations.

A check that *cannot run* says so at info level rather than passing silently,
because passing silently is indistinguishable from passing because all is well.
