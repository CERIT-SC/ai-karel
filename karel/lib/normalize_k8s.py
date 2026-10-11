"""
Kubernetes parsers for Karel. Same contract as normalize.py:
flat dotted facts, never invent values, never let a parse error kill the run.

Aggregation policy: no fact per pod. Per-pod detail explodes the snapshot and
makes day-over-day diffing useless (pod names change on every redeploy).
Restart counts are keyed by OWNER (deployment/statefulset/daemonset), which is
stable across redeploys and is what a human actually asks about.
"""

import datetime
import os
import re

import scope

# resource quantity parsing ---------------------------------------------------
# Kubernetes resource.Quantity parsing.
#
# Getting this wrong is silent and total: a suffix the regex does not match
# yields None, the fact is never recorded, and every rule that depends on it
# quietly evaluates nothing. Real nodes report memory as "792228952Ki" with a
# CAPITAL K, which an earlier version of this parser dropped entirely - taking
# the whole node-loss memory calculation with it.
#
# Valid suffixes (k8s apimachinery):
#   binary   Ki Mi Gi Ti Pi Ei
#   decimal  n u m "" k M G T P E
_QUANTITY_RE = re.compile(
    r"^\s*([+-]?[0-9.]+)\s*"
    r"(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|M|G|T|P|E|)\s*$")

_MULT = {
    "": 1.0,
    "n": 1e-9, "u": 1e-6, "m": 1e-3,
    "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
    "Ki": 2 ** 10, "Mi": 2 ** 20, "Gi": 2 ** 30,
    "Ti": 2 ** 40, "Pi": 2 ** 50, "Ei": 2 ** 60,
}


def quantity(q):
    """Parse a Kubernetes quantity to a float of base units. None if unparseable."""
    if q is None:
        return None
    if isinstance(q, (int, float)):
        return float(q)
    m = _QUANTITY_RE.match(str(q))
    if not m:
        return None
    try:
        return float(m.group(1)) * _MULT[m.group(2)]
    except (ValueError, KeyError):
        return None


def cpu_millis(q):
    v = quantity(q)
    return None if v is None else int(round(v * 1000))


def mem_bytes(q):
    v = quantity(q)
    return None if v is None else int(v)


def _iso(ts):
    if not ts:
        return None
    try:
        return datetime.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        return None


def _age_days(ts, now=None):
    d = _iso(ts)
    if not d:
        return None
    now = now or datetime.datetime.utcnow()
    return (now - d).total_seconds() / 86400.0


def _age_hours(ts, now=None):
    d = _age_days(ts, now)
    return d * 24.0 if d is not None else None


def _age_days_future(ts, now=None):
    """Signed days until a FUTURE timestamp (negative once it passes)."""
    d = _iso(ts)
    if not d:
        return None
    now = now or datetime.datetime.utcnow()
    return (d - now).total_seconds() / 86400.0


def _items(o):
    if isinstance(o, dict):
        return o.get("items") or []
    if isinstance(o, list):
        return o
    return []


# RKE2 embeds its own release in the kubelet version it reports:
# "v1.35.6+rke2r1" is RKE2 release r1 wrapping Kubernetes 1.35.6, and the
# whole string is the RKE2 version as the RKE2 project tags its releases. The
# "+" suffix is a build-metadata marker SemVer ignores, so anything that
# parses these as versions sees one number; the report shows the full RKE2
# version because the Kubernetes part and the release tag move independently.
_RKE2_RE = re.compile(r"\+rke2r\d+")


def rke2_release(kubelet_version):
    """Full RKE2 version for a node, or None when it is not an RKE2 node.

    Read from the kubelet version string, which every RKE2 node carries and
    which is itself the RKE2 version ("v1.35.6+rke2r1"). A node with no tag
    there is reported as having no known release rather than guessed at: the
    rke2.io/* labels and annotations seen on real nodes (rke2.io/node-args)
    carry no release tag to read.
    """
    if not kubelet_version:
        return None
    kv = str(kubelet_version)
    return kv if _RKE2_RE.search(kv) else None


def _nn(obj):
    md = obj.get("metadata") or {}
    return "%s/%s" % (md.get("namespace") or "-", md.get("name") or "-")


_REPO_USERINFO_RE = re.compile(r"(://)[^:/\s]+:[^@\s]+@")


def _image_split(image):
    """'reg.example.com/team/app:1.2' -> {registry, repo, tag}. A first
    component without a dot or colon is not a registry (it's a namespace)."""
    if not image:
        return None
    img = str(image).split("@", 1)[0]
    tag = None
    if ":" in img.rsplit("/", 1)[-1]:
        img, tag = img.rsplit(":", 1)
    parts = img.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        return {"registry": parts[0], "repo": parts[1], "tag": tag}
    return {"registry": "docker.io", "repo": img, "tag": tag}


def _redact_pod_message(msg, limit=300):
    """Pod statuses can embed URLs with credentials; the AI layer never sees
    them. Log-level detail truncated for the bundle."""
    if not msg:
        return None
    return _REPO_USERINFO_RE.sub(r"\1<creds>@", str(msg))[:limit]


# Objects (or whole namespaces) annotated with this key are excluded from
# housekeeping: they are deliberately kept, and are listed separately with
# their reason instead of being counted in the backlog.
KEEP_ANNOTATION = os.environ.get("KAREL_KEEP_ANNOTATION",
                                 "karel.cerit-sc.cz/keep")


def _keep(md):
    """Keep-annotation value on an object, or None."""
    v = (md.get("annotations") or {}).get(KEEP_ANNOTATION)
    return str(v)[:200] if v else None


def _gpu_driver_version(labels):
    """Driver version from the GPU operator's labels. Two schemes exist: the
    older nvidia.com/cuda.driver.{major,minor,rev} triplet and the newer
    full-version label; both parse to the same dotted version."""
    full = labels.get("nvidia.com/cuda.driver-version.full")
    if full:
        return str(full)
    pre = "nvidia.com/cuda.driver."
    major, minor, rev = (labels.get(pre + "major"), labels.get(pre + "minor"),
                         labels.get(pre + "rev"))
    if major is None and minor is None and rev is None:
        return None
    return "%s.%s.%s" % (major or "?", minor or "0", rev or "0")


def _is_gpu_node(name, gpu, gpu_labels, dra=None):
    """A GPU node advertises GPU capacity (full GPUs or nvidia.com/mig-*
    slices), is labelled gpu.present, carries a product label, or ships
    DRA ResourceSlices - the only evidence a "DRA-only allocator" has."""
    res = gpu.get(name) or {}
    if any((v.get("capacity") or 0) > 0 for v in res.values()):
        return True
    lbl = gpu_labels.get(name) or {}
    if str(lbl.get("nvidia.com/gpu.present", "")).lower() == "true":
        return True
    if lbl.get("nvidia.com/gpu.product"):
        return True
    return bool((dra or {}).get(name))


def _problem_list(F, src, path, items, limit=40, count=True):
    """Record a per-object problem list three ways.

    The list itself is truncated for the bundle, so it is ordered platform
    namespaces first - otherwise forty tenant entries sorted alphabetically
    push kube-system out of the sample. `_by_ns` is complete, so tenant
    summaries are exact, and `_count` is the real total: a rule that used
    len() of the truncated list once reported 40 OOMKills when there were 116.
    """
    items = list(items)
    F.add(path, scope.platform_first(items)[:limit], src)
    by_ns = {}
    for i in items:
        ns = scope.item_ns(i)
        if ns:
            by_ns[ns] = by_ns.get(ns, 0) + 1
    F.add(path + "_by_ns", by_ns, src)
    if count:
        F.add(path + "_count", len(items), src)


# ---------------------------------------------------------------------- nodes
def p_nodes(o, F, src):
    items = _items(o)
    F.add("k8s.node.count", len(items), src)

    names, not_ready, pressure, unsched = [], [], [], []
    roles, etcd_voters, reserved_mem, swaps = {}, [], {}, []
    kubelet_versions, os_images, runtimes = {}, {}, {}
    rke2 = {}
    gpu, gpu_labels, gpu_driver = {}, {}, {}
    gpu_upgrade_states = {}
    alloc_cpu, alloc_mem = {}, {}
    cap_pods = {}

    for n in items:
        name = (n.get("metadata") or {}).get("name")
        if not name:
            continue
        names.append(name)
        b = "k8s.node.%s" % name

        labels = (n.get("metadata") or {}).get("labels") or {}
        node_roles = sorted(k.split("/", 1)[1] for k in labels
                            if k.startswith("node-role.kubernetes.io/"))
        if node_roles:
            F.add(b + ".roles", node_roles, src)
            roles[name] = node_roles

        conds = {c.get("type"): c for c in (n.get("status") or {}).get("conditions") or []
                 if isinstance(c, dict)}

        # RKE2 publishes etcd membership as a node condition. This is
        # authoritative, unlike inferring it from static pod names.
        voter = conds.get("EtcdIsVoter")
        if voter is not None:
            F.add(b + ".etcd_voter", voter.get("status") == "True", src)
            if voter.get("status") == "True":
                etcd_voters.append(name)
        ready = (conds.get("Ready") or {}).get("status")
        F.add(b + ".ready", ready, src)
        if ready != "True":
            not_ready.append(name)
            lt = (conds.get("Ready") or {}).get("lastTransitionTime")
            F.add(b + ".not_ready_since", lt, src)

        for ctype in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"):
            c = conds.get(ctype)
            if c and c.get("status") == "True":
                pressure.append("%s/%s" % (name, ctype))
                F.add(b + ".condition.%s" % ctype, True, src)

        spec = n.get("spec") or {}
        if spec.get("unschedulable"):
            unsched.append(name)
            F.add(b + ".unschedulable", True, src)
        taints = spec.get("taints") or []
        block = [t.get("key") for t in taints
                 if t.get("effect") in ("NoSchedule", "NoExecute")]
        if block:
            F.add(b + ".taints", sorted([t for t in block if t]), src)

        alloc = (n.get("status") or {}).get("allocatable") or {}
        cap = (n.get("status") or {}).get("capacity") or {}
        c_m = cpu_millis(alloc.get("cpu"))
        m_b = mem_bytes(alloc.get("memory"))

        # GPU resources (nvidia.com/gpu plus any nvidia.com/mig-* slices) and
        # the nvidia.com/* label set the GPU operator publishes. Allocatable
        # below capacity is how the device plugin reports unhealthy GPUs.
        gpu_res = {}
        for rk in sorted(set(list(cap) + list(alloc))):
            if not rk.startswith("nvidia.com/"):
                continue
            gpu_res[rk] = {"capacity": _int(cap.get(rk)),
                           "allocatable": _int(alloc.get(rk))}
        if gpu_res:
            F.add(b + ".gpu", gpu_res, src)
            gpu[name] = gpu_res
        gpu_lbl = {k: v for k, v in labels.items() if k.startswith("nvidia.com/")}
        if gpu_lbl:
            F.add(b + ".gpu_labels", gpu_lbl, src)
            gpu_labels[name] = gpu_lbl
            driver = _gpu_driver_version(gpu_lbl)
            if driver:
                F.add(b + ".gpu_driver", driver, src)
                gpu_driver[name] = driver
            upstate = gpu_lbl.get("nvidia.com/gpu-driver-upgrade-state")
            if upstate:
                F.add(b + ".gpu_upgrade_state", upstate, src)
                gpu_upgrade_states[name] = upstate

        # capacity - allocatable is what the kubelet has held back for itself,
        # the container runtime and the OS. Zero here means a memory-hungry pod
        # can starve the kubelet, and the node goes NotReady.
        cap_m = mem_bytes(cap.get("memory"))
        cap_c = cpu_millis(cap.get("cpu"))
        if cap_m is not None and m_b is not None:
            F.add(b + ".reserved_mem_bytes", cap_m - m_b, src)
            reserved_mem[name] = cap_m - m_b
        if cap_c is not None and c_m is not None:
            F.add(b + ".reserved_cpu_m", cap_c - c_m, src)
        F.add(b + ".capacity_mem_bytes", cap_m, src)
        F.add(b + ".capacity_cpu_m", cap_c, src)

        eph = alloc.get("ephemeral-storage")
        eph_b = mem_bytes(eph) if eph else None
        if eph_b:
            F.add(b + ".ephemeral_alloc_bytes", eph_b, src)
        img_bytes = sum(i.get("sizeBytes") or 0
                        for i in (n.get("status") or {}).get("images") or [])
        if img_bytes:
            F.add(b + ".image_cache_bytes", img_bytes, src)
            if eph_b:
                F.add(b + ".image_cache_pct", round(100.0 * img_bytes / eph_b, 1), src)
        swap = (((n.get("status") or {}).get("nodeInfo") or {}).get("swap") or {})
        if swap.get("capacity"):
            F.add(b + ".swap_bytes", swap["capacity"], src)
            swaps.append(name)
        F.add(b + ".allocatable_cpu_m", c_m, src)
        F.add(b + ".allocatable_mem_bytes", m_b, src)
        F.add(b + ".capacity_pods", _int(cap.get("pods")), src)
        if c_m:
            alloc_cpu[name] = c_m
        if m_b:
            alloc_mem[name] = m_b
        if _int(cap.get("pods")):
            cap_pods[name] = _int(cap.get("pods"))

        ni = (n.get("status") or {}).get("nodeInfo") or {}
        kv = ni.get("kubeletVersion")
        F.add(b + ".kubelet_version", kv, src)
        F.add(b + ".os_image", ni.get("osImage"), src)
        F.add(b + ".kernel", ni.get("kernelVersion"), src)
        F.add(b + ".container_runtime", ni.get("containerRuntimeVersion"), src)
        rel = rke2_release(kv)
        if rel:
            F.add(b + ".rke2_release", rel, src)
            rke2[name] = rel
        if kv:
            kubelet_versions[kv] = kubelet_versions.get(kv, 0) + 1
        if ni.get("osImage"):
            os_images[ni["osImage"]] = os_images.get(ni["osImage"], 0) + 1
        if ni.get("containerRuntimeVersion"):
            runtimes[ni["containerRuntimeVersion"]] = runtimes.get(ni["containerRuntimeVersion"], 0) + 1

        # image filesystem pressure indicator
        imgs = (n.get("status") or {}).get("images") or []
        F.add(b + ".image_count", len(imgs), src)

    F.add("k8s.node.names", sorted(names), src)
    F.add("k8s.node.not_ready", sorted(not_ready), src)
    F.add("k8s.node.not_ready_count", len(not_ready), src)
    F.add("k8s.node.pressure", sorted(pressure), src)
    F.add("k8s.node.unschedulable", sorted(unsched), src)
    F.add("k8s.node.kubelet_versions", kubelet_versions, src)
    F.add("k8s.node.kubelet_version_count", len(kubelet_versions), src)
    F.add("k8s.node.os_images", os_images, src)
    F.add("k8s.node.runtimes", runtimes, src)
    F.add("k8s.node.rke2_releases", rke2, src)
    F.add("k8s.node.rke2_release_count", len(set(rke2.values())), src)
    if gpu:
        F.add("k8s.node.gpu", gpu, src)
    if gpu_labels:
        F.add("k8s.node.gpu_labels", gpu_labels, src)
    gpu_nodes = sorted(n for n in set(list(gpu) + list(gpu_labels))
                       if _is_gpu_node(n, gpu, gpu_labels))
    F.add("k8s.node.gpu_nodes", gpu_nodes, src)
    if gpu_upgrade_states:
        F.add("k8s.node.gpu_upgrade_states", gpu_upgrade_states, src)
    if gpu_driver:
        F.add("k8s.node.gpu_drivers",
              {n: gpu_driver[n] for n in sorted(gpu_driver)}, src)
        drv_versions = {}
        for v in gpu_driver.values():
            drv_versions[v] = drv_versions.get(v, 0) + 1
        F.add("k8s.node.gpu_driver_versions", drv_versions, src)
    F.add("k8s.node.allocatable_cpu_m", alloc_cpu, src)
    F.add("k8s.node.allocatable_mem_bytes", alloc_mem, src)
    F.add("k8s.node.capacity_pods", cap_pods, src)
    F.add("k8s.node.roles", roles, src)
    F.add("k8s.node.reserved_mem_bytes", reserved_mem, src)
    if etcd_voters:
        # authoritative; preferred over the static-pod inference
        F.add("k8s.controlplane.etcd_nodes", sorted(etcd_voters), src)
        F.add("k8s.controlplane.etcd_source", "EtcdIsVoter node condition", src)
    if swaps:
        F.add("k8s.node.swap_enabled", sorted(swaps), src)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------- pods
# How old a container's last OOMKill may be and still count as "recent". The
# kill time comes from lastState.terminated.finishedAt (exact, like the Failed
# path); a container that OOMed once and then ran clean keeps that lastState
# forever, so without this bound the same kill is reported forever. Two days
# handles a delayed run (a kill from just after the last collection would
# otherwise fall silent); a chronically-OOMing container still keeps
# re-killing, so its ongoing story is the restart counter and
# K8S_RESTART_SPIKE rather than a finding that never clears.
OOMKILL_RECENT_DAYS = 2.0


def p_pods(o, F, src):
    items = _items(o)
    F.add("k8s.pod.count", len(items), src)

    by_phase, by_node = {}, {}
    not_ready, pending, restarting, oomkilled, terminating = [], [], [], [], []
    node_requests = {}          # node -> {"cpu_m":, "mem_bytes":, "pods":}
    owner_restarts = {}         # ns/owner -> restarts
    pinned = {}                 # node -> [pods GENUINELY pinned to it]
    by_design = {}              # node -> {app: count} placed there deliberately
    static_pods = {}            # node -> [static/mirror pod names]
    control_plane = {}          # component -> {nodes}
    no_cpu_req = no_mem_req = containers = 0
    besteffort = []
    owner_nodes = {}            # owner -> {nodes} for replica-spread analysis
    owner_running = {}          # controller-owned owner -> running pod count
    node_pod_names = {}
    pvc_users = {}              # ns/claim -> [pods that mount it]
    by_ns = {}                  # ns -> pod count (housekeeping: empty namespaces)
    failed_pods = {}            # ns -> [{pod, owner, reason, finished_at, created}] ( trimmed )
    terminating_info = []       # pods with a deletionTimestamp, for finalizer stalls
    gpu_op = {}                 # node -> gpu-operator pod health recap
    gpu_op_pods = {}            # node -> all gpu-operator pods (exact names)
    failed_total = 0
    failed_old_by_ns = {}
    recent_total = 0
    recent_by_ns = {}
    recent_groups = {}
    gpu_users = {}              # node -> [pods holding its GPUs]
    gpu_requests = {}           # nn -> {cards, mig, gpu_mem_gb} the request breakdown
    failing = []                # AI contract: failing pods, clean and bounded

    for p in items:
        md = p.get("metadata") or {}
        spec = p.get("spec") or {}
        st = p.get("status") or {}
        ns = md.get("namespace") or "-"
        name = md.get("name") or "-"
        nn = "%s/%s" % (ns, name)

        phase = st.get("phase") or "Unknown"
        by_phase[phase] = by_phase.get(phase, 0) + 1

        node = spec.get("nodeName")
        if node:
            by_node[node] = by_node.get(node, 0) + 1
            node_pod_names.setdefault(node, []).append(nn)

        # Which pod wants each claim. A stuck VolumeAttachment only matters
        # because of the pod that is waiting on it: without this join the
        # report can name the attachment but not who is blocked by it.
        for v in spec.get("volumes") or []:
            claim = (v.get("persistentVolumeClaim") or {}).get("claimName")
            if claim:
                pvc_users.setdefault("%s/%s" % (ns, claim), []).append(
                    "pod %s%s" % (nn, " on %s" % node.split(".")[0] if node else ""))

        if md.get("deletionTimestamp"):
            terminating.append(nn)
            terminating_info.append({
                "pod": nn, "node": node,
                "deleted_at": md.get("deletionTimestamp"),
                "reason": "deletionTimestamp set",
            })

        by_ns[ns] = by_ns.get(ns, 0) + 1

        if phase == "Failed":
            finished, reason = None, None
            for cs in (st.get("containerStatuses") or []):
                t = (cs.get("state") or {}).get("terminated") or {}
                if t.get("reason") and not reason:
                    reason = t.get("reason")
                if t.get("finishedAt"):
                    finished = t["finishedAt"]
            reason = reason or "Failed"
            age = _age_days(finished or md.get("creationTimestamp"))
            # Counts ALWAYS come from the full set; per-pod details are the
            # trimmed sample. A 704-pod failure must count 704, not 50.
            failed_total += 1
            if age is not None and age >= 7:
                failed_old_by_ns[ns] = failed_old_by_ns.get(ns, 0) + 1
            else:
                recent_total += 1
                recent_by_ns[ns] = recent_by_ns.get(ns, 0) + 1
                gkey = "%s|%s" % (_owner_key(md, ns), reason)
                g = recent_groups.setdefault(
                    gkey, {"ns": ns,
                           "owner": _owner_key(md, ns).split("/", 1)[-1],
                           "reason": reason, "count": 0})
                g["count"] += 1
            fnn = failed_pods.setdefault(ns, [])
            if len(fnn) < 50:
                fnn.append({"pod": nn,
                            "owner": _owner_key(md, ns),
                            "reason": reason,
                            "finished_at": finished,
                            "created": md.get("creationTimestamp")})

        if phase == "Pending":
            pending.append(nn)

        # readiness
        conds = {c.get("type"): c.get("status")
                 for c in st.get("conditions") or [] if isinstance(c, dict)}
        if phase == "Running" and conds.get("Ready") != "True":
            not_ready.append(nn)

        # restarts and OOM, aggregated by owner
        owner = _owner_key(md, ns)
        total_restarts = 0
        for cs in (st.get("containerStatuses") or []) + \
                  (st.get("initContainerStatuses") or []):
            rc = cs.get("restartCount") or 0
            total_restarts += rc
            last = (cs.get("lastState") or {}).get("terminated") or {}
            # The node matters for platform pods: a DaemonSet crashlooping on
            # one node is a broken node, not a broken DaemonSet.
            where = " on %s" % node.split(".")[0] if node else ""
            if last.get("reason") == "OOMKilled":
                # lastState is the PREVIOUS termination and survives until the
                # next one, so a container that OOMed long ago and has run
                # cleanly since still reads reason=OOMKilled here. Only a kill
                # inside the window is news; older ones ride with restart
                # deltas instead of being re-announced every run. The kill's
                # age rides along, so the reader never has to guess "recent".
                age = _age_days(last.get("finishedAt"))
                if age is None or age < OOMKILL_RECENT_DAYS:
                    when = ""
                    if age is not None:
                        when = " (killed %s ago)" % \
                            ("%.0fh" % (age * 24) if age < 2 else
                             "%.0fd" % age)
                    oomkilled.append("%s:%s%s%s" % (nn, cs.get("name"),
                                                    where, when))
            waiting = (cs.get("state") or {}).get("waiting") or {}
            if waiting.get("reason") in ("CrashLoopBackOff", "ImagePullBackOff",
                                         "ErrImagePull", "CreateContainerConfigError"):
                restarting.append("%s:%s=%s%s" % (nn, cs.get("name"),
                                                  waiting["reason"], where))
            # The AI layer groups and narrates; Karel hands it clean facts:
            # image split, exit codes, reasons, and a redacted message.
            last_term = (cs.get("lastState") or {}).get("terminated") or {}
            cur_term = (cs.get("state") or {}).get("terminated") or {}
            is_failing = bool(waiting.get("reason")) or \
                (cur_term.get("exitCode") or 0) > 0 or \
                ((last_term.get("exitCode") or 0) > 0
                 and last_term.get("reason") not in (None, "Completed"))
            if is_failing:
                img = _image_split(cs.get("image"))
                msg = (waiting.get("message") or cur_term.get("message")
                       or last_term.get("message"))
                failing.append({
                    "ns": ns, "pod": name, "owner": owner,
                    "image": img,
                    "wait_reason": waiting.get("reason"),
                    "term_reason": cur_term.get("reason")
                                   or last_term.get("reason"),
                    "exit_code": cur_term.get("exitCode")
                                 if cur_term.get("exitCode") is not None
                                 else last_term.get("exitCode"),
                    "message": _redact_pod_message(msg),
                })
        if total_restarts:
            owner_restarts[owner] = owner_restarts.get(owner, 0) + total_restarts

        # Which pods hold which nodes' GPUs - a drain-blocked driver upgrade
        # is unblocked by exactly these. The request BREAKDOWN matters too:
        # whole cards (nvidia.com/gpu), MIG slices, or the JupyterHub
        # gpu-mem shared-memory quota, which is GiB and NOT a card count.
        cards, mig, gpu_mem = 0, 0, 0
        for c in spec.get("containers") or []:
            res = (c.get("resources") or {}).get("requests") or \
                  (c.get("resources") or {}).get("limits") or {}
            for rk, v in list(res.items()):
                if rk == "nvidia.com/gpu":
                    cards += _int(v) or 0
                elif rk.startswith("nvidia.com/mig-"):
                    mig += _int(v) or 0
                elif rk == "nvidia.com/gpu-mem":
                    gpu_mem += _int(v) or 0
            if (cards or mig) and node:
                gpu_users.setdefault(node, []).append(nn)
        if cards or mig or gpu_mem:
            gpu_requests[nn] = {"cards": cards, "mig": mig,
                                "gpu_mem_gb": gpu_mem}

        # The GPU stack is a per-node deployment: one unhappy pod on a node
        # usually means the NODE's driver stack, not the DaemonSet.
        if ns == "gpu-operator" and node:
            wait = None
            for cs in (st.get("containerStatuses") or []):
                w = ((cs.get("state") or {}).get("waiting") or {}).get("reason")
                if w and not wait:
                    wait = w
            gpu_op[node] = {
                "pod": name, "owner": owner,
                "ready": bool(phase == "Running" and conds.get("Ready") == "True"),
                "waiting_reason": wait, "restarts": total_restarts,
            }
            # ALL gpu-operator pods on the node, exact names. gpu_op keeps one
            # recap per node; the DaemonSet family really carries several pods
            # per node, and the per-node pairings (gpu-feature-discovery ->
            # nvidia-container-toolkit) need the exact random suffixes.
            gpu_op_pods.setdefault(node, []).append({
                "pod": name, "owner": owner,
                "ready": bool(phase == "Running" and conds.get("Ready") == "True"),
                "waiting_reason": wait, "restarts": total_restarts,
            })

        # Scheduling pins matter for drain simulation - but only REAL pins.
        # A DaemonSet pod is one-per-node by design: it does not "fail to
        # reschedule" when a node dies, it correctly ceases to exist. Likewise
        # podAntiAffinity is about spreading, not pinning.
        if node and phase == "Running" and (_owner_kinds(md) & {"Node"}):
            static_pods.setdefault(node, []).append(name)
            for comp in ("etcd", "kube-apiserver", "kube-scheduler",
                         "kube-controller-manager"):
                if name.startswith(comp + "-"):
                    control_plane.setdefault(comp, set()).add(node)

        if node:
            scoped = _node_scoped_app(md) if phase == "Running" else None
            if scoped:
                by_design.setdefault(node, {})
                by_design[node][scoped] = by_design[node].get(scoped, 0) + 1
            elif _is_host_pinned(spec, md):
                pinned.setdefault(node, []).append(nn)

        # resource requests per node
        if st.get("qosClass") == "BestEffort" and phase == "Running":
            besteffort.append(nn)

        if phase == "Running" and not (_owner_kinds(md) & {"DaemonSet", "Node", "Job"}):
            owner_nodes.setdefault(owner, set()).add(node)
            if _owner_kinds(md) & {"ReplicaSet", "StatefulSet"}:
                owner_running[owner] = owner_running.get(owner, 0) + 1

        # Only scheduled, non-terminal pods hold reservations. Counting
        # Succeeded Job pods inflated every node's requests - caught by
        # cross-checking against Rancher's pod-requests annotation.
        if node and phase in ("Running", "Pending"):
            agg = node_requests.setdefault(node, {"cpu_m": 0, "mem_bytes": 0, "pods": 0})
            agg["pods"] += 1
            # Sidecars (initContainers with restartPolicy: Always) run for the
            # pod's whole life and ADD to the request; ordinary initContainers
            # instead set a floor via max().
            init_max_cpu = init_max_mem = 0
            for ic in (spec.get("initContainers") or []):
                req = ((ic.get("resources") or {}).get("requests") or {})
                icm, imb = cpu_millis(req.get("cpu")) or 0, mem_bytes(req.get("memory")) or 0
                if ic.get("restartPolicy") == "Always":
                    agg["cpu_m"] += icm
                    agg["mem_bytes"] += imb
                else:
                    init_max_cpu = max(init_max_cpu, icm)
                    init_max_mem = max(init_max_mem, imb)
            run_cpu = run_mem = 0
            for c in (spec.get("containers") or []):
                req = ((c.get("resources") or {}).get("requests") or {})
                containers += 1
                cm = cpu_millis(req.get("cpu"))
                mb = mem_bytes(req.get("memory"))
                if cm is None:
                    no_cpu_req += 1
                if mb is None:
                    no_mem_req += 1
                run_cpu += cm or 0
                run_mem += mb or 0
            agg["cpu_m"] += max(run_cpu, init_max_cpu)
            agg["mem_bytes"] += max(run_mem, init_max_mem)

    F.add("k8s.pvc.pod_users", pvc_users, src)
    F.add("k8s.pod.by_phase", by_phase, src)
    F.add("k8s.pod.by_ns", by_ns, src)
    if failed_pods:
        F.add("k8s.pod.failed_pods",
              {ns: v for ns, v in sorted(failed_pods.items())}, src)
    F.add("k8s.pod.failed_count", failed_total, src)
    if failed_old_by_ns:
        F.add("k8s.pod.failed_old_by_ns", failed_old_by_ns, src)
    # Recent (< 7 d) failures, grouped by owner and reason: 704 Failed
    # pods from one Job array is ONE problem ("pods Failed (last 7
    # days)" in the tenant table), not 704 rows. Housekeeping takes the
    # same pods once they pass seven days.
    if recent_groups:
        recent_list = []
        for key, g in recent_groups.items():
            recent_list.append("%s/%s (%s x%d)" % (g["ns"], g["owner"],
                                                   g["reason"], g["count"]))
        F.add("k8s.pod.failed_recent",
              scope.platform_first(sorted(recent_list))[:40], src)
        F.add("k8s.pod.failed_recent_by_ns", recent_by_ns, src)
        F.add("k8s.pod.failed_recent_groups",
              {k: v for k, v in sorted(recent_groups.items())}, src)
    if recent_total:
        F.add("k8s.pod.failed_recent_count", recent_total, src)
    if terminating_info:
        F.add("k8s.pod.terminating_info", terminating_info[:60], src)
    if gpu_op:
        F.add("k8s.pod.gpu_operator_by_node", gpu_op, src)
    if gpu_op_pods:
        F.add("k8s.pod.gpu_operator_pods_by_node",
              {n: sorted(v, key=lambda p: (p["owner"], p["pod"]))
               for n, v in gpu_op_pods.items()}, src)
    if gpu_users:
        F.add("k8s.pod.gpu_users", {k: sorted(v) for k, v in gpu_users.items()}, src)
    if gpu_requests:
        F.add("k8s.pod.gpu_requests", gpu_requests, src)

    if failing:
        F.add("k8s.pod.failing", failing[:200], src)
    F.add("k8s.pod.failing_count", len(failing), src)
    F.add("k8s.pod.by_node", by_node, src)
    F.add("k8s.pod.not_ready", sorted(not_ready)[:40], src)
    F.add("k8s.pod.not_ready_count", len(not_ready), src)
    _problem_list(F, src, "k8s.pod.pending", pending)
    _problem_list(F, src, "k8s.pod.backoff", restarting)
    _problem_list(F, src, "k8s.pod.oomkilled", oomkilled)
    F.add("k8s.pod.terminating", sorted(terminating)[:40], src)
    F.add("k8s.pod.terminating_count", len(terminating), src)
    F.add("k8s.node.requests", node_requests, src)
    F.add("k8s.node.pinned_pods", {k: sorted(v)[:20] for k, v in pinned.items()}, src)
    F.add("k8s.node.by_design_pods", by_design, src)
    if static_pods:
        F.add("k8s.node.static_pods", {k: sorted(v) for k, v in static_pods.items()}, src)
    for comp, nodes in control_plane.items():
        key = "k8s.controlplane.%s_nodes" % comp.replace("kube-", "")
        if comp == "etcd" and F.get_value("k8s.controlplane.etcd_source"):
            continue          # node condition already answered this, definitively
        F.add(key, sorted(nodes), src)
    F.add("k8s.pod.containers", containers, src)
    F.add("k8s.pod.containers_no_cpu_request", no_cpu_req, src)
    F.add("k8s.pod.containers_no_mem_request", no_mem_req, src)
    F.add("k8s.pod.besteffort_count", len(besteffort), src)
    F.add("k8s.pod.besteffort", sorted(besteffort)[:20], src)
    singles = {o: list(n)[0] for o, n in owner_nodes.items()
               if len(n) == 1 and None not in n}
    # The node-loss fact that is actually news: a workload somebody scaled to
    # N>1 for availability, whose replicas all landed on the same node. Losing
    # that node is a full outage of something that looks redundant.
    colocated = ["%s (%d replicas on %s)" % (o, owner_running[o], singles[o])
                 for o in sorted(singles) if owner_running.get(o, 0) >= 2]
    _problem_list(F, src, "k8s.workload.colocated", colocated)
    by_node = {}
    for o, n in singles.items():
        by_node.setdefault(n, []).append(o)
    if by_node:
        F.add("k8s.node.single_replica_owners",
              {k: sorted(v) for k, v in by_node.items()}, src)
    F.add("k8s.node.pod_names", {k: sorted(v) for k, v in node_pod_names.items()}, src)

    # per-owner restart counters: the thing whose DELTA matters tomorrow
    for owner, n in sorted(owner_restarts.items(), key=lambda kv: -kv[1])[:60]:
        F.add("k8s.restarts.%s" % owner, n, src)
    F.add("k8s.pod.restarts_total", sum(owner_restarts.values()), src)



_DAEMONSET_KINDS = {"DaemonSet"}

# Workloads that live on one specific node BY DESIGN. Their absence after a node
# failure is the architecture working, not a scheduling problem. The site sets
# this via KAREL_NODE_SCOPED_APPS (comma-separated) for its own per-node
# daemons; there is no safe default, since "one pod per node" is normally a
# DaemonSet and already excluded.
NODE_SCOPED_APPS = {a.strip() for a in
                    os.environ.get("KAREL_NODE_SCOPED_APPS", "").split(",")
                    if a.strip()}


def _node_scoped_app(md):
    labels = md.get("labels") or {}
    for key in ("app", "app.kubernetes.io/name", "app.kubernetes.io/component"):
        if labels.get(key) in NODE_SCOPED_APPS:
            return labels[key]
    # A per-node daemon is often named <app>-<node>. Match the LONGEST prefix so
    # a one-shot <app>-prepare-* Job is not counted as the resident daemon.
    name = md.get("name") or ""
    best = None
    for prefix in NODE_SCOPED_APPS:
        if name.startswith(prefix + "-") and (best is None or len(prefix) > len(best)):
            best = prefix
    if best and name.startswith(best + "-prepare-"):
        return None          # a one-shot prepare Job, not a resident daemon
    return best


def _owner_kinds(md):
    return {r.get("kind") for r in (md.get("ownerReferences") or [])}


def _is_host_pinned(spec, md):
    """True only when the pod is bound to ONE specific node, would not be
    rescheduled elsewhere if that node were lost, AND that is not the intended
    design.

    Deliberately excludes:
      * DaemonSet pods - one per node is the intent, not a constraint
      * node-scoped-by-design workloads (KAREL_NODE_SCOPED_APPS)
      * podAffinity / podAntiAffinity - those are spreading rules
      * nodeSelector / nodeAffinity that does not name a specific host
    """
    if _owner_kinds(md) & _DAEMONSET_KINDS:
        return False
    if _node_scoped_app(md):
        return False
    # One-shot Job pods are not resident workloads. Nothing reschedules a
    # completed Job, and nothing needs to.
    if _owner_kinds(md) & {"Job"}:
        return False
    # Static / mirror pods are recreated by the kubelet on that node only. Their
    # loss with the node is definitional, and is reported as control-plane
    # impact instead.
    if _owner_kinds(md) & {"Node"}:
        return False

    sel = spec.get("nodeSelector") or {}
    if "kubernetes.io/hostname" in sel:
        return True

    # bare nodeName with no controller = a hand-placed pod, nothing will recreate it
    if spec.get("nodeName") and not (md.get("ownerReferences") or []):
        return True

    na = ((spec.get("affinity") or {}).get("nodeAffinity") or {})
    req = (na.get("requiredDuringSchedulingIgnoredDuringExecution") or {})
    for term in req.get("nodeSelectorTerms") or []:
        for expr in (term.get("matchExpressions") or []) + \
                    (term.get("matchFields") or []):
            if expr.get("key") in ("kubernetes.io/hostname", "metadata.name") \
                    and expr.get("operator") in ("In", "Equals", None) \
                    and len(expr.get("values") or []) == 1:
                return True
    return False


def _owner_key(md, ns):
    """Stable-across-redeploy identity for a pod."""
    refs = md.get("ownerReferences") or []
    for r in refs:
        kind = r.get("kind")
        name = r.get("name") or "?"
        if kind == "ReplicaSet":
            # strip the replicaset pod-template hash -> deployment name
            return "%s/%s" % (ns, re.sub(r"-[0-9a-f]{6,10}$", "", name))
        if kind in ("StatefulSet", "DaemonSet", "Job"):
            if kind == "Job":
                name = re.sub(r"-\d{8,}$", "", name)   # cronjob-spawned jobs
            return "%s/%s" % (ns, name)
    return "%s/%s" % (ns, md.get("name") or "?")


# --------------------------------------------------------------- storage
def p_pvc(o, F, src):
    items = _items(o)
    by_phase, pending, by_sc, sc_map = {}, [], {}, {}
    info = {}
    for c in items:
        md = c.get("metadata") or {}
        st = (c.get("status") or {}).get("phase") or "Unknown"
        by_phase[st] = by_phase.get(st, 0) + 1
        if st != "Bound":
            pending.append(_nn(c))
        sc = (c.get("spec") or {}).get("storageClassName") or "-"
        by_sc[sc] = by_sc.get(sc, 0) + 1
        sc_map[_nn(c)] = sc
        info[_nn(c)] = {
            "uid": md.get("uid"),
            "size_bytes": mem_bytes(((c.get("status") or {}).get("capacity")
                                     or {}).get("storage"))
                        or mem_bytes((((c.get("spec") or {}).get("resources")
                                       or {}).get("requests") or {}).get("storage")),
            "created": md.get("creationTimestamp"),
            "phase": st,
            "keep": _keep(md),
        }
    F.add("k8s.pvc.count", len(items), src)
    F.add("k8s.pvc.by_phase", by_phase, src)
    _problem_list(F, src, "k8s.pvc.unbound", pending, limit=30)
    F.add("k8s.pvc.by_storageclass", by_sc, src)
    F.add("k8s.pvc.storageclass_map", sc_map, src)
    F.add("k8s.pvc.info", info, src)


def p_pv(o, F, src):
    items = _items(o)
    by_phase, released, local_pvs = {}, [], []
    claims = {}                 # pv name -> ns/claim it is bound to
    info = {}
    for v in items:
        md = v.get("metadata") or {}
        st = (v.get("status") or {}).get("phase") or "Unknown"
        by_phase[st] = by_phase.get(st, 0) + 1
        name = md.get("name") or "?"
        if st == "Released":
            released.append(name)
        spec = v.get("spec") or {}
        ref = spec.get("claimRef") or {}
        if ref.get("name"):
            claims[name] = "%s/%s" % (ref.get("namespace") or "-", ref["name"])
        if spec.get("local") or spec.get("hostPath"):
            node = None
            na = (spec.get("nodeAffinity") or {}).get("required") or {}
            for term in na.get("nodeSelectorTerms") or []:
                for expr in term.get("matchExpressions") or []:
                    if expr.get("key") == "kubernetes.io/hostname":
                        vals = expr.get("values") or []
                        node = vals[0] if vals else None
            local_pvs.append("%s@%s" % (name, node or "?"))
        info[name] = {
            "uid": md.get("uid"),
            "size_bytes": mem_bytes((spec.get("capacity") or {}).get("storage")),
            "created": md.get("creationTimestamp"),
            "last_transition": (v.get("status") or {}).get("lastPhaseTransitionTime"),
            "phase": st,
            "keep": _keep(md),
        }
    F.add("k8s.pv.count", len(items), src)
    F.add("k8s.pv.by_phase", by_phase, src)
    F.add("k8s.pv.released", sorted(released)[:30], src)
    F.add("k8s.pv.released_count", len(released), src)
    F.add("k8s.pv.node_local", sorted(local_pvs)[:30], src)
    F.add("k8s.pv.node_local_count", len(local_pvs), src)
    F.add("k8s.pv.claims", claims, src)
    F.add("k8s.pv.info", info, src)


def p_volumeattach(o, F, src):
    """VolumeAttachments that never reached attached=true.

    The object name alone (`csi-abc123`) identifies nothing: an operator
    cannot tell which volume, node or pod it belongs to. Each stuck entry
    therefore carries the PV, the node it is being attached to, the CSI
    driver, and the pod(s) waiting on the claim - the join to the pod is the
    whole point, since that is what the attachment is blocking.
    """
    items = _items(o)
    stuck, stuck_named = [], []
    for a in items:
        md = a.get("metadata") or {}
        name = md.get("name")
        status = a.get("status") or {}
        if status.get("attached"):
            continue
        spec = a.get("spec") or {}
        pv = (spec.get("source") or {}).get("persistentVolumeName")
        driver = spec.get("attacher") or "-"
        node = spec.get("nodeName") or "-"
        if name:
            stuck_named.append(name)
        stuck.append({
            "name": name or "-",
            "pv": pv,
            "node": node,
            "driver": driver,
            "error": (status.get("attachError") or {}).get("message")
                     or (status.get("attachError") or {}).get("error"),
        })
    F.add("k8s.volumeattachment.count", len(items), src)
    F.add("k8s.volumeattachment.unattached_count", len(stuck), src)
    if stuck:
        F.add("k8s.volumeattachment.unattached", stuck[:20], src)
        # Kept for anything keyed on the old flat list of names.
        F.add("k8s.volumeattachment.unattached_names",
              sorted(stuck_named)[:20], src)


# ------------------------------------------------------------- disruption
def p_pdb(o, F, src):
    items = _items(o)
    blocking = []
    for p in items:
        st = p.get("status") or {}
        allowed = st.get("disruptionsAllowed")
        if allowed is not None and allowed <= 0:
            blocking.append("%s (healthy %s/%s)" % (
                _nn(p), st.get("currentHealthy"), st.get("desiredHealthy")))
    F.add("k8s.pdb.count", len(items), src)
    F.add("k8s.pdb.blocking", sorted(blocking)[:30], src)
    F.add("k8s.pdb.blocking_count", len(blocking), src)


# ---------------------------------------------------------------- webhooks
def _wh_parse(o, F, src, kind):
    items = _items(o)
    fail_closed, entries = [], {}
    for w in items:
        name = (w.get("metadata") or {}).get("name") or "?"
        for hook in w.get("webhooks") or []:
            fp = hook.get("failurePolicy", "Fail")
            cc = hook.get("clientConfig") or {}
            svc = cc.get("service") or {}
            key = "%s/%s" % (name, hook.get("name") or "?")
            # What the webhook intercepts decides the blast radius when its
            # backend is gone: a hook on pods blocks every Deployment rollout
            # in the cluster, a hook on one CRD blocks only that CRD.
            groups, resources, ops = set(), set(), set()
            for r in hook.get("rules") or []:
                gs = r.get("apiGroups") or [""]
                groups.update(gs)
                for g in gs:
                    for res in r.get("resources") or []:
                        resources.add("%s/%s" % (g or "core", res))
                ops.update(r.get("operations") or [])
            entry = {
                "failurePolicy": fp,
                "timeoutSeconds": hook.get("timeoutSeconds"),
                "service": ("%s/%s" % (svc.get("namespace"), svc.get("name"))
                            if svc.get("name") else None),
                "url": cc.get("url"),
                "kind": kind,
                "configuration": name,
                "namespace_selector": bool(hook.get("namespaceSelector")),
                "object_selector": bool(hook.get("objectSelector")),
            }
            # No rules recorded means scope UNKNOWN, not "matches nothing":
            # the rule must not downgrade what it cannot see.
            if groups:
                entry["api_groups"] = sorted(groups)
                entry["resources"] = sorted(resources)[:20]
                entry["operations"] = sorted(ops)
            entries[key] = entry
            if fp == "Fail":
                fail_closed.append(key)
    F.add("k8s.webhook.%s" % kind, entries, src)
    F.add("k8s.webhook.%s_fail_closed" % kind, sorted(fail_closed), src)


def p_validatingwh(o, F, src):
    _wh_parse(o, F, src, "validating")


def p_mutatingwh(o, F, src):
    _wh_parse(o, F, src, "mutating")


def p_endpointslices(o, F, src):
    """service -> count of ready endpoints. Input to the webhook-reachability rule.
    Also ready AND total per service for housekeeping: "no ready endpoints
    with pods behind it" is a workload problem, "no endpoints at all" may be
    an abandoned object - those are different answers."""
    ready = {}
    totals = {}
    for es in _items(o):
        md = es.get("metadata") or {}
        ns = md.get("namespace") or "-"
        svc = (md.get("labels") or {}).get("kubernetes.io/service-name")
        if not svc:
            continue
        key = "%s/%s" % (ns, svc)
        n, t = 0, 0
        for ep in es.get("endpoints") or []:
            c = ep.get("conditions") or {}
            t += len(ep.get("addresses") or []) or 1
            if c.get("ready") is not False:
                n += len(ep.get("addresses") or []) or 1
        ready[key] = ready.get(key, 0) + n
        totals[key] = totals.get(key, 0) + t
    F.add("k8s.service.ready_endpoints", ready, src)
    F.add("k8s.service.endpoints",
          {k: {"ready": ready[k], "total": totals[k]} for k in totals}, src)


# ------------------------------------------------------------ workloads
def _workload_template(d):
    """(replicas, pod-template labels/images, keep annotation, created) for
    selector joins and demo-image matching."""
    spec = d.get("spec") or {}
    labels = (((spec.get("template") or {}).get("metadata") or {})
              .get("labels")) or {}
    images = [c.get("image") for c in
              ((spec.get("template") or {}).get("spec") or {})
              .get("containers") or [] if c.get("image")]
    return {"replicas": spec.get("replicas"),
            "labels": labels, "images": images,
            "created": (d.get("metadata") or {}).get("creationTimestamp"),
            "keep": _keep(d.get("metadata") or {})}


def p_deployments(o, F, src):
    items = _items(o)
    degraded, paused, zeroed = [], [], []
    templates = {}
    for d in items:
        st = d.get("status") or {}
        spec = d.get("spec") or {}
        want = spec.get("replicas")
        have = st.get("readyReplicas") or 0
        if spec.get("paused"):
            paused.append(_nn(d))
        if want == 0:
            zeroed.append(_nn(d))
        if want and have < want:
            degraded.append("%s (%s/%s)" % (_nn(d), have, want))
        templates["Deployment:%s" % _nn(d)] = _workload_template(d)
    _problem_list(F, src, "k8s.deployment.paused", paused, limit=60)
    if zeroed:
        F.add("k8s.workload.scaled_to_zero", sorted(zeroed), src)
    F.add("k8s.deployment.count", len(items), src)
    _problem_list(F, src, "k8s.deployment.degraded", degraded, limit=30)
    F.add("k8s.deployment.templates", templates, src)


def p_statefulsets(o, F, src):
    items = _items(o)
    degraded = []
    templates = {}
    for d in items:
        st = d.get("status") or {}
        want = (d.get("spec") or {}).get("replicas")
        have = st.get("readyReplicas") or 0
        if want and have < want:
            degraded.append("%s (%s/%s)" % (_nn(d), have, want))
        templates["StatefulSet:%s" % _nn(d)] = _workload_template(d)
    F.add("k8s.statefulset.count", len(items), src)
    _problem_list(F, src, "k8s.statefulset.degraded", degraded, limit=30)
    F.add("k8s.statefulset.templates", templates, src)


def p_daemonsets(o, F, src):
    items = _items(o)
    degraded = []
    for d in items:
        st = d.get("status") or {}
        want = st.get("desiredNumberScheduled") or 0
        have = st.get("numberReady") or 0
        if want and have < want:
            degraded.append("%s (%s/%s)" % (_nn(d), have, want))
    F.add("k8s.daemonset.count", len(items), src)
    _problem_list(F, src, "k8s.daemonset.degraded", degraded, limit=30)


def p_jobs(o, F, src):
    """A Job is failed when its Failed condition is True.

    status.failed counts failed pod ATTEMPTS. A Job that failed once and then
    succeeded on retry has status.failed=1 and is perfectly healthy - counting
    it put dozens of successful CronJob runs into 'Jobs with failures'.
    """
    items = _items(o)
    failed = []
    for j in items:
        st = j.get("status") or {}
        conds = {c.get("type"): c for c in st.get("conditions") or []
                 if isinstance(c, dict)}
        fc = conds.get("Failed")
        if fc and fc.get("status") == "True":
            failed.append("%s (%s, %s pod failure(s))" % (
                _nn(j), fc.get("reason") or "Failed", st.get("failed") or 0))
    F.add("k8s.job.count", len(items), src)
    _problem_list(F, src, "k8s.job.failed", failed, limit=30)


_CRON_MACROS = {"@yearly": 366, "@annually": 366, "@monthly": 31, "@weekly": 7,
                "@daily": 1, "@midnight": 1, "@hourly": 1.0 / 24}


def _cron_gap(field, lo, hi, fold=None):
    """Largest gap, in field units, between consecutive values of one cron
    field. Anything unparseable returns the full span - the conservative
    answer, since it can only make a CronJob look LESS overdue."""
    span = hi - lo + 1 - len(fold or {})
    if field in ("*", "?"):
        return 1
    vals = set()
    try:
        for part in field.split(","):
            step = 1
            if "/" in part:
                part, st = part.split("/", 1)
                step = int(st)
            if part in ("*", "?"):
                a, b = lo, hi
            elif "-" in part:
                a, b = (int(x) for x in part.split("-", 1))
            else:
                a = int(part)
                b = a if step == 1 else hi
            vals.update(range(a, b + 1, step))
    except ValueError:
        return span
    if fold:
        vals = {fold.get(v, v) for v in vals}
        hi = max(k for k in range(lo, hi + 1) if k not in fold)
    vals = sorted(v for v in vals if lo <= v <= hi)
    if not vals:
        return span
    gaps = [b - a for a, b in zip(vals, vals[1:])] + [vals[0] + span - vals[-1]]
    return max(gaps)


def cron_period_days(expr):
    """Longest expected interval between runs of a CronJob schedule, in days.

    Approximate on purpose (months are 31 days): the question is only whether a
    CronJob is overdue by more than its own rhythm. None if unparseable.
    """
    if not expr:
        return None
    toks = [t for t in str(expr).split() if "=" not in t]   # CRON_TZ=..., TZ=...
    if len(toks) == 1 and toks[0] in _CRON_MACROS:
        return float(_CRON_MACROS[toks[0]])
    if len(toks) != 5:
        return None
    minute, hour, dom, month, dow = toks
    if month not in ("*", "?"):
        return 31.0 * _cron_gap(month, 1, 12)
    if dom not in ("*", "?"):
        return 1.0 * _cron_gap(dom, 1, 31)
    if dow not in ("*", "?"):
        return 1.0 * _cron_gap(dow, 0, 7, fold={7: 0})      # 0 and 7 are Sunday
    if hour not in ("*", "?"):
        return _cron_gap(hour, 0, 23) / 24.0
    return _cron_gap(minute, 0, 59) / 1440.0


CRONJOB_MIN_STALE_DAYS = 2.0


def p_cronjobs(o, F, src):
    """Overdue = not run for twice its own schedule interval (at least 2 days).

    A flat 2-day threshold flagged every weekly and monthly CronJob as stale
    for most of its cycle, and counted suspended ones - which are not
    supposed to run at all.
    """
    items = _items(o)
    suspended, never_ran, stale = [], [], []
    for c in items:
        spec = c.get("spec") or {}
        st = c.get("status") or {}
        if spec.get("suspend"):
            suspended.append(_nn(c))
            continue
        last = st.get("lastScheduleTime")
        if not last:
            never_ran.append(_nn(c))
            continue
        age = _age_days(last)
        period = cron_period_days(spec.get("schedule"))
        limit = max(CRONJOB_MIN_STALE_DAYS, 2 * period) if period else CRONJOB_MIN_STALE_DAYS
        if age is not None and age > limit:
            stale.append("%s (last run %.1fd ago, schedule %s)"
                         % (_nn(c), age, spec.get("schedule") or "?"))
    F.add("k8s.cronjob.count", len(items), src)
    F.add("k8s.cronjob.suspended", sorted(suspended)[:20], src)
    F.add("k8s.cronjob.suspended_count", len(suspended), src)
    F.add("k8s.cronjob.never_scheduled", sorted(never_ran)[:20], src)
    _problem_list(F, src, "k8s.cronjob.stale", stale, limit=30)


# -------------------------------------------------------------- RKE2 bits
def p_helmcharts(o, F, src):
    items = _items(o)
    charts = {}
    for c in items:
        spec = c.get("spec") or {}
        charts[_nn(c)] = {"chart": spec.get("chart"), "version": spec.get("version"),
                          "targetNamespace": spec.get("targetNamespace")}
    F.add("k8s.helmchart.count", len(items), src)
    F.add("k8s.helmchart.charts", charts, src)


def p_helmchartcfg(o, F, src):
    items = _items(o)
    F.add("k8s.helmchartconfig.names", sorted([_nn(c) for c in items]), src)
    F.add("k8s.helmchartconfig.count", len(items), src)


def p_apiservices(o, F, src):
    items = _items(o)
    unavailable = []
    for a in items:
        conds = {c.get("type"): c for c in (a.get("status") or {}).get("conditions") or []}
        av = conds.get("Available")
        if av and av.get("status") != "True":
            unavailable.append("%s (%s)" % ((a.get("metadata") or {}).get("name"),
                                            av.get("reason")))
    F.add("k8s.apiservice.count", len(items), src)
    F.add("k8s.apiservice.unavailable", sorted(unavailable), src)
    F.add("k8s.apiservice.unavailable_count", len(unavailable), src)


def p_leases(o, F, src):
    """Leader-election churn: renewals are normal, holder changes are the signal."""
    holders = {}
    for l in _items(o):
        md = l.get("metadata") or {}
        ns = md.get("namespace") or "-"
        if ns not in ("kube-system", "kube-node-lease"):
            continue
        if ns == "kube-node-lease":
            continue
        spec = l.get("spec") or {}
        holders["%s/%s" % (ns, md.get("name"))] = spec.get("holderIdentity")
    F.add("k8s.lease.holders", holders, src)


def p_version(o, F, src):
    for key, path in (("client", "clientVersion"), ("server", "serverVersion")):
        v = o.get(path) or {}
        if v.get("gitVersion"):
            F.add("k8s.version.%s" % key, v["gitVersion"], src)


def p_readyz(o, F, src):
    """Plain text: 'ok' or a verbose list with [-] markers for failures."""
    text = o if isinstance(o, str) else str(o)
    failing = [l.strip() for l in text.splitlines() if l.startswith("[-]")]
    F.add("k8s.apiserver.readyz_ok", text.strip().endswith("readyz check passed")
          or text.strip() == "ok", src)
    if failing:
        F.add("k8s.apiserver.readyz_failing", failing[:10], src)


def p_livez(o, F, src):
    text = o if isinstance(o, str) else str(o)
    failing = [l.strip() for l in text.splitlines() if l.startswith("[-]")]
    F.add("k8s.apiserver.livez_ok", text.strip().endswith("livez check passed")
          or text.strip() == "ok", src)
    if failing:
        F.add("k8s.apiserver.livez_failing", failing[:10], src)


def p_apiserver_metrics(o, F, src):
    for k, v in (o.get("metrics") or {}).items():
        F.add(k, v, src)
    if o.get("error"):
        F.add("k8s.apiserver.metrics_error", o["error"], src)


def p_tls_probe(o, F, src):
    api = o.get("apiserver") or {}
    F.add("k8s.cert.apiserver_days_remaining", api.get("days_remaining"), src)
    F.add("k8s.cert.apiserver_not_after", api.get("not_after"), src)
    if api.get("error"):
        F.add("k8s.cert.apiserver_probe_error", api["error"], src)
    F.add("k8s.cert.coverage_gaps", o.get("coverage_gaps"), src)


def p_events_doc(o, F, src):
    """The filtered-events document, from collect_events.py --once (live)
    or fetch_event_buffer.py (buffered CronJob). Both emit the same shape:
    node keys "Node|<node>|<reason>", platform keys
    "<ns>|<kind>|<owner>|<reason>", and per-reason tenant pattern aggregates.
    """
    node = o.get("node") or {}
    platform = o.get("platform") or {}
    patterns = o.get("patterns") or {}

    node_by_reason = {}
    for key, v in node.items():
        parts = key.split("|")
        if len(parts) != 3:
            continue
        reason = parts[2]
        node_by_reason[reason] = node_by_reason.get(reason, 0) + (v.get("count") or 0)
    F.add("k8s.events.node_keys", node, src)
    F.add("k8s.events.node_by_reason", node_by_reason, src)

    plat_by_reason = {}
    for key, v in platform.items():
        parts = key.split("|")
        if len(parts) != 4:
            continue
        reason = parts[3]
        plat_by_reason[reason] = plat_by_reason.get(reason, 0) + (v.get("count") or 0)
    F.add("k8s.events.platform_keys", platform, src)
    F.add("k8s.events.platform_by_reason", plat_by_reason, src)
    F.add("k8s.events.platform_key_count", len(platform), src)

    F.add("k8s.events.patterns", patterns, src)
    if o.get("dropped"):
        F.add("k8s.events.dropped", o["dropped"], src)
    if src == "k_events":
        F.add("k8s.events.mode", "live", src)
    else:
        F.add("k8s.events.mode", "buffered", src)

    buf = o.get("buffer")
    if buf:
        F.add("k8s.events.buffer_available", True, src)
        F.add("k8s.events.buffer", {
            "writes": buf.get("writes"),
            "ok_writes": buf.get("ok_writes"),
            "expected_writes": buf.get("expected_writes"),
            "last_write_at": buf.get("last_write_at"),
            "last_write_age_m": buf.get("last_write_age_m"),
            "failed_requests": buf.get("failed_requests") or [],
            "window_from": buf.get("window_from"),
        }, src)


def p_event_buffer(o, F, src):
    """The buffered (CronJob) variant. Two failure shapes must both keep the
    live k_events facts: the ConfigMap missing entirely, and the buffer
    structurally there but with zero writes in the window - which is exactly
    the stopped-CronJob case the staleness rule reports on."""
    buf = o.get("buffer") or {}
    F.add("k8s.events.buffer_available", bool(o.get("available")), src)
    if buf:
        F.add("k8s.events.buffer", {
            "writes": buf.get("writes"),
            "ok_writes": buf.get("ok_writes"),
            "expected_writes": buf.get("expected_writes"),
            "last_write_at": buf.get("last_write_at"),
            "last_write_age_m": buf.get("last_write_age_m"),
            "failed_requests": buf.get("failed_requests") or [],
            "window_from": buf.get("window_from"),
        }, src)
    if not o.get("available") or not (buf.get("writes") or 0):
        return
    p_events_doc(o, F, src)


def p_events(o, F, src):
    p_events_doc(o, F, src)


# Every k_log_* command prints the same collect_logs.py document:
# {check, status, window, pods, classes, ignored, ...}. Facts live under
# k8s.log.<check>.* so rules never touch raw command names.
def p_log_check(o, F, src):
    name = o.get("check")
    if not name:
        return
    b = "k8s.log.%s" % name
    checks = list(F.get_value("k8s.log.checks", []) or [])
    if name not in checks:
        checks.append(name)
        F.add("k8s.log.checks", sorted(checks), src)
    F.add(b + ".status", o.get("status"), src)
    F.add(b + ".expect_pods", o.get("expect_pods", True), src)
    F.add(b + ".namespace", o.get("namespace"), src)
    F.add(b + ".selector", o.get("selector"), src)
    F.add(b + ".container", o.get("container"), src)
    win = o.get("window") or {}
    F.add(b + ".window_from", win.get("from"), src)
    F.add(b + ".window_to", win.get("to"), src)
    pods = o.get("pods") or []
    F.add(b + ".pods", pods, src)
    F.add(b + ".pod_count", len(pods), src)
    if o.get("pod_overflow"):
        F.add(b + ".pod_overflow", o["pod_overflow"], src)
    worst = "complete"
    for p in pods:
        cov = p.get("coverage") or "none"
        if cov == "none":
            worst = "none"
        elif cov == "partial" and worst == "complete":
            worst = "partial"
    if pods:
        F.add(b + ".coverage", worst, src)
    for cls, data in (o.get("classes") or {}).items():
        F.add("%s.class.%s" % (b, cls), data, src)
    if o.get("ignored"):
        F.add(b + ".ignored", o["ignored"], src)


def p_top_nodes(o, F, src):
    """kubectl top nodes --no-headers: NAME CPU(cores) CPU% MEM MEM%"""
    text = o if isinstance(o, str) else str(o)
    usage = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        name = parts[0]
        try:
            usage[name] = {
                "cpu_m": cpu_millis(parts[1]),
                "cpu_pct": float(parts[2].rstrip("%")),
                "mem_bytes": mem_bytes(parts[3]),
                "mem_pct": float(parts[4].rstrip("%")),
            }
        except (ValueError, TypeError):
            continue
    if usage:
        F.add("k8s.node.usage", usage, src)


# ---------------------------------------------------------------- usage
_USAGE_YOUNG_H = 12.0


def _usage_num(v):
    """'350m', '0.35', '2', 'n/a' -> float in the column's unit, or None."""
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.lower() in ("n/a", "na", "none", "-", "null"):
        return None
    if s.endswith("%"):
        s = s[:-1]
    if s.endswith("m"):
        try:
            return float(s[:-1]) / 1000.0
        except ValueError:
            return None
    try:
        return float(s)
    except ValueError:
        return None


def _usage_age_h(v):
    s = str(v or "").strip().lower()
    if not s:
        return None
    total = 0.0
    any_part = False
    for num, unit in re.findall(r"(\d+(?:\.\d+)?)([smhd])", s):
        total += float(num) * {"s": 1 / 3600, "m": 1 / 60, "h": 1, "d": 24}[unit]
        any_part = True
    if any_part:
        return total
    try:
        return float(s)               # bare hours
    except ValueError:
        return None


def _usage_columns(header):
    """Map the CSV header to (ns, pod, request, usage, age, model) column
    indexes, tolerating the binary's column naming. Real output is
    `namespace,pod,prometheus_usage,k8s_requests,age[,model_name]`."""
    low = [h.strip().lower().replace("-", "_") for h in header]

    def idx_any(names, substrings=()):
        for n in names:
            if n in low:
                return low.index(n)
        for s in substrings:
            for i, h in enumerate(low):
                if s in h:
                    return i
        return None
    ns = idx_any(("namespace", "ns"))
    pod = idx_any(("pod", "pod_name", "name"))
    req = idx_any(("request", "requests", "cpu_request", "gpu_request",
                   "cpu_req", "requested"), ("request",))
    use = idx_any(("usage", "prometheus_usage", "usage_avg", "avg",
                   "usage_24h_avg", "cpu_usage", "gpu_usage"), ("usage",))
    age = idx_any(("age", "age_h", "age_hours", "pod_age"))
    model = idx_any(("model_name", "model", "gpu_model"))
    if ns is None or pod is None or req is None:
        raise ValueError("no usable columns in %s" % (header,))
    return ns, pod, req, use, age, model


def p_usage(o, F, src):
    """k8s-pod-resource-usage CSV, wrapped by collect_logs's sibling
    collect_usage.py. Lossy by contract: top-N rows + aggregates survive,
    the full table does not."""
    import csv as _csv
    import io as _io
    res = o.get("resource") or ("gpu" if "gpu" in src else "cpu")
    b = "k8s.usage.%s" % res
    if o.get("error"):
        F.add(b + ".error", o["error"], src)
        return
    if o.get("excluded"):
        F.add(b + ".excluded_namespaces", o["excluded"], src)

    text = o.get("csv") or ""
    rows = []
    try:
        rdr = _csv.reader(_io.StringIO(text))
        header = next(rdr, None)
        ns_i, pod_i, req_i, use_i, age_i, model_i = _usage_columns(header or [])
        for rec in rdr:
            if len(rec) <= max([i for i in (ns_i, pod_i, req_i) if i is not None]):
                continue
            req = _usage_num(rec[req_i]) if req_i is not None else None
            use = _usage_num(rec[use_i]) if use_i is not None else None
            use_raw = rec[use_i].strip() if use_i is not None else ""
            # GPU usage is a percentage of the REQUESTED cards, not an
            # absolute: "6.0%" of 1 card is 0.06, not 6 - the ratio is the
            # number that makes waste arithmetic meaningful.
            if use is not None and "%" in use_raw and req is not None:
                use = req * use / 100.0
            rows.append({
                "nn": "%s/%s" % (rec[ns_i].strip(), rec[pod_i].strip()),
                "req": req,
                "use": use,
                "use_raw": use_raw,
                "model": (rec[model_i].strip()
                          if model_i is not None else ""),
                "age_h": _usage_age_h(rec[age_i]) if age_i is not None else None,
            })
    except Exception as exc:
        F.add(b + ".parse_error", "%s: %s" % (type(exc).__name__, exc), src)
        return

    # Pods younger than 12 hours: a 24 h average over 2 h of data misleads.
    young = [r for r in rows if r["age_h"] is not None
             and r["age_h"] < _USAGE_YOUNG_H]
    ranked = [r for r in rows if r not in young]
    no_series = [r for r in ranked if r["use"] is None]

    waste_rows, waste_total = [], 0.0
    for r in ranked:
        if r["req"] is None or r["use"] is None:
            continue
        if r["use"] < r["req"]:
            w = r["req"] - r["use"]
            waste_total += w
            waste_rows.append((w, r))
    waste_rows.sort(key=lambda wr: -wr[0])
    limit = 30 if res == "gpu" else 20

    F.add(b + ".total_pods", len(rows), src)
    F.add(b + ".excluded_young", len(young), src)
    F.add(b + ".no_series", len(no_series), src)
    F.add(b + ".waste_total", round(waste_total, 3), src)
    top = [[r["nn"], r["req"], ("n/a" if r["use"] is None else r["use"]),
            round(w, 3),
            ("%.0f h" % r["age_h"]) if r["age_h"] is not None else "?"]
           for w, r in waste_rows[:20]]
    F.add(b + ".top", top, src)
    if res == "gpu":
        def key(r):
            return (0 if r["use"] is None else 1,
                    r["use"] if r["use"] is not None else 0,
                    -(r["age_h"] or 0))
        gpu_top = sorted(ranked, key=key)[:limit]
        F.add(b + ".top_gpu", [
            [r["nn"], (r["use_raw"] or "n/a"), r["req"], r.get("model") or "",
             ("%.0f h" % r["age_h"]) if r["age_h"] is not None else "?"]
            for r in gpu_top], src)


def p_storageclass(o, F, src):
    items = _items(o)
    names, default = [], None
    for s in items:
        md = s.get("metadata") or {}
        n = md.get("name")
        names.append(n)
        ann = md.get("annotations") or {}
        if ann.get("storageclass.kubernetes.io/is-default-class") == "true":
            default = n
    F.add("k8s.storageclass.names", sorted([n for n in names if n]), src)
    F.add("k8s.storageclass.default", default, src)


def p_csr(o, F, src):
    pending = [(c.get("metadata") or {}).get("name") for c in _items(o)
               if not ((c.get("status") or {}).get("certificate"))]
    pending = [p for p in pending if p]
    F.add("k8s.csr.pending_count", len(pending), src)
    if pending:
        F.add("k8s.csr.pending", sorted(pending)[:20], src)


def p_crds(o, F, src):
    """Which API groups are actually served by CRDs. A fail-closed webhook
    whose rules only name groups that are not installed can never match."""
    groups = set()
    for c in _items(o):
        g = (c.get("spec") or {}).get("group")
        if g:
            groups.add(g)
    F.add("k8s.crd.count", len(_items(o)), src)
    F.add("k8s.crd.groups", sorted(groups), src)


def p_services(o, F, src):
    """Service existence, as distinct from endpoint readiness: a webhook
    pointing at a Service that no longer exists is a leftover, not an outage
    in progress. `info` carries the housekeeping fields."""
    names, info = [], {}
    for s in _items(o):
        md = s.get("metadata") or {}
        spec = s.get("spec") or {}
        st = s.get("status") or {}
        nn = _nn(s)
        names.append(nn)
        lb_ips = []
        for i in ((st.get("loadBalancer") or {}).get("ingress") or []):
            if i.get("ip"):
                lb_ips.append(i["ip"])
            elif i.get("hostname"):
                lb_ips.append(i["hostname"])
        info[nn] = {
            "uid": md.get("uid"),
            "type": spec.get("type") or "ClusterIP",
            "selector": spec.get("selector") or {},
            "owner_kinds": sorted({r.get("kind") or "?" for r in
                                   md.get("ownerReferences") or []}),
            "created": md.get("creationTimestamp"),
            "lb_ips": lb_ips,
            "keep": _keep(md),
        }
    names = sorted(names)
    F.add("k8s.service.count", len(names), src)
    F.add("k8s.service.names", names, src)
    F.add("k8s.service.info", info, src)


def p_namespaces(o, F, src):
    info = {}
    for n in _items(o):
        md = n.get("metadata") or {}
        name = md.get("name")
        if not name:
            continue
        info[name] = {
            "uid": md.get("uid"),
            "created": md.get("creationTimestamp"),
            "phase": (n.get("status") or {}).get("phase"),
            "deletion_timestamp": md.get("deletionTimestamp"),
            "keep": _keep(md),
        }
    F.add("k8s.ns.count", len(info), src)
    F.add("k8s.ns.info", info, src)


def p_ingresses(o, F, src):
    info = {}
    for ig in _items(o):
        md = ig.get("metadata") or {}
        spec = ig.get("spec") or {}
        hosts, backends = [], []
        default_be = ((spec.get("defaultBackend") or {}).get("service") or {})
        if default_be.get("name"):
            backends.append(default_be["name"])
        for rule in spec.get("rules") or []:
            if rule.get("host"):
                hosts.append(rule["host"])
            for path in ((rule.get("http") or {}).get("paths") or []):
                svc = ((path.get("backend") or {}).get("service") or {})
                if svc.get("name"):
                    backends.append(svc["name"])
        info[_nn(ig)] = {
            "uid": md.get("uid"),
            "hosts": sorted(set(hosts)),
            "backends": sorted(set(backends)),
            "created": md.get("creationTimestamp"),
            "keep": _keep(md),
        }
    F.add("k8s.ingress.count", len(info), src)
    F.add("k8s.ingress.info", info, src)


def p_hpa(o, F, src):
    info = {}
    for h in _items(o):
        md = h.get("metadata") or {}
        spec = h.get("spec") or {}
        target = spec.get("scaleTargetRef") or {}
        able_reason, able = None, None
        for c in (h.get("status") or {}).get("conditions") or []:
            if c.get("type") == "AbleToScale":
                able = c.get("status") == "True"
                able_reason = c.get("reason")
        info[_nn(h)] = {
            "uid": md.get("uid"),
            "target_kind": target.get("kind"),
            "target_name": target.get("name"),
            "able_to_scale": able,
            "able_reason": able_reason,
            "created": md.get("creationTimestamp"),
            "keep": _keep(md),
        }
    F.add("k8s.hpa.count", len(info), src)
    F.add("k8s.hpa.info", info, src)


def p_clusterpolicy(o, F, src):
    """NVIDIA GPU operator ClusterPolicy: the one-word rollout verdict."""
    states = {}
    for c in _items(o):
        md = c.get("metadata") or {}
        st = ((c.get("status") or {}).get("state"))
        if md.get("name"):
            states[md["name"]] = st
    F.add("k8s.gpu.clusterpolicy_states", states, src)
    F.add("k8s.gpu.clusterpolicy_count", len(states), src)


# ---------------------------------------------------------------- acme/cert
def p_etcd_snapshots(o, F, src):
    """etcdsnapshotfiles.k3s.cattle.io: per node, the freshest LOCAL and S3
    snapshot age and the snapshot cadence. Snapshot rot is silent from
    inside the cluster - these are the only objects that prove it."""
    per_node = {}
    window_count = {}
    for s in _items(o):
        spec = s.get("spec") or {}
        node = spec.get("nodeName")
        loc = spec.get("location") or ""
        created = (s.get("metadata") or {}).get("creationTimestamp")
        if not node or not created:
            continue
        age_h = _age_hours(created)
        if age_h is None:
            continue
        kind = "s3" if loc.startswith("s3://") else "local"
        slot = per_node.setdefault(node, {})
        key = "%s_newest_age_h" % kind
        if key not in slot or age_h < slot[key]:
            slot[key] = age_h
        if age_h <= 48.0:
            window_count[node] = window_count.get(node, 0) + 1
    F.add("k8s.etcd.snapshot_files", per_node, src)
    F.add("k8s.etcd.snapshot_file_count", sum(window_count.values()), src)
    # Cadence per (node, kind) series: mixed nodes would interleave and
    # halve the apparent interval.
    series = {}
    for s in _items(o):
        md = s.get("metadata") or {}
        spec = s.get("spec") or {}
        created = md.get("creationTimestamp")
        node = spec.get("nodeName")
        loc = spec.get("location") or ""
        if not (created and node):
            continue
        kind = "s3" if loc.startswith("s3://") else "local"
        series.setdefault((node, kind), []).append(created)
    gaps = []
    for key, times in series.items():
        times = sorted(times)
        for a, b in zip(times, times[1:]):
            g = (_age_hours(a) or 0) - (_age_hours(b) or 0)
            if g > 0.05:
                gaps.append(g)
    if gaps:
        gaps.sort()
        F.add("k8s.etcd.snapshot_cadence_h", gaps[len(gaps) // 2], src)


def p_acme_solvers(o, F, src):
    """http-01 solver pods (label acme.cert-manager.io/http01-solver=true)."""
    solvers = []
    for p in _items(o):
        md = p.get("metadata") or {}
        st = p.get("status") or {}
        spec = p.get("spec") or {}
        created = md.get("creationTimestamp")
        solvers.append({
            "ns": md.get("namespace") or "-",
            "pod": md.get("name") or "?",
            "node": spec.get("nodeName"),
            "created": created,
            "age_h": round(_age_hours(created) or 0, 1),
            "phase": st.get("phase"),
        })
    F.add("k8s.acme.solvers", solvers, src)
    F.add("k8s.acme.solvers_count", len(solvers), src)
    old = [s for s in solvers if (s.get("age_h") or 0) >= 1.0]
    by_ns = {}
    for s in old:
        by_ns[s["ns"]] = by_ns.get(s["ns"], 0) + 1
    F.add("k8s.acme.solvers_stale", [s for s in solvers
                                     if (s.get("age_h") or 0) >= 1.0], src)
    F.add("k8s.acme.solvers_stale_count", len(old), src)
    F.add("k8s.acme.solvers_stale_by_ns", by_ns, src)


def p_acme_challenges(o, F, src):
    out = []
    for c in _items(o):
        md = c.get("metadata") or {}
        spec = c.get("spec") or {}
        out.append({
            "ns": md.get("namespace") or "-",
            "name": md.get("name") or "?",
            "dnsName": spec.get("dnsName"),
            "state": (c.get("status") or {}).get("state")
                     or (c.get("status") or {}).get("reason"),
            "reason": ((c.get("status") or {}).get("reason")
                       or spec.get("reason")),
        })
    F.add("k8s.acme.challenges", out[:500], src)
    F.add("k8s.acme.challenges_count", len(out), src)


def p_acme_certificates(o, F, src):
    expired, expiring, not_ready = [], [], []
    for c in _items(o):
        st = c.get("status") or {}
        nn = _nn(c)
        not_after = st.get("notAfter")
        days = (_age_days_future(not_after)
                if not_after else None)
        ready = None
        for cond in st.get("conditions") or []:
            if cond.get("type") == "Ready":
                ready = cond.get("status") == "True"
        if days is not None and days <= 0:
            expired.append("%s (expired %.0f days ago)"
                           % (nn, -days))
        elif days is not None and days <= 7 and ready is False:
            expiring.append("%s (%.0f days left, not Ready)"
                            % (nn, days))
        if ready is False:
            not_ready.append(nn)
    F.add("k8s.acme.certificates_count", len(_items(o)), src)
    F.add("k8s.acme.certificates_expired", sorted(expired), src)
    F.add("k8s.acme.certificates_expiring_not_ready", sorted(expiring), src)
    F.add("k8s.acme.certificates_not_ready", sorted(not_ready)[:40], src)


def p_acme_probe(o, F, src):
    F.add("k8s.acme.dns", o.get("dns") or {}, src)
    F.add("k8s.acme.dns_expected", o.get("expected") or [], src)
    if o.get("error"):
        F.add("k8s.acme.probe_error", o["error"], src)


def p_networkpolicies(o, F, src):
    by_ns = {}
    for np in _items(o):
        md = np.get("metadata") or {}
        spec = np.get("spec") or {}
        ns = md.get("namespace") or "-"
        ingress = spec.get("ingress") or []
        types = spec.get("policyTypes") or []
        by_ns.setdefault(ns, []).append({
            "name": md.get("name") or "?",
            "empty_ingress": ingress == [] or any(not r.get("from")
                        and not r.get("ports") for r in ingress or []),
            "types": types,
            "ingress": [{"from": [list(s.keys()) for s in r.get("from") or []],
                         "ports": [p.get("port") for p in r.get("ports") or []]}
                        for r in ingress],
        })
    F.add("k8s.netpol.by_ns", by_ns, src)


def p_resourceslices(o, F, src):
    """DRA ResourceSlices, per node. A DRA-only GPU node has no nvidia.com/*
    extended resources - the slice is the only way it advertises."""
    by_node = {}
    for s in _items(o):
        spec = s.get("spec") or {}
        node = spec.get("nodeName")
        if not node:
            continue
        devices = len(spec.get("devices") or []) or 0
        entry = by_node.setdefault(node, {})
        drv = str(spec.get("driver") or "?")
        slot = entry.setdefault(drv, {"driver": drv, "pools": 0, "devices": 0})
        slot["pools"] += 1
        slot["devices"] += devices
    out = {n: sorted(v.values(), key=lambda s: s["driver"])
           for n, v in by_node.items()}
    F.add("k8s.node.dra_slices", out, src)
    F.add("k8s.node.dra_nodes", sorted(out), src)
    if out:
        # p_nodes ran before this command existed; fold DRA-only allocators
        # into the GPU node set so none of them read as "no GPU".
        prev = F.get_value("k8s.node.gpu_nodes") or []
        merged = sorted(set(prev) | set(out))
        if merged != prev:
            F.add("k8s.node.gpu_nodes", merged, src)


def p_gateways(o, F, src):
    items, not_ready = [], []
    for g in _items(o):
        nn = _nn(g)
        conds = {}
        for c in (g.get("status") or {}).get("conditions") or []:
            conds[c.get("type")] = {"status": c.get("status"),
                                    "reason": c.get("reason")}
        bad = []
        for t in ("Accepted", "Programmed"):
            c = conds.get(t)
            if c and c.get("status") != "True":
                bad.append("%s=%s (%s)" % (t, c.get("status") or "?",
                                           c.get("reason") or "?"))
            elif c is None:
                bad.append("%s missing" % t)
        if bad:
            not_ready.append({"nn": nn, "issues": bad})
        items.append(nn)
    F.add("k8s.gateway.count", len(items), src)
    F.add("k8s.gateway.items", sorted(items), src)
    F.add("k8s.gateway.not_ready", not_ready, src)


def p_httproutes(o, F, src):
    items, bad, orphaned = [], [], []
    for r in _items(o):
        md = r.get("metadata") or {}
        spec = r.get("spec") or {}
        st = r.get("status") or {}
        nn = _nn(r)
        items.append(nn)
        parent_refs = spec.get("parentRefs") or []
        parents = st.get("parents") or []
        if not parent_refs and not parents:
            orphaned.append({"ns": md.get("namespace") or "-",
                             "name": md.get("name") or "?",
                             "uid": md.get("uid"),
                             "created": md.get("creationTimestamp")})
            continue
        for p in parents:
            pname = ((p.get("parentRef") or {}).get("name")) or "?"
            for c in p.get("conditions") or []:
                ctype = c.get("type")
                if ctype in ("Accepted", "ResolvedRefs") \
                        and c.get("status") != "True":
                    bad.append({
                        "ns": md.get("namespace") or "-",
                        "name": md.get("name") or "?",
                        "parent": pname,
                        "condition": ctype,
                        "reason": c.get("reason") or "?",
                    })
    F.add("k8s.httproute.count", len(items), src)
    F.add("k8s.httproute.items", sorted(items), src)
    F.add("k8s.httproute.bad_parent", bad, src)
    F.add("k8s.httproute.bad_parent_by_ns",
          {ns: sum(1 for b in bad if b["ns"] == ns)
           for ns in {b["ns"] for b in bad}}, src)
    F.add("k8s.httproute.orphaned", orphaned, src)


PARSERS = {
    "k_version": p_version,
    "k_readyz": p_readyz,
    "k_livez": p_livez,
    "k_nodes": p_nodes,
    "k_pods": p_pods,
    "k_pvc": p_pvc,
    "k_pv": p_pv,
    "k_volumeattach": p_volumeattach,
    "k_pdb": p_pdb,
    "k_validatingwh": p_validatingwh,
    "k_mutatingwh": p_mutatingwh,
    "k_endpointslices": p_endpointslices,
    "k_deployments": p_deployments,
    "k_statefulsets": p_statefulsets,
    "k_daemonsets": p_daemonsets,
    "k_jobs": p_jobs,
    "k_cronjobs": p_cronjobs,
    "k_helmcharts": p_helmcharts,
    "k_helmchartcfg": p_helmchartcfg,
    "k_apiservices": p_apiservices,
    "k_leases": p_leases,
    "k_events": p_events,
    "k_event_buffer": p_event_buffer,
    "k_top_nodes": p_top_nodes,
    "k_storageclass": p_storageclass,
    "k_csr": p_csr,
    "k_crds": p_crds,
    "k_services": p_services,
    "k_apiserver_metrics": p_apiserver_metrics,
    "k_tls_probe": p_tls_probe,
    "k_namespaces": p_namespaces,
    "k_ingresses": p_ingresses,
    "k_hpa": p_hpa,
    "k_clusterpolicy": p_clusterpolicy,
    "k_etcd_snapshots": p_etcd_snapshots,
    "k_acme_solvers": p_acme_solvers,
    "k_acme_challenges": p_acme_challenges,
    "k_acme_certificates": p_acme_certificates,
    "k_acme_probe": p_acme_probe,
    "k_networkpolicies": p_networkpolicies,
    "k_resourceslices": p_resourceslices,
    "k_gateways": p_gateways,
    "k_httproutes": p_httproutes,
    "k_top_cpu": p_usage,
    "k_top_gpu": p_usage,
    "k_log_thanos_sidecar": p_log_check,
    "k_log_thanos_compactor": p_log_check,
    "k_log_thanos_querier": p_log_check,
    "k_log_fleet_agent": p_log_check,
    "k_log_gpu_crash": p_log_check,
    "k_log_nvupdater": p_log_check,
}

# commands whose output is plain text, not JSON
TEXT_COMMANDS = {"k_readyz", "k_livez", "k_top_nodes"}
