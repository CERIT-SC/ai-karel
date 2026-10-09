#!/usr/bin/env bash
# Karel top-level runner. Monolithic container: everything in sequence.
#
#   collect (kubernetes + prometheus) -> normalize/rules/report -> persist state
#
# Produces /tmp/out/report.md (plain text, ready for your mailer) and
# /tmp/out/summary.json (machine-readable, for the dead-man's switch).
#
# Never exits non-zero for a cluster condition. Non-zero means KAREL is broken.

set -uo pipefail

# Default to the tree this script lives in: /opt/karel in the image, the
# checkout when run by hand. A hardcoded /opt/karel made every helper command
# fail with "No such file or directory" outside the image.
KAREL_HOME=${KAREL_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
export KAREL_HOME
export WORK=${WORK:-/tmp}
export OUT=${OUT:-/tmp/out}
export OUT_PROM=${OUT_PROM:-/tmp/out-prom}
export KAREL_NS=${KAREL_NS:-ai-karel-ns}
export STATE_CM=${STATE_CM:-karel-state-latest}
export SUPPRESS_CM=${SUPPRESS_CM:-karel-suppressions}
export BUDGET=${BUDGET:-600}
export RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
KEEP_DAYS=${KEEP_DAYS:-30}
KEEP_EVENT_DAYS=${KEEP_EVENT_DAYS:-3}

log() { echo "[karel $(date -u +%H:%M:%S)] $*" >&2; }

mkdir -p "$OUT"

# ------------------------------------------------------------------ 1. plan
# fields: name <TAB> timeout <TAB> tier <TAB> argv(\x1f-joined)
# \x1f is invisible in `cat` - verify with: cat -A plan.tsv
if [ -z "${K8S_MANIFEST:-}" ]; then
  K8S_MANIFEST=/etc/karel/k8s-commands.json
  [ -f "$K8S_MANIFEST" ] || K8S_MANIFEST="$KAREL_HOME/config/k8s-commands.json"
fi
if [ -f "$K8S_MANIFEST" ]; then
  jq -r --arg home "$KAREL_HOME" '
    .commands[]
    | [ .name, (.timeout // 30 | tostring), (.tier // 2 | tostring),
        (.argv | map(gsub("\\$\\{KAREL_HOME\\}"; $home)) | join("\u001f")) ] | @tsv
  ' "$K8S_MANIFEST" 2>/dev/null | sort -s -t$'\t' -k3,3n > "$WORK/plan-k8s.tsv"
  jq -r '[ .commands[] | select(.expected_status) | {(.name): .expected_status} ] | add // {}' \
    "$K8S_MANIFEST" > "$WORK/expected_status_k8s.json" 2>/dev/null || echo '{}' > "$WORK/expected_status_k8s.json"
  jq -r '[ .commands[] | select(.expect_json == false) | .name ]' \
    "$K8S_MANIFEST" > "$WORK/text_commands_k8s.json" 2>/dev/null || echo '[]' > "$WORK/text_commands_k8s.json"
  [ -s "$WORK/plan-k8s.tsv" ] || log "WARN: k8s plan is empty"
else
  log "FATAL: $K8S_MANIFEST not mounted - no Kubernetes collection"
  exit 1
fi

# name becomes a filename; reject anything that could escape raw/
BAD=$(awk -F'\t' '$1 !~ /^[a-z0-9_]+$/ {print $1}' "$WORK/plan-k8s.tsv")
[ -z "$BAD" ] || { log "FATAL: invalid command name(s): $BAD"; exit 1; }

# Tier >= 8 (the resource-usage pass) gets its own budget and runs in
# parallel with the main pass: 1200 s + 600 s does not fit the k8s budget,
# and a slow binary must not starve the rest of the collection.
awk -F'\t' '$3+0 >= 8' "$WORK/plan-k8s.tsv" > "$WORK/plan-usage.tsv" || true
awk -F'\t' '$3+0 < 8' "$WORK/plan-k8s.tsv" > "$WORK/plan-k8s.tsv.tmp" && \
  mv "$WORK/plan-k8s.tsv.tmp" "$WORK/plan-k8s.tsv"

# record the manifest digest so the report can tell whether collection changed
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$K8S_MANIFEST" | cut -d' ' -f1 > "$WORK/manifest.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$K8S_MANIFEST" | cut -d' ' -f1 > "$WORK/manifest.sha256"
fi

# ------------------------------------------------- 2. load yesterday's snapshot
# State lives in PLAIN JSON files under KAREL_STATE_DIR (a host-mounted
# volume), not in ConfigMaps: an oversized ConfigMap payload fails writes
# silently, and nobody can inspect a failing object anyway. Files you can
# read back.
export KAREL_STATE_DIR=${KAREL_STATE_DIR:-/home/ubuntu-persistent/new-reports/state}
mkdir -p "$KAREL_STATE_DIR/archive" 2>/dev/null || true
log "load previous state (from $KAREL_STATE_DIR)"

# Migration: read a legacy ConfigMap payload only when the file is absent.
load_cm_payload() {   # $1=name $2=key $3=outfile
  if kubectl -n "$KAREL_NS" get configmap "$1" \
       -o jsonpath="{.binaryData.$2}" > "$WORK/.cm.b64" 2>/dev/null \
     && [ -s "$WORK/.cm.b64" ]; then
    base64 -d < "$WORK/.cm.b64" | gunzip -c > "$3" 2>/dev/null && return 0
  fi
  kubectl -n "$KAREL_NS" get configmap "$1" \
    -o jsonpath="{.data.$2}" > "$3" 2>/dev/null
}
if [ -s "$KAREL_STATE_DIR/snapshot.json" ]; then
  cp "$KAREL_STATE_DIR/snapshot.json" "$WORK/prev.json"
  log "baseline loaded ($(wc -c < "$WORK/prev.json") bytes, file)"
elif load_cm_payload "$STATE_CM" snapshot "$WORK/prev.json" \
     && [ -s "$WORK/prev.json" ]; then
  log "baseline loaded ($(wc -c < "$WORK/prev.json") bytes, legacy ConfigMap)"
else
  echo '{}' > "$WORK/prev.json"
  log "no baseline - first run or state missing"
fi

# The log/event window starts at the previous collection; no baseline means
# now-26h, and a very old baseline is capped at 48h so the log fetch stays
# bounded. Exported: collector scripts read it from the environment.
KAREL_SINCE=$(python3 - "$WORK/prev.json" <<'EOF'
import datetime, json, sys
now = datetime.datetime.now(datetime.timezone.utc)
try:
    prev = json.load(open(sys.argv[1]))
    s = prev.get("collected_at") or ""
    since = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ") \
                .replace(tzinfo=datetime.timezone.utc)
except Exception:
    since = now - datetime.timedelta(hours=26)
since = max(since, now - datetime.timedelta(hours=48))
print(since.strftime("%Y-%m-%dT%H:%M:%SZ"))
EOF
)
export KAREL_SINCE
log "log/event window starts at $KAREL_SINCE"

# Housekeeping age state (keyed by object UID): ages must survive object
# recreation (new UID = age 0) and collection gaps.
export HK_CM=${KAREL_HOUSEKEEPING_STATE_CM:-karel-housekeeping-state}
if [ -s "$KAREL_STATE_DIR/housekeeping-state.json" ]; then
  cp "$KAREL_STATE_DIR/housekeeping-state.json" "$WORK/housekeeping-state.json"
  log "housekeeping state loaded ($(wc -c < "$WORK/housekeeping-state.json") bytes, file)"
elif load_cm_payload "$HK_CM" state "$WORK/housekeeping-state.json" \
     && [ -s "$WORK/housekeeping-state.json" ]; then
  log "housekeeping state loaded ($(wc -c < "$WORK/housekeeping-state.json") bytes, legacy ConfigMap)"
else
  echo '{"version":2,"items":{}}' > "$WORK/housekeeping-state.json"
fi

# ----------------------------------------------------- 2b. suppression ledger
if kubectl -n "$KAREL_NS" get configmap "$SUPPRESS_CM" \
     -o jsonpath='{.data.suppressions}' > "$WORK/suppressions.json" 2>/dev/null \
   && [ -s "$WORK/suppressions.json" ]; then
  log "suppressions loaded ($(wc -c < "$WORK/suppressions.json") bytes)"
else
  echo '{"suppressions":[]}' > "$WORK/suppressions.json"
fi

# ------------------------------------------------------------- 3. collect k8s
log "collect kubernetes (budget ${BUDGET}s)"
mkdir -p "$OUT"
cp "$WORK/expected_status_k8s.json" "$OUT/expected_status.json" 2>/dev/null
cp "$WORK/text_commands_k8s.json" "$OUT/text_commands.json" 2>/dev/null
USAGE_PID=""
if [ -s "$WORK/plan-usage.tsv" ]; then
  log "collect resource usage in parallel (budget ${USAGE_BUDGET:-1800}s)"
  SUPPRESSIONS_FILE="$WORK/suppressions.json" \
  SKIP_PROBE=1 BUDGET="${USAGE_BUDGET:-1800}" RUN_ID="$RUN_ID" \
    "$KAREL_HOME/bin/run-plan.sh" "$WORK/plan-usage.tsv" "$OUT-usage" &
  USAGE_PID=$!
fi
SKIP_PROBE=1 BUDGET="$BUDGET" RUN_ID="$RUN_ID" \
  "$KAREL_HOME/bin/run-plan.sh" "$WORK/plan-k8s.tsv" "$OUT"
k8s_rc=$?

# The usage pass merges into the main output dir afterwards, so the bundle
# sees one index. Its own COMPLETE/index is the coverage record.
if [ -n "$USAGE_PID" ]; then
  wait "$USAGE_PID" || true
  if [ -f "$OUT-usage/index.tsv" ]; then
    cat "$OUT-usage/index.tsv" >> "$OUT/index.tsv"
    mkdir -p "$OUT/raw"
    cp "$OUT-usage"/raw/* "$OUT/raw/" 2>/dev/null
    log "usage collection merged ($(wc -l < "$OUT-usage/index.tsv") commands)"
  else
    log "WARN: usage collection produced no index - the section will say so"
  fi
fi
# Diagnose here, where the exit code and the shell are still available.
# By the time the report is rendered all that survives is a missing file.
if [ ! -f "$OUT/COMPLETE" ]; then
  log "ERROR: k8s collector exited $k8s_rc without writing $OUT/COMPLETE"
  log "       index.tsv rows: $(wc -l < "$OUT/index.tsv" 2>/dev/null || echo 0)"
  log "       plan rows:      $(wc -l < "$WORK/plan-k8s.tsv" 2>/dev/null || echo 0)"
  log "       raw files:      $(ls "$OUT/raw" 2>/dev/null | wc -l)"
  log "       disk:           $(df -h "$OUT" 2>/dev/null | tail -1)"
fi

# --------------------------------------------------------- 3b. collect metrics
if [ "${PROM_ENABLED:-1}" = "1" ]; then
  log "collect prometheus"
  if [ ! -f "$KAREL_HOME/bin/prom_query.py" ]; then
    log "WARN: PROM_ENABLED=1 but $KAREL_HOME/bin/prom_query.py is not in this image"
  else
    OUT_PROM="$OUT_PROM" python3 "$KAREL_HOME/bin/prom_query.py" || \
      log "WARN: prometheus collector exited non-zero"
    [ -f "$OUT_PROM/result.json" ] || \
      log "ERROR: prometheus collector wrote no $OUT_PROM/result.json"
  fi
else
  log "prometheus collection disabled (PROM_ENABLED=0)"
fi

# ------------------------------------------- 4. normalize + rules + report text
log "analyse"
mkdir -p "$OUT/external"   # RT/JupyterHub captures land here before narrative
python3 "$KAREL_HOME/lib/pipeline.py" \
  --out "$OUT" \
  --prom-out "$OUT_PROM" \
  --prev "$WORK/prev.json" \
  --suppressions "$WORK/suppressions.json" \
  --housekeeping-state "$WORK/housekeeping-state.json" \
  --external-dir "$OUT/external" \
  --bundle "$OUT/bundle.json" \
  --snapshot "$OUT/snapshot.json" \
  --report "$OUT/report.md" > /dev/null 2> >(tee "$OUT/pipeline.err" >&2)
rc=$?
if [ $rc -ne 0 ] || [ ! -s "$OUT/report.md" ]; then
  log "FATAL: pipeline produced no report (rc=$rc)"
  # A crash here means NO email, which looks exactly like a healthy cluster.
  # Keep the traceback where the next run and a human can both find it.
  if [ -s "$OUT/pipeline.err" ]; then
    log "--- pipeline stderr (last 20 lines) ---"
    tail -n 20 "$OUT/pipeline.err" | while IFS= read -r l; do log "  $l"; done
  fi
  exit 2
fi

# ------------------------------------------------------------ 5. persist state
# Tier A state lives in etcd via a ConfigMap. Karel already depends on the
# Kubernetes API existing at all, so this adds no new failure mode - unlike a
# PVC on storage that may be the very thing being monitored.
#
# States are written gzipped + base64 into binaryData with `replace`, never
# ------------------------------------------------------------ 5. persist state
# Atomic file writes under KAREL_STATE_DIR: tmp + rename, so a torn write can
# never be half-read. Plain JSON - read back with any editor, no base64.
write_file_atomic() {  # $1=stage-file $2=destination
  cp "$1" "$2.tmp.$$" && mv -f "$2.tmp.$$" "$2"
}
log "persist state (files in $KAREL_STATE_DIR)"
fs_ok=1
if [ -s "$OUT/snapshot.json" ]; then
  if ! write_file_atomic "$OUT/snapshot.json" "$KAREL_STATE_DIR/snapshot.json"; then
    log "WARN: could not write $KAREL_STATE_DIR/snapshot.json - next run has no deltas"
    fs_ok=0
  fi
  ARCHIVE="archive/karel-state-$(date -u +%Y-%m-%d).json"
  write_file_atomic "$OUT/snapshot.json" "$KAREL_STATE_DIR/$ARCHIVE" || \
    log "WARN: could not write $KAREL_STATE_DIR/$ARCHIVE"
fi

# Housekeeping ages persist the same way. A failed save is detected NEXT run
# (snapshot has state, storage file is empty) and becomes
# KAREL_HOUSEKEEPING_STATE_SAVE_FAILED.
if [ -s "$OUT/housekeeping-state.json" ]; then
  if ! write_file_atomic "$OUT/housekeeping-state.json" \
       "$KAREL_STATE_DIR/housekeeping-state.json"; then
    log "WARN: could not write $KAREL_STATE_DIR/housekeeping-state.json - ages restart tomorrow"
    fs_ok=0
  fi
fi
[ "$fs_ok" = 1 ] && log "state files updated"

# ------------------------------------------------------------------- 6. prune
# Two retentions. State archives are the trend history and are worth keeping.
# Event buffers are only ever read for today and yesterday - keeping more just
# grows etcd, which Karel itself reports on.
# File archives first (name-sorted, keep the newest KEEP_DAYS):
if [ -d "$KAREL_STATE_DIR/archive" ]; then
  ls -r "$KAREL_STATE_DIR/archive"/karel-state-*.json 2>/dev/null \
    | tail -n +$(( KEEP_DAYS + 1 )) \
    | while read -r old; do rm -f "$old" && log "pruned $old"; done
fi

prune_by_label() {
  local label=$1 keep=$2 prefix=$3 cutoff cm d
  cutoff=$(date -u -d "$keep days ago" +%Y-%m-%d 2>/dev/null) || return 0
  [ -n "$cutoff" ] || return 0
  for cm in $(kubectl -n "$KAREL_NS" get configmap -l "$label" \
                -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    d=${cm#"$prefix"}
    if [[ "$d" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && [[ "$d" < "$cutoff" ]]; then
      kubectl -n "$KAREL_NS" delete configmap "$cm" >/dev/null 2>&1 && log "pruned $cm"
    fi
  done
}

# Legacy ConfigMap archives still prune themselves until migration is done.
prune_by_label "karel/kind=state-archive" "$KEEP_DAYS"        "karel-state-"
prune_by_label "karel/kind=event-buffer"  "${KEEP_EVENT_DAYS:-3}" "karel-events-"

log "done: $(python3 -c 'import json;d=json.load(open("'"$OUT"'/summary.json"));print(d["counts"])' 2>/dev/null)"
log "report: $OUT/report.md"
exit 0
