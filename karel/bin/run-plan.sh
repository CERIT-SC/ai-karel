#!/usr/bin/env bash
# Karel step 1b: execute plan.tsv. Never aborts on a command failure; always
# exit 0 unless the output dir is unusable. A non-zero exit restarts the pod,
# which is the opposite of what we want on a sick cluster.

set +e
set -uo pipefail

PLAN=${1:-/tmp/plan.tsv}
OUT=${2:-/tmp/out}
BUDGET=${BUDGET:-600}
RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}

mkdir -p "$OUT/raw" || { echo "run-plan: cannot create $OUT/raw" >&2; exit 1; }
rm -f "$OUT"/raw/* "$OUT"/index.tsv "$OUT"/COMPLETE 2>/dev/null
: > "$OUT/index.tsv"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SECONDS=0

meta() {
  local finished budget_used
  finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  budget_used=$SECONDS
  cat > "$OUT/meta.json" <<EOF
{
  "run_id": "$RUN_ID",
  "started": "$STARTED",
  "finished": "$finished",
  "budget_seconds": $BUDGET,
  "budget_used_seconds": $budget_used,
  "manifest_sha256": "$(cat "${WORK:-/tmp}/manifest.sha256" 2>/dev/null || echo unknown)"
}
EOF
}

# ------------------------------------------------------------------ main loop
while IFS=$'\t' read -r name tmo tier argstr; do
  [ -z "${name:-}" ] && continue

  if [ "$SECONDS" -ge "$BUDGET" ]; then
    printf '%s\t-\t0\t%s\tskipped_budget\t0\t%s\n' "$name" "$tier" "$tmo" \
      >> "$OUT/index.tsv"
    continue
  fi

  IFS=$'\x1f' read -r -a argv <<< "$argstr"
  t0=$SECONDS
  timeout -k 5 "$tmo" "${argv[@]}" \
    > "$OUT/raw/$name.stdout" 2> "$OUT/raw/$name.stderr"
  rc=$?
  dur=$(( SECONDS - t0 ))

  case $rc in
    0)        st=ok ;;
    124|137)  st=timeout ;;
    13)       st=eacces ;;
    1)        grep -qiE 'forbidden|permission denied|access denied' "$OUT/raw/$name.stderr" \
                && st=eacces || st=failed ;;
    *)        st=failed ;;
  esac

  # wc -c, not stat -c%s: BSD stat has no -c, and every size became 0 on macOS
  sz=$(wc -c < "$OUT/raw/$name.stdout" 2>/dev/null | tr -d ' ')
  sz=${sz:-0}
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$rc" "$dur" "$tier" "$st" "$sz" "$tmo" >> "$OUT/index.tsv"
done < "$PLAN"

meta
gzip -f "$OUT"/raw/* 2>/dev/null
touch "$OUT/COMPLETE"

ok=$(awk -F'\t' '$5=="ok"' "$OUT/index.tsv" | wc -l)
tot=$(wc -l < "$OUT/index.tsv")
echo "run-plan: $ok/$tot ok in ${SECONDS}s" >&2
exit 0
