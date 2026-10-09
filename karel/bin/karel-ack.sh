#!/usr/bin/env bash
# Manage Karel's suppression ledger.
#
#   karel-ack.sh list
#   karel-ack.sh add   <id-or-glob> <until|permanent> <reason> [by]
#   karel-ack.sh rm    <id-or-glob>
#
# Every entry needs an expiry. "permanent" is allowed but is reported in every
# report from then on, because a suppression nobody re-reads is how a real
# problem disappears.

set -uo pipefail
NS=${KAREL_NS:-ai-karel-ns}
CM=${SUPPRESS_CM:-karel-suppressions}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

load() {
  kubectl -n "$NS" get configmap "$CM" -o jsonpath='{.data.suppressions}' 2>/dev/null \
    > "$TMP/s.json"
  [ -s "$TMP/s.json" ] || echo '{"suppressions":[]}' > "$TMP/s.json"
  jq empty "$TMP/s.json" 2>/dev/null || echo '{"suppressions":[]}' > "$TMP/s.json"
}

save() {
  kubectl -n "$NS" create configmap "$CM" \
    --from-file=suppressions="$TMP/s.json" --dry-run=client -o yaml \
  | kubectl -n "$NS" apply -f - >/dev/null || { echo "apply failed" >&2; exit 1; }
  kubectl -n "$NS" label configmap "$CM" app=karel --overwrite >/dev/null 2>&1
  echo "ledger updated ($(jq '.suppressions|length' "$TMP/s.json") entries)"
}

case "${1:-list}" in
  list)
    load
    jq -r '.suppressions[]? |
      "\(.id // .pattern)\t\(.until // "-")\t\(.by // "-")\t\(.reason // "-")"' \
      "$TMP/s.json" | column -t -s$'\t' 2>/dev/null || cat "$TMP/s.json"
    ;;

  add)
    [ $# -ge 4 ] || { echo "usage: $0 add <id-or-glob> <YYYY-MM-DD|permanent> <reason> [by]" >&2; exit 1; }
    KEY=$2; UNTIL=$3; REASON=$4; BY=${5:-$(whoami 2>/dev/null || echo unknown)}
    if [ "$UNTIL" != "permanent" ] && ! date -d "$UNTIL" +%F >/dev/null 2>&1; then
      echo "until must be YYYY-MM-DD or the literal string 'permanent'" >&2; exit 1
    fi
    load
    FIELD=id
    case "$KEY" in *[\*\?]*) FIELD=pattern ;; esac
    jq --arg k "$KEY" --arg f "$FIELD" --arg u "$UNTIL" \
       --arg r "$REASON" --arg b "$BY" '
      .suppressions = ((.suppressions // [])
        | map(select((.id // .pattern) != $k))
        + [ { ($f): $k, until: $u, reason: $r, by: $b } ])
    ' "$TMP/s.json" > "$TMP/n.json" && mv "$TMP/n.json" "$TMP/s.json"
    save
    [ "$UNTIL" = "permanent" ] && echo \
      "note: permanent entries are listed in every report by design"
    ;;

  rm)
    [ $# -ge 2 ] || { echo "usage: $0 rm <id-or-glob>" >&2; exit 1; }
    load
    jq --arg k "$2" '.suppressions = ((.suppressions // [])
      | map(select((.id // .pattern) != $k)))' "$TMP/s.json" > "$TMP/n.json" \
      && mv "$TMP/n.json" "$TMP/s.json"
    save
    ;;

  *) echo "usage: $0 {list|add|rm}" >&2; exit 1 ;;
esac
