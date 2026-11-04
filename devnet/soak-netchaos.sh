#!/usr/bin/env bash
# devnet/soak-netchaos.sh — network faults on the soak's relay (docs/CHAOS.md §Network and relay).
# Every NETCHAOS_EVERY seconds (1800) pick one node and one fault, and write it as a rule for the
# relay's event policy (devnet/beacon-relay.lisp, RELAY_FAULTS) that expires on its own after
# 5–20 minutes:
#   delay   every event the node publishes arrives 5–60 s late
#   jitter  each of them arrives 0–30 s late, so they reorder
#   dup     each of them is delivered to live subscribers twice
#   lossy   10–30% of them are refused
#   cut     everything it publishes is refused, and requests addressed to it too: the node can
#           still read, but nobody hears it
# Rules this loop did not write (src != netchaos) are kept.  Touch $SOAK/netchaos.pause to pause;
# rules already written still expire.  Log: $SOAK/log/netchaos.log (via soak.sh start).
#   NETCHAOS_EVERY (1800), NETCHAOS_NODES (soak operators), NETCHAOS_FAULTS (delay jitter dup lossy cut)
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; EVERY=${NETCHAOS_EVERY:-1800}
NODES=(${NETCHAOS_NODES:-$(cld_names | head -n "${SOAK_PLAN_CL:-6}") $(ref_names)})
FAULTS=(${NETCHAOS_FAULTS:-delay jitter dup lossy cut})
key_of() { awk -v n="$1" '$1==n { k=$2; if (length(k)==66) k=substr(k,3); print k }' "$SOAK/names.tsv"; }
write_rule() {   # write_rule JSON-RULE...: replace this loop's live rules with these, keep everyone else's
  python3 - "$RELAY_FAULTS" "$@" <<'EOF'
import json, sys, time, os
path, new = sys.argv[1], [json.loads(r) for r in sys.argv[2:]]
try: rules = json.load(open(path))
except Exception: rules = []
now = time.time()
keep = [r for r in rules if r.get("src") != "netchaos" or r.get("until", 0) > now and not new]
tmp = path + ".tmp"; json.dump(keep + new, open(tmp, "w")); os.replace(tmp, path)
EOF
}
while true; do
  sleep "$EVERY"
  [ -e "$SOAK/netchaos.pause" ] && { echo "$(date +%FT%T) paused"; continue; }
  n=${NODES[$((RANDOM % ${#NODES[@]}))]}; f=${FAULTS[$((RANDOM % ${#FAULTS[@]}))]}
  k=$(key_of "$n"); [ -n "$k" ] || { echo "$(date +%FT%T) no key for $n in names.tsv"; continue; }
  dur=$(( 300 + RANDOM % 900 )); until=$(( $(date +%s) + dur ))
  base="\"src\":\"netchaos\",\"until\":$until,\"author\":\"$k\""
  case $f in
    delay)  d=$(( 5 + RANDOM % 56 )); write_rule "{$base,\"delay\":$d}"; what="delay ${d}s";;
    jitter) write_rule "{$base,\"jitter\":30}"; what="jitter 0-30s";;
    dup)    write_rule "{$base,\"dup\":$(( 2 + RANDOM % 20 ))}"; what="duplicate deliveries";;
    lossy)  p=$(( 10 + RANDOM % 21 )); write_rule "{$base,\"drop\":true,\"p\":0.$p}"; what="drop ${p}%";;
    cut)    write_rule "{$base,\"drop\":true}" "{\"src\":\"netchaos\",\"until\":$until,\"to\":\"$k\",\"drop\":true}"; what="cut off";;
  esac
  echo "$(date +%FT%T) $n: $what for ${dur}s"
done
