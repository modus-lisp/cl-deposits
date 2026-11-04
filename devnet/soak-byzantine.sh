#!/usr/bin/env bash
# devnet/soak-byzantine.sh — a Byzantine member in the soak's honest quorums (docs/ADVERSARIAL.md
# §Live attackers).  Every BYZ_EVERY seconds (21600) one soak cl node misbehaves as a MEMBER for
# 30–60 min, in a way no rule can prove against it, so the right outcome is that the quorum works
# around it and nobody is accused:
#   lag       :lag-replica on one ledger it cosigns: its replica applies nothing, it refuses or
#             challenges from a stale view (the Oct 21 false accusation started this way)
#   withhold  :withhold-rulesets: it declares no ruleset newer than v6 in its consents, so the
#             operator must not seat it under v7 (DEP-18 §operator policy)
# Cosignatures that arrive late are the network chaos loop's (devnet/soak-netchaos.sh).
# The oracle must stay at ALARM 0: an accusation against the Byzantine node, or against anyone
# because of it, is a false one.  Touch $SOAK/byzantine.pause to pause.  Log: $SOAK/log/byzantine.log.
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; EVERY=${BYZ_EVERY:-21600}
NODES=(${BYZ_NODES:-$(cld_names | head -n "${SOAK_PLAN_CL:-6}")})
member_ledger() {   # a soak ledger N cosigns but does not operate
  awk -F'\t' -v n="$1" '$3 != n { print $2 }' "$SOAK/ledgers.tsv" | while read -r id; do
    cld_ctl "$1" "(:info)" 2>/dev/null | grep -q "\"$id\" :OWNED NIL" && { echo "$id"; break; }
  done
}
while true; do
  sleep "$EVERY"
  [ -e "$SOAK/byzantine.pause" ] && { echo "$(date +%FT%T) paused"; continue; }
  n=${NODES[$((RANDOM % ${#NODES[@]}))]}; d=$(( 1800 + RANDOM % 1800 ))
  case $(( RANDOM % 2 )) in
    0) l=$(member_ledger "$n"); [ -n "$l" ] || { echo "$(date +%FT%T) $n cosigns no soak ledger it does not operate"; continue; }
       cld_ctl "$n" "(:adversary :set :lag-replica \"${l:0:16}\")" >/dev/null
       echo "$(date +%FT%T) $n: lag-replica on ${l:0:16} for ${d}s"; sleep "$d"
       cld_ctl "$n" "(:adversary :set :lag-replica nil)" >/dev/null;;
    1) cld_ctl "$n" '(:adversary :set :withhold-rulesets ("grounded-arms-v7"))' >/dev/null
       echo "$(date +%FT%T) $n: withholding grounded-arms-v7 from its declarations for ${d}s"; sleep "$d"
       cld_ctl "$n" "(:adversary :set :withhold-rulesets nil)" >/dev/null;;
  esac
  echo "$(date +%FT%T) $n: back to honest"
done
