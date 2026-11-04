#!/usr/bin/env bash
# devnet/soak-attackers.sh — live attackers in the soak (docs/ADVERSARIAL.md §Live attackers).
# Every ATTACK_EVERY seconds (14400) run the next red-team scenario of ATTACKS against the signet
# soak, with actors from the red-team pool only: cl nodes outside the soak's quorums (cld7..,
# minted on demand: REDTEAM_MINT=1), never the soak's operators (REDTEAM_AVOID).  Honest members
# of the attack ledgers include soak nodes, which is the point: they must catch the attacker and
# accuse nobody else.
#
# Before a run every pool node is registered with the oracle as `pool` ($SOAK/adversaries.tsv):
# a proof against one counts as PASS once the scenario burns it ($SOAK/redteam-tainted), and as an
# ALARM if it never does.  The run is also scheduled in $SOAK/attacks.tsv, so a scenario whose
# attacker draws no proof within ATTACK_WINDOW (3600 s) is a MISS.  Each scenario's own verdict
# (PASS/FAIL/SKIP) and output go to $SOAK/log/attacks.log and $SOAK/log/attack-<name>-<time>.log.
# Touch $SOAK/attackers.pause to pause.
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; EVERY=${ATTACK_EVERY:-14400}; WINDOW=${ATTACK_WINDOW:-3600}
ATTACKS=(${ATTACKS:-attack-vault-spend attack-vault-anchored attack-collude-q7 attack-dereliction attack-withhold-reveal})
SOAK_OPS=$(cld_names | head -n "${SOAK_PLAN_CL:-6}" | tr '\n' ' ')
register_pool() {   # every cl node that is not a soak operator, as a red-team pool key
  local n k
  [ -f "$SOAK/adversaries.tsv" ] || printf '# oracle adversaries (devnet/soak-oracle.py)\n' >"$SOAK/adversaries.tsv"
  for n in $(cld_names); do
    [[ " $SOAK_OPS " == *" $n "* ]] && continue
    k=$(awk -v n="$n" '$1==n {print $2}' "$SOAK/names.tsv"); [ -n "$k" ] || continue
    grep -q "^pool $k" "$SOAK/adversaries.tsv" || echo "pool $k $n" >>"$SOAK/adversaries.tsv"
  done
}
ai=0
while true; do
  sleep "$EVERY"
  [ -e "$SOAK/attackers.pause" ] && { echo "$(date +%FT%T) paused"; continue; }
  a=${ATTACKS[$((ai % ${#ATTACKS[@]}))]}; ai=$((ai+1))
  "$CLD_SRC/devnet/soak.sh" names >/dev/null 2>&1; register_pool
  t=$(date +%s); out="$SOAK/log/attack-$a-$(date +%m%dT%H%M).log"
  echo "$t $a - - $WINDOW" >>"$SOAK/attacks.tsv"
  echo "$(date +%FT%T) running $a"
  ( export DEVNET=signet REDTEAM_ON_SIGNET=1 REDTEAM_MINT=1 REDTEAM_AVOID="$SOAK_OPS" REFS="${ATTACK_REFS-ref6 ref7}"
    timeout --kill-after=60 5400 bash "$CLD_SRC/redteam/$a.sh" ) >"$out" 2>&1
  rc=$?; v=$(grep -oE '^(PASS|FAIL|SKIP|INVALID)[^ ]*' "$out" | tail -1)
  "$CLD_SRC/devnet/soak.sh" names >/dev/null 2>&1; register_pool   # nodes minted during the run
  echo "$(date +%FT%T) $a: ${v:-no verdict} (exit $rc, $(( $(date +%s) - t ))s)  $(grep -E '^(PASS|FAIL|SKIP)' "$out" | tail -1 | cut -c1-160)"
done
