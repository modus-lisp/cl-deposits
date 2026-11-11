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
# Each entry is SCRIPT or SCRIPT:ARG.  The default covers the fault classes the live attacker ledgers
# exercise end to end (docs/ADVERSARIAL.md): uncredited payment + unhonoured obligation with payouts
# (check-obligations: NOT in the default on signet, since it mines about 120 blocks in minutes, which
# collapses every block-counted window in the soak, the 72-block challenge window included; run it on
# regtest), forged lock, invalid credit, equivocation, unanchored and forged-anchor vault
# spends, and the omitted / falsified balance commitments that must be refused, not proven.
ATTACKS=(${ATTACKS:-attack-soak-fault:forge-lock attack-vault-spend attack-soak-fault:omit-commitments attack-soak-fault:equivocate attack-soak-fault:invalid-credit attack-vault-anchored attack-soak-fault:falsify-commitments})
REFUSAL_ATTACKS=" attack-soak-fault:omit-commitments attack-soak-fault:falsify-commitments "   # nothing to prove: no MISS clock
SOAK_OPS=$(cld_names | head -n "${SOAK_PLAN_CL:-6}" | tr '\n' ' ')
# The soak's own cl nodes (operators and members), recorded once: attacker roles are never drawn
# from them (redteam/attack-soak-fault.sh), only from nodes minted later.
[ -s "$SOAK/soak-nodes" ] || cld_names >"$SOAK/soak-nodes"
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
  t=$(date +%s); out="$SOAK/log/attack-${a/:/-}-$(date +%m%dT%H%M).log"
  script=${a%%:*}; arg=""; [[ "$a" == *:* ]] && arg=${a#*:}
  [[ "$REFUSAL_ATTACKS" == *" $a "* ]] || echo "$t $a - - $WINDOW" >>"$SOAK/attacks.tsv"
  echo "$(date +%FT%T) running $a"
  up_before=" $(for n in $(cld_names); do cld_running "$n" && echo "$n"; done | tr '\n' ' ') "
  ( export REDTEAM_V="V$(date +%s)" DEVNET=signet REDTEAM_ON_SIGNET=1 REDTEAM_MINT=1 REDTEAM_AVOID="$SOAK_OPS" REFS="${ATTACK_REFS-ref6 ref7}"
    timeout --kill-after=60 5400 bash "$CLD_SRC/redteam/$script.sh" $arg ) >"$out" 2>&1
  rc=$?; v=$(grep -oE '^(PASS|FAIL|SKIP|INVALID)[^ ]*' "$out" | tail -1)
  # Stop the actors this run started (picked or minted): each is a full cl node, and left up they
  # added ~4 nodes per turn until the box ran hot (2026-11-11). Re-source for nodes minted meanwhile.
  source "$(dirname "$0")/_common.sh"
  for n in $(cld_names); do
    [[ " $SOAK_OPS " == *" $n "* || "$up_before" == *" $n "* ]] && continue
    cld_running "$n" && stop_cld "$n" >/dev/null 2>&1 && echo "$(date +%FT%T)   stopped actor $n"
  done
  "$CLD_SRC/devnet/soak.sh" names >/dev/null 2>&1; register_pool   # nodes minted during the run
  echo "$(date +%s) $a ${v:-none} $(( $(date +%s) - t ))" >>"$SOAK/attack-outcomes.tsv"   # the oracle's per-attack table
  echo "$(date +%FT%T) $a: ${v:-no verdict} (exit $rc, $(( $(date +%s) - t ))s)  $(grep -E '^(PASS|FAIL|SKIP)' "$out" | tail -1 | cut -c1-160)"
done
