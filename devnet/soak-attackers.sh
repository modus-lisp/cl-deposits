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
# secs_per_block [N] — the chain's mean block interval over its last N (144) blocks, for the oracle
# to size a block-counted window (the vault-anchored challenge: 72 blocks took 132 min on Nov 21,
# where the 3600 s default assumed 72).  Empty if bitcoind does not answer.
secs_per_block() {
  local n=${1:-144} tip t1 t0
  tip=$(bcli getblockcount 2>/dev/null) || return 0; [ -n "$tip" ] && [ "$tip" -gt "$n" ] || return 0
  t1=$(bcli getblockheader "$(bcli getblockhash "$tip")" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['time'])" 2>/dev/null)
  t0=$(bcli getblockheader "$(bcli getblockhash $((tip - n)))" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['time'])" 2>/dev/null)
  [ -n "$t1" ] && [ -n "$t0" ] && [ "$t1" -gt "$t0" ] && echo $(( (t1 - t0) / n ))
}
ai=0
# From now on every turn's landing is recorded: the oracle reads a turn with no marker after this
# row as one that never landed (devnet/soak-oracle.py World.turn_landed).
echo "$(date +%s) markers-on" >>"$SOAK/attack-landed.tsv"
# resolve_pending_lotteries — a turn whose lottery was still unclaimed at its end (PENDING) is followed
# here, through re-arm rounds (DEP-06 Phase 4): PASS once any honest node logs a round's win, FAIL past
# LOTTERY_BOUND (default 48 h).  Rows: $SOAK/lottery-pending.tsv "TIME ATTACK LEDGER CONFISCATION";
# resolved ones are listed in $SOAK/lottery-resolved.tsv and get a row in attack-outcomes.tsv.
resolve_pending_lotteries() {
  local pend="$SOAK/lottery-pending.tsv" done="$SOAK/lottery-resolved.tsv" t a e c now won
  [ -f "$pend" ] || return 0; touch "$done"; now=$(date +%s)
  while read -r t a e c; do
    [ -n "$e" ] || continue; grep -qF " $e " "$done" && continue
    won=$(grep -lE "dispute ${e:0:8}: (lottery|re-arm round [0-9]+): won" "$CLD_ROOT"/cld*/node.log 2>/dev/null | head -1)
    [ -n "$won" ] || won=$(grep -lF "won the lottery for ledger ${e:0:16}" "$CLD_ROOT"/ref*/node.log 2>/dev/null | head -1)
    if [ -n "$won" ]; then
      echo "$now $a PASS:lottery-claimed-late $(( now - t ))" >>"$SOAK/attack-outcomes.tsv"
      echo "$now $e PASS $(basename "$(dirname "$won")")" >>"$done"
      echo "$(date +%FT%T) $a on ${e:0:16}: lottery claimed after re-arm ($(basename "$(dirname "$won")")): PASS"
    elif [ $(( now - t )) -gt "${LOTTERY_BOUND:-172800}" ]; then
      echo "$now $a FAIL:lottery-unclaimed $(( now - t ))" >>"$SOAK/attack-outcomes.tsv"
      echo "$now $e FAIL -" >>"$done"
      echo "$(date +%FT%T) $a on ${e:0:16}: lottery still unclaimed after $(( (now - t) / 3600 )) h: FAIL"
    fi
  done <"$pend"
}

while true; do
  resolve_pending_lotteries
  sleep "$EVERY"
  [ -e "$SOAK/attackers.pause" ] && { echo "$(date +%FT%T) paused"; continue; }
  a=${ATTACKS[$((ai % ${#ATTACKS[@]}))]}; ai=$((ai+1))
  "$CLD_SRC/devnet/soak.sh" names >/dev/null 2>&1; register_pool
  t=$(date +%s); out="$SOAK/log/attack-${a/:/-}-$(date +%m%dT%H%M).log"
  script=${a%%:*}; arg=""; [[ "$a" == *:* ]] && arg=${a#*:}
  # A 6th column spb=S (seconds per block) lets the oracle size a block-counted window.  The scenario
  # records its landing in $SOAK/attack-landed.tsv (redteam/_lib.sh fault_landed); a turn that never
  # lands is moot, and its failure reads INVALID: setup.
  spb=$(secs_per_block)
  [[ "$REFUSAL_ATTACKS" == *" $a "* ]] || echo "$t $a - - $WINDOW${spb:+ spb=$spb}" >>"$SOAK/attacks.tsv"
  echo "$(date +%FT%T) running $a"
  up_before=" $(for n in $(cld_names); do cld_running "$n" && echo "$n"; done | tr '\n' ' ') "
  ( export REDTEAM_V="V$(date +%s)" DEVNET=signet REDTEAM_ON_SIGNET=1 REDTEAM_MINT=1 REDTEAM_AVOID="$SOAK_OPS" REFS="${ATTACK_REFS-ref6 ref7}"
    export ATTACK_NAME="$a"
    timeout --kill-after=60 5400 bash "$CLD_SRC/redteam/$script.sh" $arg ) >"$out" 2>&1
  rc=$?; v=$(grep -oE '^(PASS|FAIL|SKIP|INVALID|PENDING)[^ ]*' "$out" | tail -1)
  source "$(dirname "$0")/_common.sh"   # CLD_NODES again: it counts the nodes minted during the run
  "$CLD_SRC/devnet/soak.sh" names >/dev/null 2>&1; register_pool   # nodes minted during the run
  # Then stop the actors this run started (picked or minted), once their keys are registered: each is
  # a full cl node, and left up they added ~4 nodes per turn until the box ran hot (2026-11-11).
  for n in $(cld_names); do
    [[ " $SOAK_OPS " == *" $n "* || "$up_before" == *" $n "* ]] && continue
    cld_running "$n" && stop_cld "$n" >/dev/null 2>&1 && echo "$(date +%FT%T)   stopped actor $n"
  done
  echo "$(date +%s) $a ${v:-none} $(( $(date +%s) - t ))" >>"$SOAK/attack-outcomes.tsv"   # the oracle's per-attack table
  echo "$(date +%FT%T) $a: ${v:-no verdict} (exit $rc, $(( $(date +%s) - t ))s)  $(grep -E '^(PASS|FAIL|SKIP|INVALID|PENDING)' "$out" | tail -1 | cut -c1-160)"
done
