#!/usr/bin/env bash
# redteam/attack-collude-q7.sh — a colluding majority at Q = 7, and contagion (DEP-19 §5-6).
#
# Forms test ledger M: cld1 operates; cld2..cld6, ref6, ref7 cosign; R = 0.5.  cld2..cld5
# (four of seven, a majority) cosign blind, and cld1 locks a depositor's funds with no
# witness.  It commits.  PASS = what the protocol promises after that:
#   - M's honest members (cld6, ref6, ref7) dispute M;
#   - contagion: a fresh ledger each colluder operates (X2..X5: cld2..cld5, quorum cld6 ref6
#     ref7, all honest) is disputed by its members;
#   - operator contagion: X1, a fresh ledger the forging operator cld1 also runs, is disputed.
#   (The soak's own colluder ledgers were deposed in earlier runs, so the targets are formed here.)
#   REDTEAM_M=name forms fresh test ledgers per run.
# Reports times from the fraud to each dispute.  WAIT (s) bounds the watch.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-300}
source "$(dirname "$0")/_lib.sh"
ROW=${REDTEAM_M:-M}
M=$(COLLATERAL_SATS=25000000 form_ledger "$ROW" cld1 "" cld2 cld3 cld4 cld5 cld6 ref6 ref7) || exit 1; echo "   M $M"
mapfile -t DEPS < <(fresh_deposits "$ROW" cld1 "$M" 2); D1=${DEPS[0]}; D2=${DEPS[1]}
[ -n "$D1" ] && [ -n "$D2" ] || fail "no deposits on M"
echo "== victim deposit $D1 credited 20000000 msat on M"
has_fork() { case $2 in cld*) cld_ctl $2 "(:forks :ledger \"$1\")" | grep -q "$(cut -c1-16 $S/pubkey.$2)";; *) false;; esac; }
declare -A X; for k in 1 2 3 4 5; do X[$k]=$(form_ledger "$ROW-x$k" cld$k "" cld6 ref6 ref7) || exit 1; echo "   X$k ${X[$k]} (cld$k)"; done
T0=$(date -u +%FT%T); t0=$(date +%s)
declare -A OFF; for n in $(ref_names); do OFF[$n]=$(stat -c %s "$(ref_dir $n)/node.log" 2>/dev/null || echo 0); done   # read only what is logged after the attack
arm :cosign-blind cld2 cld3 cld4 cld5
R=$(cld_ctl cld1 "(:forge-lock :ledger \"$M\" :from \"$D1\" :to \"$D2\" :msat 15000000)")
disarm :cosign-blind cld2 cld3 cld4 cld5
echo "== 4-of-7 attempt on M: $(echo "$R" | cut -c1-120)"
echo "$R" | grep -q ":STATUS :OK" || fail "the colluding majority did not commit"
forked() {   # forked LEDGER-ID NODE: did NODE fork LEDGER-ID after the attack
  case $2 in
    cld*) cld_ctl $2 "(:forks :ledger \"$1\")" | grep -q "$(cut -c1-16 $S/pubkey.$2)";;
    ref*) tail -c +$(( ${OFF[$2]:-0} + 1 )) "$(ref_dir $2)/node.log" | grep -F "${1:0:16}" | grep -qE "Created dispute fork|INITIATING DISPUTE";;
  esac; }
PAIRS="M:$M"; for k in 1 2 3 4 5; do PAIRS="$PAIRS X$k:${X[$k]}"; done
declare -A DONE
for i in $(seq 1 $((WAIT/10))); do
  all=1
  for pair in $PAIRS; do
    IFS=: read -r L id <<<"$pair"
    for n in cld6 ref6 ref7; do k="$L/$n"; [ -n "${DONE[$k]:-}" ] && continue; if forked "$id" "$n"; then DONE[$k]=$(( $(date +%s) - t0 )); else all=0; fi; done
  done
  [ $all = 1 ] && break
  sleep 10
done
echo "== disputes (seconds after the fraud; - = none within $WAIT s):"
missing=0
for pair in $PAIRS; do
  IFS=: read -r L id <<<"$pair"; printf "   %s:" $L
  for n in cld6 ref6 ref7; do printf " %s=%s" $n "${DONE[$L/$n]:--}"; [ -n "${DONE[$L/$n]:-}" ] || missing=$((missing+1)); done; echo
done
echo "== contagion proofs sent by cld6: $(cld_ctl cld6 '(:log)' | tr '"' '\n' | grep -c 'contagion:.*proof against')"
# A ledger is caught when a majority of its 3 honest members dispute it.
caught=0; for pair in $PAIRS; do L=${pair%%:*}; c=0; for n in cld6 ref6 ref7; do [ -n "${DONE[$L/$n]:-}" ] && c=$((c+1)); done; [ $c -ge 2 ] && caught=$((caught+1)); done
[ $caught = 6 ] || fail "$caught of 6 ledgers (M, X1..X5) disputed by a majority of their honest members ($missing member disputes missing)"
echo "PASS: M and all five colluder ledgers disputed by their honest members (contagion and operator contagion)."
