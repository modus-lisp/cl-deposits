#!/usr/bin/env bash
# redteam/attack-collude-q7.sh — a colluding majority at Q = 7, and contagion (DEP-19 §5-6).
#
# Forms test ledger M: cld1 operates; cld2..cld6, ref6, ref7 cosign; R = 0.5.  cld2..cld5
# (four of seven, a majority) cosign blind, and cld1 locks a depositor's funds with no
# witness.  It commits.  PASS = what the protocol promises after that:
#   - M's honest members (cld6, ref6, ref7) dispute M;
#   - contagion: the ledgers the four colluders operate (C, E, G, I: cld2..cld5 at Q = 7,
#     each with an honest majority) are disputed by their own members;
#   - operator contagion: A, the forging operator cld1's other ledger, is disputed by its
#     honest members.  (A ledger already confiscated from a colluder stays quiet: it has a new
#     operator.)  REDTEAM_M=name forms a fresh test ledger per run.
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
declare -A PRE; while IFS=$'\t' read -r L id _; do for n in $(cld_names); do has_fork "$id" "$n" && PRE[$id/$n]=1; done; done < "$S/ledgers.tsv"   # forks from earlier runs
T0=$(date -u +%FT%T); t0=$(date +%s)
arm :cosign-blind cld2 cld3 cld4 cld5
R=$(cld_ctl cld1 "(:forge-lock :ledger \"$M\" :from \"$D1\" :to \"$D2\" :msat 15000000)")
disarm :cosign-blind cld2 cld3 cld4 cld5
echo "== 4-of-7 attempt on M: $(echo "$R" | cut -c1-120)"
echo "$R" | grep -q ":STATUS :OK" || fail "the colluding majority did not commit"
declare -A LED; while IFS=$'\t' read -r L id op _; do LED[$L]=$id; done < "$S/ledgers.tsv"
forked() {   # forked LEDGER-ID NODE: did NODE fork LEDGER-ID after the attack (not before)
  case $2 in
    cld*) [ -z "${PRE[$1/$2]:-}" ] && has_fork "$1" "$2";;
    ref*) local L; L=$(sed 's/\x1b\[[0-9;]*m//g' "$(ref_dir $2)/node.log" | awk -v t="$T0" '$1 > t' | grep -E "${1:0:16}")
          echo "$L" | grep -qE "Created dispute fork|INITIATING DISPUTE" && ! echo "$L" | grep -q "Already have fork";;
  esac; }
declare -A DONE
for i in $(seq 1 $((WAIT/10))); do
  for pair in "M:$M:cld6 ref6 ref7" "A:${LED[A]}:ref2 ref3 ref4 ref5" "C:${LED[C]}:ref3 ref4 ref5 ref6" "E:${LED[E]}:ref4 ref5 ref6 ref7" "G:${LED[G]}:ref5 ref6 ref7 cld6" "I:${LED[I]}:ref6 ref7 ref2 ref3 cld6"; do
    IFS=: read -r L id nodes <<<"$pair"
    for n in $nodes; do k="$L/$n"; [ -z "${DONE[$k]:-}" ] && forked "$id" "$n" && DONE[$k]=$(( $(date +%s) - t0 )); done
  done
  sleep 10
done
echo "== disputes (seconds after the fraud; - = none within $WAIT s):"
for pair in "M:cld6 ref6 ref7" "A:ref2 ref3 ref4 ref5" "C:ref3 ref4 ref5 ref6" "E:ref4 ref5 ref6 ref7" "G:ref5 ref6 ref7 cld6" "I:ref6 ref7 ref2 ref3 cld6"; do
  IFS=: read -r L nodes <<<"$pair"; printf "   %s:" $L; for n in $nodes; do printf " %s=%s" $n "${DONE[$L/$n]:--}"; done; echo
done
echo "== contagion proofs sent by cld6: $(cld_ctl cld6 '(:log)' | tr '"' '\n' | grep -c 'contagion:.*proof against')"
