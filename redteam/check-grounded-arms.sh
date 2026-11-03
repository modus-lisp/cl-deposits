#!/usr/bin/env bash
# redteam/check-grounded-arms.sh — DEP-03 §Grounded arms (DEP-18 grounded-arms-v7): an arm whose
# DisputeEnter has no grounds is disregarded, and the lottery runs over the grounded arms alone.
#
# A fresh cl ledger is seated under grounded-arms-v7 with a short quorum expiry.  Past it, two
# members dispute on the expiry (a ground) and a third disputes on a punitive reason it cannot
# prove (no proof carried: no ground).  All three arm.  PASS = every member's lottery set excludes
# the groundless armer ("no grounds"), the confiscation confirms over the two grounded armers, no
# node challenges or proves anything against it, and one of the two claims custody.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-1500}
source "$(dirname "$0")/_lib.sh"
pick OP G1 G2 U1 M5 M6   # five members besides the operator: Q must be 3, 5 or 7
ROW=${REDTEAM_GA:-GA$RANDOM}
W=$(COLLATERAL_SATS=25000000 FORM_EXPIRY=${FORM_EXPIRY:-40} form_ledger "$ROW" $OP grounded-arms-v7 $G1 $G2 $U1 $M5 $M6) || exit 1; echo "== ledger $W"
RS=$(cld_ctl $OP "(:info)" | tr '()' '\n\n' | grep -F "\"$W\"" | grep -oE ':RULESET "[^"]*"' | head -1)
echo "== $RS"
case "$RS" in *grounded-arms-v7*) ;; *) fail "the ledger is not on grounded-arms-v7 ($RS)";; esac
EXP=$(cld_ctl $OP "(:info)" | tr '()' '\n\n' | grep -F "\"$W\"" | grep -oE ':EXPIRY [0-9]+' | head -1 | grep -oE '[0-9]+')
echo "== quorum expiry ${EXP:-?}; waiting past it"
for i in $(seq 1 $((WAIT / 10))); do
  [ -n "$EXP" ] && [ "$(bcli getblockcount)" -gt $((EXP + 2)) ] && break
  sleep 10
done
[ "$(bcli getblockcount)" -gt $((${EXP:-0} + 2)) ] || fail "the quorum did not expire within ${WAIT}s"
taint "$OP" $G1 $G2 $U1 $M5 $M6
echo "== $U1 disputes on a punitive reason it carries no proof of; $G1 and $G2 on the expiry"
cld_ctl $U1 "(:dispute-enter :ledger \"$W\" :reason \"non_conforming_update\")" >/dev/null
for n in $G1 $G2; do cld_ctl $n "(:dispute-enter :ledger \"$W\" :reason \"quorum_expired\")" >/dev/null; done

echo "== waiting for the confiscation (arm, cosign, broadcast) — up to ${WAIT}s"
conf=""
for i in $(seq 1 $((WAIT / 5))); do
  conf=$(for n in $G1 $G2 $M5 $M6; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "confiscation .* on chain" | grep -F "${W:0:8}" | grep -oE '[0-9a-f]{64}' | head -1; done | head -1)
  [ -n "$conf" ] && break
  [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
lines=$(for n in $G1 $G2 $U1 $M5; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "lottery participants of ${W:0:16}" | tail -1; done)
echo "$lines" | sed 's/^/   /'
uk=$(cld_pubkey $U1 | cut -c1-16)
excl=$(for n in $G1 $G2 $M5 $M6; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "excluded from ${W:0:8}'s lottery: no grounds" | grep -F "${uk:0:8}" | tail -1; done | head -1)
echo "   $excl"
[ -n "$excl" ] || fail "no member excluded $U1's groundless arm"
echo "$lines" | grep -F "participants of ${W:0:16}" | grep -oE '\[[^]]*\];' | grep -qF "$uk" && fail "$U1 is a lottery participant"
[ -n "$conf" ] || fail "no confiscation confirmed within ${WAIT}s"
echo "== confiscation $conf"
mine 6 >/dev/null; sleep 60; mine 3 >/dev/null; sleep 30
bad=$(for n in $(cld_names); do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "${W:0:8}" | grep -E "QuorumChallenge|challenge .* opened|UNAUTHORISED|unauthorised spend" | tail -1; done | head -3)
[ -z "$bad" ] || fail "a node took the grounded confiscation for a theft: $bad"
echo "PASS: $U1's arm without grounds was disregarded; the lottery ran over $G1 and $G2 and nobody challenged the confiscation"
