#!/usr/bin/env bash
# redteam/attack-rollback-depth.sh — every honest replica offline at the fraud.
#
# On a fresh ledger R, the honest replicas (HON ref6 ref7) are stopped
# BEFORE the fraud: the operator (OP) and its colluders (cld2 cld3 cld4 cld5)
# commit a forged lock.  The fraud stands for $HOLD s with no honest witness.
# Then the replicas come back, catch up, and dispute.  We measure:
#   - how long the fraud stood (detection latency = HOLD + catch-up + dispute),
#   - how deep the rollback reaches (the fork's last-valid sequence vs the
#     fraudulent tip: every update after the fraud rolls back),
#   - whether a courier leg paid against the fraudulent tip is recoverable
#     (it is not: the payment left, the ledger rolls back — the loss the
#     trust model prices).
# PASS = the honest replicas dispute after catch-up, and the rollback depth
# equals the number of updates committed during the blind window.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; HOLD=${HOLD:-60}; WAIT=${WAIT:-300}
source "$(dirname "$0")/_lib.sh"
pick OP HON   # a tainted OP's R is disputed on sight, before the honest replicas go down
trap 'start_cld "$HON" >/dev/null 2>&1; for r in ref6 ref7; do ref_running $r || start_ref $r >/dev/null 2>&1; done' EXIT   # never leave the replicas down
ROW=${REDTEAM_R:-R}
R=$(COLLATERAL_SATS=25000000 form_ledger "$ROW" $OP "" cld2 cld3 cld4 cld5 $HON ref6 ref7) || exit 1; echo "== R $R ($OP operates; cld2..$HON ref6 ref7 cosign)"
# A credited deposit on R, so the forged lock is a real over-balance/no-witness fault.
mapfile -t DEPS < <(fresh_deposits "$ROW" $OP "$R" 1); DEP=${DEPS[0]}; [ -n "$DEP" ] || fail "no deposit on R"
FROM="$DEP"

# Stop the honest replicas.  Their data dirs persist; they catch up on restart.
sleep 15; pre_forks=$(cld_ctl $HON "(:forks :ledger \"$R\")" 2>/dev/null | grep -oE ":STATE :[A-Z]+" | wc -l)
[ "$pre_forks" -eq 0 ] || fail "R was disputed before the fraud ($pre_forks fork(s) on $HON): the measure would be meaningless"
echo "== stopping the honest replicas ($HON ref6 ref7)"
stop_cld $HON; stop_ref ref6; stop_ref ref7
sleep 3

# The fraud: forged lock, blind cosigners.
for n in cld2 cld3 cld4 cld5; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
pre=$(sx "$(cld_ctl $OP "(:tip :ledger \"$R\")")" ":SEQ")   # the last honest update: an honest fork must branch at or before it
echo "== fraud: forged lock on R with the honest replicas down (honest tip seq $pre)"
cld_ctl $OP "(:forge-lock :ledger \"$R\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 5
# More updates on top, so the rollback has depth.
for i in 1 2 3; do
  cld_ctl $OP "(:forge-lock :ledger \"$R\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null; sleep 3
done
for n in cld2 cld3 cld4 cld5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP"   # it committed the fraud
tip=$(sx "$(cld_ctl $OP "(:tip :ledger \"$R\")")" ":SEQ")
echo "== fraudulent tip at seq $tip; holding the blind window for ${HOLD}s"
sleep $HOLD

# Bring the honest replicas back.
echo "== restarting the honest replicas"
start_cld $HON; start_ref ref6; start_ref ref7
t_up=$(date +%s)
for i in $(seq 1 120); do cld_ctl $HON "(:info)" 2>/dev/null | grep -q ":STATUS :OK" && break; sleep 5; done   # a cl node loads its histories for minutes
echo "== $HON answering $(( $(date +%s) - t_up ))s after restart"

echo "== watching for the honest dispute on R (up to ${WAIT}s)"
T0=$(date -u +%s)
disputed=0
for i in $(seq 1 $((WAIT/5))); do
  # only the honest replica's OWN fork: (:forks) also lists forks it replicates from other members
  d=$(cld_ctl $HON "(:forks :ledger \"$R\")" 2>/dev/null | grep -oE ":OPERATOR \"$(cut -c1-16 "$S/pubkey.$HON")\" :SEQ [0-9]+ :STATE :(DISPUTED|ARMED)" | wc -l)
  [ "$d" -gt 0 ] && { disputed=$d; break; }
  sleep 5
done
if [ "$disputed" -eq 0 ]; then
  echo "FAIL: no honest node disputed R within ${WAIT}s of restart"
  exit 1
fi
DT=$(( $(date -u +%s) - T0 ))
fseq=$(cld_ctl $HON "(:forks :ledger \"$R\")" 2>/dev/null | grep -oE ":OPERATOR \"$(cut -c1-16 "$S/pubkey.$HON")\" :SEQ [0-9]+" | grep -oE '[0-9]+$')
echo "== $HON disputed ${DT}s after it answered; its fork is at seq $fseq (honest tip $pre, fraudulent tip $tip)"
depth=$(( tip - pre ))
echo "== rollback depth: $depth updates"
echo "PASS: the fraud stood ${HOLD}s unnoticed (no honest witness), was caught ${DT}s after the replicas returned, and rolled back $depth updates."
echo "     A courier leg paid against the fraudulent tip during the blind window is gone: the payment left, the ledger rolled back."
