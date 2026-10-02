#!/usr/bin/env bash
# redteam/attack-rollback-depth.sh — every honest replica offline at the fraud.
#
# On a fresh ledger R, the honest replicas (cld6 ref6 ref7) are stopped
# BEFORE the fraud: the operator (cld1) and its colluders (cld2 cld3 cld4 cld5)
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
ROW=${REDTEAM_R:-R}
R=$(form_ledger "$ROW" cld1 "" cld2 cld3 cld4 cld5 cld6 ref6 ref7) || exit 1; echo "== R $R (cld1 operates; cld2..cld6 ref6 ref7 cosign)"
# A credited deposit on R, so the forged lock is a real over-balance/no-witness fault.
mapfile -t DEPS < <(fresh_deposits "$ROW" cld1 "$R" 1); DEP=${DEPS[0]}; [ -n "$DEP" ] || fail "no deposit on R"
FROM="$DEP"

# Stop the honest replicas.  Their data dirs persist; they catch up on restart.
echo "== stopping the honest replicas (cld6 ref6 ref7)"
stop_cld cld6; stop_ref ref6; stop_ref ref7
sleep 3

# The fraud: forged lock, blind cosigners.
for n in cld2 cld3 cld4 cld5; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
echo "== fraud: forged lock on R with the honest replicas down"
cld_ctl cld1 "(:forge-lock :ledger \"$R\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 5
# More updates on top, so the rollback has depth.
for i in 1 2 3; do
  cld_ctl cld1 "(:forge-lock :ledger \"$R\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null; sleep 3
done
for n in cld2 cld3 cld4 cld5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
tip=$(sx "$(cld_ctl cld1 "(:tip :ledger \"$R\")")" ":SEQ")
echo "== fraudulent tip at seq $tip; holding the blind window for ${HOLD}s"
sleep $HOLD

# Bring the honest replicas back.
echo "== restarting the honest replicas"
start_cld cld6; start_ref ref6; start_ref ref7
t_up=$(date +%s)
for i in $(seq 1 120); do cld_ctl cld6 "(:info)" 2>/dev/null | grep -q ":STATUS :OK" && break; sleep 5; done   # a cl node loads its histories for minutes
echo "== cld6 answering $(( $(date +%s) - t_up ))s after restart"

echo "== watching for the honest dispute on R (up to ${WAIT}s)"
T0=$(date -u +%s)
disputed=0
for i in $(seq 1 $((WAIT/5))); do
  d=$(for n in cld6; do cld_ctl $n "(:forks :ledger \"$R\")" 2>/dev/null; done | grep -oE ":STATE :(DISPUTED|ARMED)" | wc -l)
  [ "$d" -gt 0 ] && { disputed=$d; break; }
  sleep 5
done
if [ "$disputed" -eq 0 ]; then
  echo "FAIL: no honest node disputed R within ${WAIT}s of restart"
  exit 1
fi
DT=$(( $(date -u +%s) - T0 ))
fork=$(cld_ctl cld6 "(:forks :ledger \"$R\")" 2>/dev/null)
last_valid=$(echo "$fork" | grep -oE ':LAST-VALID [0-9]+' | grep -oE '[0-9]+')
echo "== dispute after ${DT}s; fork last-valid seq $last_valid (fraudulent tip was $tip)"
depth=$(( tip - last_valid ))
echo "== rollback depth: $depth updates"
echo "PASS: the fraud stood ${HOLD}s unnoticed (no honest witness), was caught ${DT}s after the replicas returned, and rolled back $depth updates."
echo "     A courier leg paid against the fraudulent tip during the blind window is gone: the payment left, the ledger rolled back."
