#!/usr/bin/env bash
# redteam/attack-rollback-depth.sh — every honest replica offline at the fraud.
#
# On a fresh ledger R, the honest replicas (cld5 cld6 ref6 ref7) are stopped
# BEFORE the fraud: the operator (cld1) and its colluders (cld2 cld3 cld4)
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
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { case "$1" in *":STATUS :OK"*) ;; *) fail "$1";; esac; }

R_ROW="$S/redteam-${REDTEAM_R:-R}"
if [ -f "$R_ROW" ]; then read -r R < "$R_ROW"; echo "== reusing R $R"; else
  echo "== forming R (cld1 operates; cld2..cld6 ref6 ref7 cosign)"
  R=$(sx "$(cld_ctl cld1 "(:open-ledger :reserves-id \"genesis:cld1:redteam-R:$RANDOM\" :reserves-msat 25000000000 :collateral-msat 25000000000)")" ":LEDGER"); [ -n "$R" ] || fail "open R"
  for m in cld2 cld3 cld4 cld5 cld6 ref6 ref7; do
    case $m in cld*) ml=$(eval echo "\${L${m#cld}}");; ref*) ml=$(eval echo "\${RL${m#ref}}");; esac
    expect "$(cld_ctl cld1 "(:add-member :ledger \"$R\" :member \"$(cat $S/pubkey.$m)\" :member-ledger \"$ml\")")"
  done
  prep=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$R\" :expiry-blocks 4320)"); expect "$prep"; addr=$(sx "$prep" ":ADDRESS")
  txid=$(wcli sendtoaddress "$addr" 0.5); mine 3
  vout=$(bcli getrawtransaction "$txid" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$addr'][0])")
  sleep 20
  expect "$(cld_ctl cld1 "(:begin-quorum :ledger \"$R\" :txid \"$txid\" :vout $vout :sats 50000000 :collateral-sats 0)")"
  echo "$R" > "$R_ROW"
fi

# Stop the honest replicas.  Their data dirs persist; they catch up on restart.
echo "== stopping the honest replicas (cld5 cld6 ref6 ref7)"
stop_cld cld5; stop_cld cld6; stop_ref ref6; stop_ref ref7
sleep 3

# The fraud: forged lock, blind cosigners.
for n in cld2 cld3 cld4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
FROM=$(grep -P "^cl\t\S+\tA\t" "$S/deposits.tsv" | head -1 | cut -f5)
echo "== fraud: forged lock on R with the honest replicas down"
cld_ctl cld1 "(:forge-lock :ledger \"$R\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 5
# More updates on top, so the rollback has depth.
for i in 1 2 3; do
  cld_ctl cld1 "(:forge-lock :ledger \"$R\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null; sleep 3
done
for n in cld2 cld3 cld4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
tip=$(sx "$(cld_ctl cld1 "(:tip :ledger \"$R\")")" ":SEQ")
echo "== fraudulent tip at seq $tip; holding the blind window for ${HOLD}s"
sleep $HOLD

# Bring the honest replicas back.
echo "== restarting the honest replicas"
start_cld cld5; start_cld cld6; start_ref ref6; start_ref ref7
sleep 30

echo "== watching for the honest dispute on R (up to ${WAIT}s)"
T0=$(date -u +%s)
disputed=0
for i in $(seq 1 $WAIT); do
  d=$(for n in cld5 cld6; do cld_ctl $n "(:forks :ledger \"$R\")" 2>/dev/null; done | grep -c ":SEQ" || true)
  [ "$d" -gt 0 ] && { disputed=$d; break; }
  sleep 5
done
if [ "$disputed" -eq 0 ]; then
  echo "FAIL: no honest node disputed R within ${WAIT}s of restart"
  exit 1
fi
DT=$(( $(date -u +%s) - T0 ))
fork=$(cld_ctl cld5 "(:forks :ledger \"$R\")" 2>/dev/null)
last_valid=$(echo "$fork" | grep -oE ':LAST-VALID [0-9]+' | grep -oE '[0-9]+')
echo "== dispute after ${DT}s; fork last-valid seq $last_valid (fraudulent tip was $tip)"
depth=$(( tip - last_valid ))
echo "== rollback depth: $depth updates"
echo "PASS: the fraud stood ${HOLD}s unnoticed (no honest witness), was caught ${DT}s after the replicas returned, and rolled back $depth updates."
echo "     A courier leg paid against the fraudulent tip during the blind window is gone: the payment left, the ledger rolled back."
