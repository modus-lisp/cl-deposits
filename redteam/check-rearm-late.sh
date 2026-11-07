#!/usr/bin/env bash
# redteam/check-rearm-late.sh — a lottery stranded past both scheduled re-arm windows is re-armed at
# a recurring window (DEP-06 Phase 4 step 3, strict-lottery-v8, ruled 2026-11-07).  As
# check-rearm.sh, but both participants (who are also the recovery voters) hold back from arming
# until the first recurring window, as members that were down, or ran a build without re-arm,
# through the scheduled window and its reopening.  That is the shape of regtest 4a6487ee and of the
# soak's stranded lotteries.
# PASS = nothing spends the round-1 lottery output through both scheduled windows; it is then spent
# into round 2's lottery after the first recurring window (o + 144), that output is claimed, exactly
# one member logs the win, and nobody takes the recovery spend for a theft.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-1500}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 H H2
ROW=${REDTEAM_RL:-RL$RANDOM}
W=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $H $H2) || exit 1; echo "== ledger $W"
FROM=$(fresh_deposits "$ROW" $OP "$W" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"
# The block ticker would race the paced mining below: pause it for the run.
"$CLD_SRC/devnet/regtest-net.sh" ticker stop
trap '"$CLD_SRC/devnet/regtest-net.sh" ticker start; for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done; for n in $H $H2; do cld_ctl $n "(:adversary :set :withhold-reveal nil :hold-rearm-until nil)" >/dev/null 2>&1; done' EXIT

for n in $H $H2; do expect "$(cld_ctl $n "(:adversary :set :withhold-reveal t :hold-rearm-until 999999999)")"; done
for n in $C2 $C3 $C4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4
echo "== $H disputes the ledger"
cld_ctl $H "(:dispute-enter :ledger \"$W\" :reason \"redteam rearm\")" >/dev/null

VAULT=$(cld_ctl $OP '(:vaults)' | tr '()' '\n\n' | grep -F "\"$W\"" -A1 | grep -oE '[0-9a-f]{64}:[0-9]+' | tail -1)
[ -n "$VAULT" ] || fail "no vault for $W"
VINTX=${VAULT%:*}; VINVOUT=${VAULT#*:}
spender_of() {   # spender_of TXID VOUT: the txid that spent it, from the last 200 blocks
  local tip h; tip=$(bcli getblockcount)
  for h in $(seq "$tip" -1 $((tip - 200))); do
    bcli getblock "$(bcli getblockhash "$h")" 2 2>/dev/null | python3 -c '
import json,sys
b=json.load(sys.stdin); t,v=sys.argv[1],int(sys.argv[2])
for tx in b["tx"]:
    for vin in tx.get("vin",[]):
        if vin.get("txid")==t and vin.get("vout")==v: print(tx["txid"]); sys.exit(0)
sys.exit(1)' "$1" "$2" && return 0
  done; return 1
}
echo "== waiting for the confiscation to confirm"
CONF=""
for i in $(seq 1 $((WAIT / 5))); do
  [ -z "$(bcli gettxout "$VINTX" "$VINVOUT" true 2>/dev/null | head -1)" ] && CONF=$(spender_of "$VINTX" "$VINVOUT") && [ -n "$CONF" ] && break
  [ $((i % 3)) -eq 0 ] && mine 1 >/dev/null   # the ticker is paused: the arm window closes on height
  sleep 5
done
[ -n "$CONF" ] || fail "no confiscation confirmed within ${WAIT}s"
echo "== confiscation $CONF; its lottery output withheld by both participants"
# The withholding stays on: it holds back round 1's reveals only; a re-arm round's reveal is sent
# regardless (DRIVE-REARM), so round 2 can be claimed.
HC=$(bcli getrawtransaction "$CONF" 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["blockhash"])')
HC=$(bcli getblockheader "$HC" | python3 -c 'import json,sys; print(json.load(sys.stdin)["height"])')
W_ARM=6; O=$((HC + 72)); K=144   # regtest ledgers name dispute_arm_blocks 6: k = 144
echo "== confiscation at height $HC: scheduled windows ($O, $((O + W_ARM))] and ($((O + W_ARM)), $((O + 2 * W_ARM))]; first recurring ($((O + K)), $((O + K + W_ARM))]"
# Hold the participants back until the first recurring window opens, then mine through both
# scheduled windows: nothing may spend the lottery output there.
for n in $H $H2; do expect "$(cld_ctl $n "(:adversary :set :hold-rearm-until $((O + K + 1)))")"; done
slow_until() { while [ "$(bcli getblockcount)" -lt "$1" ]; do mine 1 >/dev/null; sleep "$2"; done; }
slow_until $((O + 2 * W_ARM + 20)) 2
[ -n "$(bcli gettxout "$CONF" 0 true 2>/dev/null | head -1)" ] || fail "the lottery output was spent during the scheduled windows, with nobody armed"
for n in $H $H2; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "dispute ${W:0:8}:" | grep -E "next arm window" | tail -1 | sed "s/^/   $n: /"; done
echo "== both scheduled windows passed unarmed and the output is unspent; on to the recurring window"
slow_until $((O + K - 2)) 0; slow_until $((O + K + W_ARM + 2)) 15
echo "== waiting for the re-arm spend of $CONF:0"
R2=""
for i in $(seq 1 $((WAIT / 5))); do
  if [ -z "$(bcli gettxout "$CONF" 0 true 2>/dev/null | head -1)" ]; then R2=$(spender_of "$CONF" 0); [ -n "$R2" ] && break; fi
  [ $((i % 4)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
[ -n "$R2" ] || fail "the round-1 lottery output $CONF:0 was not spent within ${WAIT}s"
nout=$(bcli getrawtransaction "$R2" 1 | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["vout"]))')
[ "$nout" = 1 ] || fail "$CONF:0 was spent by $R2 with $nout outputs: not a re-arm spend (a claim?)"
for n in $H $H2; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "dispute ${W:0:8}:" | grep -E "round 2|re-arm" | tail -2 | sed "s/^/   $n: /"; done
echo "== re-arm spend $R2; waiting for round 2's reveals and claim"
CLAIM=""
for i in $(seq 1 $((WAIT / 5))); do
  if [ -z "$(bcli gettxout "$R2" 0 true 2>/dev/null | head -1)" ]; then CLAIM=$(spender_of "$R2" 0); [ -n "$CLAIM" ] && break; fi
  [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
[ -n "$CLAIM" ] || fail "round 2's lottery output $R2:0 was not claimed within ${WAIT}s"
won=$(for n in $H $H2; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "dispute ${W:0:8}: re-arm round 2: won" | head -1 | sed "s/^/$n /"; done)
[ "$(printf '%s\n' "$won" | grep -c 'won')" = 1 ] || fail "expected exactly one round-2 winner, got: ${won:-none}"
for n in $C2 $C3 $C4 $H $H2 $OP; do
  if cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "VAULT SPEND|unauthori[sz]ed spend" | grep -qi "${R2:0:16}"; then
    fail "$n took the re-arm spend for a theft"
  fi
done
spend_h=$(bcli getblockheader "$(bcli getrawtransaction "$R2" 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["blockhash"])')" | python3 -c 'import json,sys; print(json.load(sys.stdin)["height"])')
[ "$spend_h" -gt $((O + K + W_ARM)) ] || fail "the re-arm spend confirmed at $spend_h, before the recurring window closed"
echo "PASS: round 1 stranded past both scheduled windows; the recurring window re-armed it ($R2, block $spend_h) and round 2 was claimed ($CLAIM) by ${won%% *}."
