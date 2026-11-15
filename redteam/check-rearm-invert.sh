#!/usr/bin/env bash
# redteam/check-rearm-invert.sh — two rule inverters (docs/ADVERSARIAL.md §Rule inverters) in one
# re-arm round (DEP-06 Phase 4, strict-lottery-v8):
#  - H2 publishes a late same-round arm after round 2's window closed (ADVERSARY :late-rearm), as
#    an armer trying to withdraw from a closed window.  DEP-06 step 2: each armer's latest arm
#    INSIDE the window counts, so H2 stays in the cut.
#  - H3, a recovery voter, inverts the arm selection (ADVERSARY :invert-arm-selection: the latest
#    counted arm, then window-filtered), so it drops H2 and proposes a spend into a lottery without
#    it.  Nobody else rebuilds that spend, so nobody signs it; the honest spend lands anyway.
# The base is check-rearm-yield.sh: C2..C5 cosign blind and are accused; H, H2, H3 are the round-1
# participants and the recovery voters (threshold 2); all three reveal and yield round 1 (:yield-win).
# PASS = H2 logged its late arm; the round-1 output was spent into round 2 (one output); H2 is a
# round-2 participant (it reveals there); H or H2 refused H3's spend ("not the one we rebuild");
# round 2 is claimed; nobody takes the spend for a theft.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-1500}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 C5 H H2 H3
ROW=${REDTEAM_RI:-RI$RANDOM}
W=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $C5 $H $H2 $H3) || exit 1; echo "== ledger $W"
FROM=$(fresh_deposits "$ROW" $OP "$W" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"
# The block ticker would race the paced mining below: pause it for the run.
"$CLD_SRC/devnet/regtest-net.sh" ticker stop
trap '"$CLD_SRC/devnet/regtest-net.sh" ticker start; for n in $C2 $C3 $C4 $C5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done; for n in $H $H2 $H3; do cld_ctl $n "(:adversary :set :yield-win nil :late-rearm nil :invert-arm-selection nil)" >/dev/null 2>&1; done' EXIT

for n in $H $H2 $H3; do expect "$(cld_ctl $n "(:adversary :set :yield-win t)")"; done
expect "$(cld_ctl $H2 "(:adversary :set :late-rearm t)")"
expect "$(cld_ctl $H3 "(:adversary :set :invert-arm-selection t)")"
for n in $C2 $C3 $C4 $C5; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4 $C5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4 $C5
echo "== $H disputes the ledger"
cld_ctl $H "(:dispute-enter :ledger \"$W\" :reason \"redteam rearm-invert\")" >/dev/null

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
echo "== confiscation $CONF; both participants reveal, then both yield"
HC=$(bcli getrawtransaction "$CONF" 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["blockhash"])')
HC=$(bcli getblockheader "$HC" | python3 -c 'import json,sys; print(json.load(sys.stdin)["height"])')
echo "== confiscation at height $HC: with revealers, round 2's arm window opens at $((HC + 144))"
slow_until() { while [ "$(bcli getblockcount)" -lt "$1" ]; do mine 1 >/dev/null; sleep "$2"; done; }
# Slowly through the reveal deadline so both reveal and yield, fast to the CSV-144 leaf, slowly
# through round 2's arm window.
slow_until $((HC + 10)) 10; slow_until $((HC + 76)) 3
# From node.log, not (:log): a busy node's ring buffer can drop the line before we look (regtest,
# 2026-11-07: cld145's yield was logged but not counted).
# Past the reveal deadline each yields on its next pass; a busy node's pass can run minutes (reveals
# wait for 3 confirmations), so poll rather than count once (regtest, 2026-11-10: both yielded,
# 4 and 6 minutes after the count).
for i in $(seq 1 60); do
  yielded=0; for n in $H $H2 $H3; do grep -aF "dispute ${W:0:8}: lottery: yielded" "$(cld_dir $n)/node.log" >/dev/null 2>&1 && yielded=$((yielded+1)); done
  [ "$yielded" -eq 3 ] && break; sleep 10
done
echo "== $yielded of 3 participants logged a round-1 yield"
slow_until $((HC + 142)) 1; slow_until $((HC + 144 + 14)) 15
echo "== waiting for the re-arm spend of $CONF:0"
R2=""
for i in $(seq 1 $((WAIT / 5))); do
  if [ -z "$(bcli gettxout "$CONF" 0 true 2>/dev/null | head -1)" ]; then R2=$(spender_of "$CONF" 0); [ -n "$R2" ] && break; fi
  [ $((i % 4)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
[ -n "$R2" ] || fail "the round-1 lottery output $CONF:0 was not spent within ${WAIT}s"
nout=$(bcli getrawtransaction "$R2" 1 | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["vout"]))')
[ "$nout" = 1 ] || fail "$CONF:0 was spent by $R2 with $nout outputs: not a re-arm spend"
grep -aF "dispute ${W:0:8}: ADVERSARY: late re-arm of round 2" "$(cld_dir $H2)/node.log" >/dev/null || fail "$H2 never published its late arm"
echo "== re-arm spend $R2; $H2 late-armed; waiting for round 2's reveals and claim"
CLAIM=""
for i in $(seq 1 $((WAIT / 5))); do
  if [ -z "$(bcli gettxout "$R2" 0 true 2>/dev/null | head -1)" ]; then CLAIM=$(spender_of "$R2" 0); [ -n "$CLAIM" ] && break; fi
  [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
[ -n "$CLAIM" ] || fail "round 2's lottery output $R2:0 was not claimed within ${WAIT}s"
grep -aF "dispute ${W:0:8}: re-arm round 2's lottery on chain; revealed" "$(cld_dir $H2)/node.log" >/dev/null \
  || fail "$H2 is not a round-2 participant: its late arm withdrew it from the closed window"
refused=$(for n in $H $H2; do grep -aF "refused lottery_rearm_sign: the re-arm spend is not the one we rebuild" "$(cld_dir $n)/node.log" | head -1 | sed "s/^/$n: /"; done)
[ -n "$refused" ] || fail "nobody refused the inverter's spend (did $H3 propose? $(grep -aF "dispute ${W:0:8}: ADVERSARY: inverter" "$(cld_dir $H3)/node.log" | tail -1))"
for n in $C2 $C3 $C4 $C5 $H $H2 $H3 $OP; do
  if cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "VAULT SPEND|unauthori[sz]ed spend" | grep -qi "${R2:0:16}"; then
    fail "$n took the re-arm spend for a theft"
  fi
done
echo "PASS: round 2 re-armed ($R2) with late-armer $H2 in its cut; the inverter $H3's spend was refused ($(echo "$refused" | head -1 | cut -c1-60)); round 2 claimed ($CLAIM)"
