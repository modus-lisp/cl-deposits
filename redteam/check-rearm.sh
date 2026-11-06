#!/usr/bin/env bash
# redteam/check-rearm.sh — an unclaimed lottery is re-armed (DEP-06 Phase 4, strict-lottery-v8,
# provisional): every participant withholds its reveal, so nobody can claim; past the reveal
# deadline a fresh arm round opens, the recovery voters spend the lottery output into that round's
# lottery once its CSV-144 recovery leaf is open, and that round's reveals and claim hand custody
# to one participant.
#
# A cl-only ledger (operator OP; C2..C4 cosign blind and are accused; H, H2 honest) runs to a
# punitive confiscation.  Under v8 the lottery's participants are H and H2 (the accused never
# win) and its recovery voters are H and H2 (threshold 2).  Both withhold their round-1 reveal.
# PASS = a recovery spend of the round-1 lottery output pays a new lottery output, that output is
# claimed, exactly one member logs the win, and nobody takes the recovery spend for a theft.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-1500}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 H H2
ROW=${REDTEAM_RA:-RA$RANDOM}
W=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $H $H2) || exit 1; echo "== ledger $W"
FROM=$(fresh_deposits "$ROW" $OP "$W" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"
trap 'for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done; for n in $H $H2; do cld_ctl $n "(:adversary :set :withhold-reveal nil)" >/dev/null 2>&1; done' EXIT

for n in $H $H2; do expect "$(cld_ctl $n "(:adversary :set :withhold-reveal t)")"; done
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
  sleep 5
done
[ -n "$CONF" ] || fail "no confiscation confirmed within ${WAIT}s"
echo "== confiscation $CONF; its lottery output withheld by both participants"
# The withholding stays on: it holds back round 1's reveals only; a re-arm round's reveal is sent
# regardless (DRIVE-REARM), so round 2 can be claimed.
echo "== waiting for the re-arm spend of $CONF:0 (needs the CSV-144 recovery leaf: mining)"
R2=""
for i in $(seq 1 $((WAIT / 5))); do
  if [ -z "$(bcli gettxout "$CONF" 0 true 2>/dev/null | head -1)" ]; then R2=$(spender_of "$CONF" 0); [ -n "$R2" ] && break; fi
  [ $((i % 2)) -eq 0 ] && mine 2 >/dev/null
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
echo "PASS: nobody revealed round 1; round 2 re-armed ($R2) and its lottery was claimed ($CLAIM) by ${won%% *}."
