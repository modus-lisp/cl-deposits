#!/usr/bin/env bash
# redteam/check-rearm-mixed.sh — a re-arm round whose recovery spend needs a reference node's
# signature (DEP-06 Phase 4, strict-lottery-v8).  deposits-rust answered "Unknown action:
# lottery_rearm_sign" until 2026-11-14, so in a mixed quorum a re-arm went through only at a tier
# its cl voters reached alone (signet soak, Nov 8..13).
#
# A ledger (cl operator OP; C2..C4 cl, cosign blind and accused; H cl, honest; R reference,
# honest, started with DEPOSITS_REDTEAM_NO_ARM=1 so it is a voter, not a participant) runs to a
# punitive confiscation.  Under v8 the lottery's only participant is H and its recovery voters are
# H and R (threshold 2): tier 0 (CSV 144) needs R's signature, and tier 1 does not open before CSV
# 1008.  H withholds its round-1 reveal, so nobody can claim; H arms round 2 and, as proposer, asks
# R for its signature on the recovery spend.
# PASS = the round-1 lottery output is spent through tier 0 (nSequence 144) into a new lottery
# output, R logged signing it, that output is claimed by H, and nobody takes the spend for a theft.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-1500}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 H
R=${R:-ref7}
echo "== $R restarts as a voter that never arms"
stop_ref $R >/dev/null 2>&1; REF_EXTRA_ENV=DEPOSITS_REDTEAM_NO_ARM=1 start_ref $R >/dev/null || fail "$R did not restart"
RLOG="$CLD_ROOT/$R/node.log"; RFROM=$(( $(stat -c %s "$RLOG") + 1 ))
ROW=${REDTEAM_RM:-RM$RANDOM}
W=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $H $R) || exit 1; echo "== ledger $W"
FROM=$(fresh_deposits "$ROW" $OP "$W" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"
"$CLD_SRC/devnet/regtest-net.sh" ticker stop
trap '"$CLD_SRC/devnet/regtest-net.sh" ticker start; for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done; cld_ctl $H "(:adversary :set :withhold-reveal nil)" >/dev/null 2>&1; stop_ref $R >/dev/null 2>&1; start_ref $R >/dev/null 2>&1' EXIT

expect "$(cld_ctl $H "(:adversary :set :withhold-reveal t)")"
for n in $C2 $C3 $C4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4
echo "== $H disputes the ledger"
cld_ctl $H "(:dispute-enter :ledger \"$W\" :reason \"redteam rearm mixed\")" >/dev/null

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
  [ $((i % 3)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
[ -n "$CONF" ] || fail "no confiscation confirmed within ${WAIT}s"
HC=$(bcli getrawtransaction "$CONF" 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["blockhash"])')
HC=$(bcli getblockheader "$HC" | python3 -c 'import json,sys; print(json.load(sys.stdin)["height"])')
echo "== confiscation $CONF at height $HC; round 2's window opens at $((HC + 72)), tier 0 at $((HC + 144))"
slow_until() { while [ "$(bcli getblockcount)" -lt "$1" ]; do mine 1 >/dev/null; sleep "$2"; done; }
slow_until $((HC + 70)) 1; slow_until $((HC + 72 + 14)) 15; slow_until $((HC + 143)) 1
echo "== waiting for the re-arm spend of $CONF:0 (tier 0 needs $R)"
R2=""
for i in $(seq 1 $((WAIT / 5))); do
  if [ -z "$(bcli gettxout "$CONF" 0 true 2>/dev/null | head -1)" ]; then R2=$(spender_of "$CONF" 0); [ -n "$R2" ] && break; fi
  [ $((i % 4)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
if [ -z "$R2" ]; then
  tail -c +"$RFROM" "$RLOG" | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'lottery_rearm_sign|re-arm' | tail -5 | sed "s/^/   $R: /"
  cld_ctl $H '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "dispute ${W:0:8}:" | tail -3 | sed "s/^/   $H: /"
  fail "the round-1 lottery output $CONF:0 was not spent within ${WAIT}s"
fi
read -r nout seq <<<"$(bcli getrawtransaction "$R2" 1 | python3 -c 'import json,sys; t=json.load(sys.stdin); print(len(t["vout"]), t["vin"][0]["sequence"])')"
[ "$nout" = 1 ] || fail "$CONF:0 was spent by $R2 with $nout outputs: not a re-arm spend (a claim?)"
[ "$seq" = 144 ] || fail "the re-arm spend $R2 went through nSequence $seq, not tier 0's 144"
tail -c +"$RFROM" "$RLOG" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Signed the re-arm spend of ${W:0:16}" \
  || fail "$R did not log signing the re-arm spend"
echo "== re-arm spend $R2 through tier 0, signed by $R; waiting for round 2's claim"
CLAIM=""
for i in $(seq 1 $((WAIT / 5))); do
  if [ -z "$(bcli gettxout "$R2" 0 true 2>/dev/null | head -1)" ]; then CLAIM=$(spender_of "$R2" 0); [ -n "$CLAIM" ] && break; fi
  [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
[ -n "$CLAIM" ] || fail "round 2's lottery output $R2:0 was not claimed within ${WAIT}s"
await_won 600 "dispute ${W:0:8}: re-arm round 2: won" $H >/dev/null || fail "$H did not log the round-2 win within 600 s of the claim"
for n in $C2 $C3 $C4 $H $OP; do
  if cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "VAULT SPEND|unauthori[sz]ed spend" | grep -qi "${R2:0:16}"; then
    fail "$n took the re-arm spend for a theft"
  fi
done
tail -c +"$RFROM" "$RLOG" | sed 's/\x1b\[[0-9;]*m//g' | grep -iE "unauthori[sz]ed.*${R2:0:16}" && fail "$R took the re-arm spend for a theft"
echo "PASS: round 1 unclaimed; $R signed the tier-0 re-arm spend ($R2) and $H claimed round 2 ($CLAIM)."
