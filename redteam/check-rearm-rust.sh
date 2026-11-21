#!/usr/bin/env bash
# redteam/check-rearm-rust.sh — a re-arm round that deposits-rust drives end to end (DEP-06 Phase 4,
# strict-lottery-v8): it arms round 2, proposes and assembles the recovery spend, and reveals and
# claims round 2.
#
# A ledger (cl operator OP; C2..C4 cl, cosign blind and accused; H cl, honest; R reference) runs to
# a punitive confiscation.  R starts with DEPOSITS_REDTEAM_NO_ARM=1 (round 1 only: it disputes but
# does not arm), so round 1's only participant is H; H withholds its reveal, so round 1 goes
# unclaimed.  The recovery voters are H and R (threshold 2).  H never arms round 2 (ADVERSARY
# :hold-rearm-until) and never proposes (:rearm-sign-only), so R is round 2's only armer, its
# proposer and its claimer, and H's part is to answer R's lottery_rearm_sign.
# PASS = the round-1 output is spent through tier 0 (nSequence 144) into round 2's lottery by R's
# proposal, R claims that output, and nobody takes the spend for a theft.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-1500}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 H
R=${R:-ref7}
echo "== $R restarts as a voter that never arms"
stop_ref $R >/dev/null 2>&1; REF_EXTRA_ENV="DEPOSITS_REDTEAM_NO_ARM=1 DEPOSITS_REARM_DRIVE=1" start_ref $R >/dev/null || fail "$R did not restart"
RLOG="$CLD_ROOT/$R/node.log"; RFROM=$(( $(stat -c %s "$RLOG") + 1 ))
# R's round-2 pledge sits at its operator key's P2WPKH.
RPUB=$(ref_pubkey $R); [ -n "$RPUB" ] || fail "no pubkey for $R"
RADDR=$(bcli deriveaddresses "$(bcli getdescriptorinfo "wpkh($RPUB)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["descriptor"])')" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0])')
wcli sendtoaddress "$RADDR" 0.5 >/dev/null && mine 2 >/dev/null || fail "could not fund $R's pledge at $RADDR"
ROW=${REDTEAM_RR2:-RR$RANDOM}
W=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $H $R) || exit 1; echo "== ledger $W"
FROM=$(fresh_deposits "$ROW" $OP "$W" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"
"$CLD_SRC/devnet/regtest-net.sh" ticker stop
trap '"$CLD_SRC/devnet/regtest-net.sh" ticker start; for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done; cld_ctl $H "(:adversary :set :withhold-reveal nil :hold-rearm-until nil :rearm-sign-only nil)" >/dev/null 2>&1; stop_ref $R >/dev/null 2>&1; start_ref $R >/dev/null 2>&1' EXIT

expect "$(cld_ctl $H "(:adversary :set :withhold-reveal t :hold-rearm-until 100000000 :rearm-sign-only t)")"
for n in $C2 $C3 $C4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4
echo "== $H disputes the ledger"
cld_ctl $H "(:dispute-enter :ledger \"$W\" :reason \"redteam rearm rust\")" >/dev/null

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
# R passes over the dispute every 30-60 s: slowly through round 2's arm window.
slow_until $((HC + 70)) 1; slow_until $((HC + 72 + 10)) 45; slow_until $((HC + 143)) 1
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
rl() { tail -c +"$RFROM" "$RLOG" | sed 's/\x1b\[[0-9;]*m//g'; }
rlhas() { rl | grep -aq "$1"; }
rlhas "re-arm ${W:0:16}: lottery round 1 unclaimed; armed round 2" || fail "$R did not log arming round 2"
poll 300 rlhas "re-arm ${W:0:16}: lottery round 1 unclaimed; spent into round 2's lottery (tier 0)" \
  || fail "the re-arm spend $R2 is not R's proposal: $(cld_ctl $H '(:log)' | tr '"' '\n' | grep -F "dispute ${W:0:8}:" | tail -2 | tr '\n' ' ')"
echo "== re-arm spend $R2 through tier 0, proposed by $R; waiting for $R's round-2 claim"
CLAIM=""
for i in $(seq 1 $((WAIT / 5))); do
  if [ -z "$(bcli gettxout "$R2" 0 true 2>/dev/null | head -1)" ]; then CLAIM=$(spender_of "$R2" 0); [ -n "$CLAIM" ] && break; fi
  [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
if [ -z "$CLAIM" ]; then rl | grep -E "re-arm ${W:0:16}|Found lottery UTXO|claim" | tail -5 | sed "s/^/   $R: /"; fail "round 2's lottery output $R2:0 was not claimed within ${WAIT}s"; fi
# "won" follows the claim's CONFIRMATION (DisputeAcquire persisted), so keep mining while waiting.
NPOLL=0; won() { rlhas "re-arm ${W:0:16}: re-arm round 2: won" && return 0; NPOLL=$((NPOLL + 1)); [ $((NPOLL % 6)) -eq 0 ] && mine 1 >/dev/null; return 1; }
poll 600 won || fail "$R did not log the round-2 win within 600 s of its claim $CLAIM"
for n in $C2 $C3 $C4 $H $OP; do
  if cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "VAULT SPEND|unauthori[sz]ed spend" | grep -qi "${R2:0:16}"; then
    fail "$n took the re-arm spend for a theft"
  fi
done
echo "PASS: round 1 unclaimed; $R armed round 2, proposed its tier-0 spend ($R2, $H co-signing) and claimed round 2 ($CLAIM)."
