#!/usr/bin/env bash
# redteam/check-rearm-restart.sh — the all-yield re-arm (check-rearm-yield.sh) with a participant
# restarted after its round-1 yield, while the ledger's quorum has expired (signet soak 2026-11-07,
# 751e6951).  There the restarted cld7 saw its forks yielded, took the ledger for undisputed and
# expired, opened a second dispute on the confiscated vault, rebuilt a confiscation that was not on
# chain, "won" its lottery off chain; its fellows concluded "claimed by its winner", and the output
# never re-armed.  PASS additionally needs the restarted node to open no second dispute and log no
# round-1 win.
#
# Base scenario (check-rearm-yield.sh): an unclaimed lottery WITH revealers is re-armed (DEP-06 Phase 4,
# "Unclaimed with revealers", strict-lottery-v8, provisional): every participant reveals, but the
# drawn winner yields its own custody (ADVERSARY :yield-win, round 1 only; signet soak 2026-11-04,
# ledger 30ea46ac) and the loser yields as usual, so every fork is yielded and nobody claims.  Once
# the CSV-144 recovery leaf opens a fresh arm round opens on the yielded forks (a yield ends a
# round, not the dispute), the voters spend the output into its lottery, and its claim hands
# custody to one participant.
#
# A cl-only ledger (operator OP; C2..C4 cosign blind and are accused; H, H2 honest) runs to a
# punitive confiscation.  Under v8 the lottery's participants are H and H2 (the accused never
# win) and its recovery voters are H and H2 (threshold 2).  Both reveal; both yield round 1.
# PASS = a recovery spend of the round-1 lottery output pays a new lottery output, that output is
# claimed, exactly one member logs the win, and nobody takes the recovery spend for a theft.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-1500}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 H H2
ROW=${REDTEAM_RR:-RR$RANDOM}
W=$(FORM_EXPIRY=${FORM_EXPIRY:-200} COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $H $H2) || exit 1; echo "== ledger $W"
FROM=$(fresh_deposits "$ROW" $OP "$W" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"
# The block ticker would race the paced mining below: pause it for the run.
"$CLD_SRC/devnet/regtest-net.sh" ticker stop
trap '"$CLD_SRC/devnet/regtest-net.sh" ticker start; for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done; for n in $H $H2; do cld_ctl $n "(:adversary :set :yield-win nil)" >/dev/null 2>&1; done' EXIT

for n in $H $H2; do expect "$(cld_ctl $n "(:adversary :set :yield-win t)")"; done
for n in $C2 $C3 $C4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4
echo "== $H disputes the ledger"
cld_ctl $H "(:dispute-enter :ledger \"$W\" :reason \"redteam rearm-yield\")" >/dev/null

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
yielded=0; for n in $H $H2; do grep -aF "dispute ${W:0:8}: lottery: yielded" "$(cld_dir $n)/node.log" >/dev/null 2>&1 && yielded=$((yielded+1)); done
echo "== $yielded of 2 participants logged a round-1 yield"
# The restart: H comes back with only its files, its forks yielded, the vault confiscated.
LOGH="$(cld_dir $H)/node.log"; MARK=$(wc -c <"$LOGH")
echo "== restarting $H at height $(bcli getblockcount) (quorum expiry: ${FORM_EXPIRY:-200} blocks from formation)"
stop_cld $H; start_cld $H || fail "$H did not come back"
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
[ "$yielded" = 2 ] || fail "expected both participants to yield round 1, got $yielded"
after=$(tail -c +$((MARK + 1)) "$LOGH")
grep -F "dispute ${W:0:8}: lottery: won" <<<"$after" && fail "$H logged a round-1 win after its restart (a phantom claim)"
grep -E "dispute ${W:0:8}: armed, pledging" <<<"$after" && fail "$H opened a second dispute on the confiscated vault after its restart"
grep -F "dispute ${W:0:8}: not disputing" <<<"$after" | head -1 | sed "s/^/   $H: /"
echo "PASS: $H restarted after its yield; both revealed and yielded round 1; round 2 re-armed ($R2) and its lottery was claimed ($CLAIM) by ${won%% *}."
