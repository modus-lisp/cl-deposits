#!/usr/bin/env bash
# redteam/check-confiscation-bump.sh — a stuck confiscation is bumped to a higher rung (DEP-03
# §Confiscation ladder), and the lottery still completes on that rung.
#
# A dispute on a fresh ledger runs to confiscation.  The confiscation is signed at four fees; the
# proposer broadcasts rung 0 and, while none confirms, the rung min(3, (tip - h_c)/6) counted from
# its first broadcast.  Here rung 0 is made unmineable (prioritisetransaction with a large negative
# delta) and blocks are mined.  PASS = a higher rung confirms in place of rung 0, no node takes it
# for a theft, and the lottery output of that rung is claimed (custody to one participant).
# REFS="" (default) forms a cl-only quorum; REFS="ref6 ref7" adds reference members, which then
# check and sign every rung too.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-900}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 H H2   # five members: Q must be 3, 5 or 7
REFS=${REFS-}
ROW=${REDTEAM_CB:-CB$RANDOM}
W=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $H $H2 $REFS) || exit 1; echo "== ledger $W"
FROM=$(fresh_deposits "$ROW" $OP "$W" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"

# The block ticker would mine rung 0 before we can stall it: pause it for the run.
"$CLD_SRC/devnet/regtest-net.sh" ticker stop
trap '"$CLD_SRC/devnet/regtest-net.sh" ticker start; for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done' EXIT

# The fault: $OP locks a depositor's funds with no witness, $C2..$C4 cosign blind.
for n in $C2 $C3 $C4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4
echo "== $H disputes the ledger"
cld_ctl $H "(:dispute-enter :ledger \"$W\" :reason \"redteam confiscation-bump\")" >/dev/null

# The vault: the last outpoint the ledger's QuorumBegins named (display order).
VAULT=$(cld_ctl $OP '(:vaults)' | tr '()' '\n\n' | grep -F "\"$W\"" -A1 | grep -oE '[0-9a-f]{64}:[0-9]+' | tail -1)
[ -n "$VAULT" ] || fail "no vault for $W"
VINTX=${VAULT%:*}; VINVOUT=${VAULT#*:}
echo "== vault $VAULT"
# The mempool transaction spending the vault, if any (one RPC, so the check right before each
# block leaves no window for the confiscation to be mined unseen).
spending_vault() {
  bcli gettxspendingprevout "[{\"txid\":\"$VINTX\",\"vout\":$VINVOUT}]" 2>/dev/null \
    | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0].get("spendingtxid",""))' 2>/dev/null
}

echo "== waiting for the confiscation's rung 0 (arm, cosign, broadcast); mining only while the vault is unspent"
R0=""
for i in $(seq 1 $((WAIT / 5))); do
  R0=$(spending_vault)
  [ -n "$R0" ] && break
  if [ $((i % 6)) -eq 0 ]; then   # the arm window closes on height
    R0=$(spending_vault); [ -n "$R0" ] && break
    mine 1 >/dev/null
  fi
  [ -n "$(bcli gettxout "$VINTX" "$VINVOUT" false 2>/dev/null | head -1)" ] || fail "the vault was spent in a block before we saw it in the mempool"
  sleep 5
done
[ -n "$R0" ] || fail "no confiscation reached the mempool within ${WAIT}s"
bcli prioritisetransaction "$R0" 0 -100000000 >/dev/null
echo "== rung 0 $R0 made unmineable; mining 7 blocks"
proposed=$(for n in $C2 $C3 $C4 $H $H2 $OP; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "dispute ${W:0:8}: proposed confiscation" | tail -1; done | head -1)
echo "   $proposed"
for i in $(seq 1 7); do mine 1 >/dev/null; sleep 8; done
sleep 90; mine 1 >/dev/null; sleep 10   # a drive-disputes pass (once a minute) pushes the due rung

# The confirmed spend of the vault.
conf=$(bcli getblock "$(bcli getbestblockhash)" 2 >/dev/null | python3 -c '
import json,sys
b=json.load(sys.stdin); t,v=sys.argv[1],int(sys.argv[2])
for tx in b["tx"]:
    for vin in tx.get("vin",[]):
        if vin.get("txid")==t and vin.get("vout")==v: print(tx["txid"]); sys.exit()' "$VINTX" "$VINVOUT" 2>/dev/null)
if [ -z "$conf" ]; then
  tip=$(bcli getblockcount)
  for h in $(seq "$tip" -1 $((tip - 12))); do
    conf=$(bcli getblock "$(bcli getblockhash "$h")" 2 2>/dev/null | python3 -c '
import json,sys
b=json.load(sys.stdin); t,v=sys.argv[1],int(sys.argv[2])
for tx in b["tx"]:
    for vin in tx.get("vin",[]):
        if vin.get("txid")==t and vin.get("vout")==v: print(tx["txid"]); sys.exit()' "$VINTX" "$VINVOUT")
    [ -n "$conf" ] && break
  done
fi
[ -n "$conf" ] || fail "no rung of the confiscation confirmed after the bump window (rung 0 $R0)"
[ "$conf" != "$R0" ] || fail "rung 0 confirmed despite its prioritisation (the test proves nothing)"
echo "== confirmed: $conf (a higher rung)"
for n in $C2 $C3 $C4 $H $H2; do
  cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "dispute ${W:0:8}:" | grep -E "broadcast rung|rebroadcast rung" | tail -1
done

echo "== waiting for the reveals and the claim of $conf:0 (up to ${WAIT}s)"
claim=""
for i in $(seq 1 $((WAIT / 5))); do
  if [ -z "$(bcli gettxout "$conf" 0 false 2>/dev/null | head -1)" ]; then
    tip=$(bcli getblockcount)
    for h in $(seq "$tip" -1 $((tip - 20))); do
      claim=$(bcli getblock "$(bcli getblockhash "$h")" 2 2>/dev/null | python3 -c '
import json,sys
b=json.load(sys.stdin); t=sys.argv[1]
for tx in b["tx"]:
    for vin in tx.get("vin",[]):
        if vin.get("txid")==t and vin.get("vout")==0: print(tx["txid"]); sys.exit()' "$conf")
      [ -n "$claim" ] && break
    done
    [ -n "$claim" ] && break
  fi
  [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
[ -n "$claim" ] || fail "the lottery output of the confirmed rung ($conf:0) was not claimed within ${WAIT}s"
won=$(for n in $C2 $C3 $C4 $H $H2; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "dispute ${W:0:8}: lottery: won" | head -1 | sed "s/^/$n: /"; done)
echo "== claimed by $claim; winner: ${won:-none among the cl members}"
[ "$(printf '%s\n' "$won" | grep -c 'lottery: won')" -le 1 ] || fail "more than one member won the lottery"
# No node took the bumped rung for a theft.
for n in $C2 $C3 $C4 $H $H2 $OP; do
  if cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "VAULT SPEND|unauthori[sz]ed spend" | grep -qi "${conf:0:16}\|${W:0:8}"; then
    fail "$n took the confiscation's rung for a theft"
  fi
done
echo "PASS: rung 0 stalled, a higher rung ($conf) replaced it, nobody took it for a theft, and its lottery output was claimed ($claim)."
