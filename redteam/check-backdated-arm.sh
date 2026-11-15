#!/usr/bin/env bash
# redteam/check-backdated-arm.sh — reproduction of the unruled backdated-arm finding for round 1
# (docs/ADVERSARIAL.md §Rule inverters).  A fork's DisputeArmed is self-signed, so after a
# confiscation confirms at block c a counted armer can publish a round-1 re-arm signed at a height
# at or below c (the fold takes a same-round re-arm with the same commitment).  Judges rebuild the
# confiscation from each armer's LATEST arm as of c (rebuild-matches-p over armers-of :until c), so
# a re-arm declaring a pledge that was not confirmed by the eligibility snapshot E drops that
# armer from every subset's cut, and no subset rebuilds the confirmed transaction.
#
# A cl-only ledger (OP; C2..C5 cosign blind and are accused; H, X, J honest) runs to a punitive
# confiscation with H, X and J in its lottery.  J judges it (the vault watch) as everyone does.  Then
# X pledges a coin created after c and publishes a round-1 re-arm signed at c.  J restarts without
# its vault-watch state (as a node that judges the spend afresh: a new member, a wiped data dir),
# so it holds no cached verdict, and judges the spend again.
# PASS = J still finds the confiscation authorised (no challenge, no proof against its signers).
# FAIL = the finding reproduced: J challenges it, or proves against the honest signers.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-1500}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 C5 H X J
# Every actor runs this tree's code (CLD_SRC): the same script records the behaviour before and
# after a change by pointing CLD_SRC at each build.
echo "== restarting the actors from $CLD_SRC"
for n in $OP $C2 $C3 $C4 $C5 $H $X $J; do ( stop_cld $n >/dev/null 2>&1; start_cld $n >/dev/null ) & done; wait
for n in $OP $C2 $C3 $C4 $C5 $H $X $J; do
  for i in $(seq 1 120); do cld_ctl $n '(:info)' 2>/dev/null | grep -q ':STATUS :OK' && break; sleep 5; done
  [ "$(live_build $n)" = "$CLD_SRC" ] || fail "$n runs $(live_build $n), not $CLD_SRC"
done
ROW=${REDTEAM_BA:-BA$RANDOM}
W=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $C5 $H $X $J) || exit 1; echo "== ledger $W"
FROM=$(fresh_deposits "$ROW" $OP "$W" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"
"$CLD_SRC/devnet/regtest-net.sh" ticker stop
trap '"$CLD_SRC/devnet/regtest-net.sh" ticker start; for n in $C2 $C3 $C4 $C5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done' EXIT
for n in $C2 $C3 $C4 $C5; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4 $C5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4 $C5
echo "== $H disputes the ledger"
cld_ctl $H "(:dispute-enter :ledger \"$W\" :reason \"redteam backdated arm\")" >/dev/null
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
HC=$(bcli getblockheader "$(bcli getrawtransaction "$CONF" 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["blockhash"])')" | python3 -c 'import json,sys; print(json.load(sys.stdin)["height"])')
echo "== confiscation $CONF at height $HC"
# J's first verdict, with every arm as it was at c.
mine 3 >/dev/null; cld_ctl $J '(:vault-watch)' >/dev/null
for i in $(seq 1 36); do grep -aF "vault watch: ${W:0:8}'s spend ${CONF:0:16}" "$(cld_dir $J)/node.log" >/dev/null && break; sleep 5; done
echo "== $J's first verdict: $(grep -aF "vault watch: ${W:0:8}'s spend ${CONF:0:16}" "$(cld_dir $J)/node.log" | tail -1 | cut -c1-160)"
# X's pledge: a coin created after c, so not confirmed by the eligibility snapshot E.
XA=$(sx "$(cld_ctl $X '(:address)')" ":ADDRESS")
PT=$(wcli sendtoaddress "$XA" 0.3); mine 1 >/dev/null
PV=$(bcli getrawtransaction "$PT" 1 | python3 -c 'import json,sys; t=json.load(sys.stdin); a=sys.argv[1]
for o in t["vout"]:
    if o["scriptPubKey"].get("address")==a: print(o["n"], round(o["value"]*1e8)); break' "$XA")
[ -n "$PV" ] || fail "no pledge output"
echo "== $X re-arms round 1, signed at $HC, pledging $PT:${PV% *} (created at $(bcli getblockcount))"
OUT=$(cld_ctl $X "(:backdated-rearm :ledger \"$W\" :height $HC :pledge \"$PT:${PV% *}:${PV#* }\")")
echo "   $OUT"
expect "$OUT"
sleep 30
echo "== $J restarts without its vault-watch state, and judges the spend again"
JLOG="$(cld_dir $J)/node.log"; JFROM=$(( $(stat -c %s "$JLOG") + 1 ))
stop_cld $J >/dev/null; rm -f "$(cld_dir $J)/vault-watch.sexp"; start_cld $J >/dev/null || fail "$J did not restart"
for i in $(seq 1 60); do cld_ctl $J '(:info)' 2>/dev/null | grep -q ':STATUS :OK' && break; sleep 5; done
cld_ctl $J '(:vault-watch)' >/dev/null
for i in $(seq 1 48); do
  tail -c +$JFROM "$JLOG" | grep -qaE "vault watch: ${W:0:8}'s spend ${CONF:0:16}|VAULT SPEND[A-Z ]*: ${W:0:8}'s reserves were spent by ${CONF:0:16}" && break
  [ $((i % 6)) -eq 0 ] && { mine 1 >/dev/null; cld_ctl $J '(:vault-watch)' >/dev/null; }
  sleep 5
done
# Past any challenge's answer window (72 blocks), so an unanswered challenge becomes a proof.
for i in $(seq 1 80); do mine 1 >/dev/null; sleep 2; done
cld_ctl $J '(:vault-watch)' >/dev/null; sleep 30
echo "== $J's log since the restart, on this ledger and spend:"
tail -c +$JFROM "$JLOG" | grep -aE "${CONF:0:16}|vault spend|VAULT SPEND|arm manifest|${W:0:8}'s spend" | grep -viE 'cosigned|catch-up|replaying' | tail -12 | sed 's/^/   /' | cut -c1-220
bad=$(tail -c +$JFROM "$JLOG" | grep -aE "VAULT SPEND[A-Z ]*: ${W:0:8}'s reserves were spent by ${CONF:0:16}|lapsed-challenge proof|unanchored proof")
ok=$(tail -c +$JFROM "$JLOG" | grep -aF "vault watch: ${W:0:8}'s spend ${CONF:0:16}" | grep -i "answered by its anchor")
[ -z "$bad" ] && [ -n "$ok" ] && { echo "PASS: $J, judging afresh after $X's backdated re-arm, still found the confiscation authorised"; exit 0; }
[ -n "$bad" ] && fail "the finding reproduced: $J, judging afresh after $X's backdated re-arm, $(echo "$bad" | head -2 | tr '\n' ' ' | cut -c1-300)"
fail "$J gave no verdict on $CONF after its restart"
