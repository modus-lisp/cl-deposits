#!/usr/bin/env bash
# redteam/attack-vault-anchored.sh — a theft that forges an anchor (DEP-06 §Spend challenge).
#
# A colluding majority spends the vault to an address of theirs, as attack-vault-spend.sh does, but
# gives the theft an anchor: OP_RETURN <the ledger's tip chain hash>, the shape of an honest
# rotation.  No QuorumBegin is the child of that tip naming the theft (the operator's next update
# there is an ordinary one: the "non-rotation child", which proves nothing by itself, since an
# honest confiscation looks the same).  Honest watchers therefore cannot prove it on its face: they
# challenge (QuorumChallenge on their own ledger, Kind 9111), nobody can answer, and once the
# ledger's service window (service_response_blocks, 72 by default) has passed they prove the spend
# in the lapsed form, which disputes the thieves' own ledgers like any theft.
#
# PASS = the honest node challenged, recorded no proof while the challenge was open, and proved
# the spend in the lapsed form once the window passed.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP T2 T3 T4 T5 HON
V=$(form_ledger "${REDTEAM_VA:-VA$RANDOM}" $OP "" $T2 $T3 $T4 $T5 $HON ${REFS-ref6 ref7}) || exit 1
echo "== V $V ($OP operates; $T2 $T3 $T4 $T5 $HON ${REFS-ref6 ref7} cosign)"
DEST=$(sx "$(cld_ctl $T2 '(:address)')" ":ADDRESS")
for n in $T2 $T3 $T4 $T5; do expect "$(cld_ctl $n "(:adversary :set :theft-sign t)")"; done
trap 'for n in $T2 $T3 $T4 $T5; do cld_ctl $n "(:adversary :set :theft-sign nil)" >/dev/null 2>&1; done' EXIT
echo "== spending the vault at Tier 0, anchored at the ledger's tip"
out=$(vault_spend $OP "$V" "$DEST" 0 tip)
case "$out" in *":STATUS :OK"*) ;; *) fail "theft failed: $out";; esac
THEFT=$(sx "$out" ":TXID"); taint $OP $T2 $T3 $T4 $T5
echo "== theft broadcast: $THEFT"
mine 5 >/dev/null; sleep 5
[ "$(bcli getrawtransaction "$THEFT" true | python3 -c "import json,sys; print(json.load(sys.stdin)['vout'][-1]['scriptPubKey']['hex'][:4])")" = 6a20 ] \
  || fail "the theft carries no anchor"
# The operator keeps operating: its next update is the tip's non-rotation child.
r=$(cld_ctl $OP "(:deposit-open :ledger \"$V\" :descriptor \"pk($(pubkey_of $HON))\")"); echo "   operator's next update: ${r:0:60}"
ch=
for i in $(seq 1 30); do
  cld_ctl $HON '(:vault-watch)' >/dev/null 2>&1
  cld_ctl $HON '(:log :n 4000)' | grep -q "VAULT SPEND CHALLENGED: ${V:0:8}" && { ch=1; break; }
  sleep 10
done
[ -n "$ch" ] || fail "$HON never challenged the anchored theft"
cld_ctl $HON '(:log :n 4000)' | grep -q "challenge of ${V:0:8}'s spend recorded on our ledger" || fail "$HON did not record its challenge"
if accused $HON "$V" 30; then fail "$HON proved an anchored spend on its face (it must challenge)"; fi
if cld_ctl $HON '(:log :n 4000)' | grep -q "lapsed-challenge proof against"; then fail "$HON proved the spend before its challenge lapsed"; fi
echo "== challenge open; mining past the service window (72 blocks)"
mine 80 >/dev/null; sleep 10
proved_lapsed $HON "$V" 600 || fail "$HON never proved the spend once its challenge lapsed"
cld_ctl $HON '(:log :n 4000)' | grep "lapsed-challenge proof against" | tail -3
echo "PASS: the anchored theft $THEFT was challenged, went unanswered, and was proven in the lapsed form."
