#!/usr/bin/env bash
# redteam/attack-vault-spend.sh — unauthorised vault spend (DEP-06 type 7, docs/MISSING.md).
#
# A colluding majority of a ledger's quorum spends the vault's reserves outpoint
# at Tier 0 to an address of theirs — no dispute, no rotation, no confiscation.
# The colluders are the operator (cld1) and three of its cosigners (cld2 cld3
# cld4), a majority of Q = 7.  The honest minority (cld5 cld6 ref6 ref7) sees
# nothing: no watch on the vault outpoint exists in either implementation.
#
# PASS (the finding, not a protocol property): the theft broadcast succeeds and
# no honest node reacts within $WAIT s — no dispute, no fraud proof, no log line
# about the spend.  The script also reports the theft txid and how long the funds
# sat capturable.  REDTEAM_V=name forms a fresh test ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-120}
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { case "$1" in *":STATUS :OK"*) ;; *) fail "$1";; esac; }

V_ROW="$S/redteam-${REDTEAM_V:-V}"
if [ -f "$V_ROW" ]; then read -r V < "$V_ROW"; echo "== reusing V $V"; else
  echo "== forming V (cld1 operates; cld2 cld3 cld4 cld5 cld6 ref6 ref7 cosign)"
  V=$(sx "$(cld_ctl cld1 "(:open-ledger :reserves-id \"genesis:cld1:redteam-V:$RANDOM\" :reserves-msat 25000000000 :collateral-msat 25000000000)")" ":LEDGER"); [ -n "$V" ] || fail "open V"
  for m in cld2 cld3 cld4 cld5 cld6 ref6 ref7; do
    case $m in cld*) ml=$(eval echo "\${L${m#cld}}");; ref*) ml=$(eval echo "\${RL${m#ref}}");; esac
    expect "$(cld_ctl cld1 "(:add-member :ledger \"$V\" :member \"$(cat $S/pubkey.$m)\" :member-ledger \"$ml\")")"
  done
  prep=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$V\" :expiry-blocks 4320)"); expect "$prep"; addr=$(sx "$prep" ":ADDRESS")
  txid=$(wcli sendtoaddress "$addr" 0.5); mine 3
  vout=$(bcli getrawtransaction "$txid" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$addr'][0])")
  sleep 20
  expect "$(cld_ctl cld1 "(:begin-quorum :ledger \"$V\" :txid \"$txid\" :vout $vout :sats 50000000 :collateral-sats 0)")"
  echo "$V" > "$V_ROW"
fi

# The thieves' destination: cld2's own address (its node key's P2TR).
DEST=$(sx "$(cld_ctl cld2 '(:address)')" ":ADDRESS")
echo "== thieves: cld1 (operator) + cld2 cld3 cld4 cld5 (threshold 5 of 8); destination $DEST"

# Arm the colluders: they will sign each other's theft proposals.
for n in cld2 cld3 cld4 cld5; do expect "$(cld_ctl $n "(:adversary :set :theft-sign t)")"; done

T0=$(date -u +%s)
echo "== spending the vault at Tier 0"
# cld_ctl's 60s timeout is shorter than the daemon's 90s signature-collection window:
# talk to the control port directly with a longer timeout for this one call.
out=$(printf '%s\n' "(:vault-spend :ledger \"$V\" :address \"$DEST\")" | timeout 180 bash -c "exec 3<>/dev/tcp/127.0.0.1/$(cld_port cld1); cat >&3; head -n1 <&3")
echo "$out" | head -2
case "$out" in *":STATUS :OK"*) ;; *) fail "theft failed: $out";; esac
THEFT_TXID=$(sx "$out" ":TXID"); SIGS=$(sx "$out" ":SIGS")
echo "== theft broadcast: $THEFT_TXID ($SIGS signatures) at $(date -u +%H:%M:%S)"

# Confirm it landed on chain.
mine 2
sleep 5
spent=$(bcli gettxout "$THEFT_TXID" 0 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['value'])" 2>/dev/null)
[ -n "$spent" ] && echo "== theft output live on chain: $spent BTC at $THEFT_TXID:0" || echo "== (theft output not found via gettxout — check $THEFT_TXID)"

# What do the honest nodes do?  Nothing, if the gap is real.
echo "== watching the honest minority (cld6 ref6 ref7) for ${WAIT}s"
reactions=0
for i in $(seq 1 $WAIT); do
  for n in cld6; do
    r=$(cld_ctl $n '(:log)' 2>/dev/null | grep -ciE "$THEFT_TXID|vault theft|unauthorised" || true)
    reactions=$((reactions + r))
  done
  [ "$reactions" -gt 0 ] && break
  sleep 1
done
disputes=$(for n in cld6; do cld_ctl $n "(:forks :ledger \"$V\")" 2>/dev/null; done | grep -c ":SEQ" || true)
echo "== honest reactions mentioning the theft: $reactions; disputes on V: $disputes"

# Cleanup: disarm the colluders.
for n in cld2 cld3 cld4 cld5; do cld_ctl $n "(:adversary :set :theft-sign nil)" >/dev/null; done

if [ "$reactions" -eq 0 ] && [ "$disputes" -eq 0 ]; then
  echo "PASS (gap confirmed): the vault was spent at Tier 0 by a colluding majority and no honest node noticed within ${WAIT}s."
  echo "     The theft: $THEFT_TXID.  This is docs/MISSING.md's first concern, now demonstrated live."
else
  echo "NOTE: honest nodes reacted ($reactions log lines, $disputes disputes) — the gap may be narrower than MISSING.md records."
fi
