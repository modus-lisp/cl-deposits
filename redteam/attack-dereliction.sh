#!/usr/bin/env bash
# redteam/attack-dereliction.sh — DEP-19 §6 duty to act.  On a fresh ledger D1 (cld1
# operates; cld2..cld6 cosign, short dispute_response_blocks), cld1 forges a lock with a
# colluding majority (cld2 cld3 cld4), so a NonConformingUpdate proof is published and D1 is
# disputed.  cld5 is set to :ignore-fraud: it drops the proof but keeps operating its own
# ledger (I).  PASS = cld5's own ledger is disputed for dereliction within the window, by a
# member that produced a DisputeDereliction proof.  (cld4, which acts, is not accused.)
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-300}; RESP=${RESP:-5}
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { case "$1" in *":STATUS :OK"*) ;; *) fail "$1";; esac; }
D1_ROW="$S/redteam-${REDTEAM_D:-D1}"
if [ -f "$D1_ROW" ]; then read -r D1 txid vout < "$D1_ROW"; echo "== reusing D1 $D1"; else
  echo "== forming D1 (cld1 operates; cld2 cld3 cld4 cld5 cosign; dispute_response_blocks=$RESP)"
  D1=$(sx "$(cld_ctl cld1 "(:open-ledger :reserves-id \"genesis:cld1:derelict:$RANDOM\" :reserves-msat 20000000000 :collateral-msat 20000000000)")" ":LEDGER"); [ -n "$D1" ] || fail "open D1"
  for m in cld2 cld3 cld4 cld5 cld6; do
    ml=$(eval echo "\${L${m#cld}}")
    expect "$(cld_ctl cld1 "(:add-member :ledger \"$D1\" :member \"$(cat $S/pubkey.$m)\" :member-ledger \"$ml\" :dispute-response-blocks $RESP)")"
  done
  prep=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$D1\" :expiry-blocks 4320)"); expect "$prep"; addr=$(sx "$prep" ":ADDRESS")
  txid=$(wcli sendtoaddress "$addr" 0.4); mine 3
  vout=$(bcli getrawtransaction "$txid" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$addr'][0])")
  sleep 20
  expect "$(cld_ctl cld1 "(:begin-quorum :ledger \"$D1\" :txid \"$txid\" :vout $vout :sats 20000000 :collateral-sats 20000000)")"
  expect "$(cld_ctl cld1 "(:advertise :ledger \"$D1\")")"
  echo "$D1 $txid $vout" > "$D1_ROW"
fi
# a credited deposit on D1, so the forged lock is a real fault
DEP=""; for i in 1 2 3 4 5; do DEP=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" drw$i "$D1" open)" ":DEPOSIT"); [ -n "$DEP" ] && break; sleep 5; done; [ -n "$DEP" ] || fail "open deposit"
expect "$(cld_ctl cld1 "(:credit :ledger \"$D1\" :deposit \"$DEP\" :msat 100000 :txid \"$txid\" :vout $vout)")"
I=$(awk -F"\t" '$3=="cld5"{print $2}' "$S/ledgers.tsv")   # cld5's operated soak ledger (has a quorum to slash it)
echo "== cld5 own ledger (to be slashed) $I"
echo "== cld5 -> :ignore-fraud; cld2 cld3 cld4 -> cosign-blind"
expect "$(cld_ctl cld5 "(:adversary :set :ignore-fraud t)")"
for n in cld2 cld3 cld4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
T0=$(date -u +%FT%T); t0=$(date +%s)
R=$(cld_ctl cld1 "(:forge-lock :ledger \"$D1\" :from \"$DEP\" :to \"$DEP\" :msat 50000)")
for n in cld2 cld3 cld4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
echo "== forged lock on D1: $(echo "$R" | cut -c1-80)"
echo "$R" | grep -q ":STATUS :OK" || { cld_ctl cld5 "(:adversary :set :ignore-fraud nil)" >/dev/null; fail "forge did not commit (need the colluding majority)"; }
echo "== D1 disputed by honest members; cld5 ignoring.  Mining past the $RESP-block window."
der=""; act_not=""
for i in $(seq 1 $((WAIT/10))); do
  mine 2 >/dev/null
  # cld5's own ledger I disputed => dereliction fired
  for n in cld1 cld2 cld6; do
    f=$(cld_ctl $n "(:forks :ledger \"$I\")" 2>/dev/null | grep -oE ':STATE :[A-Z]+' | head -1)
    [ -n "$f" ] && [ -z "$der" ] && der=$(( $(date +%s) - t0 ))
  done
  # cld6 acted, so cld6's own ledger must NOT be disputed
  [ -n "$der" ] && break
  sleep 8
done
cld_ctl cld5 "(:adversary :set :ignore-fraud nil)" >/dev/null
echo "== dereliction proofs produced: $(for n in cld1 cld2 cld3 cld4 cld6; do cld_ctl $n '(:log)' | tr '"' '\n' | grep -c 'DERELICTION:'; done | paste -sd+ | bc)"
I6=$(awk -F"\t" '$3=="cld6"{print $2}' "$S/ledgers.tsv")
a6=$(cld_ctl cld1 "(:forks :ledger \"$I6\")" 2>/dev/null | grep -oE ':STATE :[A-Z]+' | head -1)
echo "== cld5's own ledger disputed for dereliction: ${der:+after ${der}s}${der:-NO}"
echo "== cld6 (which acted) disputed: ${a6:-no}"
[ -n "$der" ] && [ -z "$a6" ] && echo "PASS: the derelict member was slashed; the acting member was not." || echo "RESULT: der=${der:-none} cld6=${a6:-none}"
