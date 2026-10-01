#!/usr/bin/env bash
# redteam/attack-dereliction.sh — DEP-19 §6 duty to act.  On a fresh ledger DL (cld1
# operates; cld2 cld3 cld4 cld5 cld6 cosign, short dispute_response_blocks), cld1 forges a
# lock with a colluding majority (cld3 cld4 cld5 cosign blind), so a NonConformingUpdate
# proof is published and DL is disputed.  cld6 is set to :ignore-fraud: it drops the proof
# but keeps operating the ledger it runs (K).  cld2 is the honest acting member.
# PASS = an honest member produces a DisputeDereliction proof against cld6, and cld6's own
# operated ledger (K, clean before) is freshly disputed, while cld2's ledger (C) is not.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-480}; RESP=${RESP:-5}
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { case "$1" in *":STATUS :OK"*) ;; *) fail "$1";; esac; }
oper_ledger() { awk -F'\t' -v o="$1" '$3==o{print $2}' "$S/ledgers.tsv"; }
K=$(oper_ledger cld6)    # the derelict member's operated ledger (must be clean to be slashed)
C=$(oper_ledger cld2)    # the acting member's operated ledger (must NOT be disputed)
[ -n "$K" ] && [ -n "$C" ] || fail "cld6/cld2 operated ledgers not found"
clean() { [ -z "$(cld_ctl cld1 "(:forks :ledger \"$1\")" 2>/dev/null | grep -oE ':STATE :[A-Z]+')" ]; }
clean "$K" || fail "cld6's ledger K is already disputed; pick another derelict member"
DL_ROW="$S/redteam-${REDTEAM_D:-DL}"
if [ -f "$DL_ROW" ]; then read -r DL txid vout < "$DL_ROW"; echo "== reusing DL $DL"; else
  echo "== forming DL (cld1 operates; cld2..cld6 cosign; dispute_response_blocks=$RESP)"
  DL=$(sx "$(cld_ctl cld1 "(:open-ledger :reserves-id \"genesis:cld1:derelict:$RANDOM\" :reserves-msat 20000000000 :collateral-msat 20000000000)")" ":LEDGER"); [ -n "$DL" ] || fail "open DL"
  for m in cld2 cld3 cld4 cld5 cld6; do
    ml=$(eval echo "\${L${m#cld}}")
    expect "$(cld_ctl cld1 "(:add-member :ledger \"$DL\" :member \"$(cat $S/pubkey.$m)\" :member-ledger \"$ml\" :dispute-response-blocks $RESP)")"
  done
  prep=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$DL\" :expiry-blocks 4320)"); expect "$prep"; addr=$(sx "$prep" ":ADDRESS")
  txid=$(wcli sendtoaddress "$addr" 0.4); mine 3
  vout=$(bcli getrawtransaction "$txid" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$addr'][0])")
  sleep 20
  expect "$(cld_ctl cld1 "(:begin-quorum :ledger \"$DL\" :txid \"$txid\" :vout $vout :sats 20000000 :collateral-sats 20000000)")"
  expect "$(cld_ctl cld1 "(:advertise :ledger \"$DL\")")"
  echo "$DL $txid $vout" > "$DL_ROW"
fi
DEP=""; for i in 1 2 3 4 5; do DEP=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" drw$i "$DL" open)" ":DEPOSIT"); [ -n "$DEP" ] && break; sleep 5; done; [ -n "$DEP" ] || fail "open deposit"
expect "$(cld_ctl cld1 "(:credit :ledger \"$DL\" :deposit \"$DEP\" :msat 100000 :txid \"$txid\" :vout $vout)")"
der0=$(for n in cld1 cld2 cld3 cld4; do cld_ctl $n '(:log)' | tr '"' '\n' | grep -c 'DERELICTION:'; done | paste -sd+ | bc)
echo "== cld6 -> :ignore-fraud (derelict); cld3 cld4 cld5 -> cosign-blind (colluding majority)"
expect "$(cld_ctl cld6 "(:adversary :set :ignore-fraud t)")"
for n in cld3 cld4 cld5; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
t0=$(date +%s)
R=$(cld_ctl cld1 "(:forge-lock :ledger \"$DL\" :from \"$DEP\" :to \"$DEP\" :msat 50000)")
for n in cld3 cld4 cld5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
echo "== forged lock on DL: $(echo "$R" | cut -c1-80)"
echo "$R" | grep -q ":STATUS :OK" || { cld_ctl cld6 "(:adversary :set :ignore-fraud nil)" >/dev/null; fail "forge did not commit"; }
echo "== DL disputed; cld6 ignoring.  Mining past the $RESP-block window."
der=""
for i in $(seq 1 $((WAIT/10))); do
  mine 2 >/dev/null
  ! clean "$K" && [ -z "$der" ] && der=$(( $(date +%s) - t0 ))
  [ -n "$der" ] && break
  sleep 8
done
cld_ctl cld6 "(:adversary :set :ignore-fraud nil)" >/dev/null
der1=$(for n in cld1 cld2 cld3 cld4; do cld_ctl $n '(:log)' | tr '"' '\n' | grep -c 'DERELICTION:'; done | paste -sd+ | bc)
echo "== DERELICTION proofs produced this run: $(( der1 - der0 ))"
echo "== cld6's operated ledger K freshly disputed: ${der:+after ${der}s}${der:-NO}"
echo "== cld2's operated ledger C disputed (should be no): $(clean "$C" && echo no || echo YES)"
if [ -n "$der" ] && [ "$(( der1 - der0 ))" -gt 0 ] && clean "$C"; then
  echo "PASS: the derelict member (cld6) was reported and its vault disputed; the acting member (cld2) was not."
else
  echo "RESULT: K=${der:-none} proofs=$(( der1 - der0 )) C=$(clean "$C" && echo clean || echo disputed)"
fi
