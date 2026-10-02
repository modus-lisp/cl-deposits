#!/usr/bin/env bash
# redteam/attack-dereliction.sh — DEP-19 §6 duty to act.  On a fresh ledger DL (cld1
# operates; cld2 cld3 cld4 cld5 cld6 cosign, short dispute_response_blocks), cld1 forges a
# lock with a colluding majority (cld3 cld4 cld5 cosign blind), so a NonConformingUpdate
# proof is published and DL is disputed.  cld6 is set to :ignore-fraud: it drops the proof
# but keeps operating a ledger it runs (K: a fresh ledger, quorum cld2 ref6 ref7).  cld2 is
# the honest acting member and also operates a fresh control ledger (C: quorum cld6 ref6 ref7).
# PASS = an honest member produces a DisputeDereliction proof against cld6, and cld6's operated
# ledger K is freshly disputed (seen by cld2), while cld2's ledger C is not (seen by cld6).
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-480}; RESP=${RESP:-5}
source "$(dirname "$0")/_lib.sh"
ROW=${REDTEAM_D:-DL}
K=$(form_ledger "$ROW-k" cld6 "" cld2 ref6 ref7) || exit 1; echo "== K $K (cld6 operates; cld2 ref6 ref7)"
C=$(form_ledger "$ROW-c" cld2 "" cld6 ref6 ref7) || exit 1; echo "== C $C (cld2 operates; cld6 ref6 ref7)"
clean_at() { [ -z "$(cld_ctl $2 "(:forks :ledger \"$1\")" 2>/dev/null | grep -oE ':STATE :[A-Z]+')" ]; }
# Contagion taints a key for good: a node accused in an earlier run (a theft it signed, or a false
# accusation such as vault-rotate-late's) has every new ledger disputed on sight.  Give the proofs a
# moment to land; if K or C is disputed before the fraud, the run cannot tell dereliction apart.
sleep 45
clean_at "$K" cld2 && clean_at "$C" cld6 || { echo "SKIP: cld6 or cld2 is already accused by an earlier run (contagion taint): K $(clean_at "$K" cld2 && echo clean || echo disputed), C $(clean_at "$C" cld6 && echo clean || echo disputed); needs fresh-key nodes"; exit 0; }
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
  ! clean_at "$K" cld2 && [ -z "$der" ] && der=$(( $(date +%s) - t0 ))
  [ -n "$der" ] && break
  sleep 8
done
cld_ctl cld6 "(:adversary :set :ignore-fraud nil)" >/dev/null
der1=$(for n in cld1 cld2 cld3 cld4; do cld_ctl $n '(:log)' | tr '"' '\n' | grep -c 'DERELICTION:'; done | paste -sd+ | bc)
echo "== DERELICTION proofs produced this run: $(( der1 - der0 ))"
echo "== cld6's operated ledger K freshly disputed: ${der:+after ${der}s}${der:-NO}"
echo "== cld2's operated ledger C disputed (should be no): $(clean_at "$C" cld6 && echo no || echo YES)"
if [ -n "$der" ] && [ "$(( der1 - der0 ))" -gt 0 ] && clean_at "$C" cld6; then
  echo "PASS: the derelict member (cld6) was reported and its vault disputed; the acting member (cld2) was not."
else
  echo "FAIL: K=${der:-none} proofs=$(( der1 - der0 )) C=$(clean_at "$C" cld6 && echo clean || echo disputed)"
fi
