#!/usr/bin/env bash
# redteam/attack-dereliction.sh — DEP-19 §6 duty to act.  On a fresh ledger DL (OP
# operates; ACT cld3 cld4 cld5 DER cosign, short dispute_response_blocks), OP forges a
# lock with a colluding majority (cld3 cld4 cld5 cosign blind), so a NonConformingUpdate
# proof is published and DL is disputed.  DER is set to :ignore-fraud: it drops the proof
# but keeps operating a ledger it runs (K: a fresh ledger, quorum ACT ref6 ref7).  ACT is
# the honest acting member and also operates a fresh control ledger (C: quorum DER ref6 ref7).
# PASS = an honest member produces a DisputeDereliction proof against DER, and DER's operated
# ledger K is freshly disputed (seen by ACT), while ACT's ledger C is not (seen by DER).
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-480}; RESP=${RESP:-5}
source "$(dirname "$0")/_lib.sh"
pick OP ACT DER   # a tainted OP's DL, or a tainted ACT/DER's K or C, is disputed on sight
trap 'cld_ctl "$DER" "(:adversary :set :ignore-fraud nil)" >/dev/null 2>&1' EXIT
ROW=${REDTEAM_D:-DL}
K=$(COLLATERAL_SATS=25000000 form_ledger "$ROW-k" $DER "" $ACT ref6 ref7) || exit 1; echo "== K $K ($DER operates; $ACT ref6 ref7)"
C=$(COLLATERAL_SATS=25000000 form_ledger "$ROW-c" $ACT "" $DER ref6 ref7) || exit 1; echo "== C $C ($ACT operates; $DER ref6 ref7)"
clean_at() { [ -z "$(cld_ctl $2 "(:forks :ledger \"$1\")" 2>/dev/null | grep -oE ':STATE :[A-Z]+')" ]; }
# Contagion taints a key for good: a node accused in an earlier run (a theft it signed, or a false
# accusation such as vault-rotate-late's) has every new ledger disputed on sight.  Give the proofs a
# moment to land; if K or C is disputed before the fraud, the run cannot tell dereliction apart.
sleep 45
clean_at "$K" $ACT && clean_at "$C" $DER || { echo "SKIP: $DER or $ACT is already accused by an earlier run (contagion taint): K $(clean_at "$K" $ACT && echo clean || echo disputed), C $(clean_at "$C" $DER && echo clean || echo disputed); needs fresh-key nodes"; exit 0; }
# A deposit on K, credited each round after the fraud (below): the derelict keeps operating.
mapfile -t KDEPS < <(fresh_deposits "$ROW-k" $DER "$K" 1); KD=${KDEPS[0]}; [ -n "$KD" ] || fail "no deposit on K"
read -r ktxid kvout <"$S/redteam-$ROW-k.outpoint"
DL_ROW="$S/redteam-${REDTEAM_D:-DL}"
if [ -f "$DL_ROW" ]; then read -r DL txid vout < "$DL_ROW"; echo "== reusing DL $DL"; else
  echo "== forming DL ($OP operates; $ACT..$DER cosign; dispute_response_blocks=$RESP)"
  DL=$(sx "$(cld_ctl $OP "(:open-ledger :reserves-id \"genesis:$OP:derelict:$RANDOM\" :reserves-msat 20000000000 :collateral-msat 20000000000)")" ":LEDGER"); [ -n "$DL" ] || fail "open DL"
  for m in $ACT cld3 cld4 cld5 $DER; do
    ml=$(eval echo "\${L${m#cld}}")
    expect "$(cld_ctl $OP "(:add-member :ledger \"$DL\" :member \"$(pubkey_of $m)\" :member-ledger \"$ml\" :dispute-response-blocks $RESP)")"
  done
  prep=$(cld_ctl $OP "(:prepare-quorum :ledger \"$DL\" :expiry-blocks 4320)"); expect "$prep"; addr=$(sx "$prep" ":ADDRESS")
  txid=$(wcli sendtoaddress "$addr" 0.4); mine 3
  vout=$(bcli getrawtransaction "$txid" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$addr'][0])")
  sleep 20
  expect "$(cld_ctl $OP "(:begin-quorum :ledger \"$DL\" :txid \"$txid\" :vout $vout :sats 20000000 :collateral-sats 20000000)")"
  expect "$(cld_ctl $OP "(:advertise :ledger \"$DL\")")"
  echo "$DL $txid $vout" > "$DL_ROW"
fi
DEP=""; for i in 1 2 3 4 5; do DEP=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" drw$i "$DL" open)" ":DEPOSIT"); [ -n "$DEP" ] && break; sleep 5; done; [ -n "$DEP" ] || fail "open deposit"
expect "$(cld_ctl $OP "(:credit :ledger \"$DL\" :deposit \"$DEP\" :msat 100000 :txid \"$txid\" :vout $vout)")"
der0=$(for n in $OP $ACT cld3 cld4; do cld_ctl $n '(:log)' | tr '"' '\n' | grep -c 'DERELICTION:'; done | paste -sd+ | bc)
echo "== $DER -> :ignore-fraud (derelict); cld3 cld4 cld5 -> cosign-blind (colluding majority)"
expect "$(cld_ctl $DER "(:adversary :set :ignore-fraud t)")"
for n in cld3 cld4 cld5; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
t0=$(date +%s)
R=$(cld_ctl $OP "(:forge-lock :ledger \"$DL\" :from \"$DEP\" :to \"$DEP\" :msat 50000)")
for n in cld3 cld4 cld5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP"   # it committed the fraud
echo "== forged lock on DL: $(echo "$R" | cut -c1-80)"
echo "$R" | grep -q ":STATUS :OK" || { cld_ctl $DER "(:adversary :set :ignore-fraud nil)" >/dev/null; fail "forge did not commit"; }
echo "== DL disputed; $DER ignoring.  Mining past the $RESP-block window."
# Dereliction needs the member to keep operating a ledger past the window (an update on K at
# height >= fraud + RESP): without traffic K never advances and no proof can fire.  Credit a
# deposit on K each round (opened above); once the honest members dispute K, the credits stop committing.
der=""
for i in $(seq 1 $((WAIT/10))); do
  mine 2 >/dev/null
  cld_ctl $DER "(:credit :ledger \"$K\" :deposit \"$KD\" :msat 1000 :txid \"$ktxid\" :vout $kvout)" >/dev/null 2>&1
  ! clean_at "$K" $ACT && [ -z "$der" ] && der=$(( $(date +%s) - t0 ))
  [ -n "$der" ] && break
  sleep 8
done
cld_ctl $DER "(:adversary :set :ignore-fraud nil)" >/dev/null
taint "$DER"   # derelict: its K is disputed
der1=$(for n in $OP $ACT cld3 cld4; do cld_ctl $n '(:log)' | tr '"' '\n' | grep -c 'DERELICTION:'; done | paste -sd+ | bc)
echo "== DERELICTION proofs produced this run: $(( der1 - der0 ))"
echo "== $DER's operated ledger K freshly disputed: ${der:+after ${der}s}${der:-NO}"
echo "== $ACT's operated ledger C disputed (should be no): $(clean_at "$C" $DER && echo no || echo YES)"
if [ -n "$der" ] && [ "$(( der1 - der0 ))" -gt 0 ] && clean_at "$C" $DER; then
  echo "PASS: the derelict member ($DER) was reported and its vault disputed; the acting member ($ACT) was not."
else
  echo "FAIL: K=${der:-none} proofs=$(( der1 - der0 )) C=$(clean_at "$C" $DER && echo clean || echo disputed)"
fi
