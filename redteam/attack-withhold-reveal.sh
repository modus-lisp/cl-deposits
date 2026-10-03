#!/usr/bin/env bash
# redteam/attack-withhold-reveal.sh — an armer withholds its lottery reveal.
#
# A dispute on a fresh ledger W runs to confiscation; one armer (WH, the
# adversary :withhold-reveal) never publishes its preimage.  DEP-06: past the
# reveal deadline (72 blocks) the winner over the revealers claims through its
# subset leaf with the recovery voters' attestation.  PASS: the lottery output
# is claimed by a revealer, not by the withholder and not by the accused
# operator.  REDTEAM_W=name forms a fresh test ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-300}
source "$(dirname "$0")/_lib.sh"
pick OP WH   # both need clean keys: a tainted operator's W is disputed on sight, before the fraud
trap 'cld_ctl "$WH" "(:adversary :set :withhold-reveal nil)" >/dev/null 2>&1' EXIT
ROW=${REDTEAM_W:-W}   # a fresh ledger W: $OP operates; cld2..$WH ref6 ref7 cosign
REFS=${REFS-ref6 ref7}   # REFS="" forms a cl-only quorum (a reference armer that pledges a spent coin vetoes the confiscation)
W=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" cld2 cld3 cld4 cld5 $WH $REFS) || exit 1; echo "== W $W"
mapfile -t DEPS < <(fresh_deposits "$ROW" $OP "$W" 1); FROM=${DEPS[0]}; [ -n "$FROM" ] || fail "no deposit on W"

# The fraud: $OP locks a depositor's funds with no witness, cld2..cld4 cosign blind.
for n in cld2 cld3 cld4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in cld2 cld3 cld4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP"   # it committed the fraud

# $WH will dispute, arm, confiscate — but withhold its reveal.
expect "$(cld_ctl $WH "(:adversary :set :withhold-reveal t)")"
echo "== $WH disputes W (honest member); it will withhold its reveal"
cld_ctl $WH "(:dispute-enter :ledger \"$W\" :reason \"redteam withhold-reveal\")" >/dev/null

echo "== waiting for the dispute to run to confiscation (arm, cosign, broadcast) — up to ${WAIT}s"
conf_txid=""
for i in $(seq 1 $WAIT); do
  out=$(cld_ctl $WH "(:forks :ledger \"$W\")" 2>/dev/null)
  state=$(echo "$out" | grep -oE ':STATE :[A-Z-]+' | head -1)
  log=$(cld_ctl $WH '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "confiscation .* on chain|withholding" | grep -F "dispute ${W:0:8}:" | tail -2)
  [ -n "$log" ] && echo "  [$i s] $log"
  case "$log" in *"withholding"*) conf_txid=$(echo "$log" | grep -oE '[0-9a-f]{64}' | head -1); break;; esac
  [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null   # the arm window closes on height
  sleep 5
done
[ -n "$conf_txid" ] || fail "no confiscation reached within ${WAIT}s (state: $state)"

echo "== confiscation on chain: $conf_txid; $WH is withholding its reveal"
echo "== mining past the reveal deadline (72 blocks), then watching ${WAIT}s for the subset claim"
for i in $(seq 1 8); do mine 10 >/dev/null; sleep 5; done
claim=""
for i in $(seq 1 $WAIT); do
  if [ -z "$(bcli gettxout "$conf_txid" 0 2>/dev/null | head -1)" ]; then
    tip=$(bcli getblockcount)
    for h in $(seq "$tip" -1 $((tip - 30))); do
      claim=$(bcli getblock "$(bcli getblockhash "$h")" 2 2>/dev/null | python3 -c '
import json,sys
b=json.load(sys.stdin); t=sys.argv[1]
for tx in b["tx"]:
    for vin in tx.get("vin",[]):
        if vin.get("txid")==t and vin.get("vout")==0:
            print(tx["txid"], tx["vout"][0]["scriptPubKey"]["hex"], len(vin.get("txinwitness",[]))); sys.exit()
' "$conf_txid")
      [ -n "$claim" ] && break
    done
    [ -z "$claim" ] && claim=$(bcli getrawmempool | tr -d '[]", ' | head -1)
    break
  fi
  [ $((i % 10)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
cld_ctl $WH "(:adversary :set :withhold-reveal nil)" >/dev/null
[ -n "$claim" ] || fail "the lottery output $conf_txid:0 was not claimed within ${WAIT}s past the reveal deadline"
read -r claim_txid claim_spk witness_items <<<"$claim"
op_pk=$(pubkey_of "$OP")
op_spk=$(python3 -c 'import hashlib,sys; k=bytes.fromhex(sys.argv[1]); print("0014"+hashlib.new("ripemd160",hashlib.sha256(k).digest()).hexdigest())' "$op_pk" 2>/dev/null)
wh_acq=$(cld_ctl $WH "(:forks :ledger \"$W\")" 2>/dev/null | grep -c "DISPUTE-ACQUIRE")
echo "== claimed by $claim_txid (output $claim_spk, $witness_items witness items)"
[ -n "$op_spk" ] && [ "$claim_spk" = "$op_spk" ] && fail "the lottery output paid the accused operator"
[ "$wh_acq" -gt 0 ] && fail "the withholder took custody"
echo "PASS: the withholder only removed itself; a revealer claimed the lottery through its subset leaf ($claim_txid)."
