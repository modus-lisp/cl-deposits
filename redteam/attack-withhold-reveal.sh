#!/usr/bin/env bash
# redteam/attack-withhold-reveal.sh — the last revealer holds the lottery hostage.
#
# A dispute on a fresh ledger V2 runs to confiscation; one armer (cld6, the
# adversary :withhold-reveal) never publishes its preimage.  The lottery cannot
# be claimed without it.  PASS (the finding): custody waits indefinitely — the
# confiscation tx is on chain, the honest armers revealed, and the winner
# cannot claim; we measure how long the funds sit and whether the recovery
# sweep (CSV-144) fires.  REDTEAM_W=name forms a fresh test ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-300}
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { case "$1" in *":STATUS :OK"*) ;; *) fail "$1";; esac; }

W_ROW="$S/redteam-${REDTEAM_W:-W}"
if [ -f "$W_ROW" ]; then read -r W < "$W_ROW"; echo "== reusing W $W"; else
  echo "== forming W (cld1 operates; cld2 cld3 cld4 cld5 cld6 ref6 ref7 cosign)"
  W=$(sx "$(cld_ctl cld1 "(:open-ledger :reserves-id \"genesis:cld1:redteam-W:$RANDOM\" :reserves-msat 25000000000 :collateral-msat 25000000000)")" ":LEDGER"); [ -n "$W" ] || fail "open W"
  for m in cld2 cld3 cld4 cld5 cld6 ref6 ref7; do
    case $m in cld*) ml=$(eval echo "\${L${m#cld}}");; ref*) ml=$(eval echo "\${RL${m#ref}}");; esac
    expect "$(cld_ctl cld1 "(:add-member :ledger \"$W\" :member \"$(cat $S/pubkey.$m)\" :member-ledger \"$ml\")")"
  done
  prep=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$W\" :expiry-blocks 4320)"); expect "$prep"; addr=$(sx "$prep" ":ADDRESS")
  txid=$(wcli sendtoaddress "$addr" 0.5); mine 3
  vout=$(bcli getrawtransaction "$txid" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$addr'][0])")
  sleep 20
  expect "$(cld_ctl cld1 "(:begin-quorum :ledger \"$W\" :txid \"$txid\" :vout $vout :sats 50000000 :collateral-sats 0)")"
  echo "$W" > "$W_ROW"
fi

# The fraud: cld1 locks a depositor's funds with no witness, cld2..cld4 cosign blind.
for n in cld2 cld3 cld4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
FROM=$(grep -P "^cl\t\S+\tA\t" "$S/deposits.tsv" | head -1 | cut -f5)
cld_ctl cld1 "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in cld2 cld3 cld4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done

# cld6 will dispute, arm, confiscate — but withhold its reveal.
expect "$(cld_ctl cld6 "(:adversary :set :withhold-reveal t)")"
echo "== cld6 disputes W (honest member); it will withhold its reveal"
cld_ctl cld6 "(:dispute-enter :ledger \"$W\" :reason \"redteam withhold-reveal\")" >/dev/null

echo "== waiting for the dispute to run to confiscation (arm, cosign, broadcast) — up to ${WAIT}s"
conf_txid=""
for i in $(seq 1 $WAIT); do
  out=$(cld_ctl cld6 "(:forks :ledger \"$W\")" 2>/dev/null)
  state=$(echo "$out" | grep -oE ':STATE :[A-Z-]+' | head -1)
  log=$(cld_ctl cld6 '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "confiscation .* on chain|withholding" | tail -2)
  [ -n "$log" ] && echo "  [$i s] $log"
  case "$log" in *"withholding"*) conf_txid=$(echo "$log" | grep -oE '[0-9a-f]{64}' | head -1); break;; esac
  sleep 5
done
[ -n "$conf_txid" ] || fail "no confiscation reached within ${WAIT}s (state: $state)"

echo "== confiscation on chain: $conf_txid; cld6 is withholding its reveal"
# The honest armers (cld5, ref6, ref7 — whoever armed) reveal; the lottery needs
# every participant's preimage.  Watch for a claim or a recovery sweep.
echo "== watching ${WAIT}s for a claim or the CSV-144 recovery sweep"
outcome="held"
for i in $(seq 1 $WAIT); do
  spent=$(bcli gettxout "$conf_txid" 0 2>/dev/null | head -1)
  [ -z "$spent" ] && { outcome="spent"; break; }
  sleep 5
done
cld_ctl cld6 "(:adversary :set :withhold-reveal nil)" >/dev/null
if [ "$outcome" = held ]; then
  echo "PASS (gap confirmed): the lottery output is unspent and unclaimable — the withholder holds custody hostage."
  echo "     Confiscation $conf_txid:0.  No claim, no recovery sweep within ${WAIT}s (CSV-144 needs 144 confirmations)."
else
  echo "NOTE: the lottery output was spent — someone claimed or swept it.  Investigate $conf_txid."
fi
