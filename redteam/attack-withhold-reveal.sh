#!/usr/bin/env bash
# redteam/attack-withhold-reveal.sh — the last revealer holds the lottery hostage.
#
# A dispute on a fresh ledger V2 runs to confiscation; one armer (WH, the
# adversary :withhold-reveal) never publishes its preimage.  The lottery cannot
# be claimed without it.  PASS (the finding): custody waits indefinitely — the
# confiscation tx is on chain, the honest armers revealed, and the winner
# cannot claim; we measure how long the funds sit and whether the recovery
# sweep (CSV-144) fires.  REDTEAM_W=name forms a fresh test ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-300}
source "$(dirname "$0")/_lib.sh"
pick OP WH   # both need clean keys: a tainted operator's W is disputed on sight, before the fraud
trap 'cld_ctl "$WH" "(:adversary :set :withhold-reveal nil)" >/dev/null 2>&1; tune_arming 720' EXIT
# Fewer than Q arm here, and cl then waits *full-arming-wait-blocks* (720) before confiscating (the
# Lottery-N mitigation): shorten it for the run, restore it after.
tune_arming() { local n; for n in $(cld_names); do cld_ctl "$n" "(:tune :full-arming-wait-blocks $1)" >/dev/null 2>&1; done; }
tune_arming 2
ROW=${REDTEAM_W:-W}   # a fresh ledger W: $OP operates; cld2..$WH ref6 ref7 cosign
W=$(RESP=${RESP:-5} form_ledger "$ROW" $OP "" cld2 cld3 cld4 cld5 $WH ref6 ref7) || exit 1; echo "== W $W"
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
# The honest armers (cld5, ref6, ref7 — whoever armed) reveal; the lottery needs
# every participant's preimage.  Watch for a claim or a recovery sweep.
echo "== watching ${WAIT}s for a claim or the CSV-144 recovery sweep"
outcome="held"
for i in $(seq 1 $WAIT); do
  spent=$(bcli gettxout "$conf_txid" 0 2>/dev/null | head -1)
  [ -z "$spent" ] && { outcome="spent"; break; }
  sleep 5
done
# Past the recovery delay: mine 150 blocks (CSV-144) and see whether anything recovers the output.
if [ "$outcome" = held ]; then
  echo "== mining 150 blocks past the confiscation (CSV-144 recovery path)"
  for i in $(seq 1 15); do
    mine 10 >/dev/null; sleep 10
    [ -z "$(bcli gettxout "$conf_txid" 0 2>/dev/null | head -1)" ] && { outcome="swept-after-csv"; break; }
  done
  [ "$outcome" = held ] && sleep 60 && [ -z "$(bcli gettxout "$conf_txid" 0 2>/dev/null | head -1)" ] && outcome="swept-after-csv"
fi
cld_ctl $WH "(:adversary :set :withhold-reveal nil)" >/dev/null
if [ "$outcome" = swept-after-csv ]; then
  echo "PASS (bounded): the withholder stalled the lottery, but the output was recovered after the CSV-144 delay."
  echo "     Confiscation $conf_txid:0 spent after ~$((i*10)) blocks."
elif [ "$outcome" = held ]; then
  echo "PASS (gap confirmed): the lottery output is unspent and unclaimable — the withholder holds custody hostage."
  echo "     Confiscation $conf_txid:0.  No claim, and no recovery sweep even 150 blocks past CSV-144."
else
  echo "NOTE: the lottery output was spent — someone claimed or swept it.  Investigate $conf_txid."
fi
