#!/usr/bin/env bash
# devnet/soak-chainchaos.sh — chain faults on the soak's signet (docs/CHAOS.md §Chain).
# Every CHAINCHAOS_EVERY seconds (7200) one of:
#   reorg     invalidate the last 1–3 blocks and mine a longer competing branch; the old branch's
#             transactions go back to the mempool and confirm again, in other blocks.  Depth stays
#             within the 3-deep rule a vault spend is judged at.
#   feespike  for 20–45 min, every mempool transaction below CHAINCHAOS_SPIKE_SATVB (12) is held
#             out of blocks (prioritisetransaction with a large negative delta, undone after):
#             a rotation's low rungs stall, so its holders must climb the fee ladder.
# We mine the chain ourselves (mine.sh), so a reorg is ours to make.  Touch $SOAK/chainchaos.pause
# to pause.  Log: $SOAK/log/chainchaos.log (via soak.sh start).
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; EVERY=${CHAINCHAOS_EVERY:-7200}; SPIKE=${CHAINCHAOS_SPIKE_SATVB:-12}
HELD="$SOAK/chainchaos.held"; DELTA=100000000
release_held() {   # undo every hold we placed; txids no longer in the mempool just fail
  [ -s "$HELD" ] || return 0
  local t n=0; while read -r t; do bcli prioritisetransaction "$t" 0 "$DELTA" >/dev/null 2>&1 && n=$((n+1)); done <"$HELD"
  : >"$HELD"; echo "$(date +%FT%T)   released $n held transactions"
}
release_held   # a previous run that died mid-spike
reorg() {
  local d=$(( 1 + RANDOM % 3 )) h b
  h=$(bcli getblockcount); b=$(bcli getblockhash $(( h - d + 1 )))
  bcli invalidateblock "$b" || { echo "$(date +%FT%T) reorg: invalidateblock failed"; return; }
  mine $(( d + 1 )) || echo "$(date +%FT%T) reorg: mining the competing branch failed"
  echo "$(date +%FT%T) reorg depth $d at height $h: $(bcli getblockcount) on the new branch, old $(echo "$b" | cut -c1-16) invalidated"
  bcli reconsiderblock "$b" >/dev/null 2>&1   # the old branch is shorter now; nodes stay on the new one
}
feespike() {
  local dur=$(( 1200 + RANDOM % 1500 )) end n=0
  end=$(( $(date +%s) + dur )); echo "$(date +%FT%T) fee spike: holding transactions below $SPIKE sat/vB for ${dur}s"
  while [ "$(date +%s)" -lt "$end" ]; do
    bcli getrawmempool true 2>/dev/null | python3 -c "
import json, sys
held = set(open('$HELD').read().split()) if __import__('os').path.exists('$HELD') else set()
for txid, e in json.load(sys.stdin).items():
    if txid not in held and e['fees']['base'] * 1e8 / e['vsize'] < $SPIKE: print(txid)
" | while read -r t; do bcli prioritisetransaction "$t" 0 "-$DELTA" >/dev/null 2>&1 && echo "$t" >>"$HELD"; done
    sleep 20
  done
  n=$(wc -l <"$HELD" 2>/dev/null || echo 0); echo "$(date +%FT%T) fee spike over: $n transactions were held"
  release_held
}
while true; do
  sleep "$EVERY"
  [ -e "$SOAK/chainchaos.pause" ] && { echo "$(date +%FT%T) paused"; continue; }
  case $(( RANDOM % 2 )) in 0) reorg;; 1) feespike;; esac
done
