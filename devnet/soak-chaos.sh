#!/usr/bin/env bash
# devnet/soak-chaos.sh — every SOAK_RESTART_EVERY seconds kill the next node in
# SOAK_CHAOS_NODES (round robin), wait, start it again, and record how long it took to
# answer.  Operators go down mid-traffic on purpose: the bots must recover on their own.
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; EVERY=${SOAK_RESTART_EVERY:-10800}; NODES=(${SOAK_CHAOS_NODES:-cld2 cld3 ref3 cld4 cld1 ref2}); ci=0   # not "i": start_cld uses it
while true; do
  sleep "$EVERY"
  n=${NODES[$((ci % ${#NODES[@]}))]}; ci=$((ci+1)); t0=$(date +%s)
  echo "$(date +%FT%T) restarting $n"
  case "$n" in cld*) stop_cld "$n"; sleep 5; start_cld "$n";; ref*) stop_ref "$n"; sleep 5; start_ref "$n";; esac
  echo "$(date +%FT%T) $n back after $(( $(date +%s) - t0 ))s"
done
