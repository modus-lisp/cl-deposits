#!/usr/bin/env bash
# devnet/soak-chaos.sh — every SOAK_RESTART_EVERY seconds take the next node in SOAK_CHAOS_NODES
# (round robin) and do one of these to it, mid-traffic, then record how long it took to answer:
#   restart  stop it, start it again (most turns)
#   freeze   SIGSTOP it for 5–20 min, then SIGCONT: it wakes far behind, with stale requests queued
#            (CHAOS_FREEZE_PCT, 20)
#   kill9    kill -9, then start it: a crash, wherever it was in a write (CHAOS_KILL9_PCT, 20)
# The bots must recover on their own.  Process faults are docs/CHAOS.md §Processes and versions.
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; EVERY=${SOAK_RESTART_EVERY:-10800}; NODES=(${SOAK_CHAOS_NODES:-$(cld_names) $(ref_names)}); ci=0   # not "i": start_cld uses it
FREEZE=${CHAOS_FREEZE_PCT:-20}; KILL9=${CHAOS_KILL9_PCT:-20}
pid_of() { case $1 in cld*) cld_pid "$1";; ref*) ref_pid "$1";; esac; }
answers() { case $1 in cld*) cld_ctl "$1" '(:info)' 2>/dev/null | grep -q ':STATUS :OK';; ref*) ref_running "$1";; esac; }
while true; do
  sleep "$EVERY"
  n=${NODES[$((ci % ${#NODES[@]}))]}; ci=$((ci+1)); t0=$(date +%s); r=$((RANDOM % 100))
  if [ "$r" -lt "$FREEZE" ] && p=$(pid_of "$n") && [ -n "$p" ]; then
    d=$(( 300 + RANDOM % 900 ))
    echo "$(date +%FT%T) freezing $n (pid $p) for ${d}s"
    kill -STOP "$p"; sleep "$d"; kill -CONT "$p"
    for w in $(seq 1 120); do answers "$n" && break; sleep 5; done
    echo "$(date +%FT%T) $n resumed; answering $(( $(date +%s) - t0 - d ))s after SIGCONT  $(node_version "$n")"
  elif [ "$r" -lt $((FREEZE + KILL9)) ] && p=$(pid_of "$n") && [ -n "$p" ]; then
    echo "$(date +%FT%T) kill -9 $n (pid $p)"
    ( flock -w 1800 9 || exit 1
      kill -9 "$p"; for w in $(seq 1 60); do kill -0 "$p" 2>/dev/null || break; sleep 1; done
      case $n in cld*) start_cld "$n" 9>&-;; ref*) start_ref "$n" 9>&-;; esac ) 9>"$(node_dir "$n")/restart.lock"
    echo "$(date +%FT%T) $n back after $(( $(date +%s) - t0 ))s  $(node_version "$n")"
  else
    echo "$(date +%FT%T) restarting $n"
    restart_node "$n"   # under the node's restart lock (a deploy may be switching it), onto the version it runs
    echo "$(date +%FT%T) $n back after $(( $(date +%s) - t0 ))s  $(node_version "$n")"
  fi
done
