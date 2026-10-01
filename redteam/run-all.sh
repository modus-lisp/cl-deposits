#!/usr/bin/env bash
# redteam/run-all.sh — the red-team scenario suite against the live devnet (redteam/scenarios.lisp).
#   redteam/run-all.sh --list | --dry-run | [--only a,b] [--skip a,b] [--tags safe,contagion,disruptive,slow]
# The soak's chaos loop (scheduled node restarts) is paused for the run and restored after.
cd "$(dirname "$0")/.." || exit 1
case " $* " in *" --list "*|*" --dry-run "*) exec "${CLD_SBCL:-/usr/bin/sbcl}" --script redteam/scenarios.lisp -- "$@";; esac
source devnet/_common.sh >/dev/null 2>&1
CHAOS_PID="$CLD_ROOT/soak/pids/chaos"
if p=$(cat "$CHAOS_PID" 2>/dev/null) && kill -0 "$p" 2>/dev/null; then
  kill -- -"$p" 2>/dev/null || kill "$p"; rm -f "$CHAOS_PID"; echo "(chaos loop paused for the run)"
  trap 'devnet/soak.sh start >/dev/null 2>&1; echo "(soak processes restored)"' EXIT
fi
"${CLD_SBCL:-/usr/bin/sbcl}" --script redteam/scenarios.lisp -- "$@"
