#!/usr/bin/env bash
# redteam/run-all.sh — the red-team scenario suite against the live devnet (redteam/scenarios.lisp).
#   redteam/run-all.sh --list | --dry-run | [--only a,b] [--skip a,b] [--tags safe,contagion,disruptive,slow]
# The soak's chaos loop (scheduled node restarts) is paused for the run and restored after.
cd "$(dirname "$0")/.." || exit 1
case " $* " in *" --list "*|*" --dry-run "*) exec "${CLD_SBCL:-/usr/bin/sbcl}" --script redteam/scenarios.lisp -- "$@";; esac
source devnet/_common.sh >/dev/null 2>&1
CHAOS_PID="$CLD_ROOT/soak/pids/chaos"
restore_soak=""
if p=$(cat "$CHAOS_PID" 2>/dev/null) && kill -0 "$p" 2>/dev/null; then
  kill -- -"$p" 2>/dev/null || kill "$p"; rm -f "$CHAOS_PID"; echo "(chaos loop paused for the run)"
  restore_soak=1
fi
# On any exit, interrupted or killed too: take the running scenario's process group down
# (each scenario runs in its own, see run-one), then restore the soak if we paused it.
cleanup() {
  local f
  for f in "$CLD_ROOT"/soak/scenarios/*/*.pgid; do [ -f "$f" ] && kill -KILL -- -"$(cat "$f")" 2>/dev/null; rm -f "$f"; done
  [ -n "$restore_soak" ] && { devnet/soak.sh start >/dev/null 2>&1; echo "(soak processes restored)"; }
}
trap cleanup EXIT
trap 'exit 130' INT TERM
"${CLD_SBCL:-/usr/bin/sbcl}" --script redteam/scenarios.lisp -- "$@"
