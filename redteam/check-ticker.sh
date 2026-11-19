#!/usr/bin/env bash
# redteam/check-ticker.sh — the regtest block ticker survives the shell that (re)started it.
# Every scenario that pauses the ticker restarts it from its EXIT trap, and run-all.sh then kills
# that scenario's process group; a ticker forked into that group died with it and regtest stopped
# mining (2026-11-19).  This stops the ticker, starts it again from a throwaway process group,
# kills that group, and requires the ticker to be alive, in its own session, single, and mining.
#   DEVNET=regtest redteam/check-ticker.sh
set -u
export DEVNET=regtest
source "$(dirname "$0")/../devnet/_common.sh"
NET="$CLD_SRC/devnet/regtest-net.sh"
fail() { echo "FAIL: $*" >&2; "$NET" ticker start >/dev/null 2>&1; exit 1; }
pid() { cat "$CLD_ROOT/ticker.pid" 2>/dev/null; }

"$NET" ticker stop
p=$(pid); [ -z "$p" ] || ! kill -0 "$p" 2>/dev/null || fail "ticker $p still running after stop"
echo "== ticker stopped"

# Start it inside a group of our own making, then kill that whole group, as run-all.sh does.
setsid bash -c "'$NET' ticker start; sleep 300" </dev/null >/dev/null 2>&1 & G=$!
for i in $(seq 1 50); do p=$(pid) && kill -0 "$p" 2>/dev/null && break; sleep 0.1; done
[ -n "${p:-}" ] && kill -0 "$p" 2>/dev/null || fail "ticker start from a scenario-like group did not start a ticker"
kill -- -"$G" 2>/dev/null; wait "$G" 2>/dev/null
sleep 1
kill -0 "$p" 2>/dev/null || fail "ticker $p died with the process group that started it"
[ "$(ps -o sid= -p "$p" | tr -d ' ')" != "$(ps -o sid= -p $$ | tr -d ' ')" ] || fail "ticker $p shares this shell's session"
[ "$(ps -o sid= -p "$p" | tr -d ' ')" != "$G" ] || fail "ticker $p is in the killed group's session"
echo "== ticker $p survived its starter's group being killed"

# Idempotent: a second start must not fork a second loop.
"$NET" ticker start; [ "$(pid)" = "$p" ] || fail "a second start replaced ticker $p with $(pid)"
# Count loops, not processes: the loop's own $(mine ...) subshells carry its command line, and one
# that exits between pgrep and ps reads as parentless.  A real second loop persists, so take the
# smallest count over a few samples.
count_loops() { local loops q n=0; loops=$(pgrep -f "regtest-net.sh ticker-loop")
  for q in $loops; do pp=$(ps -o ppid= -p "$q" | tr -d ' '); [ -n "$pp" ] || continue
    grep -qx "$pp" <<<"$loops" || n=$((n+1)); done; echo $n; }
n=9; for i in 1 2 3 4 5; do c=$(count_loops); [ "$c" -lt "$n" ] && n=$c; sleep 0.5; done
[ "$n" -eq 1 ] || { ps -eo pid,ppid,sid,pgid,cmd | grep -E "ticker|check-ticker" | grep -v grep >&2; fail "$n ticker loops running"; }

# Every REGTEST_COLLATERAL_EVERY blocks the loop runs a collateral pass in line (minutes when many
# actors ran short), so allow for one before calling it stalled.
h0=$(bcli getblockcount); h1=$h0
for i in $(seq 1 60); do sleep 5; h1=$(bcli getblockcount); [ "$h1" -gt "$h0" ] && break; done
[ "$h1" -gt "$h0" ] || fail "no block mined in 300 s ($h0 -> $h1)"
echo "PASS: ticker restarted, detached (session $(ps -o sid= -p "$p" | tr -d ' ')), single, mining ($h0 -> $h1)"
