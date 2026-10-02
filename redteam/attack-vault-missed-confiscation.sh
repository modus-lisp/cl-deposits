#!/usr/bin/env bash
# redteam/attack-vault-missed-confiscation.sh — a confiscation the watcher does not know of.
#
# A vault spend is excused if it is a recorded rotation or a confiscation the WATCHER knows
# (one it disputed in or signed).  On a fresh cl-only ledger (OP, a clean node, operates; cld2..cld6 cosign),
# cld3 cld4 cld5 cld6 dispute and confiscate (majority 4 of 6).  cld2 never disputes.  Then:
#   - cld6 (a disputant) must NOT report the confiscation as a vault spend   [PASS condition]
#   - cld2 (no fork) does report it, naming the honest confiscation signers  [the known limit]
# The limit's contagion lands on the signers' (honest) ledgers wherever a verifier also lacks the
# record.  REDTEAM_MC=name forms a fresh ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
# Fewer than Q arm here, and cl then waits *full-arming-wait-blocks* (720) before confiscating (the
# Lottery-N mitigation): shorten it for the run, restore it after.
tune_arming() { local n; for n in $(cld_names); do cld_ctl "$n" "(:tune :full-arming-wait-blocks $1)" >/dev/null 2>&1; done; }
tune_arming 2; trap 'tune_arming 720' EXIT
WAIT=${WAIT:-600}
pick OP   # clean: a tainted operator's ledger is disputed on sight by cld2 too, hiding the limit
X=$(RESP=${RESP:-5} form_ledger "${REDTEAM_MC:-MC}" $OP "" cld2 cld3 cld4 cld5 cld6) || exit 1
taint "$OP"   # confiscated below
echo "== ledger $X: cld3 cld4 cld5 cld6 dispute"
for n in cld3 cld4 cld5 cld6; do cld_ctl $n "(:dispute-enter :ledger \"$X\" :reason \"redteam missed-confiscation\")" >/dev/null; done
conf=""
for i in $(seq 1 $((WAIT / 5))); do
  for n in cld3 cld4 cld5 cld6; do   # any disputant: one that armed late is not in the lottery and never logs it
    conf=$(cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "confiscation .* on chain" | grep -F "dispute ${X:0:8}:" | grep -oE '[0-9a-f]{64}' | tail -1)
    [ -n "$conf" ] && break
  done
  [ -n "$conf" ] && break
  [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null   # the arm window closes on height
  sleep 5
done
[ -n "$conf" ] || fail "no confiscation within ${WAIT}s"
echo "== confiscation $conf"
mine 5 >/dev/null; sleep 5
accused cld6 "$X" && fail "cld6, a disputant, reported its own confiscation as a vault spend"
if accused cld2 "$X"; then
  echo "PASS: the disputant excused the confiscation; cld2 (no fork) reported it as a vault spend — the known limit, demonstrated."
else
  if cld_ctl cld2 "(:forks :ledger \"$X\")" | grep -q ":STATE"; then
    echo "PASS: the disputant excused the confiscation; cld2 disputed too (the operator's key is tainted by an earlier run), so it knew the confiscation and the limit could not show."
  else
    echo "PASS: the disputant excused the confiscation, and cld2 did not report it either (the limit did not show)."
  fi
fi
