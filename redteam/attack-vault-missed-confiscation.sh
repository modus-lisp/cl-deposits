#!/usr/bin/env bash
# redteam/attack-vault-missed-confiscation.sh — a confiscation the watcher does not know of.
#
# A vault spend is excused if it is a recorded rotation or a confiscation the rules rebuild from
# public state; once it was excused only if the WATCHER knew it (one it disputed in or signed).
# On a fresh cl-only ledger (OP, a clean node, operates; members C2..C5, D5, D6, OBS), C2..C5
# cosign a forged lock blind: a real fault, so the dispute has grounds under grounded-arms-v7
# (2026-11-15: the earlier form disputed with no fraud proof, every arm was ungrounded and nothing
# ever confiscated). D5 and D6 dispute on its proof and confiscate (the accused are no voters).
#   - D6 (a disputant) must NOT report the confiscation as a vault spend   [PASS condition]
#   - OBS either disputed too (it saw the fault), or rebuilds the confiscation from the relay and
#     excuses it; one that reports it names the honest signers (the old limit).
# REDTEAM_MC=name forms a fresh ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
WAIT=${WAIT:-600}
pick OP OBS C2 C3 C4 C5 D5 D6
X=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "${REDTEAM_MC:-MC}" $OP "" $C2 $C3 $C4 $C5 $D5 $D6 $OBS) || exit 1
FROM=$(fresh_deposits "${REDTEAM_MC:-MC}" $OP "$X" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"
trap 'for n in $C2 $C3 $C4 $C5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done' EXIT
for n in $C2 $C3 $C4 $C5; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$X\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4 $C5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4 $C5   # confiscated below
echo "== ledger $X: the forged lock is proven; $D5 and $D6 dispute"
for n in $D5 $D6; do cld_ctl $n "(:dispute-enter :ledger \"$X\" :reason \"redteam missed-confiscation\")" >/dev/null; done
D3=$D5; D4=$D6
conf=""
for i in $(seq 1 $((WAIT / 5))); do
  for n in $D5 $D6 $OBS; do   # any disputant: one that armed late is not in the lottery and never logs it
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
accused $D6 "$X" 40 && fail "$D6, a disputant, reported its own confiscation as a vault spend"
if accused $OBS "$X"; then
  echo "PASS: the disputant excused the confiscation; $OBS (no fork) reported it as a vault spend — the known limit, demonstrated."
else
  if cld_ctl $OBS "(:forks :ledger \"$X\")" | grep -q ":STATE"; then
    echo "PASS: the disputant excused the confiscation; $OBS disputed too (the operator's key is tainted by an earlier run), so it knew the confiscation and the limit could not show."
  else
    echo "PASS: the disputant excused the confiscation, and $OBS did not report it either (the limit did not show)."
  fi
fi
