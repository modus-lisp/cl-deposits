#!/usr/bin/env bash
# redteam/check-proof-lag.sh — a member whose replica lags when the fraud proof arrives must still
# enter the dispute (DEP-06 §Verification: a proof we cannot judge YET is parked, the replica catches
# up, and the proof is re-judged; it is not refused).
#
# regtest 1120-075609 (rearm-rust): ref7's main loop was 3 s behind, its cosign requests for seq 5..8
# were dropped as stale, and the four NonConformingUpdate proofs against seq 9 arrived while its
# replica stood at seq 4: "fault update at seq 9 follows an update that is not in this ledger's
# history".  It caught up milliseconds later, never re-judged, and never entered the dispute.
#
# Here the lag is made, not waited for: R (a reference member) is SIGSTOPped while the operator
# credits deposits it therefore never cosigns or applies, then forges a non-conforming TransferLock
# that the blind members cosign; the honest member H disputes; R is resumed with the proofs and the
# DisputeEnter already on the relay.
# PASS = R parked a proof for this ledger AND re-judged it AND published its own dispute fork.
# A fork with no parked proof means R's replica was current when the proof reached it — the race was
# not reproduced — and that is a FAIL (inconclusive), never a pass.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 H
R=${R:-ref5}
PAUSE=${PAUSE:-25}
RLOG="$CLD_ROOT/$R/node.log"
ROW=${REDTEAM_PL:-PL$RANDOM}
W=$(COLLATERAL_SATS=25000000 form_ledger "$ROW" $OP "" $C2 $C3 $C4 $H $R) || exit 1; echo "== ledger $W (members $C2 $C3 $C4 $H $R)"
mapfile -t DEPS < <(fresh_deposits "$ROW" $OP "$W" 2); FROM=${DEPS[0]}; OTHER=${DEPS[1]}
[ -n "$FROM" ] && [ -n "$OTHER" ] || fail "no deposits on the ledger"
read -r TXID VOUT <"$S/redteam-$ROW.outpoint"
RPID=$(ref_pid $R); [ -n "$RPID" ] || fail "$R is not running"
RFROM=$(( $(stat -c %s "$RLOG") + 1 ))
trap 'kill -CONT '"$RPID"' 2>/dev/null; for n in '"$C2 $C3 $C4"'; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done' EXIT

echo "== $R paused (SIGSTOP pid $RPID); the ledger moves on without it"
kill -STOP "$RPID" || fail "could not pause $R"
for i in 1 2 3; do   # updates R never sees: each credit is a cosigned update past R's replica
  expect "$(cld_ctl $OP "(:credit :ledger \"$W\" :deposit \"$OTHER\" :msat 1000000 :txid \"$TXID\" :vout $VOUT)")" "credit $i without $R"
done
for n in $C2 $C3 $C4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4
echo "== $H disputes the ledger"
cld_ctl $H "(:dispute-enter :ledger \"$W\" :reason \"redteam proof lag\")" >/dev/null
sleep $(( PAUSE > 15 ? PAUSE - 15 : 1 ))
echo "== $R resumed after ${PAUSE}s"
kill -CONT "$RPID"

# R's fork, as C2 sees it.
fork_state() { cld_ctl $C2 "(:forks :ledger \"$W\")" | grep -oE "\(:OPERATOR \"$(pubkey_of $1 | cut -c1-16)\" [^)]*" | grep -oE ':STATE :[A-Z]+' | cut -d: -f3; }
rlog() { tail -c +"$RFROM" "$RLOG" | sed 's/\x1b\[[0-9;]*m//g'; }
FS=""
for i in $(seq 1 60); do FS=$(fork_state $R); [ -n "$FS" ] && break; sleep 5; done
PARKED=$(rlog | grep -cE "Re-judging parked fraud proof .* on ${W:0:16}")
REFUSED=$(rlog | grep -F "${W:0:16}" | grep -c "follows an update that is not in this ledger's history")
echo "== $R: fork state ${FS:-none}; parked proofs re-judged for this ledger: $PARKED; proofs refused for missing history: $REFUSED"
rlog | grep -F "${W:0:16}" | grep -E 'parked|Re-judging|fork|Fraud proof|DisputeEnter|gap' | cut -c1-260 | head -n 12 | sed "s/^/   $R: /"
[ -n "$FS" ] || fail "$R did not enter the dispute on $W within 300 s of resuming (lagging replica; $PARKED parked proof(s) re-judged, $REFUSED refused)"
[ "$PARKED" -gt 0 ] || fail "race not reproduced: $R entered the dispute but parked no proof (its replica was current when the proof arrived) — inconclusive"
echo "PASS: $R's replica lagged when the proof arrived; it parked the proof, re-judged it after catching up, and entered the dispute ($FS)"
