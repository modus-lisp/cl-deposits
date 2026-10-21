#!/usr/bin/env bash
# redteam/check-rotation-lag.sh — a lagging watcher must not take an honest rotation for a theft.
#
# Signet soak, 2026-10-21: a reference member under backpressure missed three updates of a cl
# ledger just before its rotation's QuorumBegin, so its replica could not apply it.  Three blocks
# after the rotation confirmed, its vault watch judged the spend on that stale replica alone and
# broadcast UnauthorizedVaultSpend against all five signers; cl members that did not follow the
# ledger accepted the proofs and disputed the signers' own ledgers.  DEP-06 "Recorded rotation":
# the QuorumBegin is on the relay before the rotation is broadcast, so a judge consults the relay's
# updates past its replica before it calls a spend unauthorised.
#
# A fresh mixed-quorum ledger (three cl members, two reference members); member LAG's replica of it
# applies nothing from just before the rotation (fault switch :lag-replica).  The operator rotates.
# PASS = LAG's replica is still behind the QuorumBegin after the rotation is buried past the grace,
# and LAG does not report the rotation as a theft.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 LAG
R1=${R1:-ref6}; R2=${R2:-ref7}
X=$(form_ledger "${REDTEAM_LAG:-LAG$RANDOM}" $OP "" $C1 $C2 $LAG $R1 $R2) || exit 1
echo "== ledger $X"
consent "$X" $OP $C1 $C2 $LAG $R1 $R2
trap 'cld_ctl $LAG "(:adversary :set :lag-replica nil)" >/dev/null 2>&1' EXIT
expect "$(cld_ctl $LAG "(:adversary :set :lag-replica \"${X:0:16}\")")" "lag-replica"
seq_of() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$X\"[^)]*" | grep -oE ':SEQ [0-9]+' | grep -oE '[0-9]+'; }
before=$(seq_of $LAG); echo "== $LAG's replica frozen at seq ${before:-?}"
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"
RT=$(sx "$r" ":TXID"); echo "== rotation $RT"
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; mine 1 >/dev/null; sleep 15; done
expect "$r" "begin-quorum"
mine 6 >/dev/null; sleep 10
[ -n "$(bcli getrawtransaction "$RT" true 2>/dev/null | grep -o '"confirmations": [0-9]*')" ] || fail "the rotation $RT did not confirm"
now=$(seq_of $LAG); op=$(seq_of $OP)
echo "   $LAG's replica at seq ${now:-?}, the operator's at ${op:-?}"
[ -n "$now" ] && [ -n "$op" ] && [ "$now" -lt "$op" ] || fail "$LAG's replica caught up (${now:-?} vs ${op:-?}): the lag did not hold, so this run proves nothing"
if accused $LAG "$X" 60; then fail "the lagging watcher $LAG reported the rotation as a theft"; fi
cld_ctl $LAG "(:log :n 4000)" | grep -q "vault watch on ${X:0:8}.*retrying" && echo "   ($LAG deferred a judgement while the relay was unreachable)"
echo "PASS: $LAG's replica lagged behind the rotation's QuorumBegin, and it judged the spend on the relay's updates too: no theft reported."
