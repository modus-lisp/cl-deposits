#!/usr/bin/env bash
# redteam/check-rotation-lag.sh — a lagging watcher never takes an honest rotation for a theft.
#
# Signet soak, 2026-10-21: a reference member under backpressure missed three updates of a cl
# ledger just before its rotation's QuorumBegin, so its replica could not apply it.  Three blocks
# after the rotation confirmed, its vault watch judged the spend on that stale replica alone and
# broadcast UnauthorizedVaultSpend against all five signers.  DEP-06 §Spend challenge: a spend is
# judged by its anchor.  The rotation names, by its anchor, the update its QuorumBegin extends; a
# judge looks for the answer (the QuorumBegin) on its replica, the relay and published answers,
# and when it finds none it challenges instead of proving anything.
#
# A fresh mixed-quorum ledger (three cl members, two reference members, and two lagging cl members).
# LAG's replica applies nothing from just before the rotation (fault :lag-replica); BLIND lags too
# and reads nothing of the ledger on the relay (fault :blind-relay), so only an answer can clear
# the spend for it.  Both sign nothing (:mute).  The operator rotates.
# PASS = after the rotation is buried past the grace: LAG found the QuorumBegin on the relay and
# reported nothing; BLIND challenged, an honest node answered (Kind 9112), BLIND accepted the
# answer; nobody reported a theft or proved one.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 C3 LAG BLIND
R1=${R1:-ref6}; R2=${R2:-ref7}
X=$(form_ledger "${REDTEAM_LAG:-LAG$RANDOM}" $OP "" $C1 $C2 $C3 $LAG $BLIND $R1 $R2) || exit 1
echo "== ledger $X"
consent "$X" $OP $C1 $C2 $C3 $LAG $BLIND $R1 $R2
trap 'for n in $LAG $BLIND; do cld_ctl $n "(:adversary :set :lag-replica nil)" >/dev/null 2>&1; done; cld_ctl $BLIND "(:adversary :set :blind-relay nil)" >/dev/null 2>&1; disarm :mute $LAG $BLIND' EXIT
for n in $LAG $BLIND; do expect "$(cld_ctl $n "(:adversary :set :lag-replica \"${X:0:16}\")")" "lag-replica"; done
expect "$(cld_ctl $BLIND "(:adversary :set :blind-relay \"${X:0:16}\")")" "blind-relay"
arm :mute $LAG $BLIND
seq_of() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$X\"[^)]*" | grep -oE ':SEQ [0-9]+' | grep -oE '[0-9]+'; }
echo "== $LAG's and $BLIND's replicas frozen at seq $(seq_of $LAG) / $(seq_of $BLIND)"
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"
RT=$(sx "$r" ":TXID")
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; mine 1 >/dev/null; sleep 15; done
expect "$r" "begin-quorum"
t=$(sx "$r" ":TXID"); [ -n "$t" ] && [ "$t" != NIL ] && RT=$t; echo "== rotation $RT (rungs: $(sx "$r" ":RUNGS"))"
mine 6 >/dev/null; sleep 10
[ -n "$(bcli getrawtransaction "$RT" true 2>/dev/null | grep -o '"confirmations": [0-9]*')" ] || fail "the rotation $RT did not confirm"
[ "$(bcli getrawtransaction "$RT" true | python3 -c "import json,sys; print(json.load(sys.stdin)['vout'][-1]['scriptPubKey']['hex'][:4])")" = 6a20 ] \
  || fail "the rotation $RT carries no anchor"
now=$(seq_of $LAG); op=$(seq_of $OP)
echo "   $LAG's replica at seq ${now:-?}, the operator's at ${op:-?}"
[ -n "$now" ] && [ -n "$op" ] && [ "$now" -lt "$op" ] || fail "$LAG's replica caught up (${now:-?} vs ${op:-?}): the lag did not hold, so this run proves nothing"
disarm :mute $LAG $BLIND
for n in $LAG $BLIND; do
  if cld_ctl $n "(:log :n 4000)" | grep -q "signing the .* rungs of ${X:0:8}"; then fail "$n signed the rotation; it was meant not to"; fi
done
if accused $LAG "$X" 60; then fail "the lagging watcher $LAG reported the rotation as a theft"; fi
cld_ctl $LAG "(:log :n 4000)" | grep -q "vault watch: ${X:0:8}'s spend .* is answered by its anchor" \
  || fail "$LAG never judged the spend answered (its log): the watch did not reach it"
echo "   $LAG found the rotation's QuorumBegin (on the relay) and reported nothing"
# BLIND: challenged, answered, accepted.  Its watch runs each pass; give the answer a few.
ok=
for i in $(seq 1 30); do
  cld_ctl $BLIND '(:vault-watch)' >/dev/null 2>&1
  cld_ctl $BLIND "(:log :n 4000)" | grep -q "the challenge of ${X:0:8}'s spend .* is answered" && { ok=1; break; }
  sleep 10
done
cld_ctl $BLIND "(:log :n 4000)" | grep -q "VAULT SPEND CHALLENGED: ${X:0:8}" || fail "$BLIND never challenged the spend"
cld_ctl $BLIND "(:log :n 4000)" | grep -q "challenge of ${X:0:8}'s spend recorded on our ledger" || fail "$BLIND did not record its challenge"
answered_by=$(for n in $OP $C1 $C2 $C3; do cld_ctl $n "(:log :n 4000)" | grep -q "answering the challenge of ${X:0:8}" && echo $n; done)
for n in $R1 $R2; do grep -q "answering the challenge of ${X:0:8}" "$(ref_dir $n)/node.log" 2>/dev/null && answered_by="$answered_by $n"; done
echo "   answered by:${answered_by:- (none logged)}"
[ -n "$ok" ] || fail "$BLIND never accepted an answer to its challenge"
if cld_ctl $BLIND "(:log :n 4000)" | grep -q "lapsed-challenge proof against"; then fail "$BLIND proved the rotation"; fi
echo "PASS: $LAG judged the rotation answered from the relay; $BLIND, blind to the relay, challenged it, was answered${answered_by:+ by$answered_by}, and proved nothing."
