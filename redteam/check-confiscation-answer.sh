#!/usr/bin/env bash
# redteam/check-confiscation-answer.sh — a confiscation challenge is answered by a reference holder.
#
# Signet soak, 2026-11-04: a cl member's watch challenged rung 1 of a confiscation (it could not
# rebuild it), the reference members that held the dispute answered only rotation challenges, the
# challenge lapsed, and lapsed-challenge proofs reached the honest member ref6 and every ledger it
# operates.  DEP-06 §Spend challenge, answer 2: any node that holds the dispute and rebuilds the
# spend as a rung of it answers, with the dispute's disputant updates.
#
# A fresh ledger: a cl operator, three cl members that cosign blind, a reference member R1 that
# disputes, and a cl member BLIND whose replica is frozen before the fault and which reads nothing
# of the ledger on the relay (it never disputes, and cannot rebuild the confiscation).  The
# operator forges a lock; R1 disputes; the confiscation confirms.
# PASS = BLIND challenged the confiscation, R1 answered it (its log: "its confiscation's dispute"),
# BLIND accepted the answer, and nobody proved a theft against anyone.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-1200}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4 BLIND
R1=${R1:-ref6}
ROW=${REDTEAM_CA:-CA$RANDOM}
W=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $BLIND $R1) || exit 1; echo "== ledger $W"
FROM=$(fresh_deposits "$ROW" $OP "$W" 1 | head -1); [ -n "$FROM" ] || fail "no deposit on the ledger"
trap 'for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null 2>&1; done; cld_ctl $BLIND "(:adversary :set :lag-replica nil)" >/dev/null 2>&1; cld_ctl $BLIND "(:adversary :set :blind-relay nil)" >/dev/null 2>&1; disarm :mute $BLIND' EXIT
expect "$(cld_ctl $BLIND "(:adversary :set :lag-replica \"${W:0:16}\")")" "lag-replica"
expect "$(cld_ctl $BLIND "(:adversary :set :blind-relay \"${W:0:16}\")")" "blind-relay"
arm :mute $BLIND

# The fault: $OP locks a depositor's funds with no witness, $C2..$C4 cosign blind.
for n in $C2 $C3 $C4; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$W\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $C2 $C3 $C4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $C2 $C3 $C4

VAULT=$(cld_ctl $OP '(:vaults)' | tr '()' '\n\n' | grep -F "\"$W\"" -A1 | grep -oE '[0-9a-f]{64}:[0-9]+' | tail -1)
[ -n "$VAULT" ] || fail "no vault for $W"
VINTX=${VAULT%:*}; VINVOUT=${VAULT#*:}
echo "== vault $VAULT; waiting for $R1 to dispute and the confiscation to confirm (up to ${WAIT}s)"
conf=""
for i in $(seq 1 $((WAIT / 10))); do
  if [ -z "$(bcli gettxout "$VINTX" "$VINVOUT" false 2>/dev/null | head -1)" ]; then
    conf=$(bcli gettxspendingprevout "[{\"txid\":\"$VINTX\",\"vout\":$VINVOUT}]" 2>/dev/null \
             | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0].get("spendingtxid",""))' 2>/dev/null)
    [ -n "$conf" ] || conf=spent
    break
  fi
  sleep 10
done
[ -n "$conf" ] || fail "the vault was not spent within ${WAIT}s"
echo "== the vault is spent; mining past the spend-judging grace and waiting for a challenge and its answer"
answered="" challenged=""
for i in $(seq 1 $((WAIT / 10))); do
  [ $((i % 3)) -eq 0 ] && mine 1 >/dev/null
  challenged=$(cld_ctl $BLIND '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "challenge" | grep -F "${W:0:8}" | head -1)
  answered=$(tail -c 30000000 "$(ref_dir $R1)/node.log" 2>/dev/null | sed "s/\x1b\[[0-9;]*m//g" | grep -F "answering the challenge of ${W:0:8}" | grep -F "confiscation's dispute" | head -1)
  [ -n "$challenged" ] && [ -n "$answered" ] && break
  sleep 10
done
echo "   $BLIND: ${challenged:-no challenge}"
echo "   $R1: ${answered:-no answer}"
[ -n "$challenged" ] || fail "$BLIND never challenged the confiscation (the scenario proves nothing)"
[ -n "$answered" ] || fail "$R1 did not answer the challenge of the confiscation"
sleep 30; mine 1 >/dev/null; sleep 20
for n in $OP $C2 $C3 $C4 $BLIND; do
  if cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "VAULT SPEND|lapsed" | grep -qF "${W:0:8}"; then
    fail "$n proved the confiscation of $W as a theft"
  fi
done
if tail -c 30000000 "$(ref_dir $R1)/node.log" 2>/dev/null | sed "s/\x1b\[[0-9;]*m//g" | grep -E "VAULT SPEND|lapsed" | grep -qF "${W:0:8}"; then fail "$R1 proved the confiscation as a theft"; fi
echo "PASS: $BLIND challenged the confiscation of $W, $R1 answered with its dispute, and nobody proved a theft."
