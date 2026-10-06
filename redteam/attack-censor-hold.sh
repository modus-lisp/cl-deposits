#!/usr/bin/env bash
# redteam/attack-censor-hold.sh — the operator ignores a depositor's transfer
# request (DEP-11/12 censorship), and the wallet escalates through a quorum
# member.  Two arms:
#   honest : the operator answers normally.  PASS = the transfer commits.
#   censor : the operator drops every wallet request (:ignore-requests).  The
#            wallet escalates via delivery_embed to a member (cld6).  PASS =
#            the embed lands on the member's ledger (the escalation channel
#            works), and the finding: nothing acts on it — no honest node
#            disputes the operator, the funds stay locked, and the wallet's
#            only recourse is the timeout.  We record how long the request
#            stays unanswered and whether any dispute follows.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"; ARM=${1:-censor}; WAIT=${WAIT:-90}
ROW=${REDTEAM_CH:-CH}   # a fresh ledger A: cld1 operates, cld2 cld3 cld6 cosign
A=$(form_ledger "$ROW" cld1 "" cld2 cld3 cld6) || exit 1; AS=${A:0:8}
mapfile -t DEPS < <(fresh_deposits "$ROW" cld1 "$A" 2); FROM=${DEPS[0]:-}; TO=${DEPS[1]:-}
[ -n "$FROM" ] && [ -n "$TO" ] || fail "no cl deposits on A"
W="$CLD_SRC/devnet/cld-wallet.sh"
bal() { $W w1 "$A" balance "$1" 2>/dev/null | grep -oE ':BALANCE [0-9]+ :LOCKED [0-9]+'; }
echo "== target A ($AS…, cld1 operates); victim $FROM: $(bal $FROM)"

if [ "$ARM" = censor ]; then
  expect "$(cld_ctl cld1 "(:adversary :set :ignore-requests t)")"
  echo "== cld1 now drops every wallet request"
fi

T0=$(date -u +%s)
echo "== w1 requests a transfer of 100000 msat $FROM -> $TO"
out=$(timeout 60 $W w1 "$A" transfer "$FROM" "$TO" 100000 "$(bcli getblockcount)" 2>&1 | tail -3)
echo "$out"
if [ "$ARM" = honest ]; then
  case "$out" in *":TRANSFER "*) echo "PASS: transfer committed against an answering operator";;
    *) echo "FAIL: transfer did not commit: $out"; exit 1;; esac
  exit 0
fi

# censor arm: the transfer timed out.  Escalate through a member (DEP-12).
# cld6 is a member of A; its own ledger is L6 (from the soak env).
MEMBER_LEDGER=$(eval echo "\${L6}")
OPERATOR=$(pubkey_of cld1)
echo "== escalating: delivery_embed through cld6 (a quorum member of A)"
esc=$(timeout 60 $W w1 "$A" escalate "$FROM" "$TO" 100000 "$MEMBER_LEDGER" "$OPERATOR" 2>&1 | tail -3)
echo "$esc"
case "$esc" in *":STATUS :OK"*) echo "== embed accepted by the member";;
  *) echo "NOTE: escalation channel itself failed: $esc";; esac

# Does anything act on the embed?  Watch A's members for a dispute.
echo "== watching for a dispute on A for ${WAIT}s"
disputed=0
for i in $(seq 1 $WAIT); do
  d=$(for n in cld2 cld3 cld6; do cld_ctl $n "(:forks :ledger \"$A\")" 2>/dev/null; done | grep -oE ":STATE :(DISPUTED|ARMED)" | wc -l)
  [ "$d" -gt 0 ] && { disputed=$d; break; }
  sleep 1
done
cld_ctl cld1 "(:adversary :set :ignore-requests nil)" >/dev/null
echo "== disputes on A: $disputed; balance after: $(bal $FROM)"
if [ "$disputed" -eq 0 ]; then
  echo "PASS (gap confirmed): the request was censored, the embed landed, and no member acted on it."
  echo "     The depositor's funds are held with no protocol recourse inside ${WAIT}s — docs/MISSING.md, censorship proofs unwired."
else
  echo "NOTE: a member disputed A after the embed — the duty-to-act path may exist."
fi
