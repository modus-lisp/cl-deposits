#!/usr/bin/env bash
# redteam/check-rotation-recorded-threshold.sh — a rotation recorded below its rungs' tier floor but at
# the ledger's own threshold answers the spend of its rung (DEP-06 §Spend challenge, strict-lottery-v8
# recorded-threshold answer, ruled 2026-11-19), on a real network with both judges.
#
# Signet ledger C's shape, rebuilt: Q=5 (C1 C2 C3 C4 and a reference member R1), a short expiry the
# chain runs past.  The rotation is planned one block before lifecycle tier 1 opens (expiry+720), so
# its rungs spend vault tier 0 (6 voters: 4 signatures, the operator's among them, so the tier floor
# is 3 member cosignatures), and recorded two blocks after, where DEP-05 asks the minority of 5 = 2.
# C2-C4 refuse to cosign the QuorumBegin, so it carries C1's and R1's: 2, final, below the floor.
# The operator records anyway (red-team :skip-answer-floor; DEP-05 forbids it, f28a49f enforces it)
# and C1 C2 C3 sign the rungs anyway (:sign-below-floor; R1 and C4 refuse, as the floor says).
#   PASS = the rung confirms; every cl member's judge logs "answered by rotation ... at the ledger's
#          recorded threshold", R1 (deposits-rust) opens no challenge, no QuorumChallenge is recorded
#          on the ledger and no proof names any rung signer, within JUDGE_WAIT (600) s.
# The ticker is paused and every cl member holds its arm, so nothing confiscates the expired vault
# while the operator re-establishes (as in check-rotation-post-expiry.sh rescue).
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 C3 C4
R1=${R1:-ref6}
RV=$(live_version $R1); echo "== reference member $R1 runs $RV"
# R1 must judge by the ruling (deposits-rust with the recorded-threshold answer): RUST_EXPECT names it.
[ -n "${RUST_EXPECT:-}" ] || fail "set RUST_EXPECT to the deposits-rust build R1 must run (one with the recorded-threshold answer)"
[ "$RV" = "$RUST_EXPECT" ] || fail "$R1 runs $RV, not $RUST_EXPECT"
X=$(FORM_EXPIRY=${FORM_EXPIRY:-30} form_ledger "${REDTEAM_RT:-RT$RANDOM}" $OP "" $C1 $C2 $C3 $C4 $R1) || exit 1
TICKER_PAUSED=""
ticker_start() { setsid -f bash -c "cd '$CLD_SRC' && DEVNET=regtest devnet/regtest-net.sh ticker start" >/dev/null 2>&1; sleep 2; }
cleanup() {
  disarm :hold-arm $C1 $C2 $C3 $C4; disarm :refuse-cosign $C2 $C3 $C4; disarm :sign-below-floor $C1 $C2 $C3
  disarm :skip-answer-floor $OP
  [ -n "$TICKER_PAUSED" ] && ticker_start
}
trap cleanup EXIT
info() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$X\" :OWNED [^)]*" | head -1; }
EXP=$(info $OP | grep -oE ':EXPIRY [0-9]+' | cut -d' ' -f2); [ -n "$EXP" ] || fail "no expiry for $X"
VAULT=$(cld_ctl $OP '(:vaults)' | tr '()' '\n\n' | grep -F "\"$X\"" -A1 | grep -oE '[0-9a-f]{64}:[0-9]+' | tail -1)
[ -n "$VAULT" ] || fail "no vault for $X"; VTX=${VAULT%:*}; VVOUT=${VAULT#*:}
OPEN1=$((EXP + 720))
echo "== ledger $X (Q=5: $C1 $C2 $C3 $C4 $R1), expiry $EXP, tier 1 opens at $OPEN1, vault $VAULT"
"$CLD_SRC/devnet/regtest-net.sh" ticker stop >/dev/null; TICKER_PAUSED=1
arm :hold-arm $C1 $C2 $C3 $C4
M=$(date -u +%FT%T)
# To one block before tier 1 opens, in steps the nodes can follow.
while [ "$(bcli getblockcount)" -lt $((OPEN1 - 1)) ]; do
  left=$(( OPEN1 - 1 - $(bcli getblockcount) )); mine $(( left > 50 ? 50 : left )) >/dev/null; sleep 2
done
sleep 20
echo "== at $(bcli getblockcount): planning the rotation (vault tier 0)"
for m in $C1 $C2 $C3 $C4 $R1; do
  r=$(CLD_CTL_TIMEOUT=240 cld_ctl $OP "(:add-member :ledger \"$X\" :member \"$(pubkey_of $m)\" :member-ledger \"$(own_ledger "$m")\")")
  case "$r" in *":STATUS :OK"*) echo "   $m consented";; *) fail "$m did not consent: $r";; esac
done
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"
RT=$(sx "$r" ":TXID")
mine 2 >/dev/null; sleep 15
echo "== at $(bcli getblockcount) (tier 1): recording below the floor"
arm :refuse-cosign $C2 $C3 $C4; arm :sign-below-floor $C1 $C2 $C3; arm :skip-answer-floor $OP
for i in 1 2 3; do r=$(CLD_CTL_TIMEOUT=180 cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; sleep 15; done
expect "$r" "begin-quorum"
mine 1 >/dev/null; sleep 5
[ -z "$(bcli gettxout "$VTX" "$VVOUT" false | head -1)" ] || fail "the old vault $VAULT is unspent after a block"
# The rung is in a block by now, and gettxspendingprevout sees only the mempool: find it in the tip.
SP=$(bcli getblock "$(bcli getbestblockhash)" 2 | python3 -c 'import json,sys
b=json.load(sys.stdin); t,v=sys.argv[1],int(sys.argv[2])
print(next((x["txid"] for x in b["tx"] for i in x["vin"] if i.get("txid")==t and i.get("vout")==v),""))' "$VTX" "$VVOUT")
[ -n "$SP" ] || fail "no transaction in the tip spends the old vault $VAULT"
echo "== rung ${SP:0:16} confirmed at $(bcli getblockcount)"
mine 2 >/dev/null
disarm :hold-arm $C1 $C2 $C3 $C4; ticker_start; TICKER_PAUSED=""
clog() { sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$1/node.log" | awk -v m="$M" '$1 >= m'; }
rlog() { sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$R1/node.log" | awk -v m="$M" '$1 >= m'; }
answered=""; for t in $(seq 1 $(( ${JUDGE_WAIT:-600} / 10 ))); do
  answered=$(for n in $C1 $C2 $C3 $C4 $OP; do clog $n | grep -q "vault spend ${SP:0:16} of ${X:0:8}: answered by rotation .* recorded threshold" && echo $n; done | tr '\n' ' ')
  [ "$(wc -w <<<"$answered")" -ge 3 ] && break; sleep 10
done
echo "== judged answered at the recorded threshold by: ${answered:-none}"
[ -n "$answered" ] || fail "no cl judge answered the rung by the recorded threshold"
for n in $C1 $C2 $C3 $C4 $OP; do
  clog $n | grep -q "VAULT SPEND CHALLENGED: ${X:0:8}" && fail "$n challenged the spend"
  clog $n | grep -qE "lapsed-challenge proof against|vault spend: .* signed it" && fail "$n proved a rung signer"
done
rlog | grep -iE "challeng" | grep -qi "${X:0:16}" && fail "$R1 (deposits-rust) challenged the spend: $(rlog | grep -iE challeng | grep -i ${X:0:16} | tail -1)"
echo "PASS: rotation recorded with 2 of 5 (tier-1 minority), below tier 0's floor of 3, answers rung ${SP:0:16}; no challenge, no proof"
