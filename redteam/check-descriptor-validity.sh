#!/usr/bin/env bash
# redteam/check-descriptor-validity.sh — DEP-16 §descriptor validity, across implementations.
# A cl operator (cld2) opens a deposit on a fresh mixed ledger (cld3, cld4, ref3 cosign;
# REDTEAM_DV names it) with the descriptor pk(v6-1234), which neither parser accepts.  The
# operator is armed :sign-invalid so it proposes what its own check refuses.
#   honest  : PASS = every cosigner, cl and reference, refuses; nothing commits.
#   collude : cld3 and cld4 cosign blind, so the update commits.  PASS = it is not fraud on
#             either side: within $WAIT s no member disputes the ledger, no fraud proof names
#             cld2, and no cl node holds a fork of it.  (Before the rule, cl members cosigned it
#             and reference members disputed and confiscated the ledger.)
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"; ARM=${1:-honest}; WAIT=${WAIT:-120}
ROW=${REDTEAM_DV:-DV}; BAD='pk(v6-1234)'
C=$(COLLATERAL_SATS=25000000 form_ledger "$ROW" cld2 "" cld3 cld4 ref3) || exit 1
seq_of() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$C\"[^)]*" | grep -oE ':SEQ [0-9]+' | cut -d' ' -f2; }
CS=${C:0:8}; CS16=${C:0:16}; SEQ0=$(seq_of cld2); T0=$(date -u +%FT%T)
echo "== $CS before: seq $SEQ0"
[ "$ARM" = collude ] && arm :cosign-blind cld3 cld4
arm :sign-invalid cld2
R=$(cld_ctl cld2 "(:deposit-open :ledger \"$C\" :descriptor \"$BAD\")")
echo "== operator's attempt (arm=$ARM): $(echo "$R" | cut -c1-200)"
cld_ctl cld2 "(:adversary :set :sign-invalid nil)" >/dev/null; for n in cld3 cld4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
sleep 5; SEQ1=$(seq_of cld2)
ref3_since() { tail -c 30000000 "$(ref_dir ref3)/node.log" | sed 's/\x1b\[[0-9;]*m//g' | awk -v t="$T0" '$1 > t' | grep -E "$CS"; }
echo "== $CS after: seq $SEQ1"
echo "== verdicts:"
for n in cld3 cld4; do echo "   $n: $(cld_ctl $n '(:log)' | tr '"' '\n' | grep -E "cosigned $CS|refused cosign" | tail -1 | cut -c1-160)"; done
echo "   ref3: $(ref3_since | grep -oE 'Cosign refused: [^;]*|UnparseableDescriptor[^,]*' | head -1 | cut -c1-160)"
if [ "$ARM" = honest ]; then
  [ "$SEQ0" = "$SEQ1" ] || fail "the invalid DepositOpen committed (seq $SEQ0 -> $SEQ1)"
  ref3_since | grep -q 'UnparseableDescriptor' || fail "ref3 did not refuse it as UnparseableDescriptor"
  for n in cld3 cld4; do cld_ctl $n '(:log)' | tr '"' '\n' | grep -E "refused cosign" | tail -3 | grep -q 'UnparseableDescriptor' \
    || fail "$n did not refuse it as UnparseableDescriptor"; done
  echo "PASS: cl and reference cosigners refused pk(v6-1234); nothing committed ($CS at seq $SEQ1)"
else
  [ "$SEQ1" -gt "$SEQ0" ] || fail "the colluding majority did not commit (seq $SEQ0 -> $SEQ1)"
  echo "== waiting $WAIT s: nobody may take seq $SEQ1 for fraud"
  sleep "$WAIT"
  L=$(ref3_since)
  echo "$L" | grep -qE "NON-CONFORMING COSIGNED|DisputeEnter|Broadcast fraud proof|arming dispute" \
    && { echo "$L" | grep -E "NON-CONFORMING|Dispute|fraud" | head -5; fail "ref3 took the invalid descriptor for fraud"; }
  for n in cld3 cld4 cld5; do
    F=$(cld_ctl $n "(:forks :ledger \"$C\")"); case "$F" in *":OPERATOR"*) fail "$n forked $CS: $F";; esac
  done
  [ "$(seq_of cld3)" -ge "$SEQ1" ] || fail "cld3's replica did not apply seq $SEQ1"
  echo "PASS: the colluding majority committed pk(v6-1234) at seq $SEQ1; no dispute, no fraud proof, no fork on either side"
fi
