#!/usr/bin/env bash
# redteam/attack1-invalid-credit.sh — docs/REDTEAM.md #1: an operator asks its quorum to
# cosign a credit that takes obligations over reserves.  Two arms on ledger C
# (cld2 operates; cld3, cld4, ref3 cosign):
#   honest   : no cosigner misbehaves.  PASS = every cosigner refuses, nothing commits.
#   collude  : cld3 and cld4 cosign blind (a colluding majority).  The update commits.
#              PASS = the honest minority (ref3) refuses AND disputes within $WAIT s
#              (a DisputeEnter on C, or a kind-9101 proof naming cld2).
# Reports attacker cost (collateral bonded on C) and exposure (the credited msats).
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; ARM=${1:-honest}; WAIT=${WAIT:-120}
C=$(awk -F'\t' '$1=="C"{print $2}' "$S/ledgers.tsv"); read -r _ _ _ CTX CVOUT < <(grep -P '^C\t' "$S/ledgers.tsv")
D=$(grep -P "^cl\tw1\tC\t" "$S/deposits.tsv" | cut -f5)
info() { cld_ctl cld2 "(:info)" | grep -oE "\(:ID \"$C\"[^)]*:MEMBERS [1-9][^)]*" | grep -oE ':SEQ [0-9]+|:OBLIGATIONS [0-9]+|:RESERVES [0-9]+|:COLLATERAL [0-9]+' | tr '\n' ' '; }
echo "== C before: $(info)"
RES=$(cld_ctl cld2 "(:info)" | grep -oE "\(:ID \"$C\"[^)]*:MEMBERS [1-9][^)]*" | grep -oE ':RESERVES [0-9]+' | cut -d' ' -f2)
AMT=$(( RES * 2 ))     # twice the reserves: unambiguously over the limit
for n in cld3 cld4; do cld_ctl $n "(:adversary :set :cosign-blind $([ "$ARM" = collude ] && echo t || echo nil))" >/dev/null; done
cld_ctl cld2 "(:adversary :set :sign-invalid t)" >/dev/null
t0=$(date +%s); R=$(cld_ctl cld2 "(:credit :ledger \"$C\" :deposit \"$D\" :msat $AMT :txid \"$CTX\" :vout $CVOUT)")
echo "== operator's attempt (arm=$ARM): $R"
cld_ctl cld2 "(:adversary :set :sign-invalid nil)" >/dev/null; for n in cld3 cld4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
echo "== C after: $(info)"
echo "== cosigners' verdicts:"; for n in cld3 cld4; do echo "   $n: $(cld_ctl $n '(:log)' | tr '"' '\n' | grep -E "cosigned 2b01cc1a|refused cosign" | tail -1)"; done
sleep 5; echo "   ref3: $(tail -c 3000000 "$(ref_dir ref3)/node.log" | sed 's/\x1b\[[0-9;]*m//g' | grep "2b01cc1a" | grep -iE "refus|violation|cosign_update.*success=false" | tail -1 | cut -c1-200)"
if [ "$ARM" = collude ]; then
  echo "== waiting up to $WAIT s for the honest minority to dispute"
  for i in $(seq 1 $((WAIT/5))); do
    F=$(cld_ctl cld3 "(:forks :ledger \"$C\")"); P=$(tail -c 3000000 "$(ref_dir ref3)/node.log" | sed 's/\x1b\[[0-9;]*m//g' | grep -c "2b01cc1a.*\(DisputeEnter\|fraud\|dispute fork\)")
    [[ "$F" == *":OPERATOR"* ]] || [ "$P" -gt 0 ] && { echo "   DISPUTED after $(( $(date +%s) - t0 )) s: forks=$F ref3-lines=$P"; break; }; sleep 5
  done; [ "$i" -ge $((WAIT/5)) ] && echo "   NOT DISPUTED within $WAIT s (forks: $(cld_ctl cld3 "(:forks :ledger \"$C\")"))"
fi
echo "== cost/exposure: attacker bonded $(( $(cld_ctl cld2 "(:info)" | grep -oE "\(:ID \"$C\"[^)]*:MEMBERS [1-9][^)]*" | grep -oE ':COLLATERAL [0-9]+' | cut -d' ' -f2) / 1000 )) sats collateral; attempted exposure $(( AMT / 1000 )) sats"
