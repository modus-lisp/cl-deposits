#!/usr/bin/env bash
# redteam/attack-relabel.sh — an update's ledger_id is signed by no one (DEP-02 §Signing),
# and an operator signs all its ledgers with one key.  A third party republishes the
# operator's honest updates from its small ledger under the id of the ledger it
# operates (A, cld1), at sequences A already has.  PASS = no member of A takes them
# for an equivocation or a non-conforming update: no fraud proof on A, no fork.
#   redteam/attack-relabel.sh [TARGET-LETTER] [OPERATOR]     default: A cld1
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; T=${1:-A}; OP=${2:-cld1}; WAIT=${WAIT:-60}
TID=$(awk -F'\t' -v t="$T" '$1==t{print $2}' "$S/ledgers.tsv"); TS=${TID:0:8}
# The operator's other ledgers: owned, signed by the same key, not the target.
SRC=$(cld_ctl $OP "(:info)" | grep -oE '\(:ID "[0-9a-f]{64}" :OWNED T :SEQ [0-9]+' | grep -v "$TID" | sort -k6 -n | tail -1 | grep -oE '[0-9a-f]{64}')
FILE="$(cld_dir $OP)/ledger_${SRC:0:16}.json"
MEMBERS=$(for n in $(cld_names); do [ $n != $OP ] && cld_ctl $n "(:info)" | grep -q "\"$TID\"" && echo $n; done)
forks() { for n in $MEMBERS; do printf "%s:%s " $n "$(cld_ctl $n "(:forks :ledger \"$TID\")" | grep -oE ':OPERATOR "[0-9a-f]+' | wc -l)"; done; }
seen() { cld_ctl $1 '(:log)' | tr '"' '\n' | grep -cE "$2"; }
echo "== target $T ($TS…, operated by $OP); source: $OP's own ledger ${SRC:0:16}, $(python3 -c "import json;print(len(json.load(open('$FILE'))))" 2>/dev/null) updates"
echo "== members replicating $T: $(echo $MEMBERS)"
echo "== before: forks $(forks)"
declare -A E0 F0; for n in $MEMBERS; do E0[$n]=$(seen $n "EQUIVOCATION on $TS"); F0[$n]=$(seen $n "fraud proof .* on $TS"); done
cd "$CLD_SRC" && CLD_RELAYS="$RELAY_URL" CL_SOURCE_REGISTRY="(:source-registry (:tree \"$CLD_SRC\") :inherit-configuration)" \
  "${CLD_SBCL:-/usr/bin/sbcl}" --noinform --non-interactive --load redteam/relabel.lisp -- "$FILE" "$TID" 2>&1 | grep -E "^\(" | sed 's/^/   /'
echo "== waiting $WAIT s"; sleep $WAIT
fail=0
for n in $MEMBERS; do
  e=$(( $(seen $n "EQUIVOCATION on $TS") - ${E0[$n]} )); f=$(( $(seen $n "fraud proof .* on $TS") - ${F0[$n]} ))
  r=$(cld_ctl $n '(:log)' | tr '"' '\n' | grep -c "ignored an update on $TS")
  echo "   $n: equivocations flagged $e, fraud proofs handled $f, relabelled updates ignored $r"; [ $e -eq 0 ] && [ $f -eq 0 ] || fail=1
done
echo "== after: forks $(forks)"
for n in $(ref_names); do
  c=$(tail -c 20000000 "$(ref_dir $n)/node.log" | sed 's/\x1b\[[0-9;]*m//g' | grep -E "${TID:0:16}" | grep -ciE "equivocat|fraud proof|DisputeEnter" )
  echo "   $n log lines on $T mentioning equivocation/fraud/dispute (last 20 MB): $c"
done
[ $fail -eq 0 ] && echo "PASS: nobody took the relabelled updates for fraud" || echo "FAIL"
