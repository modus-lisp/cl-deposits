#!/usr/bin/env bash
# redteam/attack-forge-lock.sh — the operator of A (cld1) locks a depositor's funds with NO
# depositor witness, straight to its cosigners (cld2, cld3, ref2).  Two arms:
#   honest   : PASS = every cosigner refuses, nothing commits, the balance is untouched.
#   collude  : cld2 and cld3 cosign blind; the lock commits.  PASS = the honest minority
#              (ref2) detects it as non-conforming and disputes within $WAIT s.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; ARM=${1:-honest}; WAIT=${WAIT:-180}
A=$(awk -F'\t' '$1=="A"{print $2}' "$S/ledgers.tsv"); AS=${A:0:8}
FROM=$(grep -P "^cl\t\S+\tA\t" "$S/deposits.tsv" | head -1 | cut -f5); TO=$(grep -P "^cl\t\S+\tA\t" "$S/deposits.tsv" | sed -n 2p | cut -f5)
bal() { "$CLD_SRC/devnet/cld-wallet.sh" w1 "$A" balance "$1" 2>/dev/null | grep -oE ':BALANCE [0-9]+ :LOCKED [0-9]+'; }
echo "== target A ($AS…, cld1 operates; cld2 cld3 ref2 cosign); victim deposit $FROM: $(bal $FROM)"
[ "$ARM" = collude ] && for n in cld2 cld3; do cld_ctl $n "(:adversary :set :cosign-blind t)" >/dev/null; done
T0=$(date -u +%FT%T); t0=$(date +%s)
R=$(cld_ctl cld1 "(:forge-lock :ledger \"$A\" :from \"$FROM\" :to \"$TO\" :msat 5000000)")
[ "$ARM" = collude ] && for n in cld2 cld3; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
echo "== operator's attempt (arm=$ARM): $(echo "$R" | cut -c1-160)"
SEQ=$(echo "$R" | grep -oE ':SEQ [0-9]+' | cut -d' ' -f2)
for n in cld2 cld3; do echo "   $n: $(cld_ctl $n '(:log)' | tr '"' '\n' | grep -E "refused cosign|cosigned $AS" | tail -1)"; done
ref2_since() { sed 's/\x1b\[[0-9;]*m//g' "$(ref_dir ref2)/node.log" | awk -v t="$T0" '$1 > t'; }
sleep 5; echo "   ref2: $(ref2_since | grep -E "Cosign (validation FAILED|REFUSED)" | grep -oE "violations=\[[A-Za-z]+|FAILED \([a-z/]+\)" | sort | uniq -c | tr '\n' ' ')"
echo "== victim after: $(bal $FROM)"
if [ -n "$SEQ" ]; then
  echo "== committed at seq $SEQ; waiting up to $WAIT s for ref2 to detect and dispute"
  DET=""; DIS=""
  for i in $(seq 1 $((WAIT/5))); do
    L=$(ref2_since | grep -E "${A:0:16}|$AS")
    [ -z "$DET" ] && echo "$L" | grep -qiE "non-conforming|conformance|Unauthorized|violation" && DET=$(( $(date +%s)-t0 ))
    [ -z "$DIS" ] && echo "$L" | grep -qE "DisputeEnter|dispute fork" && DIS=$(( $(date +%s)-t0 ))
    [ -n "$DET" ] && [ -n "$DIS" ] && break; sleep 5
  done
  echo "   ref2 detected: $([ -n "$DET" ] && echo "within $DET s of the attempt" || echo NO); ref2 disputed: $([ -n "$DIS" ] && echo "within $DIS s" || echo NO) (log timestamps below are exact)"
  ref2_since | grep -E "${A:0:16}|$AS" | grep -iE "non-conforming|conformance|Unauthorized|Dispute" | sed -E 's/^[^ ]+T([0-9:]{8})[^ ]* +/\1 /' | cut -c1-200 | head -4 | sed 's/^/     /'
else
  echo "== nothing committed"
fi
