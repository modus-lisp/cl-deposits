#!/usr/bin/env bash
# redteam/attack-forge-lock.sh — the operator of a fresh ledger A (cld1; REDTEAM_FL names it) locks a
# depositor's funds with NO depositor witness, straight to its cosigners (cld2, cld3, ref2).  Two arms:
#   honest   : PASS = every cosigner refuses, nothing commits, the balance is untouched.
#   collude  : cld2 and cld3 cosign blind; the lock commits.  PASS = the honest minority
#              (ref2) detects it as non-conforming and disputes within $WAIT s.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"; ARM=${1:-honest}; WAIT=${WAIT:-180}
ROW=${REDTEAM_FL:-FL}
A=$(COLLATERAL_SATS=25000000 form_ledger "$ROW" cld1 "" cld2 cld3 ref2) || exit 1; AS=${A:0:8}
mapfile -t DEPS < <(fresh_deposits "$ROW" cld1 "$A" 2); FROM=${DEPS[0]}; TO=${DEPS[1]}
[ -n "$FROM" ] && [ -n "$TO" ] || fail "no deposits on A"
bal() { "$CLD_SRC/devnet/cld-wallet.sh" w1 "$A" balance "$1" 2>/dev/null | grep -oE ':BALANCE [0-9]+ :LOCKED [0-9]+'; }
BAL0=$(bal $FROM); echo "== target A ($AS…, cld1 operates; cld2 cld3 ref2 cosign); victim deposit $FROM: $BAL0"
[ "$ARM" = collude ] && arm :cosign-blind cld2 cld3
T0=$(date -u +%FT%T); t0=$(date +%s)
R=$(cld_ctl cld1 "(:forge-lock :ledger \"$A\" :from \"$FROM\" :to \"$TO\" :msat 5000000)")
[ "$ARM" = collude ] && for n in cld2 cld3; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
echo "== operator's attempt (arm=$ARM): $(echo "$R" | cut -c1-160)"
SEQ=$(echo "$R" | grep -oE ':SEQ [0-9]+' | cut -d' ' -f2)
for n in cld2 cld3; do echo "   $n: $(cld_ctl $n '(:log)' | tr '"' '\n' | grep -E "refused cosign|cosigned $AS" | tail -1)"; done
ref2_since() { tail -c 30000000 "$(ref_dir ref2)/node.log" | sed 's/\x1b\[[0-9;]*m//g' | awk -v t="$T0" '$1 > t'; }
sleep 5; echo "   ref2: $(ref2_since | grep -E "Cosign (validation FAILED|REFUSED)" | grep -oE "violations=\[[A-Za-z]+|FAILED \([a-z/]+\)" | sort | uniq -c | tr '\n' ' ')"
BAL1=$(bal $FROM); echo "== victim after: $BAL1"
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
if [ "$ARM" = honest ]; then
  if [ -z "$SEQ" ] && [ "$BAL0" = "$BAL1" ]; then echo "PASS: every cosigner refused the forged lock; balance untouched"
  else echo "FAIL: forged lock committed (seq ${SEQ:-?}) or balance moved ($BAL0 -> $BAL1)"; exit 1; fi
elif [ -n "$SEQ" ] && [ -n "$DIS" ]; then echo "PASS: the colluding majority committed seq $SEQ; ref2 disputed within $DIS s"
else echo "FAIL: collude arm: committed=${SEQ:-no}, ref2 detected=${DET:-no}, disputed=${DIS:-no}"; exit 1; fi
