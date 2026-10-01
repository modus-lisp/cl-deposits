#!/usr/bin/env bash
# redteam/attack1-invalid-credit.sh — docs/REDTEAM.md #1: an operator asks its quorum to
# cosign a credit that takes obligations over reserves.  Two arms on a fresh ledger C
# (cld2 operates; cld3, cld4, ref3 cosign; REDTEAM_IC names it):
#   honest   : no cosigner misbehaves.  PASS = every cosigner refuses, nothing commits.
#   collude  : cld3 and cld4 cosign blind (a colluding majority).  The update commits.
#              PASS = the honest minority (ref3) refuses AND disputes within $WAIT s
#              (a DisputeEnter on C, or a kind-9101 proof naming cld2).
# Reports attacker cost (collateral bonded on C) and exposure (the credited msats).
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"; ARM=${1:-honest}; WAIT=${WAIT:-120}
ROW=${REDTEAM_IC:-IC}
C=$(COLLATERAL_SATS=25000000 form_ledger "$ROW" cld2 "" cld3 cld4 ref3) || exit 1
read -r CTX CVOUT <"$S/redteam-$ROW.outpoint"
D=$(fresh_deposits "$ROW" cld2 "$C" 1 | head -1); [ -n "$D" ] || fail "no deposit on C"
info() { cld_ctl cld2 "(:info)" | grep -oE "\(:ID \"$C\"[^)]*:MEMBERS [1-9][^)]*" | grep -oE ':SEQ [0-9]+|:OBLIGATIONS [0-9]+|:RESERVES [0-9]+|:COLLATERAL [0-9]+' | tr '\n' ' '; }
echo "== C before: $(info)"; SEQ0=$(info | grep -oE ':SEQ [0-9]+' | cut -d' ' -f2)
RES=$(cld_ctl cld2 "(:info)" | grep -oE "\(:ID \"$C\"[^)]*:MEMBERS [1-9][^)]*" | grep -oE ':RESERVES [0-9]+' | cut -d' ' -f2)
AMT=$(( RES * 2 ))     # twice the reserves: unambiguously over the limit
for n in cld3 cld4; do cld_ctl $n "(:adversary :set :cosign-blind $([ "$ARM" = collude ] && echo t || echo nil))" >/dev/null; done
cld_ctl cld2 "(:adversary :set :sign-invalid t)" >/dev/null
t0=$(date +%s); T0=$(date -u +%FT%T); CS=${C:0:8}; CS16=${C:0:16}
R=$(cld_ctl cld2 "(:credit :ledger \"$C\" :deposit \"$D\" :msat $AMT :txid \"$CTX\" :vout $CVOUT)")
echo "== operator's attempt (arm=$ARM): $R"
cld_ctl cld2 "(:adversary :set :sign-invalid nil)" >/dev/null; for n in cld3 cld4; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
echo "== C after: $(info)"; SEQ1=$(info | grep -oE ':SEQ [0-9]+' | cut -d' ' -f2)
ref3_since() { tail -c 30000000 "$(ref_dir ref3)/node.log" | sed 's/\x1b\[[0-9;]*m//g' | awk -v t="$T0" '$1 > t' | grep -E "$CS"; }
SEQ=$(cld_ctl cld3 '(:log)' | tr '"' '\n' | grep -oE "cosigned $CS seq [0-9]+" | tail -1 | grep -oE '[0-9]+$')
echo "== cosigners' verdicts on seq ${SEQ:-?}:"; for n in cld3 cld4; do echo "   $n: $(cld_ctl $n '(:log)' | tr '"' '\n' | grep -E "cosigned $CS|refused cosign" | tail -1)"; done
sleep 5; echo "   ref3: $(ref3_since | grep -E "cosign_update|refus|violation|DROP" | sed -E 's/^[^ ]+ +//' | cut -c1-150 | sort | uniq -c | sort -rn | head -3 | tr '\n' ';')"
PUBLISHED=$(cld_ctl cld2 '(:log)' | tr '"' '\n' | grep -c "ADVERSARY: committing seq ${SEQ:-x} on $CS")
echo "== published by the operator: $([ "$PUBLISHED" -gt 0 ] && echo "yes, seq $SEQ" || echo no)"
if [ "$ARM" = collude ] && [ "$PUBLISHED" -gt 0 ]; then
  echo "== waiting up to $WAIT s for the honest minority (ref3) to detect seq $SEQ and dispute"
  DET=""; DIS=""
  for i in $(seq 1 $((WAIT/5))); do
    L=$(ref3_since)
    [ -z "$DET" ] && echo "$L" | grep -qE "NON-CONFORMING.*seq $SEQ|seq=$SEQ.*(non-conforming|violation)|Non-conforming.*$CS16" && DET=$(( $(date +%s) - t0 ))
    [ -z "$DIS" ] && echo "$L" | grep -qE "DisputeEnter|dispute fork|Published DisputeEnter" && DIS=$(( $(date +%s) - t0 ))
    [ -n "$DET" ] && [ -n "$DIS" ] && break; sleep 5
  done
  echo "   ref3 detected: ${DET:+after $DET s}${DET:-NO}; ref3 disputed: ${DIS:+after $DIS s}${DIS:-NO}"
  echo "   ref3's lines on $CS since the attack:"; ref3_since | grep -iE "non-conforming|dispute|violation|fraud|arm" | sed -E 's/^[^ ]+T([0-9:]{8})[^ ]* +/\1 /' | cut -c1-200 | head -8 | sed 's/^/     /'
  echo "   cl forks of $CS (fraud proofs reach them too): $(cld_ctl cld3 "(:forks :ledger \"$C\")" | cut -c1-200)"
fi
echo "== cost/exposure: attacker bonded $(( $(cld_ctl cld2 "(:info)" | grep -oE "\(:ID \"$C\"[^)]*:MEMBERS [1-9][^)]*" | grep -oE ':COLLATERAL [0-9]+' | cut -d' ' -f2) / 1000 )) sats collateral; attempted exposure $(( AMT / 1000 )) sats"
if [ "$ARM" = honest ]; then
  if [ "$PUBLISHED" -eq 0 ] && [ "$SEQ0" = "$SEQ1" ]; then echo "PASS: every cosigner refused; nothing committed (C at seq $SEQ1)"
  else echo "FAIL: the over-reserve credit committed (seq $SEQ0 -> $SEQ1, published=$PUBLISHED)"; exit 1; fi
elif [ "$PUBLISHED" -gt 0 ] && [ -n "$DIS" ]; then echo "PASS: the colluding majority committed seq $SEQ; ref3 disputed after $DIS s"
else echo "FAIL: collude arm: published=$PUBLISHED, ref3 detected=${DET:-no}, disputed=${DIS:-no}"; exit 1; fi
