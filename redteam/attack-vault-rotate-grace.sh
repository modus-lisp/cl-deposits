#!/usr/bin/env bash
# redteam/attack-vault-rotate-grace.sh — a rotation that SPENDS the old vault into the new one (DEP-03).
#
# The operator rotates with :rotate-vault (rotation_sign from the members, broadcast), and the
# QuorumBegin naming the new vault follows once it confirms.  The vault watch judges a spend only
# 3 blocks deep (*vault-spend-grace-blocks*), and a member that signed the rotation remembers it.
#   inside : the QuorumBegin lands one block after the rotation confirms.
#            PASS = no honest node (H1, H2) reports VAULT SPEND for the ledger.
#   late   : the QuorumBegin is held back 5 blocks.  A member that signed the rotation still does
#            not report it (PASS); one that did not sign reports it, the documented bound (PASS);
#            a signer that reports it is a FAIL.
# REDTEAM_RG=name forms a fresh ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 C3 H1 H2
ARM=${1:-inside}
X=$(form_ledger "${REDTEAM_RG:-RG}" $OP "" $C1 $C2 $C3 $H1 $H2) || exit 1
echo "== ledger $X ($ARM)"
consent "$X" $OP $C1 $C2 $C3 $H1 $H2
out=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$out"; SPEND=$(sx "$out" ":TXID")
echo "== old vault spent into the new quorum's reserves: $SPEND"
begin() {
  local r; r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")")
  case "$r" in *"ledger disputed"*) echo "SKIP: the operator ($OP) is already accused, so its members disputed this ledger and it cannot rotate: $r"; exit 0;; esac
  expect "$r"
}
signed() { grep -q "signing rotation of ${X:0:8}" "$CLD_ROOT/$1/node.log" 2>/dev/null; }
case $ARM in
  inside)
    mine 1 >/dev/null; begin; echo "== QuorumBegin appended one block after the spend"
    mine 5 >/dev/null; sleep 5
    hit=""; for n in $H1 $H2; do accused $n "$X" 40 && hit="$hit $n"; done
    [ -z "$hit" ] && echo "PASS: a rotation recorded within the grace was not taken for a theft." || fail "accused by$hit";;
  late)
    mine 5 >/dev/null; sleep 5
    if accused $H2 "$X"; then hit=1; else hit=0; fi
    begin
    if signed $H2; then
      [ $hit -eq 0 ] && echo "PASS: $H2 signed the rotation and did not take it for a theft, though its QuorumBegin came late." \
                     || fail "$H2 signed the rotation yet reported it"
    else
      [ $hit -eq 1 ] && echo "PASS (bound): $H2 did not sign, and a rotation recorded after the ${GRACE:-3}-block grace was reported." \
                     || echo "PASS: $H2 did not sign and did not report it."
    fi;;
  *) fail "arm: inside | late";;
esac
