#!/usr/bin/env bash
# redteam/attack-vault-rotate-grace.sh — a rotation that SPENDS the old vault into the new one.
#
# The vault watch judges a spend only once it is 3 blocks deep (*vault-spend-grace-blocks*), so a
# rotation's QuorumBegin can arrive after its spend confirms.  On a fresh cl-only ledger (cld1
# operates; cld2..cld6 cosign; majority 4 of 6), the quorum re-consents, the old vault is spent at
# Tier 0 straight into the new quorum's address (cld2 cld3 cld4 sign, :theft-sign), and then:
#   inside : the QuorumBegin naming that output is appended within the grace.
#            PASS = no honest node (cld5, cld6) reports VAULT SPEND for the ledger.
#   late   : the watch runs 5 blocks after the spend, before the QuorumBegin.
#            PASS (the bound, documented) = it is reported: a rotation recorded later than the
#            grace is indistinguishable from a theft.  Contagion follows on the signers' ledgers.
# REDTEAM_RG=name forms a fresh ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
ARM=${1:-inside}
trap 'disarm :theft-sign cld2 cld3 cld4' EXIT
X=$(form_ledger "${REDTEAM_RG:-RG}" cld1 "" cld2 cld3 cld4 cld5 cld6) || exit 1
echo "== ledger $X ($ARM)"
consent "$X" cld1 cld2 cld3 cld4 cld5 cld6
prep=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$X\" :expiry-blocks 4320)"); expect "$prep"; NEW=$(sx "$prep" ":ADDRESS")
arm :theft-sign cld2 cld3 cld4
out=$(vault_spend cld1 "$X" "$NEW"); expect "$out"; SPEND=$(sx "$out" ":TXID")
echo "== old vault spent into the new quorum's address: $SPEND"
disarm :theft-sign cld2 cld3 cld4
# cld1 is the thief in the other vault scenarios.  Once accused, contagion disputes every ledger it
# operates, this one included, and it stands down: the rotation cannot be recorded at all.
begin() {
  local r; r=$(cld_ctl cld1 "(:begin-quorum :ledger \"$X\" :txid \"$SPEND\" :vout 0 :sats $(out_sats "$SPEND" 0) :collateral-sats 0)")
  case "$r" in *"ledger disputed"*) echo "SKIP: the operator (cld1) is already accused of an earlier theft, so its members disputed this ledger and it cannot rotate: $r"; exit 0;; esac
  expect "$r"
}
case $ARM in
  inside)
    mine 1 >/dev/null; begin; echo "== QuorumBegin appended one block after the spend"
    mine 5 >/dev/null; sleep 5
    hit=""; for n in cld5 cld6; do accused $n "$X" && hit="$hit $n"; done
    [ -z "$hit" ] && echo "PASS: a rotation recorded within the grace was not taken for a theft." || fail "accused by$hit";;
  late)
    mine 5 >/dev/null; sleep 5
    if accused cld6 "$X"; then r=0; else r=1; fi
    cld_ctl cld1 "(:begin-quorum :ledger \"$X\" :txid \"$SPEND\" :vout 0 :sats $(out_sats "$SPEND" 0) :collateral-sats 0)" >/dev/null   # too late either way
    [ $r -eq 0 ] && echo "PASS (bound): a rotation recorded after the ${GRACE:-3}-block grace was reported as a theft." || fail "late rotation not reported";;
  *) fail "arm: inside | late";;
esac
