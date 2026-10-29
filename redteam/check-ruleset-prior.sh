#!/usr/bin/env bash
# redteam/check-ruleset-prior.sh — DEP-18: a ledger formed under an earlier ruleset keeps that
# ruleset's rules until a QuorumBegin moves it.
#
# Part 1: ledger P is opened and seated under cltv-offset-v2 (its LedgerOpen and QuorumBegin name
# it).  A colluding majority spends its vault at Tier 0 with no anchor.  Under anchor-ladder-v5
# that is theft on its face, but proof 10 is a rule of anchor-ladder-v5 and P's vault was created
# under cltv-offset-v2: the honest members (a cl node and two reference nodes) must not prove it,
# challenge it or dispute anyone.  Part 2: ledger Q is seated under cltv-offset-v2 too, then its
# operator rotates it after fresh consents, which now declare anchor-ladder-v5: the new
# QuorumBegin names anchor-ladder-v5 and every member's replica moves with it.
# PASS = both.  (attack-vault-spend.sh is the same theft of an anchor-ladder-v5 vault: proven.)
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-150}
source "$(dirname "$0")/_lib.sh"
pick OP T2 T3 T4 T5 HON
R1=${R1:-ref6}; R2=${R2:-ref7}
ruleset_of() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$2\"[^)]*" | grep -oE ':RULESET "[^"]*"|:RULESET NIL' | head -1; }

echo "== part 1: a vault created under cltv-offset-v2 is never proven against"
P=$(OPEN_RULESET=cltv-offset-v2 form_ledger "PRIOR$RANDOM" $OP cltv-offset-v2 $T2 $T3 $T4 $T5 $HON $R1 $R2) || exit 1
rp=$(ruleset_of $HON "$P"); echo "   $P on $HON: $rp"
[ "$rp" = ':RULESET "cltv-offset-v2"' ] || fail "P is not under cltv-offset-v2 on $HON: $rp"
DEST=$(sx "$(cld_ctl $T2 '(:address)')" ":ADDRESS")
for n in $T2 $T3 $T4 $T5; do expect "$(cld_ctl $n "(:adversary :set :theft-sign t)")"; done
out=$(printf '%s\n' "(:vault-spend :ledger \"$P\" :address \"$DEST\")" | timeout 180 bash -c "exec 3<>/dev/tcp/127.0.0.1/$(cld_port $OP); cat >&3; head -n1 <&3")
for n in $T2 $T3 $T4 $T5; do cld_ctl $n "(:adversary :set :theft-sign nil)" >/dev/null; done
case "$out" in *":STATUS :OK"*) ;; *) fail "the unanchored spend failed: $out";; esac
TXID=$(sx "$out" ":TXID"); taint $OP $T2 $T3 $T4 $T5
echo "   unanchored spend $TXID broadcast; watching $HON $R1 $R2 for ${WAIT}s"
mine 5
for i in $(seq 1 $WAIT); do sleep 1; done
hits=$(cld_ctl $HON '(:log)' 2>/dev/null | grep -cE "VAULT SPEND|SPEND CHALLENGED" || true)
rh=0; for r in $R1 $R2; do
  c=$(tail -c 20000000 "$(ref_dir $r)/node.log" 2>/dev/null | grep -a "$TXID\|${P:0:16}" | grep -acE "UnauthorizedVaultSpend|VAULT SPEND|challeng" || true); rh=$((rh + c)); done
forks=0; for l in "$L1" "$L2" "$L3" "$L4" "$L5"; do
  [ -n "$l" ] || continue; d=$(cld_ctl $HON "(:forks :ledger \"$l\")" 2>/dev/null | grep -c ":SEQ" || true); forks=$((forks + d)); done
echo "   $HON proof or challenge lines: $hits; reference lines: $rh; signer ledgers disputed: $forks"
[ "$hits" -eq 0 ] && [ "$rh" -eq 0 ] || fail "a spend of a cltv-offset-v2 vault was proven or challenged"

echo "== part 2: a rotation moves a cltv-offset-v2 ledger to anchor-ladder-v5"
pick C1 C2 C3 C4
Q=$(OPEN_RULESET=cltv-offset-v2 form_ledger "PRIORQ$RANDOM" $C1 cltv-offset-v2 $C2 $C3 $C4 $R1 $R2) || exit 1
rq=$(ruleset_of $C2 "$Q"); echo "   $Q before: $rq"
[ "$rq" = ':RULESET "cltv-offset-v2"' ] || fail "Q is not under cltv-offset-v2: $rq"
consent "$Q" $C1 $C2 $C3 $C4 $R1 $R2
r=$(printf '%s\n' "(:rotate-vault :ledger \"$Q\" :expiry-blocks 4320)" | timeout 300 bash -c "exec 3<>/dev/tcp/127.0.0.1/$(cld_port $C1); cat >&3; head -n1 <&3")
expect "$r" "rotate-vault"
mine 3 >/dev/null; sleep 20
for i in 1 2 3; do r=$(printf '%s\n' "(:begin-quorum :ledger \"$Q\")" | timeout 300 bash -c "exec 3<>/dev/tcp/127.0.0.1/$(cld_port $C1); cat >&3; head -n1 <&3")
  case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; mine 1 >/dev/null; sleep 15; done
expect "$r" "begin-quorum"
mine 3 >/dev/null; sleep 20
for n in $C1 $C2 $C3 $C4; do
  ra=$(ruleset_of $n "$Q"); echo "   $Q on $n after: $ra"
  [ "$ra" = ':RULESET "anchor-ladder-v5"' ] || fail "$n did not move $Q to anchor-ladder-v5: $ra"
done
echo "PASS: the cltv-offset-v2 vault's unanchored spend was never proven ($TXID), and the rotation moved $Q to anchor-ladder-v5"
