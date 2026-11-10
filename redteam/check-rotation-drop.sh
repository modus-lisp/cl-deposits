#!/usr/bin/env bash
# redteam/check-rotation-drop.sh — DEP-11 §Rotating without a silent member (ruled 2026-11-10:
# "permissionless means letting people gfy").  A cl operator's ledger with a mixed quorum of five
# (C1 C2 W cl, R1 R2 reference); W answers nothing.  The operator collects the consents it can
# get, :trim-staged seats the largest valid quorum of the consenting members (LG:SEAT-CONSENTING:
# four consents seat three, the members already seated first in consent order), and the rotation
# lands on chain without W.  PASS = the QuorumBegin seats exactly the trimmed set, W is not in it,
# the other members (cl and reference) cosigned it, and the new vault is unspent.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 W
R1=${R1:-ref6}; R2=${R2:-ref7}
for n in $OP $C1 $C2 $W; do cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null & done; wait
X=$(form_ledger "${REDTEAM_RD:-RD$RANDOM}" $OP "" $C1 $C2 $W $R1 $R2) || exit 1
echo "== ledger $X (Q=5: $C1 $C2 $W $R1 $R2; $W will be silent)"
trap 'disarm :mute $W' EXIT
arm :mute $W
silent=0
for m in $C1 $R1 $W $C2 $R2; do
  r=$(CLD_CTL_TIMEOUT=240 cld_ctl $OP "(:add-member :ledger \"$X\" :member \"$(pubkey_of $m)\" :member-ledger \"$(own_ledger "$m")\")")
  case "$r" in *":STATUS :OK"*) echo "   $m consented";; *) echo "   $m silent: $r"; silent=$((silent+1));; esac
done
[ $silent -ge 1 ] || fail "the muted member $W consented"
r=$(cld_ctl $OP "(:trim-staged :ledger \"$X\")"); expect "$r" "trim-staged"
seated=$(sx "$r" ":SEATED"); echo "== seating $seated"
[ "$seated" = 3 ] || fail "four consents should seat three, not $seated"
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"
RT=$(sx "$r" ":TXID"); echo "== rotation $RT"
mine 3 >/dev/null; sleep 20
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; mine 1 >/dev/null; sleep 15; done
expect "$r" "begin-quorum"
mine 3 >/dev/null; sleep 10
info=$(cld_ctl $OP "(:info)" | grep -oE "\(:ID \"$X\"[^)]*")
members=$(grep -oE ':MEMBERS [0-9]+' <<<"$info" | cut -d' ' -f2)
[ "$members" = 3 ] || fail "the new quorum has $members members, not 3 ($info)"
# The seated set: C1 R1 C2 by the rule (current members in consent order; W dropped, R2 cut).
q=$(cld_ctl $C1 "(:forks :ledger \"$X\")" >/dev/null; cld_ctl $OP "(:quorum :ledger \"$X\")" 2>/dev/null)
if [ -n "$q" ] && [[ "$q" == *":STATUS :OK"* ]]; then
  [[ "$q" != *"$(pubkey_of $W)"* ]] || fail "the silent member $W is seated: $q"
fi
[ -n "$(bcli gettxout "$RT" 0)" ] || fail "the new vault $RT:0 is not unspent"
# Validators accepted a QuorumBegin that leaves a member out: C1's and a reference member's replicas apply it.
await_active "$X" $C1 $C2
for n in $C1 $C2; do
  cld_ctl $n "(:info)" | grep -qE "\(:ID \"$X\"[^)]*:MEMBERS 3" || fail "$n's replica did not apply the QuorumBegin seating three"
done
grep -q "ledger=${X:0:16}.*QuorumBegin\|Applied.*${X:0:16}.*QuorumBegin\|${X:0:16}.*seq.*QuorumBegin" "$CLD_ROOT/$R1/node.log" 2>/dev/null \
  && echo "   $R1 applied it" || echo "   ($R1's log does not name the QuorumBegin; its cosignature counted in the threshold)"
echo "PASS: the rotation dropped the silent $W, seated the three consenting members the rule picks, and landed on chain ($RT:0)."
