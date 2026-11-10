#!/usr/bin/env bash
# redteam/check-fraud-rotation.sh — DEP-05 §Deposed operator under strict-lottery-v8 (ruled
# 2026-11-10: "no", a rotation does not end a fraud dispute).  A cl operator's ledger with a
# quorum of five (C1 C2 D cl, R1 R2 reference).  D enters a dispute on a fraud ground
# (equivocation); the other four keep cosigning, and the operator rotates (D consents, so it is
# seated again).  Before the rule, the rotation's QuorumBegin scoped D's dispute away and D
# cosigned the operator's chain again.  PASS = after the rotation D still refuses to cosign the
# operator's updates ("we disputed it"), and its dispute fork is still there.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 D
R1=${R1:-ref6}; R2=${R2:-ref7}
for n in $OP $C1 $C2 $D; do cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null & done; wait
ROW=${REDTEAM_FR:-FR$RANDOM}
X=$(form_ledger "$ROW" $OP "" $C1 $C2 $D $R1 $R2) || exit 1
rs=$(cld_ctl $OP "(:info)" | grep -oE "\(:ID \"$X\"[^)]*" | grep -oE ':RULESET "[^"]*"' | cut -d'"' -f2)
echo "== ledger $X (ruleset ${rs:-?}); $D disputes it on a fraud ground"
[ "$rs" = strict-lottery-v8 ] || echo "   (not on strict-lottery-v8: the old reading applies, and this check expects the new one)"
expect "$(cld_ctl $D "(:dispute-enter :ledger \"$X\" :reason \"equivocation\")")" "dispute-enter"
sleep 10
echo "== rotating (all five consent; D is re-seated)"
consent "$X" $OP $C1 $C2 $D $R1 $R2
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"
RT=$(sx "$r" ":TXID")
mine 3 >/dev/null; sleep 20
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; mine 1 >/dev/null; sleep 15; done
expect "$r" "begin-quorum"
QB=$(sx "$r" ":SEQ"); echo "== rotated: QuorumBegin seq ${QB:-?}"
mine 3 >/dev/null; sleep 15
await_active "$X" $C1 $D
# An update after the rotation that needs D: C1 and C2 are muted, so of five members only D, R1
# and R2 can answer, and the threshold is three.  Under the old reading the QuorumBegin scoped D's
# dispute away and D signed; now D refuses, and the credit falls short.
out=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$X" open); dep=$(sx "$out" ":DEPOSIT"); [ -n "$dep" ] || fail "deposit open: $out"
T=$(date -u +%FT%TZ)
trap 'disarm :mute $C1 $C2' EXIT
arm :mute $C1 $C2
r=$(cld_ctl $OP "(:credit :ledger \"$X\" :deposit \"$dep\" :msat 1000000 :txid \"$RT\" :vout 0)"); echo "   credit needing D: ${r:0:160}"
sleep 10
disarm :mute $C1 $C2
post=$(awk -v t="$T" '$1 >= t' "$CLD_ROOT/$D/node.log")
if grep -qE "^[^ ]+ cosigned ${X:0:8} seq" <<<"$post"; then
  fail "$D cosigned the operator's chain after the rotation, though it disputed it on a fraud ground: $(grep -E "cosigned ${X:0:8}" <<<"$post" | head -2)"
fi
grep -qE "refused cosign seq [0-9]+: .*we disputed it" <<<"$post" || fail "$D logged no refusal after the rotation (asked? $(grep -c . <<<"$post") log lines since $T)"
case "$r" in *":STATUS :OK"*) fail "the credit reached threshold without D, though C1 and C2 were muted: ${r:0:160}";; esac
echo "   $D refused: $(grep -E "refused cosign seq [0-9]+: .*we disputed it" <<<"$post" | head -1)"
echo "PASS: $D's fraud dispute outlived the rotation: it still refuses to extend the operator's chain."
