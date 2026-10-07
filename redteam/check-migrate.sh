#!/usr/bin/env bash
# redteam/check-migrate.sh — DEP-20 §10 migration: exits that pay other operators' offers.
#
# One depositor on a cl ledger X migrates two amounts in one rotation: 1000000 msat to a ledger a
# cl operator runs (D1) and 500000 msat to a ledger a reference operator runs (D2). Each
# destination cosigns a DEP-10 offer; the exits expire 6 blocks before the offers' deadlines.
# PASS = X's rotation pays both offer addresses, X debits the depositor 1500000, and after the
#        wallet names each payment (complete_offer: txid, vout) D1 and D2 credit exactly the
#        migrated amounts to the depositor's deposits there.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env" 2>/dev/null; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 C3
R1=${R1:-ref6}; R2=${R2:-ref7}
for n in $OP $C1 $C2 $C3; do cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null & done; wait
TAG=${REDTEAM_MIGRATE:-MIG$RANDOM}
X=$(form_ledger "${TAG}x" $OP "" $C1 $C2 $C3 $R1 $R2) || exit 1
D1=$(form_ledger "${TAG}d" $C1 "" $OP $C2 $C3) || exit 1
await_active "$X" $OP $C1 $C2 $C3; await_active "$D1" $C1 $OP $C2 $C3
DEP=$(fresh_deposits "${TAG}x" $OP "$X" 1 3000000) || exit 1
echo "== source $X ($OP), cl destination $D1 ($C1)"

# D2: a reference operator's ledger with cl and reference members.
D2=$(ref_cli $R1 ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p'); [ -n "$D2" ] || fail "ref ledger open"
rmembers() { ref_cli $R1 quorum list | awk -v l="${D2:0:16}" '/^  [0-9a-f]{16}/ { inblk = index($1, l) == 1; next } inblk && /^    [0-9a-f]/ { print }'; }
radd() { local i; for i in 1 2 3 4 5 6; do ref_cli $R1 quorum add "$D2" "$1" "$2" >/dev/null 2>&1 || true; rmembers | grep -q "$(echo "$1" | cut -c1-16)" && return 0; sleep 10; done; return 1; }
for m in $C2 $C3; do radd "$(pubkey_of $m)" "$(own_ledger $m)" || fail "add $m to $D2"; done
radd "$(pubkey_of $R2)" "$(own_ledger $R2)" || fail "add $R2 to $D2"
out=$(ref_begin_quorum $R1 "$D2" 0.5); case "$out" in *rror*) fail "quorum begin on $D2: $out";; esac; sleep 15
await_active "$D2" $C2 $C3
echo "== reference destination $D2 ($R1)"

H=$(bcli getblockcount)
w() { "$CLD_SRC/devnet/cld-wallet.sh" w1 "$@"; }
m1=$(w "$X" migrate "$DEP" 1000000 "$D1" "$H" 288); O1=$(sx "$m1" ":OFFER-ID"); A1=$(sx "$m1" ":FUNDING-ADDRESS"); [ -n "$O1" ] || fail "migrate to D1: $m1"
m2=$(w "$X" migrate "$DEP" 500000 "$D2" "$H" 288);  O2=$(sx "$m2" ":OFFER-ID"); A2=$(sx "$m2" ":FUNDING-ADDRESS"); [ -n "$O2" ] || fail "migrate to D2: $m2"
echo "   offers: D1 $A1, D2 $A2"
consent "$X" $OP $C1 $C2 $C3 $R1 $R2
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"; RT=$(sx "$r" ":TXID")
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; sleep 15; done
expect "$r" "begin-quorum"; mine 3 >/dev/null; sleep 15
tx=$(bcli getrawtransaction "$RT" true) || fail "rotation $RT is not on chain"
pays() { python3 -c "import json,sys; t=json.loads(sys.argv[1]); print([o['n'] for o in t['vout'] if o['scriptPubKey'].get('address')==sys.argv[2]][0])" "$tx" "$1"; }
V1=$(pays "$A1") || fail "the rotation does not pay D1's offer"; V2=$(pays "$A2") || fail "the rotation does not pay D2's offer"
val() { python3 -c "import json,sys; t=json.loads(sys.argv[1]); print(round(t['vout'][int(sys.argv[2])]['value']*1e8))" "$tx" "$1"; }
S1=$(val "$V1"); S2=$(val "$V2")
echo "   rotation $RT pays D1 $S1 sats at vout $V1 and D2 $S2 sats at vout $V2 (each less its own cost)"
b=$(w "$X" balance "$DEP"); [ "$(sx "$b" ":BALANCE")" = 1500000 ] || fail "source not debited by 1500000: $b"
expect "$(w "$D1" complete-offer "$O1" "$RT" "$V1")" "complete D1"
c2=$(w "$D2" complete-offer "$O2" "$RT" "$V2"); echo "   D2 completion: $c2" | cut -c1-160
sleep 10
bal() { local i b; for i in 1 2 3 4 5; do b=$(w "$1" balance "$DEP"); case "$b" in *":BALANCE "*) echo "$b"; return;; esac; sleep 10; done; echo "$b"; }
b1=$(bal "$D1"); [ "$(sx "$b1" ":BALANCE")" = $((S1 * 1000)) ] || fail "D1 credited $b1, not $((S1 * 1000))"
b2=$(bal "$D2"); [ "$(sx "$b2" ":BALANCE")" = $((S2 * 1000)) ] || fail "D2 credited $b2, not $((S2 * 1000))"
echo "   D1 (cl) credited $((S1 * 1000)), D2 (reference) credited $((S2 * 1000)): each its output's value"
echo "PASS: two migrations in one rotation landed on a cl and a reference destination, each credited on completion."
