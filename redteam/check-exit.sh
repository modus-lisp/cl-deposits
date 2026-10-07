#!/usr/bin/env bash
# redteam/check-exit.sh — DEP-20 §3 exits settle at the next rotation, on chain.
#
# A fresh ledger operated by a cl node with a mixed quorum (three cl members, two reference
# members).  A depositor asks for three exits: one above the dust floor, one below it (200 sats),
# and one it then cancels.  The operator rotates: every member rebuilds the rotation with the due
# exits and cosigns its QuorumBegin.
# PASS = the rotation pays the due exit to its address after the new vault, the dust request is
#        carried (still locked and pending), the cancelled one is released, and the deposit is
#        debited by exactly the settled amount.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 C3
R1=${R1:-ref6}; R2=${R2:-ref7}
for n in $OP $C1 $C2 $C3; do cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null & done; wait
NAME=${REDTEAM_EXIT:-EXIT$RANDOM}
X=$(form_ledger "$NAME" $OP "" $C1 $C2 $C3 $R1 $R2) || exit 1
await_active "$X" $OP $C1 $C2 $C3
D=$(fresh_deposits "$NAME" $OP "$X" 1 3000000) || exit 1
echo "== ledger $X, deposit $D (3000000 msat)"
H=$(bcli getblockcount)
A1=$(wcli getnewaddress "" bech32m); A2=$(wcli getnewaddress "" bech32)
w() { "$CLD_SRC/devnet/cld-wallet.sh" w1 "$X" "$@"; }
r1=$(w exit "$D" 1000000 "$A1" "$H"); id1=$(sx "$r1" ":EXIT-REQUEST"); [ -n "$id1" ] || fail "exit request: $r1"
r2=$(w exit "$D" 200000 "$A2" "$H");  id2=$(sx "$r2" ":EXIT-REQUEST"); [ -n "$id2" ] || fail "dust exit request: $r2"
r3=$(w exit "$D" 500000 "$A2" "$H");  id3=$(sx "$r3" ":EXIT-REQUEST"); [ -n "$id3" ] || fail "third exit request: $r3"
expect "$(w exit-cancel "$D" "$id3" "$H")" "exit-cancel"
b=$(w balance "$D"); echo "   after three requests and one cancel: $b"
[ "$(sx "$b" ":LOCKED")" = 1200000 ] || fail "expected 1200000 locked (1000000 + 200000 dust), got: $b"
consent "$X" $OP $C1 $C2 $C3 $R1 $R2
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"
RT=$(sx "$r" ":TXID"); echo "== rotation $RT"
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; sleep 15; done
expect "$r" "begin-quorum"
mine 2 >/dev/null; sleep 10
tx=$(bcli getrawtransaction "$RT" true) || fail "rotation $RT is not on chain"
read -r n0 v1 a1 <<<"$(python3 -c "import json,sys; t=json.loads(sys.argv[1]); o=t['vout']; print(len(o), round(o[1]['value']*1e8) if len(o)>1 else 0, o[1]['scriptPubKey'].get('address','') if len(o)>1 else '')" "$tx")"
[ "$n0" = 2 ] || fail "the rotation has $n0 outputs; expected the new vault and one exit"
[ "$a1" = "$A1" ] || fail "output 1 pays $a1, not the requested $A1"
# DEP-20 §3: the exit pays its own output's cost, feerate (2) x (9 + 34-byte P2TR script).
[ "$v1" = $((1000 - 2 * 43)) ] || fail "output 1 pays $v1 sats, expected 1000 less its own cost = $((1000 - 86))"
echo "   output 1 pays $v1 sats (1000 less its own cost) to the requested address"
b=$(w balance "$D"); echo "   after the rotation: $b"
[ "$(sx "$b" ":BALANCE")" = 2000000 ] || fail "the deposit was not debited by exactly the settled exit: $b"
[ "$(sx "$b" ":LOCKED")" = 200000 ] || fail "the dust request is not still locked: $b"
refsigned=0
for m in $R1 $R2; do
  if sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$m/node.log" 2>/dev/null | grep -q "action=rotation_sign, ledger=${X:0:16}.*success=true"; then refsigned=$((refsigned+1))
  else echo "   $m did not sign the rotation: $(sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$m/node.log" | grep "action=rotation_sign, ledger=${X:0:16}" | tail -1 | grep -oE 'error=.*' | cut -c1-120)"; fi
done
[ $refsigned -ge 1 ] || fail "no reference member signed the rotation with its exit: a reference-majority quorum could not rotate"
echo "   reference members that signed the rotation: $refsigned of 2"
echo "PASS: the due exit settled on chain at the rotation (mixed quorum), the dust request was carried, the cancel released its lock."
