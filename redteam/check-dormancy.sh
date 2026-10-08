#!/usr/bin/env bash
# redteam/check-dormancy.sh — DEP-20 §8.1-8.3 dormancy, live, mixed quorums.
#
# A cl operator's ledger with cl and reference members agreeing dormancy_blocks 5 and
# dormancy_notice_blocks 3. Two pk() deposits of 3000000 msat each and a small one (335000 msat,
# below the spin-out floor); after a DormancyNotice the second shows signed activity (an exit
# request and its cancel). The notice names a receiver (§8.3): a second cl operator's ledger, same
# mixed members, that accepted the offered manifest (the small deposit). At the notice's rotation:
# PASS = the rotation pays the dormant deposit's full balance (3000 sats) to the key-path P2TR of
#        its key and the small deposit's 335 sats to the receiver's accept address, both are zero
#        on the source, the active deposit keeps its balance; the receiver credits the small
#        deposit (its members cosigning) and splices the migration output in at its next
#        rotation; reference members signed and cosigned every step.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env" 2>/dev/null; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 C3 OP2
R1=${R1:-ref6}; R2=${R2:-ref7}
for n in $OP $C1 $C2 $C3 $OP2; do cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null & done; wait
export DORM=5 DORM_NOTICE=3
NAME=${REDTEAM_DORMANCY:-DORM$RANDOM}
X=$(form_ledger "$NAME" $OP "" $C1 $C2 $C3 $R1 $R2) || exit 1
await_active "$X" $OP $C1 $C2 $C3
DS=($(fresh_deposits "$NAME" $OP "$X" 2 3000000)) || exit 1
D1=${DS[0]}; D2=${DS[1]}
w() { "$CLD_SRC/devnet/cld-wallet.sh" "$@"; }
D3=$(cat "$S/redteam-$NAME.small" 2>/dev/null)
if [ -z "$D3" ]; then
  read -r ftx fvout <"$S/redteam-$NAME.outpoint"
  D3=$(sx "$(w w3 "$X" open)" ":DEPOSIT"); [ -n "$D3" ] || fail "w3 open"
  expect "$(cld_ctl $OP "(:credit :ledger \"$X\" :deposit \"$D3\" :msat 335000 :txid \"$ftx\" :vout $fvout)")" "credit small"
  echo "$D3" >"$S/redteam-$NAME.small"
fi
Y=$(form_ledger "${NAME}R" $OP2 "" $C1 $C2 $C3 $R1 $R2) || exit 1
await_active "$Y" $OP2 $C1 $C2 $C3
echo "== ledger $X, dormant $D1, active $D2, small $D3; receiver $Y ($OP2)"
mine 7 >/dev/null; sleep 5
H=$(bcli getblockcount)
r=$(cld_ctl $OP "(:dormancy-offer :ledger \"$X\")"); expect "$r" "dormancy-offer"
M=$(sx "$r" ":MANIFEST"); [ "$(sx "$r" ":COUNT")" = 1 ] || fail "the offer should list only the small deposit: $r"
r=$(cld_ctl $OP2 "(:dormancy-accept :ledger \"$Y\" :manifest \"$M\" :total 335000)"); expect "$r" "dormancy-accept (receiver's members cosign)"
ACC=$(sx "$r" ":ACCEPT"); MA=$(sx "$r" ":ADDRESS")
expect "$(cld_ctl $OP "(:dormancy-notice :ledger \"$X\" :rotation-height $((H + 4)) :receiver \"$(pubkey_of $OP2)\" :manifest \"$M\" :accept \"$ACC\")")" "dormancy-notice with migration"
A=$(wcli getnewaddress "" bech32m)
r=$(w w2 "$X" exit "$D2" 1000000 "$A" "$H"); id=$(sx "$r" ":EXIT-REQUEST"); [ -n "$id" ] || fail "w2 exit: $r"
expect "$(w w2 "$X" exit-cancel "$D2" "$id" "$H")" "w2 exit-cancel"
mine 5 >/dev/null; sleep 5
consent "$X" $OP $C1 $C2 $C3 $R1 $R2
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"; RT=$(sx "$r" ":TXID")
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; sleep 15; done
expect "$r" "begin-quorum"; mine 3 >/dev/null; sleep 15
tx=$(bcli getrawtransaction "$RT" true) || fail "rotation $RT is not on chain"
PK=$(sx "$(w w1 "$X" pubkey)" ":PUBKEY"); XO=${PK:2}
TR=$(bcli deriveaddresses "$(bcli getdescriptorinfo "tr($XO)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["descriptor"])')" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0])')
paid=$(python3 -c "import json,sys; t=json.loads(sys.argv[1]); print(sum(round(o['value']*1e8) for o in t['vout'] if o['scriptPubKey'].get('address')==sys.argv[2]))" "$tx" "$TR")
[ "$paid" = 3000 ] || fail "the rotation pays $paid sats to $TR, expected the dormant deposit's 3000"
echo "   rotation $RT pays 3000 sats to the dormant deposit's key ($TR)"
MV=$(outpoint_vout "$RT" "$MA") || fail "the rotation pays nothing to the receiver's accept address $MA"
[ "$(out_sats "$RT" "$MV")" = 335 ] || fail "the migration output carries $(out_sats "$RT" "$MV") sats, expected 335"
echo "   rotation pays the migration output $RT:$MV (335 sats) to the receiver's accept address"
bal_on() { local i b; for i in 1 2 3 4 5; do b=$(w "$1" "$2" balance "$3"); case "$b" in *":BALANCE "*) echo "$b"; return;; esac; sleep 10; done; echo "$b"; }
bal() { bal_on "$1" "$X" "$2"; }
[ "$(sx "$(bal w1 "$D1")" ":BALANCE")" = 0 ] || fail "the dormant deposit was not debited: $(bal w1 "$D1")"
[ "$(sx "$(bal w2 "$D2")" ":BALANCE")" = 3000000 ] || fail "the active deposit changed: $(bal w2 "$D2")"
[ "$(sx "$(bal w3 "$D3")" ":BALANCE")" = 0 ] || fail "the migrated deposit was not debited on the source: $(bal w3 "$D3")"
echo "   dormant and migrated deposits debited to zero; active deposit untouched"
signed=0; for m in $R1 $R2; do sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$m/node.log" 2>/dev/null | grep -q "action=rotation_sign, ledger=${X:0:16}.*success=true" && signed=$((signed+1)); done
[ $signed -ge 1 ] || fail "no reference member signed the rotation carrying the spin-out"
cos=0; for m in $R1 $R2; do sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$m/node.log" 2>/dev/null | grep "action=cosign_update, ledger=${X:0:16}" | tail -1 | grep -q "success=true" && cos=$((cos+1)); done
[ $cos -ge 1 ] || fail "no reference member cosigned the QuorumBegin recording the spin-out"
echo "   reference members: $signed signed the rotation, $cos cosigned its QuorumBegin"
# §8.3 receiver: credit the migrated deposit, then splice the migration output at the next rotation.
expect "$(cld_ctl $OP2 "(:dormancy-credit :ledger \"$Y\" :manifest \"$M\" :txid \"$RT\" :vout $MV)")" "dormancy-credit"
[ "$(sx "$(bal_on w3 "$Y" "$D3")" ":BALANCE")" = 335000 ] || fail "the receiver did not credit the migrated deposit: $(bal_on w3 "$Y" "$D3")"
echo "   receiver credited the migrated deposit (335000 msat) under its own ledger"
mine 2 >/dev/null; sleep 5
consent "$Y" $OP2 $C1 $C2 $C3 $R1 $R2
r=$(cld_ctl $OP2 "(:rotate-vault :ledger \"$Y\" :expiry-blocks 4320 :splice \"$RT:$MV\")"); expect "$r" "receiver rotate-vault splicing the migration"; RT2=$(sx "$r" ":TXID")
for i in 1 2 3; do r=$(cld_ctl $OP2 "(:begin-quorum :ledger \"$Y\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; sleep 15; done
expect "$r" "receiver begin-quorum"; mine 3 >/dev/null; sleep 10
bcli getrawtransaction "$RT2" true | grep -q "\"txid\": \"$RT\"" || fail "the receiver's rotation $RT2 does not spend the migration output"
echo "   receiver's rotation $RT2 splices the migration output in"
cos=0; for m in $R1 $R2; do sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$m/node.log" 2>/dev/null | grep "action=cosign_update, ledger=${Y:0:16}" | tail -1 | grep -q "success=true" && cos=$((cos+1)); done
[ $cos -ge 1 ] || fail "no reference member cosigned the receiver's splicing QuorumBegin"
echo "PASS: dormant deposit spun out, small deposit migrated, credited and spliced in, across implementations."
