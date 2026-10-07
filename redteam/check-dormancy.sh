#!/usr/bin/env bash
# redteam/check-dormancy.sh — DEP-20 §8.1-8.2 dormancy, live, mixed quorum.
#
# A cl operator's ledger with cl and reference members agreeing dormancy_blocks 5 and
# dormancy_notice_blocks 3. Two pk() deposits of 3000000 msat each; after a DormancyNotice the
# second shows signed activity (an exit request and its cancel). At the notice's rotation:
# PASS = the rotation pays the dormant deposit's full balance (3000 sats) to the key-path P2TR of
#        its key, its balance is zero on the operator and members, the active deposit keeps its
#        balance, and a reference member signed the rotation and cosigned its QuorumBegin.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env" 2>/dev/null; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 C3
R1=${R1:-ref6}; R2=${R2:-ref7}
for n in $OP $C1 $C2 $C3; do cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null & done; wait
export DORM=5 DORM_NOTICE=3
NAME=${REDTEAM_DORMANCY:-DORM$RANDOM}
X=$(form_ledger "$NAME" $OP "" $C1 $C2 $C3 $R1 $R2) || exit 1
await_active "$X" $OP $C1 $C2 $C3
DS=($(fresh_deposits "$NAME" $OP "$X" 2 3000000)) || exit 1
D1=${DS[0]}; D2=${DS[1]}
echo "== ledger $X, dormant $D1, active $D2"
mine 7 >/dev/null; sleep 5
H=$(bcli getblockcount)
expect "$(cld_ctl $OP "(:dormancy-notice :ledger \"$X\" :rotation-height $((H + 4)))")" "dormancy-notice"
w() { "$CLD_SRC/devnet/cld-wallet.sh" "$@"; }
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
bal() { local i b; for i in 1 2 3 4 5; do b=$(w "$1" "$X" balance "$2"); case "$b" in *":BALANCE "*) echo "$b"; return;; esac; sleep 10; done; echo "$b"; }
[ "$(sx "$(bal w1 "$D1")" ":BALANCE")" = 0 ] || fail "the dormant deposit was not debited: $(bal w1 "$D1")"
[ "$(sx "$(bal w2 "$D2")" ":BALANCE")" = 3000000 ] || fail "the active deposit changed: $(bal w2 "$D2")"
echo "   dormant deposit debited to zero; active deposit untouched"
signed=0; for m in $R1 $R2; do sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$m/node.log" 2>/dev/null | grep -q "action=rotation_sign, ledger=${X:0:16}.*success=true" && signed=$((signed+1)); done
[ $signed -ge 1 ] || fail "no reference member signed the rotation carrying the spin-out"
cos=0; for m in $R1 $R2; do sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$m/node.log" 2>/dev/null | grep "action=cosign_update, ledger=${X:0:16}" | tail -1 | grep -q "success=true" && cos=$((cos+1)); done
[ $cos -ge 1 ] || fail "no reference member cosigned the QuorumBegin recording the spin-out"
echo "   reference members: $signed signed the rotation, $cos cosigned its QuorumBegin"
echo "PASS: the dormant deposit was spun out at the notice's rotation, across implementations."
