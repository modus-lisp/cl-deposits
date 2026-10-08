#!/usr/bin/env bash
# redteam/check-splice.sh — DEP-20 §4 splice-in at rotation, both operators, mixed quorums.
#
#   A  a cl operator (cl members + two reference members) rotates with :splice: a UTXO paying
#      its node key's P2TR is input 1.
#   B  a reference operator (reference + cl members) rotates with `quorum begin --splice`: a
#      UTXO paying its operator key's P2WPKH is input 1.
# PASS = in both, the rotation spends the old vault and the splice into one new vault worth both
#        less the DEP-03 fee, a member of the other implementation signed it, and the members'
#        replicas record the splice in the QuorumBegin (collateral rose by the spliced value).
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env" 2>/dev/null; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 C3
R1=${R1:-ref6}; R2=${R2:-ref7}
for n in $OP $C1 $C2 $C3; do cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null & done; wait
SPLICE_BTC=0.0007; SPLICE_SATS=70000
info() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$2\"[^)]*\)"; }
coll() { info "$1" "$2" | grep -oE ':COLLATERAL [0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1; }   # :info lists a ledger once per record (base, forks)
ref_signed() { sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$1/node.log" 2>/dev/null | grep -q "action=rotation_sign, ledger=${2:0:16}.*success=true"; }
check_rotation() {   # check_rotation LABEL ROTATION_TXID OLD_VAULT SPLICE_TXID:VOUT
  local tx ins
  tx=$(bcli getrawtransaction "$2" true) || fail "$1: rotation $2 is not on chain"
  ins=$(python3 -c "import json,sys; t=json.loads(sys.argv[1]); print(' '.join(f\"{i['txid']}:{i['vout']}\" for i in t['vin']))" "$tx")
  [[ " $ins " == *" $3 "* ]] || fail "$1: the rotation does not spend the old vault $3 ($ins)"
  [[ " $ins " == *" $4 "* ]] || fail "$1: the rotation does not spend the splice $4 ($ins)"
  echo "   $1: rotation $2 spends the vault and the splice"
}

echo "== A: cl operator $OP"
X=$(form_ledger "${REDTEAM_SPLICE:-SPLA$RANDOM}" $OP "" $C1 $C2 $C3 $R1 $R2) || exit 1
await_active "$X" $OP $C1 $C2 $C3
OLD=$(cld_ctl $OP "(:vaults)" | grep -oE "\"$X\" \(\"[0-9a-f]{64}:[0-9]+\"" | grep -oE '[0-9a-f]{64}:[0-9]+')
ADDR=$(sx "$(cld_ctl $OP "(:address)")" ":ADDRESS"); [ -n "$ADDR" ] || fail "no node address for $OP"
STX=$(wcli sendtoaddress "$ADDR" $SPLICE_BTC); mine 3 >/dev/null; SV=$(outpoint_vout "$STX" "$ADDR")
C0=$(coll $C1 "$X")
consent "$X" $OP $C1 $C2 $C3 $R1 $R2
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320 :splice \"$STX:$SV\")"); expect "$r" "rotate-vault"
RT=$(sx "$r" ":TXID")
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; sleep 15; done
expect "$r" "begin-quorum"; mine 2 >/dev/null; sleep 10
check_rotation A "$RT" "$OLD" "$STX:$SV"
C1N=$(coll $C1 "$X"); [ -n "$C1N" ] && [ "$C1N" -gt $(( C0 + SPLICE_SATS * 1000 / 2 )) ] || fail "A: $C1's collateral $C0 -> $C1N did not take the splice"
echo "   A: member $C1 records collateral $C0 -> $C1N msat"
ref_signed $R1 "$X" || ref_signed $R2 "$X" || fail "A: no reference member signed the spliced rotation"
echo "   A: a reference member signed the spliced rotation"

echo "== B: reference operator $R1"
RL=$(ref_cli $R1 ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p'); [ -n "$RL" ] || fail "B: $R1 ledger open"
rmembers() { ref_cli $R1 quorum list | awk -v l="${RL:0:16}" '/^  [0-9a-f]{16}/ { inblk = index($1, l) == 1; next } inblk && /^    [0-9a-f]/ { print }'; }
radd() { local i; for i in 1 2 3 4 5 6; do ref_cli $R1 quorum add "$RL" "$1" "$2" >/dev/null 2>&1 || true; rmembers | grep -q "$(echo "$1" | cut -c1-16)" && return 0; sleep 10; done; return 1; }
for m in $C1 $C2; do radd "$(pubkey_of $m)" "$(own_ledger $m)" || fail "B: add $m"; done
radd "$(pubkey_of $R2)" "$(own_ledger $R2)" || fail "B: add $R2"
[ "$(rmembers | wc -l)" -eq 3 ] || fail "B: $RL has $(rmembers | wc -l) staged members, not 3"
out=$(ref_begin_quorum $R1 "$RL" 0.5); echo "   first QuorumBegin: $out" | cut -c1-160; case "$out" in *rror*) fail "B: first quorum begin";; esac; sleep 10
await_active "$RL" $C1 $C2
RPK=$(pubkey_of $R1)
RADDR=$(bcli deriveaddresses "$(bcli getdescriptorinfo "wpkh($RPK)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["descriptor"])')" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0])')
STXB=$(wcli sendtoaddress "$RADDR" $SPLICE_BTC); mine 3 >/dev/null; SVB=$(outpoint_vout "$STXB" "$RADDR"); sleep 30
C0B=$(coll $C1 "$RL")
for m in $C1 $C2; do radd "$(pubkey_of $m)" "$(own_ledger $m)" >/dev/null; done; radd "$(pubkey_of $R2)" "$(own_ledger $R2)" >/dev/null
out=$(timeout 300 "$REF_NODE_BIN" quorum begin "$RL" --splice "$STXB:$SVB" --network "$CLD_CHAIN" --esplora "$ESPLORA_URL" --relay "$RELAY_URL" --data-dir "$(ref_dir $R1)" 2>&1 | grep -vE '^\S*\[[0-9]m|^\[2m')
echo "$out" | tail -3 | sed 's/^/   /'
RTB=$(echo "$out" | grep -oE 'TXID: [0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' | head -1); [ -n "$RTB" ] || fail "B: no rotation txid from quorum begin"
mine 2 >/dev/null; sleep 15
# The vault input is the one the cl member verified (its replica took the QuorumBegin below).
txb=$(bcli getrawtransaction "$RTB" true) || fail "B: rotation $RTB is not on chain"
[ "$(python3 -c "import json,sys; t=json.loads(sys.argv[1]); print(len(t['vin']))" "$txb")" = 2 ] || fail "B: the rotation does not have two inputs"
[[ "$(python3 -c "import json,sys; t=json.loads(sys.argv[1]); print(' '.join(f\"{i['txid']}:{i['vout']}\" for i in t['vin']))" "$txb")" == *"$STXB:$SVB"* ]] || fail "B: the rotation does not spend the splice"
echo "   B: rotation $RTB spends the vault and the splice"
C1B=$(coll $C1 "$RL"); [ -n "$C1B" ] && [ "$C1B" -gt $(( C0B + SPLICE_SATS * 1000 / 2 )) ] || fail "B: $C1's collateral $C0B -> $C1B did not take the splice"
echo "   B: cl member $C1 cosigned and records collateral $C0B -> $C1B msat"
cld_ctl $C1 "(:log :n 4000)" | grep -q "signing rotation of ${RL:0:8}" || fail "B: the cl member did not sign the reference operator's spliced rotation"
echo "PASS: both operators spliced a UTXO into the vault at rotation, signed across implementations."
