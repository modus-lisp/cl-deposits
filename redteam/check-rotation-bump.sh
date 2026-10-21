#!/usr/bin/env bash
# redteam/check-rotation-bump.sh — a stuck rotation is bumped to a higher rung (DEP-03 §Fee ladder).
#
# A rotation is signed at four feerates (m, 2m, 4m, 8m); the QuorumBegin names every rung.  Rung 0
# is broadcast; holders move to rung i once the QuorumBegin is 6·i blocks old with no rung
# confirmed, a BIP-125 replacement of the one below.  Here rung 0 is made unmineable
# (prioritisetransaction with a large negative delta), blocks are mined, and a holder replaces it.
# PASS = a higher rung confirms in place of rung 0, and the ledger's next rotation spends that
# rung's output (every replica resolved the vault to it).
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 C3
R1=${R1:-ref6}; R2=${R2:-ref7}
X=$(form_ledger "${REDTEAM_BUMP:-BUMP$RANDOM}" $OP "" $C1 $C2 $C3 $R1 $R2) || exit 1
echo "== ledger $X"
rotate() {
  consent "$X" $OP $C1 $C2 $C3 $R1 $R2
  local r i; r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"
  for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r" >&2; sleep 15; done
  expect "$r" "begin-quorum"; echo "$r"
}
# The block ticker would mine rung 0 before we can stall it: pause it for the run.
"$CLD_SRC/devnet/regtest-net.sh" ticker stop
trap '"$CLD_SRC/devnet/regtest-net.sh" ticker start' EXIT
r=$(rotate); RUNGS=$(sx "$r" ":RUNGS"); set -- $RUNGS
echo "== rungs: $*"
[ $# -ge 2 ] || fail "the rotation has $# rung(s); a ladder needs two or more"
R0=$1
sleep 5
bcli getmempoolentry "$R0" >/dev/null 2>&1 || fail "rung 0 $R0 is not in the mempool"
bcli prioritisetransaction "$R0" 0 -100000000 >/dev/null
echo "== rung 0 made unmineable; mining 7 blocks"
for i in $(seq 1 7); do mine 1 >/dev/null; sleep 8; done
sleep 30; mine 1 >/dev/null; sleep 10
conf=
for t in "$@"; do
  c=$(bcli getrawtransaction "$t" true 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('confirmations',0))" 2>/dev/null)
  [ "${c:-0}" -ge 1 ] && { conf=$t; break; }
done
[ -n "$conf" ] || fail "no rung confirmed after the bump window"
[ "$conf" != "$R0" ] || fail "rung 0 confirmed despite its prioritisation (the test proves nothing)"
echo "== confirmed: $conf (a higher rung)"
mine 5 >/dev/null; sleep 10
r2=$(rotate); t2=$(sx "$r2" ":TXID"); [ -n "$t2" ] && [ "$t2" != NIL ] || fail "the next rotation was not signed: $r2"
mine 3 >/dev/null; sleep 5
prev=$(bcli getrawtransaction "$t2" true | python3 -c "import json,sys; print(json.load(sys.stdin)['vin'][0]['txid'])")
[ "$prev" = "$conf" ] || fail "the next rotation spends $prev, not the confirmed rung $conf"
echo "PASS: rung 0 stalled, a holder replaced it, rung $conf confirmed, and the next rotation spent it."
