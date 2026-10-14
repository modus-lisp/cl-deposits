#!/usr/bin/env bash
# redteam/check-obligations.sh — DEP-06 §Confiscation obligations, live, mixed quorums.
#
# A receiver ledger Y (cl operator, cl and reference members) owes two things it never credits:
#   - a DEP-20 §8.3 migration from a source ledger X (a small dormant pk() deposit), whose output
#     sits at Y's vault script; Y accepts but never sends MigrationCredit;
#   - an ordinary DEP-10 funding offer a wallet paid (50000 sats) that Y never credits.
# Y's terms are the default 72 blocks. A member proves the uncredited payment (UncreditedOnchainPayment, deposit-bound offer evidence)
# and the members dispute Y. Before arming they record both obligations (ObligationRecord).
# PASS = the confiscation on chain spends Y's vault and the migration output (swept through the
#        tier) and pays the migrated deposit's owner and the payment's owner their key-path P2TR
#        outputs net of their own cost, a reference member having signed it.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env" 2>/dev/null; source "$(dirname "$0")/_lib.sh"
WAIT=${WAIT:-900}
pick OP C1 C2 C3 OP2
R1=${R1:-ref6}; R2=${R2:-ref7}
for n in $OP $C1 $C2 $C3 $OP2; do cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null & done; wait
export DORM=5 DORM_NOTICE=3
NAME=${REDTEAM_OBL:-OBL$RANDOM}
w() { "$CLD_SRC/devnet/cld-wallet.sh" "$@"; }
X=$(form_ledger "$NAME" $OP "" $C1 $C2 $C3 $R1 $R2) || exit 1
Y=$(RESP=${RESP:-5} form_ledger "${NAME}Y" $OP2 "" $C1 $C2 $C3 $R1 $R2) || exit 1
await_active "$X" $OP $C1 $C2 $C3; await_active "$Y" $OP2 $C1 $C2 $C3
read -r ftx fvout <"$S/redteam-$NAME.outpoint"
D3=$(sx "$(w w3 "$X" open)" ":DEPOSIT"); [ -n "$D3" ] || fail "w3 open"
expect "$(cld_ctl $OP "(:credit :ledger \"$X\" :deposit \"$D3\" :msat 600000 :txid \"$ftx\" :vout $fvout)")" "credit the small deposit"
echo "== source $X (small dormant $D3), receiver $Y ($OP2)"
mine 7 >/dev/null; sleep 5; H=$(bcli getblockcount)
r=$(cld_ctl $OP "(:dormancy-offer :ledger \"$X\")"); expect "$r" "dormancy-offer"; M=$(sx "$r" ":MANIFEST")
r=$(cld_ctl $OP2 "(:dormancy-accept :ledger \"$Y\" :manifest \"$M\" :total 600000 :source \"$X\")"); expect "$r" "dormancy-accept"
ACC=$(sx "$r" ":ACCEPT"); VAULT=$(sx "$r" ":ADDRESS")
expect "$(cld_ctl $OP "(:dormancy-notice :ledger \"$X\" :rotation-height $((H + 4)) :receiver \"$(pubkey_of $OP2)\" :manifest \"$M\" :accept \"$ACC\")")" "notice"
mine 5 >/dev/null; sleep 5
consent "$X" $OP $C1 $C2 $C3 $R1 $R2
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "source rotation"; RT=$(sx "$r" ":TXID")
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; sleep 15; done
expect "$r" "source begin-quorum"; mine 3 >/dev/null; sleep 10
MV=$(outpoint_vout "$RT" "$VAULT") || fail "the migration does not pay Y's vault $VAULT"
echo "   migration output $RT:$MV pays Y's vault; Y never credits it"
# the ordinary payment Y never credits
D4=$(sx "$(w w4 "$Y" open)" ":DEPOSIT"); [ -n "$D4" ] || fail "w4 open"
r=$(w w4 "$Y" offer 100000); expect "$r" "w4 offer"
OADDR=$(sx "$r" ":FUNDING-ADDRESS"); ODESC=$(sx "$r" ":DESCRIPTOR")
OFFER=$(printf '%s' "$r" | python3 -c 'import sys,json; s=sys.stdin.read(); print(json.JSONDecoder().raw_decode(s.split(":OFFER ",1)[1])[0])')
PT=$(wcli sendtoaddress "$OADDR" 0.0005); mine 8 >/dev/null; sleep 10
PV=$(outpoint_vout "$PT" "$OADDR")
echo "   w4 paid Y's offer $PT:$PV (50000 sats); Y never credits it"
# a payment too small to splice out (400 - 86 < 330 sats): residue the winner must credit
r=$(w w5 "$Y" offer 1000); expect "$r" "w5 offer"
RADDR=$(sx "$r" ":FUNDING-ADDRESS"); RDESC=$(sx "$r" ":DESCRIPTOR")
ROFFER=$(printf '%s' "$r" | python3 -c 'import sys,json; s=sys.stdin.read(); print(json.JSONDecoder().raw_decode(s.split(":OFFER ",1)[1])[0])')
RT5=$(wcli sendtoaddress "$RADDR" 0.000004); mine 8 >/dev/null; sleep 10
RV5=$(outpoint_vout "$RT5" "$RADDR")
echo "   w5 paid Y's offer $RT5:$RV5 (400 sats, residue); Y never credits it"
# Y's terms: no member declares service_response_blocks, so 72 (DEP-05). The proofs need an update
# Y signed that long after the payment (and the migration) confirmed: a fresh deposit opens one.
mine 72 >/dev/null; sleep 15
[ -n "$(sx "$(w w2 "$Y" open)" ":DEPOSIT")" ] || fail "w2 open on Y (Y's late update)"
r=$(cld_ctl $C1 "(:uncredited-offer-proof :ledger \"$Y\" :offer $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$OFFER") :descriptor \"$ODESC\" :txid \"$PT\" :vout $PV)")
expect "$r" "uncredited-offer-proof (verifies, broadcast)"
r=$(cld_ctl $C1 "(:uncredited-offer-proof :ledger \"$Y\" :offer $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$ROFFER") :descriptor \"$RDESC\" :txid \"$RT5\" :vout $RV5)")
expect "$r" "uncredited-offer-proof of the residue payment"
# Proof 11, live: a cl winner withholds the residue (ADVERSARY :withhold-residue); a reference
# winner credits it. OBL_WITHHOLD=0 runs every winner honest.
if [ "${OBL_WITHHOLD:-1}" = 1 ]; then
  for n in $C1 $C2 $C3; do expect "$(cld_ctl $n '(:adversary :set :withhold-residue t)')" "withhold switch on $n"; done
fi
echo "== the members dispute Y; waiting for the confiscation (up to ${WAIT}s)"
P3=$(sx "$(w w3 "$X" pubkey)" ":PUBKEY"); P4=$(sx "$(w w4 "$Y" pubkey)" ":PUBKEY")
tr_of() { bcli deriveaddresses "$(bcli getdescriptorinfo "tr(${1:2})" | python3 -c 'import json,sys; print(json.load(sys.stdin)["descriptor"])')" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0])'; }
A3=$(tr_of "$P3"); A4=$(tr_of "$P4")
# The confiscation is the transaction that spends Y's vault, whoever proposed it: the
# reference members arm at once and can run the whole lottery before a cl member's
# once-a-minute dispute pass arms, so the cl members' logs need not mention it.
read -r ytx yvout <"$S/redteam-${NAME}Y.outpoint"
H0=$(( $(bcli getblockcount) - 30 ))
vault_spender() {
  local tip h; tip=$(bcli getblockcount)
  for h in $(seq "$H0" "$tip"); do
    bcli getblock "$(bcli getblockhash "$h")" 2 | python3 -c '
import json, sys
b = json.load(sys.stdin)
for t in b["tx"]:
    if any(i.get("txid") == sys.argv[1] and i.get("vout") == int(sys.argv[2]) for i in t["vin"]):
        print(t["txid"]); break' "$ytx" "$yvout"
  done | head -1
}
conf=""
for i in $(seq 1 $((WAIT / 10))); do
  conf=$(vault_spender)
  [ -n "$conf" ] && break
  conf=$(for n in $C1 $C2 $C3; do cld_ctl $n '(:log :tail 400)' 2>/dev/null; done | tr '"' '\n' | grep -F "dispute ${Y:0:8}:" | grep -oE "confiscation [0-9a-f]{64} on chain" | grep -oE '[0-9a-f]{64}' | head -1)
  [ -n "$conf" ] && break; mine 1 >/dev/null; sleep 10
done
[ -n "$conf" ] || fail "no confiscation of Y within ${WAIT}s"
tx=$(bcli getrawtransaction "$conf" true)
python3 - "$tx" "$RT" "$MV" "$A3" "$A4" <<'PY' || fail "the confiscation does not settle the obligations"
import json, sys
t = json.loads(sys.argv[1]); rt, mv, a3, a4 = sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
ins = [(i["txid"], i["vout"]) for i in t["vin"]]
paid = {o["scriptPubKey"].get("address"): round(o["value"] * 1e8) for o in t["vout"]}
ok = (rt, mv) in ins and paid.get(a3) == 600 - 86 and paid.get(a4) == 50000 - 86
print(f"   inputs {len(ins)}: migration swept {(rt, mv) in ins}; pays {a3[:12]}… {paid.get(a3)}, {a4[:12]}… {paid.get(a4)}")
sys.exit(0 if ok else 1)
PY
signed=0; for m in $R1 $R2; do sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$m/node.log" 2>/dev/null | grep -qi "Signed confiscation sighash for ledger ${Y:0:16}" && signed=$((signed+1)); done
echo "   reference members that signed the confiscation: $signed"
# DEP-06 §Residue: the lottery's winner takes custody (DisputeAcquire) and credits what the
# confiscation did not pay: the dangling migration (MigrationCredit) and the 400-sat payment.
ledger_ops() {   # "seq op" for every update the relay holds of Y
  python3 - "$CLD_ROOT/beacon-data/events.log" "${Y:0:16}" <<'PY'
import json, sys
seen = set()
for raw in open(sys.argv[1], "rb"):
    s = raw.decode("latin-1")
    if sys.argv[2] not in s: continue
    j = 0
    while True:
        i = s.find('{"id"', j)
        if i < 0: break
        try: ev, end = json.JSONDecoder().raw_decode(s[i:])
        except Exception: j = i + 5; continue
        j = i + end
        t = {x[0]: x[1] for x in ev.get("tags", []) if len(x) > 1}
        if ev.get("kind") == 9100 and t.get("d") == sys.argv[2] and (t.get("n"), t.get("t"), ev["pubkey"]) not in seen:
            seen.add((t.get("n"), t.get("t"), ev["pubkey"])); print(t.get("n"), t.get("t"), ev["pubkey"][:12])
PY
}
acq=""; credits=""
for i in $(seq 1 $((WAIT / 10))); do
  acq=$(ledger_ops | awk '$2==55 {print $1, $3; exit}')
  if [ -n "$acq" ]; then
    set -- $acq
    credits=$(ledger_ops | awk -v s="$1" -v k="$2" '$3==k && $1>s && ($2==35 || $2==105) {print $2}' | sort | uniq -c | tr '\n' ' ')
    case "$credits" in *" 35"*) case "$credits" in *" 105"*) break;; esac;; esac
  fi
  mine 1 >/dev/null; sleep 10
done
[ -n "$acq" ] || fail "no DisputeAcquire of Y within ${WAIT}s"
W=""; for n in $C1 $C2 $C3; do [ "$(pubkey_of $n | cut -c3-14)" = "${acq#* }" ] && W=$n; done
echo "   custody: DisputeAcquire at seq ${acq% *} by ${acq#* } (${W:-a reference member}); credits after it (count op): $credits"
if [ -n "$W" ] && [ "${OBL_WITHHOLD:-1}" = 1 ]; then
  [ -z "$credits" ] || fail "the withholding winner $W credited anyway: $credits"
  # The winner signs on, past its service_response_blocks (72), still not crediting: proof 11.
  mine 75 >/dev/null; sleep 10
  expect "$(cld_ctl $W "(:deposit-open :ledger \"$Y\" :descriptor \"pk($(pubkey_of $OP))\")")" "the winner's late update"
  disputed=""
  for i in $(seq 1 $((WAIT / 10))); do
    disputed=$(for n in $C1 $C2 $C3; do [ "$n" = "$W" ] && continue
                 cld_ctl $n '(:log :tail 600)' 2>/dev/null | tr '"' '\n' | grep -q "UNHONOURED OBLIGATION on ${Y:0:8} verified: disputing" && echo $n; done | tr '\n' ' ')
    [ -n "$disputed" ] && break; mine 1 >/dev/null; sleep 10
  done
  [ -n "$disputed" ] || fail "no member disputed the withholding winner $W (proof 11)"
  rp=0; for m in $R1 $R2; do sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$m/node.log" 2>/dev/null | grep "${Y:0:16}" | grep -q "UnhonouredObligation" && rp=$((rp+1)); done
  echo "   proof 11: members that disputed the withholding winner: $disputed; reference members that received it: $rp"
  echo "PASS: the confiscation paid both owed deposits; the withholding winner was proven (proof 11) and disputed."
  exit 0
fi
case "$credits" in *" 35"*) ;; *) fail "the winner did not credit the residue payment (OnchainCredit)";; esac
case "$credits" in *" 105"*) ;; *) fail "the winner did not resolve the dangling migration (MigrationCredit)";; esac
echo "PASS: the confiscation swept the migration output and paid both owed deposits; the winner credited the residue."
