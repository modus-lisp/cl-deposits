#!/usr/bin/env bash
# redteam/check-confiscation-vault-rung.sh — a confiscation of a vault whose rotation confirmed at a
# higher rung is judged answered by a node that never saw that rung while it was unspent.
#
# Signet soak, 2026-11-08: ledger G's rotation confirmed at a bumped rung (DEP-03 §Fee ladder).  Its
# quorum expired, the members confiscated, and its operator cld4, judging the spend, looked the rung
# up in the UTXO set (gettxout).  The vault was spent by then, so cl fell back to rung 0's recorded
# amounts, rebuilt the confiscation 6076 sats off, challenged it, and its lapse "proved" theft by the
# three members that signed it (oracle ALARMs, 2026-11-08T20:43).  DEP-03: "a judge of a later spend
# reads the rung from the spending input without a chain lookup".
#
# A fresh ledger: a cl operator OP and cl members C2..C4.  Its rotation is stalled at rung 0 so a
# higher rung confirms, with a short expiry.  The quorum lapses, the members dispute (QUORUM-EXPIRED)
# and confiscate.  OP is restarted after the confiscation confirms, so it holds no memory of the rung.
# PASS = a higher rung confirmed, the confiscation spent it, OP judged the spend answered, and no node
# challenged it or proved a theft.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-2400}
source "$(dirname "$0")/_lib.sh"
pick OP C2 C3 C4
ROW=${REDTEAM_CVR:-CVR$RANDOM}
X=$(form_ledger "$ROW" $OP "" $C2 $C3 $C4) || exit 1; echo "== ledger $X"
"$CLD_SRC/devnet/regtest-net.sh" ticker stop
trap '"$CLD_SRC/devnet/regtest-net.sh" ticker start' EXIT
consent "$X" $OP $C2 $C3 $C4
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks ${EXPIRY:-60})"); expect "$r" "rotate-vault"
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r" >&2; sleep 15; done
expect "$r" "begin-quorum"
RUNGS=$(sx "$r" ":RUNGS"); set -- $RUNGS; [ $# -ge 2 ] || fail "the rotation has $# rung(s); a ladder needs two or more"
R0=$1; sleep 5
bcli getmempoolentry "$R0" >/dev/null 2>&1 || fail "rung 0 $R0 is not in the mempool"
bcli prioritisetransaction "$R0" 0 -100000000 >/dev/null
echo "== rung 0 made unmineable; mining past the bump"
for i in $(seq 1 7); do mine 1 >/dev/null; sleep 8; done
sleep 30; mine 1 >/dev/null; sleep 10
conf=
for t in "$@"; do
  c=$(bcli getrawtransaction "$t" true 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('confirmations',0))" 2>/dev/null)
  [ "${c:-0}" -ge 1 ] && { conf=$t; break; }
done
[ -n "$conf" ] && [ "$conf" != "$R0" ] || fail "no higher rung confirmed (got '${conf:-none}')"
echo "== the vault is output 0 of $conf (a higher rung)"

echo "== mining past the quorum's expiry; waiting for the confiscation to reach the mempool (up to ${WAIT}s)"
# OP must judge the spend with no memory of the rung (cld4 never looked while the vault was
# unspent): stop it as soon as the confiscation is in the mempool, confirm it and mine past the
# spend-judging grace while it is down, then start it; its vault watch resumes below the spend.
spend=""
for i in $(seq 1 $((WAIT / 10))); do
  spend=$(bcli gettxspendingprevout "[{\"txid\":\"$conf\",\"vout\":0}]" 2>/dev/null \
            | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0].get("spendingtxid",""))' 2>/dev/null)
  [ -n "$spend" ] && break
  mine 1 >/dev/null; sleep 10
done
[ -n "$spend" ] || fail "no spend of the vault reached the mempool within ${WAIT}s"
echo "== $spend spends the vault; stopping $OP before it confirms"
stop_cld $OP
mine 1 >/dev/null; sleep 5
c=$(bcli getrawtransaction "$spend" true 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('confirmations',0))" 2>/dev/null)
[ "${c:-0}" -ge 1 ] || fail "the spend $spend did not confirm"
anchor=$(bcli getrawtransaction "$spend" true | python3 -c "import json,sys; t=json.load(sys.stdin); print(any(o['scriptPubKey']['hex'].startswith('6a20') for o in t['vout']))")
[ "$anchor" = True ] || fail "the vault's spend $spend carries no anchor (not a confiscation)"
mine 4 >/dev/null
echo "== confiscated by $spend; starting $OP"
start_cld $OP >/dev/null || fail "$OP did not restart"
for i in $(seq 1 60); do cld_ctl $OP '(:info)' 2>/dev/null | grep -q ':STATUS :OK' && break; sleep 5; done
verdict=""
for i in $(seq 1 90); do
  [ $((i % 3)) -eq 0 ] && mine 1 >/dev/null
  verdict=$(cld_ctl $OP '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "${X:0:8}'s (spend|reserves)" | grep -F "${spend:0:16}" | grep -E "is answered|CHALLENGED|VAULT SPEND" | head -1)
  [ -n "$verdict" ] && break; sleep 10
done
echo "   $OP: ${verdict:-no verdict}"
[ -n "$verdict" ] || fail "$OP never judged the spend"
case "$verdict" in *"is answered"*) ;; *) fail "$OP did not recognise the confiscation of a bumped-rung vault: $verdict";; esac
for n in $OP $C2 $C3 $C4; do
  if cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "VAULT SPEND|vault spend: .* signed it" | grep -qF "${X:0:8}"; then
    fail "$n challenged or proved the confiscation of $X"
  fi
done
echo "PASS: $X's vault was rung $conf, its confiscation $spend, and $OP (restarted) judged it answered."
