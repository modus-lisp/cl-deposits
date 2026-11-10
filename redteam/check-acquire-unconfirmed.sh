#!/usr/bin/env bash
# redteam/check-acquire-unconfirmed.sh — DEP-06 §Phase 4 under strict-lottery-v8 (ruled
# 2026-11-10: "yes", an acquire binds once its claim confirms).  A cl operator's ledger with a
# quorum of five (C1 C2 P cl, R1 R2 reference).  P publishes a DisputeAcquire on its fork for a
# claim that never reaches the chain (:phantom-acquire).  Before the rule every member read
# custody as moved and refused the operator ("custody moved by DisputeAcquire"); the ledger
# froze on nothing (signet soak, 2026-11-07: cld7 on 751e6951).  PASS = the operator still gets
# its updates cosigned by C1 C2 and the reference members, and none logs "custody moved" for it.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1 C2 P
R1=${R1:-ref6}; R2=${R2:-ref7}
for n in $OP $C1 $C2 $P; do cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null & done; wait
ROW=${REDTEAM_AU:-AU$RANDOM}
X=$(form_ledger "$ROW" $OP "" $C1 $C2 $P $R1 $R2) || exit 1
read -r VTX VOUT <"$S/redteam-$ROW.outpoint"
echo "== ledger $X; $P publishes a DisputeAcquire for a claim that never reaches the chain"
r=$(cld_ctl $P "(:phantom-acquire :ledger \"$X\")"); expect "$r" "phantom-acquire"
echo "   claim $(sx "$r" ":CLAIM") (never broadcast)"
T=$(date -u +%FT%T); mine 2 >/dev/null; sleep 30
out=$("$CLD_SRC/devnet/cld-wallet.sh" w1 "$X" open); dep=$(sx "$out" ":DEPOSIT"); [ -n "$dep" ] || fail "deposit open after the phantom acquire: $out"
r=$(cld_ctl $OP "(:credit :ledger \"$X\" :deposit \"$dep\" :msat 1000000 :txid \"$VTX\" :vout $VOUT)")
echo "   credit after the phantom acquire: ${r:0:160}"
for n in $C1 $C2; do
  if cld_ctl $n "(:log :n 3000)" | grep -qE "refused cosign seq .*custody moved by DisputeAcquire"; then
    cld_ctl $n "(:forks :ledger \"$X\")" | grep -q 'ARMED' && fail "$n read the unconfirmed acquire on $X as custody moved"
  fi
done
for n in $R1 $R2; do
  awk -v t="$T" '$1 >= t' "$CLD_ROOT/$n/node.log" 2>/dev/null | grep -q "${X:0:16}.*custody moved by DisputeAcquire\|deposed: custody moved" \
    && fail "$n (reference) read the unconfirmed acquire on $X as custody moved"
done
expect "$r" "credit after the phantom acquire (the operator must still reach threshold)"
echo "PASS: an acquire whose claim never confirmed deposed no one; $X's operator still reaches its threshold."
