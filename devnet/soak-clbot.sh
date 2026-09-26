#!/usr/bin/env bash
# devnet/soak-clbot.sh — one cl-wallet worker (SOAK_WORKER=n; several run at once).  Every
# tick: pick a cl deposit with balance above the floor, pick any other deposit on the same
# ledger (cl or reference wallet), transfer a random amount, complete it with the preimage.
# Counters in $SOAK/clbot-N.counts (ok fail); one line per attempt on stdout.
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; REG="$SOAK/deposits.tsv"; W=${SOAK_WORKER:-1}; INTERVAL=${SOAK_CL_INTERVAL:-20}
FLOOR=${SOAK_CL_FLOOR_MSAT:-500000}; RESERVE=${SOAK_CL_RESERVE_MSAT:-100000}; MAXAMT=${SOAK_CL_MAX_MSAT:-2000000}
ok=0; fail=0; [ -f "$SOAK/clbot-$W.counts" ] && read ok fail <"$SOAK/clbot-$W.counts"
fee_for() {   # fee LEDGERNAME AMOUNT_MSAT — cl operators charge nothing; reference operators enforce 2 msat + 20 bps
  case "$(awk -F'\t' -v n="$1" '$1==n {print $3}' "$SOAK/ledgers.tsv")" in cld*) echo 0;; *) echo $(( 2 + $2 * 20 / 10000 ));; esac
}
sx1() { printf '%s' "$1" | grep -oiE "$2 (\"[^\"]*\"|[^ )]+)" | head -1 | sed -E "s/^$2 //; s/^\"//; s/\"$//"; }
while true; do
  mapfile -t CL < <(grep -P '^cl\t' "$REG")
  IFS=$'\t' read -r _ w name L D <<<"${CL[$((RANDOM % ${#CL[@]}))]}"
  bal=$(sx1 "$("$CLD_SRC/devnet/cld-wallet.sh" "$w" "$L" balance "$D")" ":BALANCE"); bal=${bal:-0}
  if [ "$bal" -gt "$FLOOR" ] 2>/dev/null; then
    mapfile -t PEERS < <(awk -F'\t' -v l="$L" -v d="$D" '$4==l && $5!=d {print $5}' "$REG")
    dst=${PEERS[$((RANDOM % ${#PEERS[@]}))]}
    room=$(( bal - RESERVE )); [ "$room" -gt "$MAXAMT" ] && room=$MAXAMT
    amt=$(( 1000 + (RANDOM * 32768 + RANDOM) % (room - 1000) )); fee=$(fee_for "$name" "$amt")
    H=$(bcli getblockcount 2>/dev/null || echo 0)
    T=$("$CLD_SRC/devnet/cld-wallet.sh" "$w" "$L" transfer "$D" "$dst" "$amt" "$H" "$fee"); TID=$(sx1 "$T" ":TRANSFER"); PRE=$(sx1 "$T" ":PREIMAGE")
    if [ -n "$TID" ] && "$CLD_SRC/devnet/cld-wallet.sh" "$w" "$L" complete "$TID" "$PRE" | grep -q ":STATUS :OK"; then
      ok=$((ok+1)); echo "$(date +%FT%T) ok   $w $name ${D:0:8}->${dst:0:8} $amt msat fee $fee (balance was $bal)"
    else
      fail=$((fail+1)); echo "$(date +%FT%T) FAIL $w $name ${D:0:8}->${dst:0:8} $amt msat fee $fee: $T"
    fi
  else
    echo "$(date +%FT%T) skip $w $name ${D:0:8} balance $bal <= floor"
  fi
  echo "$ok $fail" >"$SOAK/clbot-$W.counts"
  sleep $(( INTERVAL / 2 + RANDOM % INTERVAL ))
done
