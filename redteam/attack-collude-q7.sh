#!/usr/bin/env bash
# redteam/attack-collude-q7.sh — a colluding majority at Q = 7, and contagion (DEP-19 §5-6).
#
# Forms test ledger M: cld1 operates; cld2..cld6, ref6, ref7 cosign; R = 0.5.  cld2..cld5
# (four of seven, a majority) cosign blind, and cld1 locks a depositor's funds with no
# witness.  It commits.  PASS = what the protocol promises after that:
#   - M's honest members (cld6, ref6, ref7) dispute M;
#   - contagion: the ledgers the four colluders operate (C, E, G, I: cld2..cld5 at Q = 7,
#     each with an honest majority) are disputed by their own members.
# Reports times from the fraud to each dispute.  WAIT (s) bounds the watch.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-300}
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { case "$1" in *":STATUS :OK"*) ;; *) fail "$1";; esac; }
M_ROW="$S/redteam-M"
if [ -f "$M_ROW" ]; then read -r M < "$M_ROW"; echo "== reusing M $M"; else
  echo "== forming M (cld1 operates; cld2 cld3 cld4 cld5 cld6 ref6 ref7 cosign)"
  M=$(sx "$(cld_ctl cld1 "(:open-ledger :reserves-id \"genesis:cld1:redteam-M:$RANDOM\" :reserves-msat 25000000000 :collateral-msat 25000000000)")" ":LEDGER"); [ -n "$M" ] || fail "open M"
  for m in cld2 cld3 cld4 cld5 cld6 ref6 ref7; do
    case $m in cld*) ml=$(eval echo "\${L${m#cld}}");; ref*) ml=$(eval echo "\${RL${m#ref}}");; esac
    expect "$(cld_ctl cld1 "(:add-member :ledger \"$M\" :member \"$(cat $S/pubkey.$m)\" :member-ledger \"$ml\")")"
  done
  prep=$(cld_ctl cld1 "(:prepare-quorum :ledger \"$M\" :expiry-blocks 4320)"); expect "$prep"; addr=$(sx "$prep" ":ADDRESS")
  txid=$(wcli sendtoaddress "$addr" 0.5); mine 3
  vout=$(bcli getrawtransaction "$txid" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$addr'][0])")
  sleep 20
  expect "$(cld_ctl cld1 "(:begin-quorum :ledger \"$M\" :txid \"$txid\" :vout $vout :sats 25000000 :collateral-sats 25000000)")"
  expect "$(cld_ctl cld1 "(:advertise :ledger \"$M\")")"
  echo "$M $txid $vout" > "$M_ROW"; echo "   M $M"
fi
read -r M txid vout < "$M_ROW"
D1=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" rt1 "$M" open)" ":DEPOSIT"); D2=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" rt2 "$M" open)" ":DEPOSIT")
expect "$(cld_ctl cld1 "(:credit :ledger \"$M\" :deposit \"$D1\" :msat 20000000 :txid \"$txid\" :vout $vout)")"
echo "== victim deposit $D1 credited 20000000 msat on M"
T0=$(date -u +%FT%T); t0=$(date +%s)
for n in cld2 cld3 cld4 cld5; do cld_ctl $n "(:adversary :set :cosign-blind t)" >/dev/null; done
R=$(cld_ctl cld1 "(:forge-lock :ledger \"$M\" :from \"$D1\" :to \"$D2\" :msat 15000000)")
for n in cld2 cld3 cld4 cld5; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
echo "== 4-of-7 attempt on M: $(echo "$R" | cut -c1-120)"
echo "$R" | grep -q ":STATUS :OK" || fail "the colluding majority did not commit"
declare -A LED; while IFS=$'\t' read -r L id op _; do LED[$L]=$id; done < "$S/ledgers.tsv"
forked() {   # forked LEDGER-ID NODE: has NODE a fork of its own on LEDGER-ID
  case $2 in
    cld*) cld_ctl $2 "(:forks :ledger \"$1\")" | grep -q "$(cut -c1-16 $S/pubkey.$2)";;
    ref*) sed 's/\x1b\[[0-9;]*m//g' "$(ref_dir $2)/node.log" | awk -v t="$T0" '$1 > t' | grep -E "${1:0:16}" | grep -qE "Created dispute fork|INITIATING DISPUTE";;
  esac; }
declare -A DONE
for i in $(seq 1 $((WAIT/10))); do
  for pair in "M:$M:cld6 ref6 ref7" "C:${LED[C]}:ref3 ref4 ref5 ref6" "E:${LED[E]}:ref4 ref5 ref6 ref7" "G:${LED[G]}:ref5 ref6 ref7 cld6" "I:${LED[I]}:ref6 ref7 ref2 ref3 cld6"; do
    IFS=: read -r L id nodes <<<"$pair"
    for n in $nodes; do k="$L/$n"; [ -z "${DONE[$k]:-}" ] && forked "$id" "$n" && DONE[$k]=$(( $(date +%s) - t0 )); done
  done
  sleep 10
done
echo "== disputes (seconds after the fraud; - = none within $WAIT s):"
for pair in "M:cld6 ref6 ref7" "C:ref3 ref4 ref5 ref6" "E:ref4 ref5 ref6 ref7" "G:ref5 ref6 ref7 cld6" "I:ref6 ref7 ref2 ref3 cld6"; do
  IFS=: read -r L nodes <<<"$pair"; printf "   %s:" $L; for n in $nodes; do printf " %s=%s" $n "${DONE[$L/$n]:--}"; done; echo
done
echo "== contagion proofs sent by cld6: $(cld_ctl cld6 '(:log)' | tr '"' '\n' | grep -c 'contagion:.*proof against')"
