# redteam/_lib.sh — shared by the scenario scripts.  Source after devnet/_common.sh and $S/env.
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { case "$1" in *":STATUS :OK"*) ;; *) fail "$1";; esac; }
own_ledger() { case $1 in cld*) eval echo "\${L${1#cld}}";; ref*) eval echo "\${RL${1#ref}}";; esac; }
outpoint_vout() {   # outpoint_vout TXID ADDRESS
  bcli getrawtransaction "$1" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$2'][0])"
}
out_sats() {        # out_sats TXID VOUT
  bcli getrawtransaction "$1" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print(round(tx['vout'][$2]['value']*1e8))"
}
consent() {         # consent LEDGER OPERATOR MEMBER... — a reference member's consent can time out under load: retry
  local l=$1 op=$2 m r i; shift 2
  for m in "$@"; do
    for i in 1 2 3; do
      r=$(cld_ctl "$op" "(:add-member :ledger \"$l\" :member \"$(cat "$S/pubkey.$m")\" :member-ledger \"$(own_ledger "$m")\")")
      [[ "$r" == *":STATUS :OK"* ]] && break; sleep 5
    done; expect "$r"
  done
}
# form_ledger ROWNAME OPERATOR RULESET MEMBER... — a fresh funded ledger, remembered in $S/redteam-ROWNAME
# (its reserves outpoint in ROWNAME.outpoint).  Prints the ledger id.  RULESET "" means the default.
# COLLATERAL_SATS (default 0) of the 0.5 BTC vault is collateral, the rest reserves.
form_ledger() {
  local row="$S/redteam-$1" op=$2 rs=$3 l prep addr txid vout coll=${COLLATERAL_SATS:-0}; shift 3
  if [ -f "$row" ]; then cat "$row"; return; fi
  l=$(sx "$(cld_ctl "$op" "(:open-ledger :reserves-id \"genesis:$op:redteam-$(basename "$row"):$RANDOM\" :reserves-msat 25000000000 :collateral-msat 25000000000)")" ":LEDGER")
  [ -n "$l" ] || fail "open ledger $1"
  consent "$l" "$op" "$@" >&2
  prep=$(cld_ctl "$op" "(:prepare-quorum :ledger \"$l\" :expiry-blocks 4320${rs:+ :ruleset \"$rs\"})"); expect "$prep"; addr=$(sx "$prep" ":ADDRESS")
  txid=$(wcli sendtoaddress "$addr" 0.5); mine 3 >/dev/null
  vout=$(outpoint_vout "$txid" "$addr")
  expect "$(cld_ctl "$op" "(:begin-quorum :ledger \"$l\" :txid \"$txid\" :vout $vout :sats $(( 50000000 - coll )) :collateral-sats $coll)")"
  cld_ctl "$op" "(:advertise :ledger \"$l\")" >/dev/null 2>&1
  echo "$txid $vout" > "$row.outpoint"; echo "$l" > "$row"; echo "$l"
}
# fresh_deposits ROWNAME OPERATOR LEDGER N [MSAT] — N cl wallet deposits (w1..wN) on a form_ledger ledger,
# each credited MSAT (default 20000000) by its operator.  Prints the deposit ids, one per line.
fresh_deposits() {
  local row="$S/redteam-$1" op=$2 l=$3 n=$4 msat=${5:-20000000} i d txid vout
  if [ -f "$row.deposits" ]; then cat "$row.deposits"; return; fi
  read -r txid vout <"$row.outpoint"
  for i in $(seq 1 "$n"); do
    d=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" "w$i" "$l" open)" ":DEPOSIT"); [ -n "$d" ] || fail "w$i open on $1"
    expect "$(cld_ctl "$op" "(:credit :ledger \"$l\" :deposit \"$d\" :msat $msat :txid \"$txid\" :vout $vout)")"
    echo "$d" >>"$row.deposits.tmp"
  done
  mv "$row.deposits.tmp" "$row.deposits"; cat "$row.deposits"
}
# vault_spend OPERATOR LEDGER ADDRESS [TIER] — the colluders must already be armed (:theft-sign).
# Talks to the control port directly: the daemon's signature window (90 s) outlasts cld_ctl's 60 s.
vault_spend() {
  printf '%s\n' "(:vault-spend :ledger \"$2\" :address \"$3\" :tier ${4:-0})" |
    timeout 180 bash -c "exec 3<>/dev/tcp/127.0.0.1/$(cld_port "$1"); cat >&3; head -n1 <&3"
}
# accused NODE LEDGER — run NODE's vault watch now; true if it logs VAULT SPEND for LEDGER.
accused() {
  cld_ctl "$1" '(:vault-watch)' >/dev/null 2>&1
  cld_ctl "$1" '(:log)' 2>/dev/null | grep -q "VAULT SPEND: ${2:0:8}"
}
arm()    { local k=$1 n; shift; for n in "$@"; do expect "$(cld_ctl "$n" "(:adversary :set $k t)")"; done; }
disarm() { local k=$1 n; shift; for n in "$@"; do cld_ctl "$n" "(:adversary :set $k nil)" >/dev/null 2>&1; done; }
