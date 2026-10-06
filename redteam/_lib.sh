# redteam/_lib.sh — shared by the scenario scripts.  Source after devnet/_common.sh and $S/env.
fail() { echo "FAIL: $*" >&2; exit 1; }
pubkey_of() {   # pubkey_of NODE — its protocol key, cached in $S/pubkey.NODE (a key never changes)
  local c="$S/pubkey.$1" k i; [ -s "$c" ] && { cat "$c"; return 0; }
  for i in 1 2 3 4 5 6; do
    k=$(case $1 in cld*) cld_pubkey "$1";; ref*) ref_pubkey "$1";; esac)
    [ -n "$k" ] && { echo "$k" >"$c"; echo "$k"; return 0; }; sleep 5
  done; fail "no pubkey for $1"
}
expect() { case "$1" in *":STATUS :OK"*) ;; *) fail "${2:+$2: }${1:-no answer (control port timed out?)}";; esac; }
own_ledger() {      # own_ledger NODE — the ledger NODE cites as a member; opened and recorded in $S/env on first use
  local var id; case $1 in cld*) var="L${1#cld}";; ref*) var="RL${1#ref}";; esac
  [ -f "$S/env" ] && source "$S/env"
  if [ -z "${!var:-}" ]; then
    case $1 in
      cld*) id=$(sx "$(cld_ctl "$1" "(:open-ledger :reserves-id \"genesis:$1:redteam:$RANDOM\")")" ":LEDGER");;
      ref*) id=$(ref_ledger "$1"); [ -n "$id" ] || id=$(ref_cli "$1" ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p');;
    esac
    [ -n "$id" ] || fail "own ledger for $1"; printf '%s=%s\n' "$var" "$id" >>"$S/env"; declare -g "$var=$id"
  fi; echo "${!var}"
}
outpoint_vout() {   # outpoint_vout TXID ADDRESS
  bcli getrawtransaction "$1" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$2'][0])"
}
out_sats() {        # out_sats TXID VOUT
  bcli getrawtransaction "$1" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print(round(tx['vout'][$2]['value']*1e8))"
}
consent() {         # consent LEDGER OPERATOR MEMBER... — a reference member's consent can time out under load: retry
  local l=$1 op=$2 m r i; shift 2
  for m in "$@"; do
    for i in 1 2 3 4 5 6; do   # a reference node can hang and be restarted by the devnet watchdog: ride it out
      r=$(cld_ctl "$op" "(:add-member :ledger \"$l\" :member \"$(pubkey_of $m)\" :member-ledger \"$(own_ledger "$m")\"${RESP:+ :dispute-response-blocks $RESP})")
      [[ "$r" == *":STATUS :OK"* ]] && break; sleep 20
    done; expect "$r" "add-member $m"
  done
}
# form_ledger ROWNAME OPERATOR RULESET MEMBER... — a fresh funded ledger, remembered in $S/redteam-ROWNAME
# (its reserves outpoint in ROWNAME.outpoint).  Prints the ledger id.  RULESET "" means the default.
# COLLATERAL_SATS (default 0) of the 0.5 BTC vault is collateral, the rest reserves.  RESP (blocks), when
# set, is each member's dispute_response_blocks: the arm window, so a scenario need not mine ~720 blocks.
form_ledger() {
  local row="$S/redteam-$1" op=$2 rs=$3 l prep addr txid vout coll=${COLLATERAL_SATS:-0}; shift 3
  if [ -f "$row" ]; then cat "$row"; return; fi
  l=$(sx "$(cld_ctl "$op" "(:open-ledger :reserves-id \"genesis:$op:redteam-$(basename "$row"):$RANDOM\" :reserves-msat 25000000000 :collateral-msat 25000000000)")" ":LEDGER")
  [ -n "$l" ] || fail "open ledger $(basename "$row")"
  consent "$l" "$op" "$@" >&2
  prep=$(cld_ctl "$op" "(:prepare-quorum :ledger \"$l\" :expiry-blocks ${FORM_EXPIRY:-4320}${rs:+ :ruleset \"$rs\"})"); expect "$prep" "prepare-quorum"; addr=$(sx "$prep" ":ADDRESS")
  txid=$(wcli sendtoaddress "$addr" 0.5); mine 3 >/dev/null
  vout=$(outpoint_vout "$txid" "$addr")
  local r i; for i in 1 2 3; do   # a busy member can miss the cosign round: retry
    r=$(cld_ctl "$op" "(:begin-quorum :ledger \"$l\" :txid \"$txid\" :vout $vout :sats $(( 50000000 - coll )) :collateral-sats $coll)")
    case "$r" in *":STATUS :OK"*) break;; *"cosignatures"*) echo "   begin-quorum retry $i: $r" >&2; sleep 15;; *) break;; esac
  done
  expect "$r" "begin-quorum"
  cld_ctl "$op" "(:advertise :ledger \"$l\")" >/dev/null 2>&1
  await_active "$l" "$@" >&2
  echo "$txid $vout" > "$row.outpoint"; echo "$l" > "$row"; echo "$l"
}
# await_active LEDGER NODE... — until each cl NODE's replica has applied the QuorumBegin (a member that
# has only cosigned it refuses requests that need it, e.g. theft_sign's "no QuorumBegin").  60 s cap.
await_active() {
  local l=$1 n i; shift
  for n in "$@"; do
    case $n in cld*) ;; *) continue;; esac
    for i in $(seq 1 30); do
      cld_ctl "$n" "(:info)" 2>/dev/null | grep -qE "\(:ID \"$l\"[^)]*:QUORUM :ACTIVE" && break; sleep 2
    done
  done
}
# fresh_deposits ROWNAME OPERATOR LEDGER N [MSAT] — N cl wallet deposits (w1..wN) on a form_ledger ledger,
# each credited MSAT (default 20000000) by its operator.  Prints the deposit ids, one per line.
fresh_deposits() {
  local row="$S/redteam-$1" op=$2 l=$3 n=$4 msat=${5:-20000000} i d txid vout out
  if [ -f "$row.deposits" ]; then cat "$row.deposits"; return; fi
  read -r txid vout <"$row.outpoint"
  for i in $(seq 1 "$n"); do
    out=$("$CLD_SRC/devnet/cld-wallet.sh" "w$i" "$l" open); d=$(sx "$out" ":DEPOSIT")
    [ -n "$d" ] || fail "w$i open on $1: ${out:-no reply}"
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
# accused NODE LEDGER [SECS] — run NODE's vault watch now; true if it logs VAULT SPEND for LEDGER
# within SECS (default 180).  After mining hundreds of blocks a pass scans them all, which outlasts
# one control call (60 s), so poll the log rather than trusting the call's return.
accused() {
  local i
  cld_ctl "$1" '(:vault-watch)' >/dev/null 2>&1
  for i in $(seq 1 $(( ${3:-180} / 10 ))); do
    cld_ctl "$1" '(:log)' 2>/dev/null | grep -q "VAULT SPEND: ${2:0:8}" && return 0
    sleep 10; cld_ctl "$1" '(:vault-watch)' >/dev/null 2>&1
  done; return 1
}
arm()    { local k=$1 n; shift; for n in "$@"; do expect "$(cld_ctl "$n" "(:adversary :set $k t)")"; done; }
disarm() { local k=$1 n; shift; for n in "$@"; do cld_ctl "$n" "(:adversary :set $k nil)" >/dev/null 2>&1; done; }
# Actors.  Contagion taints a key for good (a theft it signed, a fraud it committed, a false accusation):
# every later ledger it operates is disputed on sight, so a scenario that needs a clean operator or a
# clean honest member must not reuse it.  $S/redteam-tainted lists tainted cl nodes; a scenario calls
# `taint` on the keys it burns.  clean_cl prints the untainted cl nodes, freshest (highest-numbered) first,
# and also drops — and records — a node any of whose operated ledgers its own :info shows disputed.
TAINTED="$S/redteam-tainted"
taint() { local n; for n in "$@"; do grep -qx "$n" "$TAINTED" 2>/dev/null || echo "$n" >>"$TAINTED"; done; }
tainted() { grep -qx "$1" "$TAINTED" 2>/dev/null; }
clean_cl() {
  local n; for n in $(cld_names | sort -t d -k2 -nr); do
    tainted "$n" && continue
    [[ " ${REDTEAM_AVOID:-} " == *" $n "* ]] && continue   # clean but busy (e.g. still in an earlier scenario's dispute)
    if cld_ctl "$n" '(:info)' 2>/dev/null | grep -qE ':OWNED T [^)]*:DISPUTED [1-9]'; then taint "$n"; continue; fi
    echo "$n"
  done
}
# pick ROLE... — bind each named shell variable to a distinct clean cl node (in order).  Not enough clean
# nodes is a SKIP, not a FAIL: the scenario cannot tell its result apart from earlier taint.
# mint_cl K — on regtest, start K more cl nodes with fresh keys (cldN+1..), each with collateral coins,
# so a scenario never runs out of untainted actors.  They persist (counted in $CLD_ROOT/minted-cl).
mint_cl() {
  [ "$CLD_CHAIN" = regtest ] || return 1
  local k=$1 have i n a j
  have=$(cld_names | wc -l)
  echo $(( $(cat "$CLD_ROOT/minted-cl" 2>/dev/null || echo 0) + k )) >"$CLD_ROOT/minted-cl"
  source "$CLD_SRC/devnet/_common.sh" >/dev/null 2>&1
  for i in $(seq $((have + 1)) $((have + k))); do
    n=cld$i; start_cld "$n" >&2 || return 1
    pubkey_of "$n" >/dev/null
    a=$(sx "$(cld_ctl "$n" '(:address)')" ":ADDRESS") || return 1
    for j in 1 2 3 4 5 6 7 8; do wcli sendtoaddress "$a" 0.01 >/dev/null; done
    touch "$S/.cl-collateral-funded.$n"
  done
  mine 2 >/dev/null; echo "== minted $k fresh cl nodes (cld$((have + 1))..cld$((have + k)))" >&2
}
pick() {
  local pool=($(clean_cl)) i=0 v
  if [ ${#pool[@]} -lt $# ] && [ "$CLD_CHAIN" = regtest ]; then
    mint_cl $(( $# - ${#pool[@]} )) && pool=($(clean_cl))
  fi
  [ ${#pool[@]} -ge $# ] || { echo "SKIP: needs $# clean cl nodes ($*), have ${#pool[@]} (${pool[*]:-none}); add fresh-key nodes (devnet/_common.sh CLD_NODES)"; exit 0; }
  for v in "$@"; do declare -g "$v=${pool[$i]}"; i=$((i+1)); done
  echo "== actors: $(for v in "$@"; do printf '%s=%s ' "$v" "${!v}"; done)"
}
