#!/usr/bin/env bash
# devnet/soak.sh — long-running operation on the whole signet devnet, both
# implementations on both sides.  Every node operates a ledger with a mixed quorum of
# three others (one reference member each, see UPSTREAM-NOTES on the scan race);
# deposit-bots (deposits-rust) and cl wallets move sats on all of them while blocks
# tick, a monitor records state, and a chaos loop restarts nodes under traffic.
#
#   devnet/soak.sh setup            # form the ledgers, open + credit deposits from BOTH wallets (idempotent, resumable)
#   devnet/soak.sh start            # mining clock, ref swarms, cl bot workers, monitor, chaos
#   devnet/soak.sh status           # latest monitor snapshot + bot counters
#   devnet/soak.sh stop             # stop the soak processes (nodes stay up)
#   devnet/soak.sh reset            # stop + forget setup (next setup forms fresh ledgers)
#
# Knobs: SOAK_REF_DEPOSITS (bots per ledger, 12), SOAK_CL_WALLETS (each on every ledger, 12),
#        SOAK_CL_WORKERS (4), SOAK_CREDIT_MSAT (20000000), SOAK_BLOCK_EVERY (60 s),
#        SOAK_BOT_INTERVAL_MS (10000), SOAK_CL_INTERVAL (20 s), SOAK_MONITOR_EVERY (300 s),
#        SOAK_RESTART_EVERY (10800 s; 0 = no chaos), SOAK_CHAOS_NODES.
# State: $CLD_ROOT/soak/{env,ledgers.tsv,deposits.tsv,refwallet-*,log/,pids/,status.*}
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; mkdir -p "$SOAK/pids" "$SOAK/log"
ENV="$SOAK/env"; [ -f "$ENV" ] && source "$ENV"
SOAK_REF_DEPOSITS=${SOAK_REF_DEPOSITS:-12}; SOAK_CL_WALLETS=${SOAK_CL_WALLETS:-12}; SOAK_CL_WORKERS=${SOAK_CL_WORKERS:-4}
SOAK_CREDIT_MSAT=${SOAK_CREDIT_MSAT:-20000000}; SOAK_BLOCK_EVERY=${SOAK_BLOCK_EVERY:-60}; SOAK_BOT_INTERVAL_MS=${SOAK_BOT_INTERVAL_MS:-10000}
SOAK_MONITOR_EVERY=${SOAK_MONITOR_EVERY:-300}; SOAK_RESTART_EVERY=${SOAK_RESTART_EVERY:-10800}
SOAK_CHAOS_NODES=${SOAK_CHAOS_NODES:-"cld2 cld3 ref3 cld4 cld1 ref2"}
# NAME:operator:member,member,member — at most one reference member per quorum.
LEDGER_PLAN=${SOAK_LEDGER_PLAN:-"A:cld1:cld2,cld3,ref2 B:ref2:cld2,cld3,ref3 C:cld2:cld3,cld4,ref3 D:cld3:cld1,cld4,ref2 E:cld4:cld1,cld2,ref3 F:ref3:cld1,cld4,ref2"}
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { case "$1" in *":STATUS :OK"*) ;; *) fail "$1";; esac; }
refwallet() { local dir=$1; shift; WALLET_DATA_DIR="$dir" timeout 180 "$REF_WALLET_BIN" "$@" --relay "$RELAY_URL" --network "$CLD_CHAIN" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -vE '^\S*(INFO|WARN|ERROR)|^\[' ; }
dep_id() { python3 -c "import json,sys; print([d['deposit_id'] for d in json.load(open('$1/deposits.json')) if d['alias']=='$2'][0])"; }
ref_members() { ref_cli "$1" quorum list | awk -v l="$(echo "$2" | cut -c1-16)" '/^  [0-9a-f]{16}/ { inblk = index($1, l) == 1; next } inblk && /^    [0-9a-f]/ { print }'; }
retry_add() { local i; for i in 1 2 3 4; do ref_cli "$1" quorum add "$2" "$3" "$4" >/dev/null 2>&1 || true; ref_members "$1" "$2" | grep -q "$(echo "$3" | cut -c1-16)" && return 0; sleep 5; done; return 1; }
pubkey_of() { case "$1" in cld*) cld_pubkey "$1";; ref*) ref_pubkey "$1";; esac; }
own_ledger() {   # own_ledger NODE — the (quorum-less) ledger a node cites when it joins another's quorum; opened once, kept in env
  local var; case "$1" in cld*) var="L${1#cld}";; ref*) var="RL${1#ref}";; esac
  if [ -z "${!var:-}" ]; then
    local id; case "$1" in
      cld*) id=$(sx "$(cld_ctl "$1" "(:open-ledger :reserves-id \"genesis:$1:soak:$RANDOM\")")" ":LEDGER");;
      ref*) id=$(ref_ledger "$1"); [ -n "$id" ] || id=$(ref_cli "$1" ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p');;
    esac
    [ -n "$id" ] || fail "own ledger for $1"; printf '%s=%s\n' "$var" "$id" >>"$ENV"; declare -g "$var=$id"
  fi; echo "${!var}"
}
ledger_row() { grep -P "^$1\t" "$SOAK/ledgers.tsv" 2>/dev/null; }   # NAME id operator txid vout
form_ledger() {   # form_ledger NAME OPERATOR "m1,m2,m3"
  local name=$1 op=$2 members=$3 id m mp ml
  [ -n "$(ledger_row "$name")" ] && return 0
  echo "== forming ledger $name ($op operates; ${members//,/ } cosign)"
  case "$op" in
    cld*)
      id=$(sx "$(cld_ctl "$op" "(:open-ledger :reserves-id \"genesis:$op:soak:$name:$RANDOM\" :reserves-msat 20000000000 :collateral-msat 30000000000)")" ":LEDGER"); [ -n "$id" ] || fail "open $name"
      for m in ${members//,/ }; do mp=$(pubkey_of "$m"); ml=$(own_ledger "$m"); expect "$(cld_ctl "$op" "(:add-member :ledger \"$id\" :member \"$mp\" :member-ledger \"$ml\")")"; done
      local prep addr txid vout; prep=$(cld_ctl "$op" "(:prepare-quorum :ledger \"$id\" :expiry-blocks 4320)"); expect "$prep"; addr=$(sx "$prep" ":ADDRESS")
      txid=$(wcli sendtoaddress "$addr" 0.5); mine 3
      vout=$(bcli getrawtransaction "$txid" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$addr'][0])")
      sleep 20   # the reference wallets sync through the shim on a timer
      expect "$(cld_ctl "$op" "(:begin-quorum :ledger \"$id\" :txid \"$txid\" :vout $vout :sats 20000000 :collateral-sats 30000000)")"
      expect "$(cld_ctl "$op" "(:advertise :ledger \"$id\")")"
      printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$id" "$op" "$txid" "$vout" >>"$SOAK/ledgers.tsv";;
    ref*)
      id=$(ref_cli "$op" ledger open --collateral-ratio 0.5 | sed -nE 's/.*Ledger ID: ([0-9a-f]{64}).*/\1/p'); [ -n "$id" ] || fail "$op ledger open"
      for m in ${members//,/ }; do mp=$(pubkey_of "$m"); ml=$(own_ledger "$m"); retry_add "$op" "$id" "$mp" "$ml" || fail "add $m to $name"; done
      ref_begin_quorum "$op" "$id" 0.5 || fail "quorum begin on $name"; sleep 8
      ref_cli "$op" ledger advertise "$id" >/dev/null 2>&1 || true
      printf '%s\t%s\t%s\t-\t-\n' "$name" "$id" "$op" >>"$SOAK/ledgers.tsv";;
  esac
  echo "   $name $id"
}
credit() {   # credit NAME DEPOSIT MSAT — through whichever implementation operates that ledger
  local row id op txid vout; row=$(ledger_row "$1"); IFS=$'\t' read -r _ id op txid vout <<<"$row"
  case "$op" in
    cld*) expect "$(cld_ctl "$op" "(:credit :ledger \"$id\" :deposit \"$2\" :msat $3 :txid \"$txid\" :vout $vout)")";;
    ref*) ref_cli "$op" deposit credit "$id" "$2" "$3" "soak-$RANDOM$RANDOM" | grep -q "New balance" || fail "credit on $1: $2";;
  esac
}
spawn() { local name=$1; shift; setsid nohup "$@" >>"$SOAK/log/$name.log" 2>&1 & echo $! >"$SOAK/pids/$name"; echo "  $name (pid $!)"; }
alive() { local p; p=$(cat "$SOAK/pids/$1" 2>/dev/null) && [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }

setup() {
  for n in $(cld_names); do cld_running "$n" || fail "$n not running (devnet/up.sh)"; done
  for n in $(ref_names); do ref_running "$n" || fail "$n not running (devnet/up.sh)"; done
  if [ ! -f "$SOAK/.collateral-funded" ]; then   # replacement collateral at each reference's operator-key address, for disputes
    for n in $(ref_names); do
      CA=$(env $(ref_env) RUST_LOG=error "$REF_NODE_BIN" pubkey-to-p2wpkh --network "$CLD_CHAIN" --seed-file "$(ref_dir "$n")/seed.hex" --data-dir "$(ref_dir "$n")" 2>&1 | grep -oE '(tb1|bcrt1)[0-9a-z]+' | head -1)
      wcli sendtoaddress "$CA" 0.01 >/dev/null
    done; mine 1; touch "$SOAK/.collateral-funded"
  fi
  for spec in $LEDGER_PLAN; do IFS=: read -r name op members <<<"$spec"; form_ledger "$name" "$op" "$members"; done
  echo "== deposits: $SOAK_REF_DEPOSITS reference bots per ledger + $SOAK_CL_WALLETS cl wallets on every ledger, $SOAK_CREDIT_MSAT msat each"
  touch "$SOAK/deposits.tsv"; local n=0
  while IFS=$'\t' read -r name id op _ _; do
    RW="$SOAK/refwallet-$name"; mkdir -p "$RW"; lc=$(echo "$name" | tr A-Z a-z)
    for i in $(seq 1 "$SOAK_REF_DEPOSITS"); do
      al="$lc$i"
      if ! grep -qP "^ref\t$RW:$al\t" "$SOAK/deposits.tsv"; then
        grep -q "\"alias\": *\"$al\"" "$RW/deposits.json" 2>/dev/null || { refwallet "$RW" open "$id" --alias "$al" | grep -q "created" || fail "reference wallet open $al on $name"; }
        credit "$name" "$(dep_id "$RW" "$al")" "$SOAK_CREDIT_MSAT"
        printf 'ref\t%s\t%s\t%s\t%s\n' "$RW:$al" "$name" "$id" "$(dep_id "$RW" "$al")" >>"$SOAK/deposits.tsv"; n=$((n+1))
      fi
    done
    for i in $(seq 1 "$SOAK_CL_WALLETS"); do
      w="w$i"
      if ! grep -qP "^cl\t$w\t$name\t" "$SOAK/deposits.tsv"; then
        D=$(sx "$("$CLD_SRC/devnet/cld-wallet.sh" "$w" "$id" open)" ":DEPOSIT"); [ -n "$D" ] || fail "cl wallet $w open on $name"
        credit "$name" "$D" "$SOAK_CREDIT_MSAT"
        printf 'cl\t%s\t%s\t%s\t%s\n' "$w" "$name" "$id" "$D" >>"$SOAK/deposits.tsv"; n=$((n+1))
      fi
    done
    echo "   $name: $(grep -cP "\t$name\t" "$SOAK/deposits.tsv") deposits"
  done <"$SOAK/ledgers.tsv"
  mine 1; echo "   $n new, $(wc -l <"$SOAK/deposits.tsv") deposits total on $(wc -l <"$SOAK/ledgers.tsv") ledgers"
}
start() {
  [ -s "$SOAK/ledgers.tsv" ] && [ -s "$SOAK/deposits.tsv" ] || fail "run setup first"
  echo "== starting soak processes (logs in $SOAK/log)"
  alive mine || spawn mine "$SIGNET_ROOT/mine.sh" --every "$SOAK_BLOCK_EVERY"
  while IFS=$'\t' read -r name _ _ _ _; do
    alive "swarm-$name" || spawn "swarm-$name" "$DEPOSITS_RUST/../../bin/swarm.sh" --data-dir "$SOAK/refwallet-$name" --relay "$RELAY_URL" --network "$CLD_CHAIN" \
        --bitcoin-cli "$BCLI" --interval-ms "$SOAK_BOT_INTERVAL_MS" --floor-sats 500 --reserve-sats 100
  done <"$SOAK/ledgers.tsv"
  for i in $(seq 1 "$SOAK_CL_WORKERS"); do alive "clbot-$i" || spawn "clbot-$i" env SOAK_WORKER="$i" "$CLD_SRC/devnet/soak-clbot.sh"; done
  alive monitor || spawn monitor "$CLD_SRC/devnet/soak-monitor.sh"
  alive rotate || spawn rotate "$CLD_SRC/devnet/soak-rotate.sh"
  if [ "$SOAK_RESTART_EVERY" -gt 0 ]; then alive chaos || spawn chaos "$CLD_SRC/devnet/soak-chaos.sh"; fi
}
stop() { for f in "$SOAK"/pids/*; do [ -f "$f" ] || continue; p=$(cat "$f"); kill -- -"$p" 2>/dev/null || kill "$p" 2>/dev/null; rm -f "$f"; echo "  stopped $(basename "$f")"; done; pkill -f "deposit-bot --data-dir $SOAK/" 2>/dev/null; true; }
status() {
  for f in "$SOAK"/pids/*; do [ -f "$f" ] && printf '%-9s %s\n' "$(basename "$f")" "$(alive "$(basename "$f")" && echo running || echo STOPPED)"; done
  echo; [ -f "$SOAK/status.txt" ] && cat "$SOAK/status.txt"
}
case "${1:-}" in
  setup) setup;; start) start;; stop) stop;; status) status;;
  reset) stop; rm -f "$ENV" "$SOAK/ledgers.tsv" "$SOAK/deposits.tsv" "$SOAK/.collateral-funded"; echo "reset (ledgers on the nodes are untouched)";;
  *) sed -n '2,19p' "$0"; exit 2;;
esac
