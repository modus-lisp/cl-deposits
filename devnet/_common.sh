# devnet/_common.sh — shared by the cl-deposits devnet scripts.
# CLD_CHAIN=signet (default) rides on the signet devnet at /mnt/lisp/signet
# (bitcoind + miner wallet + Lightning).  CLD_CHAIN=regtest runs a private
# bitcoind of its own under CLD_ROOT with no Lightning: what CI uses.
set -u
CLD_CHAIN="${CLD_CHAIN:-signet}"
SIGNET_ROOT="${SIGNET_ROOT:-/mnt/lisp/signet}"
CLD_SRC="${CLD_SRC:-$HOME/cl-deposits}"
MINER_WALLET="${MINER_WALLET:-miner}"
case "$CLD_CHAIN" in
  signet)
    RELAY_PORT="${RELAY_PORT:-7777}"
    CLD_NODES=("cld1:10041" "cld2:10042" "cld3:10043" "cld4:10044")     # name:control-port; cld1 operates, the rest cosign (Q=3)
    CLD_ROOT="${CLD_ROOT:-$SIGNET_ROOT/deposits}"        # data dirs live OUTSIDE the repo
    BITCOIN_DATADIR="$SIGNET_ROOT/bitcoin"
    BITCOIN_CLI="${BITCOIN_CLI:-$SIGNET_ROOT/bin/bitcoin-cli}"
    BCLI="$BITCOIN_CLI -signet -datadir=$BITCOIN_DATADIR"
    mine() { "$SIGNET_ROOT/mine.sh" "${1:-1}" >/dev/null; }
    ;;
  regtest)
    CLD_ROOT="${CLD_ROOT:-/tmp/cld-regtest}"
    RELAY_PORT="${RELAY_PORT:-7787}"                       # distinct ports: a signet devnet may be up alongside
    CLD_NODES=("cld1:10051" "cld2:10052" "cld3:10053" "cld4:10054")
    BITCOIN_DATADIR="$CLD_ROOT/bitcoin"
    BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
    BITCOIND="${BITCOIND:-bitcoind}"
    BITCOIN_RPC_PORT="${BITCOIN_RPC_PORT:-18543}"
    BCLI="$BITCOIN_CLI -regtest -datadir=$BITCOIN_DATADIR -rpcport=$BITCOIN_RPC_PORT"
    mine() { $BCLI -rpcwallet="$MINER_WALLET" -generate "${1:-1}" >/dev/null; }
    ;;
  *) echo "CLD_CHAIN must be signet or regtest" >&2; exit 2;;
esac
RELAY_URL="ws://127.0.0.1:$RELAY_PORT"
RELAY_STORE="$CLD_ROOT/relay.jsonl"
bcli() { $BCLI "$@"; }
wcli() { $BCLI -rpcwallet="$MINER_WALLET" "$@"; }

CLD_LN_NODE="${CLD_LN_NODE:-clp3}"                       # cld1's Lightning node (a cl-payments daemon)
CLD_LN_CONTROL="127.0.0.1:$(( 9930 + ${CLD_LN_NODE#clp} + 100 ))"
ln_cli() { "$SIGNET_ROOT/bin/lightning-cli" --lightning-dir="$SIGNET_ROOT/$1" "${@:2}"; }   # CLN nodes only
cld_names() { for e in "${CLD_NODES[@]}"; do echo "${e%%:*}"; done; }
cld_port()  { for e in "${CLD_NODES[@]}"; do [ "${e%%:*}" = "$1" ] && echo "${e##*:}" && return; done; return 1; }
cld_dir()   { echo "$CLD_ROOT/$1"; }
cld_ctl()   { local n=$1; shift; printf '%s\n' "$*" | timeout 60 bash -c "exec 3<>/dev/tcp/127.0.0.1/$(cld_port "$n"); cat >&3; head -n1 <&3"; }
cld_pid()   { cat "$(cld_dir "$1")/cld.pid" 2>/dev/null; }
cld_running(){ local p; p=$(cld_pid "$1") && [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }
cld_pubkey(){ cld_ctl "$1" "(:info)" | sed -E 's/.*:PUBKEY "([0-9a-f]+)".*/\1/'; }
# field extraction from an s-expression reply: sx REPLY :KEY  -> value token (strings unquoted)
sx() { printf '%s' "$1" | grep -oiE "$2 (\"[^\"]*\"|[^ )]+)" | head -1 | sed -E "s/^$2 //; s/^\"//; s/\"$//"; }

bitcoind_running() { $BCLI getblockcount >/dev/null 2>&1; }
start_bitcoind() {   # regtest only: a private chain under CLD_ROOT with a funded miner wallet
  bitcoind_running && return 0
  mkdir -p "$BITCOIN_DATADIR"
  $BITCOIND -regtest -datadir="$BITCOIN_DATADIR" -rpcport=$BITCOIN_RPC_PORT -port=$((BITCOIN_RPC_PORT+1)) \
    -listen=0 -txindex=1 -fallbackfee=0.0001 -daemonwait >"$CLD_ROOT/bitcoind.log" 2>&1 || { echo "bitcoind did not start; see $CLD_ROOT/bitcoind.log" >&2; return 1; }
  $BCLI -named createwallet wallet_name="$MINER_WALLET" load_on_startup=true >/dev/null 2>&1 || $BCLI loadwallet "$MINER_WALLET" >/dev/null
  [ "$(bcli getblockcount)" -ge 101 ] || mine 101
}
stop_bitcoind() { bitcoind_running && $BCLI stop >/dev/null 2>&1; }

ESPLORA_PORT="${ESPLORA_PORT:-3002}"
ESPLORA_URL="http://127.0.0.1:$ESPLORA_PORT"
esplora_running() { pgrep -f "esplora[.]py" >/dev/null; }
start_esplora() {   # Esplora-compatible API over our bitcoind, for the reference node's wallet
  esplora_running && return 0
  mkdir -p "$CLD_ROOT"
  ESPLORA_BITCOIN_CLI="$BCLI" ESPLORA_PORT=$ESPLORA_PORT setsid nohup python3 "$CLD_SRC/devnet/esplora.py" >"$CLD_ROOT/esplora.log" 2>&1 &
  for i in $(seq 1 120); do curl -sf "$ESPLORA_URL/blocks/tip/height" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "esplora shim did not come up" >&2; return 1
}
relay_running() { (echo >/dev/tcp/127.0.0.1/$RELAY_PORT) 2>/dev/null; }
start_relay() {
  relay_running && return 0
  mkdir -p "$CLD_ROOT"
  RELAY_PORT=$RELAY_PORT RELAY_STORE=$RELAY_STORE setsid nohup python3 "$CLD_SRC/devnet/relay.py" >"$CLD_ROOT/relay.log" 2>&1 &
  echo $! >"$CLD_ROOT/relay.pid"
  for i in $(seq 1 30); do (echo >/dev/tcp/127.0.0.1/$RELAY_PORT) 2>/dev/null && return 0; sleep 0.2; done
  echo "relay did not come up" >&2; return 1
}
start_cld() {
  local n=$1 dir; dir=$(cld_dir "$n"); mkdir -p "$dir"
  cld_running "$n" && { echo "$n already running"; return 0; }
  local lnenv=(); [ "$n" = cld1 ] && lnenv=("CLD_LN_CONTROL=$CLD_LN_CONTROL")
  ( cd "$CLD_SRC" && setsid nohup env CLD_DIR="$dir" CLD_RELAYS="$RELAY_URL" CLD_CONTROL_PORT="$(cld_port "$n")" CLD_NETWORK=$CLD_CHAIN \
      CLD_BITCOIN_CLI="$BCLI" CLD_MIN_CONFS=1 "${lnenv[@]}" \
      CL_SOURCE_REGISTRY="(:source-registry (:tree \"$CLD_SRC\") :inherit-configuration)" \
      sbcl --noinform --non-interactive --load bin/cl-deposits.lisp >"$dir/cld.log" 2>&1 & )
  for i in $(seq 1 120); do (echo >/dev/tcp/127.0.0.1/$(cld_port "$n")) 2>/dev/null && { echo "$n up (control $(cld_port "$n"))"; return 0; }; sleep 0.5; done
  echo "$n did not come up; see $dir/cld.log" >&2; return 1
}
stop_relay() { local p; p=$(cat "$CLD_ROOT/relay.pid" 2>/dev/null) && [ -n "$p" ] && kill "$p" 2>/dev/null; rm -f "$CLD_ROOT/relay.pid"; }
stop_cld() { local p; p=$(cld_pid "$1") || return 0; [ -n "$p" ] && kill "$p" 2>/dev/null && echo "$1 stopped"; rm -f "$(cld_dir "$1")/cld.pid"; }
