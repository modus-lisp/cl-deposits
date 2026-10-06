# devnet/_common.sh — shared by the cl-deposits devnet scripts.
# DEVNET (or CLD_CHAIN) selects the network:
#   signet (default)  the signet devnet at /mnt/lisp/signet (bitcoind + miner wallet + Lightning):
#                     the soak, at real block pacing.
#   regtest           a private bitcoind under CLD_ROOT with no Lightning, where `mine` is instant:
#                     the persistent red-team network (devnet/regtest-net.sh, CLD_ROOT
#                     /mnt/lisp/regtest-devnet, REGTEST_CL cl nodes + REGTEST_REFS reference
#                     nodes) and CI's smoke (devnet/regtest.sh: /tmp, 4 cl nodes, no references).
set -u
CLD_CHAIN="${CLD_CHAIN:-${DEVNET:-signet}}"
SIGNET_ROOT="${SIGNET_ROOT:-/mnt/lisp/signet}"
CLD_SRC="${CLD_SRC:-$HOME/cl-deposits}"
MINER_WALLET="${MINER_WALLET:-miner}"
case "$CLD_CHAIN" in
  signet)
    RELAY_PORT="${RELAY_PORT:-7777}"
    CLD_NODES=("cld1:10041" "cld2:10042" "cld3:10043" "cld4:10044" "cld5:10045" "cld6:10046"   # name:control-port
               "cld7:10047" "cld8:10048" "cld9:10049" "cld10:10050"     # fresh keys for the red team (2026-10-02);
               "cld11:10055" "cld12:10056" "cld13:10057" "cld14:10058"   # 10101+ are the regtest network's
               "cld15:10059" "cld16:10060" "cld17:10061" "cld18:10062")
    CLD_ROOT="${CLD_ROOT:-$SIGNET_ROOT/deposits}"        # data dirs live OUTSIDE the repo
    BITCOIN_DATADIR="$SIGNET_ROOT/bitcoin"
    BITCOIN_CLI="${BITCOIN_CLI:-$SIGNET_ROOT/bin/bitcoin-cli}"
    BCLI="$BITCOIN_CLI -signet -datadir=$BITCOIN_DATADIR"
    mine() { "$SIGNET_ROOT/mine.sh" "${1:-1}" >/dev/null; }
    ;;
  regtest)
    CLD_ROOT="${CLD_ROOT:-/mnt/lisp/regtest-devnet}"
    RELAY_PORT="${RELAY_PORT:-7787}"                       # distinct ports: the signet devnet is up alongside
    # REGTEST_CL nodes from `up`, plus any the red-team harness minted since (redteam/_lib.sh mint_cl).
    _ncl=$(( ${REGTEST_CL:-24} + $(cat "$CLD_ROOT/minted-cl" 2>/dev/null || echo 0) ))
    CLD_NODES=(); for i in $(seq 1 "$_ncl"); do CLD_NODES+=("cld$i:$((${REGTEST_PORT_BASE:-10100}+i))"); done
    BITCOIN_DATADIR="$CLD_ROOT/bitcoin"
    _bin() { command -v "$1" 2>/dev/null || { [ -x "$SIGNET_ROOT/bin/$1" ] && echo "$SIGNET_ROOT/bin/$1"; } || echo "$1"; }
    BITCOIN_CLI="${BITCOIN_CLI:-$(_bin bitcoin-cli)}"
    BITCOIND="${BITCOIND:-$(_bin bitcoind)}"
    BITCOIN_RPC_PORT="${BITCOIN_RPC_PORT:-18543}"
    BCLI="$BITCOIN_CLI -regtest -datadir=$BITCOIN_DATADIR -rpcport=$BITCOIN_RPC_PORT"
    mine() { $BCLI -rpcwallet="$MINER_WALLET" -generate "${1:-1}" >/dev/null; }
    ;;
  *) echo "CLD_CHAIN must be signet or regtest" >&2; exit 2;;
esac
RELAY_URL="ws://127.0.0.1:$RELAY_PORT"
RELAY_STORE="$CLD_ROOT/relay.jsonl"
RELAY_IMPL="${RELAY_IMPL:-beacon}"                       # beacon (pure CL, ~/beacon) | py (devnet/relay.py, kept one cycle)
BEACON_DIR="$CLD_ROOT/beacon-data/"
RELAY_FAULTS="$RELAY_STORE.faults.json"                  # red-team fault rules, read by either relay
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
    -listen=0 -txindex=1 -fallbackfee=0.0001 -rpcthreads=32 -rpcworkqueue=512 -daemonwait >"$CLD_ROOT/bitcoind.log" 2>&1 || { echo "bitcoind did not start; see $CLD_ROOT/bitcoind.log" >&2; return 1; }
  $BCLI -named createwallet wallet_name="$MINER_WALLET" load_on_startup=true >/dev/null 2>&1 || $BCLI loadwallet "$MINER_WALLET" >/dev/null
  [ "$(bcli getblockcount)" -ge 101 ] || mine 101
}
stop_bitcoind() { bitcoind_running && $BCLI stop >/dev/null 2>&1; }

# ─── Reference nodes (deposits-rust) ─────────────────────────────────────────
# The second implementation in the quorum, as LND is to CLN on the Lightning
# devnet: name:admin-port.  Each has its own data dir (seed.hex, wallet, node.log)
# and talks to the same relay and bitcoind; its wallet syncs through the Esplora
# shim.  (ref1 is the hand-run node from the first interop session; left alone.)
if [ "$CLD_CHAIN" = regtest ]; then
  REF_NODES=(); for i in $(seq 2 $(( ${REGTEST_REFS:-6} + 1 ))); do REF_NODES+=("ref$i:$((8864+i))"); done
else
  REF_NODES=("ref2:8766" "ref3:8767" "ref4:8768" "ref5:8769" "ref6:8770" "ref7:8771")
fi
# regtest runs its own build (a rebuild for the signet devnet never pulls the binary from under it)
DEPOSITS_RUST="${DEPOSITS_RUST:-$([ "$CLD_CHAIN" = regtest ] && echo /mnt/lisp/cargo-target/regtest-net/release || echo "$HOME/workspace/deposits-rust/target/release")}"
REF_NODE_BIN="$DEPOSITS_RUST/deposits-node"; REF_WALLET_BIN="$DEPOSITS_RUST/deposits-wallet"
ref_names() { for e in "${REF_NODES[@]}"; do echo "${e%%:*}"; done; }
ref_port()  { for e in "${REF_NODES[@]}"; do [ "${e%%:*}" = "$1" ] && echo "${e##*:}" && return; done; return 1; }
ref_dir()   { echo "$CLD_ROOT/$1"; }
ref_pid()   { pgrep -nf "deposits-node run .*--data-dir $(ref_dir "$1") " 2>/dev/null || cat "$(ref_dir "$1")/ref.pid" 2>/dev/null; }   # the daemon itself, not a wrapper
ref_running(){ local p; p=$(ref_pid "$1") && [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }
ref_env()   { echo "LIGHTNING_BACKEND=none CHAIN_BACKEND=bitcoind BITCOIND_RPC_URL=http://127.0.0.1:${BITCOIN_RPC_PORT:-38332} BITCOIND_COOKIE_FILE=$BITCOIN_DATADIR/$CLD_CHAIN/.cookie"; }
# ref_cli NAME CMD ARGS...  — the reference CLI against NAME's data dir (the daemon may be running; the CLI reaches it over the relay)
ref_cli()   { local n=$1; shift; env $(ref_env) RUST_LOG=error "$REF_NODE_BIN" "$@" --network "$CLD_CHAIN" --esplora "$ESPLORA_URL" --relay "$RELAY_URL" --data-dir "$(ref_dir "$n")" 2>&1 | grep -vE '^\S*\[[0-9]m|^\[2m' ; }
# The protocol identity (operator/cosigner key) is NOT the Nostr key: it is what `quorum show-identity` prints.
ref_pubkey(){ ref_cli "$1" quorum show-identity | sed -nE 's/^ *pubkey: *([0-9a-f]{66}).*/\1/p' | head -1; }
ref_ledger(){ ref_cli "$1" quorum show-identity | sed -nE 's/^ *([0-9a-f]{66}):([0-9a-f]{64}).*/\2/p' | head -1; }   # its first own ledger
# soak_plan — the soak's ledgers as "NAME:operator:m1,...,m7 ...": every node operates one
# ledger with Q = 7 (docs/TRUST-MODEL.md §2a: ~30% collusion tolerated at R = 0.5).  Nodes
# are interleaved cl, ref, cl, ref ... and each operator takes the next seven around the
# ring, so every node serves 7 quorums, every quorum splits 4-3 by implementation, and the
# operator's own implementation is always the minority of its quorum.  (With two
# implementations one always holds a majority of 7; a third is needed to avoid that.)
soak_plan() {
  local ring=() c r i j names=(A B C D E F G H I J K L M N O P) plan=""
  local cl=($(cld_names | head -n "${SOAK_PLAN_CL:-6}")) rf=($(ref_names))   # cld7+ are red-team actors, not soak operators
  for i in "${!cl[@]}"; do ring+=("${cl[$i]}"); [ -n "${rf[$i]:-}" ] && ring+=("${rf[$i]}"); done
  local n=${#ring[@]} q=${SOAK_Q:-7}
  for i in $(seq 0 $((n-1))); do
    local m=(); for j in $(seq 1 $q); do m+=("${ring[$(( (i+j) % n ))]}"); done
    plan+="${names[$i]}:${ring[$i]}:$(IFS=,; echo "${m[*]}") "
  done
  echo "${plan% }"
}
start_ref() {
  local n=$1 dir; dir=$(ref_dir "$n"); mkdir -p "$dir"
  ref_running "$n" && { echo "$n already running"; return 0; }
  [ -f "$dir/seed.hex" ] || head -c 32 /dev/urandom | xxd -p -c 64 >"$dir/seed.hex"
  local from=$(( $(stat -c %s "$dir/node.log" 2>/dev/null || echo 0) + 1 ))   # the log is ~1 GB: grep only this run's part
  ( cd "$dir" && setsid nohup env $(ref_env) "$REF_NODE_BIN" run --network "$CLD_CHAIN" --relay "$RELAY_URL" --esplora "$ESPLORA_URL" \
      --data-dir "$dir" --seed-file "$dir/seed.hex" --name "$n" --admin-bind "127.0.0.1:$(ref_port "$n")" >>"$dir/node.log" 2>&1 &
    sleep 1; pgrep -nf "deposits-node run .*--data-dir $dir " >"$dir/ref.pid" )
  for i in $(seq 1 120); do tail -c +"$from" "$dir/node.log" 2>/dev/null | grep -q 'Wallet synced' && { echo "$n up (admin $(ref_port "$n"))"; return 0; }; ref_running "$n" || break; sleep 1; done
  echo "$n did not come up; see $dir/node.log" >&2; return 1
}
# ref_begin_quorum NAME LEDGER [ratio] — fund the ledger's reserves address, then drive `quorum begin`
# (the CLI times out at 30 s while the daemon waits for confirmations; a rerun resumes).
ref_begin_quorum() {
  local n=$1 l=$2 ratio=${3:-0.5} addr out i
  addr=$(ref_cli "$n" ledger address "$l" | grep -oE '(tb1|bcrt1)[0-9a-z]+' | head -1) || return 1
  wcli sendtoaddress "$addr" 0.5 >/dev/null && mine 3 && sleep 45     # the reference wallet syncs through the shim on a timer
  for i in 1 2 3 4 5 6; do
    out=$(timeout 120 "$REF_NODE_BIN" quorum begin "$l" --collateral-ratio "$ratio" --network "$CLD_CHAIN" --esplora "$ESPLORA_URL" --relay "$RELAY_URL" --data-dir "$(ref_dir "$n")" 2>&1 | grep -vE '^\S*\[[0-9]m|^\[2m')
    echo "$out" | grep -qi 'No response' || { echo "$out" | tail -1; return 0; }
    mine 1; sleep 15
  done
  echo "quorum begin on $l did not complete" >&2; return 1
}
stop_ref() { local p; p=$(ref_pid "$1") || return 0; [ -n "$p" ] && kill "$p" 2>/dev/null && echo "$1 stopped"; rm -f "$(ref_dir "$1")/ref.pid"; }

ESPLORA_PORT="${ESPLORA_PORT:-$([ "$CLD_CHAIN" = regtest ] && echo 3012 || echo 3002)}"
ESPLORA_URL="http://127.0.0.1:$ESPLORA_PORT"
esplora_running() { curl -sf "$ESPLORA_URL/blocks/tip/height" >/dev/null 2>&1; }   # by port: each network has its own shim
start_esplora() {   # Esplora-compatible API over our bitcoind, for the reference node's wallet
  esplora_running && return 0
  mkdir -p "$CLD_ROOT"
  ESPLORA_BITCOIN_CLI="$BCLI" ESPLORA_PORT=$ESPLORA_PORT setsid nohup python3 "$CLD_SRC/devnet/esplora.py" >"$CLD_ROOT/esplora.log" 2>&1 &
  echo $! >"$CLD_ROOT/esplora.pid"
  for i in $(seq 1 120); do curl -sf "$ESPLORA_URL/blocks/tip/height" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "esplora shim did not come up" >&2; return 1
}
relay_running() { (echo >/dev/tcp/127.0.0.1/$RELAY_PORT) 2>/dev/null; }
relay_events() {   # stored events, for status lines
  if [ "$RELAY_IMPL" = py ]; then wc -l < "$RELAY_STORE" 2>/dev/null || echo 0
  else curl -s "http://127.0.0.1:$RELAY_PORT/stats" 2>/dev/null | grep -o '"events":[0-9]*' | cut -d: -f2; fi
}
relay_mb() { if [ "$RELAY_IMPL" = py ]; then du -m "$RELAY_STORE" 2>/dev/null | cut -f1; else du -sm "$BEACON_DIR" 2>/dev/null | cut -f1; fi; }
start_relay() {
  relay_running && return 0
  mkdir -p "$CLD_ROOT"
  if [ "$RELAY_IMPL" = py ]; then
    RELAY_PORT=$RELAY_PORT RELAY_STORE=$RELAY_STORE setsid nohup python3 "$CLD_SRC/devnet/relay.py" >"$CLD_ROOT/relay.log" 2>&1 &
    sleep 0.5; pgrep -nf "python3 $CLD_SRC/devnet/relay.py" >"$CLD_ROOT/relay.pid"   # the python, not the setsid wrapper
  else
    local sbcl="${CLD_SBCL:-/usr/bin/sbcl}" lisp=(--dynamic-space-size "${BEACON_HEAP:-16GB}" --noinform --non-interactive --load "$CLD_SRC/devnet/beacon-relay.lisp" --end-toplevel-options)
    if [ ! -s "$BEACON_DIR/events.log" ] && [ -s "$RELAY_STORE" ]; then   # first start: carry relay.py's store over
      mkdir -p "$BEACON_DIR"; BEACON_DIR=$BEACON_DIR "$sbcl" "${lisp[@]}" import "$RELAY_STORE" >>"$CLD_ROOT/relay.log" 2>&1
    fi
    RELAY_PORT=$RELAY_PORT BEACON_DIR=$BEACON_DIR RELAY_FAULTS=$RELAY_FAULTS setsid nohup "$sbcl" "${lisp[@]}" >"$CLD_ROOT/relay.log" 2>&1 &
    sleep 1; pgrep -nf "sbcl.*devnet/beacon-relay[.]lisp" >"$CLD_ROOT/relay.pid"
  fi
  for i in $(seq 1 600); do (echo >/dev/tcp/127.0.0.1/$RELAY_PORT) 2>/dev/null && return 0; sleep 0.3; done   # beacon replays its log first
  echo "relay did not come up; see $CLD_ROOT/relay.log" >&2; return 1
}
start_cld() {
  local n=$1 dir; dir=$(cld_dir "$n"); mkdir -p "$dir"
  cld_running "$n" && { echo "$n already running"; return 0; }
  (echo >/dev/tcp/127.0.0.1/$(cld_port "$n")) 2>/dev/null && { echo "$n: control port $(cld_port "$n") already bound by another process; stop_cld first" >&2; return 1; }
  local lnenv=(); [ "$n" = cld1 ] && lnenv=("CLD_LN_CONTROL=$CLD_LN_CONTROL")
  ( cd "$CLD_SRC" && setsid nohup env CLD_DIR="$dir" CLD_RELAYS="$RELAY_URL" CLD_CONTROL_PORT="$(cld_port "$n")" CLD_NETWORK=$CLD_CHAIN \
      CLD_BITCOIN_CLI="$BCLI" CLD_MIN_CONFS=1 "${lnenv[@]}" \
      CL_SOURCE_REGISTRY="(:source-registry (:tree \"$CLD_SRC\") :inherit-configuration)" \
      "${CLD_SBCL:-/usr/bin/sbcl}" --noinform --dynamic-space-size "${CLD_HEAP_MB:-32768}" --non-interactive --load bin/cl-deposits.lisp >"$dir/cld.log" 2>&1 & )
      # A pinned SBCL, not whatever is first on PATH: under the 2.6.8 in ~/.local/bin
      # secp256k1-fast derives a WRONG public key and no signature verifies — a node
      # started with it comes back as a stranger to its own ledgers (2026-09-24 night).
      # 32 GB, not SBCL's 1 GB default: a node keeps every replica's full history in memory
      # (~1 KB per update; the soak's ledgers passed 80k updates overnight) and the old
      # loader held an 84 MB file as a 4-byte-per-char string.  Three nodes died "Heap
      # exhausted, game over" on the first night.
  for i in $(seq 1 120); do (echo >/dev/tcp/127.0.0.1/$(cld_port "$n")) 2>/dev/null && { echo "$n up (control $(cld_port "$n"))"; return 0; }; sleep 0.5; done
  echo "$n did not come up; see $dir/cld.log" >&2; return 1
}
stop_relay() { local p; p=$(cat "$CLD_ROOT/relay.pid" 2>/dev/null) && [ -n "$p" ] && kill "$p" 2>/dev/null; rm -f "$CLD_ROOT/relay.pid"; }
stop_cld() {   # every daemon on this data dir, not just the one the pid file names: a stale
               # instance kept a control port and its ledger files while a new one died
               # beside it, and "did not come up" hid it (2026-09-25)
  local p killed=0
  for p in $(pgrep -f "sbcl.*bin/cl-deposits.lisp"); do
    if tr '\0' '\n' < /proc/$p/environ 2>/dev/null | grep -qx "CLD_DIR=$(cld_dir "$1")"; then kill "$p" 2>/dev/null && killed=$((killed+1)); fi
  done
  [ "$killed" -gt 0 ] && echo "$1 stopped ($killed process(es))"; rm -f "$(cld_dir "$1")/cld.pid"
  local i; for i in $(seq 1 20); do (echo >/dev/tcp/127.0.0.1/$(cld_port "$1")) 2>/dev/null || return 0; sleep 1; done
  echo "$1: control port $(cld_port "$1") still bound after stop" >&2; return 1
}
