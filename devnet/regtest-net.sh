#!/usr/bin/env bash
# devnet/regtest-net.sh — a persistent mixed network on a private regtest chain, for the red-team
# scenarios that must mine past quorum expiry (hundreds of blocks: minutes on regtest, weeks on the
# signet once its difficulty caught up).  Runs alongside the signet devnet on its own ports and data
# dir (/mnt/lisp/regtest-devnet): bitcoind, a beacon relay, the Esplora shim, REGTEST_CL cl nodes
# (default 18) and REGTEST_REFS reference nodes (default 6, its own deposits-rust build), a block
# ticker (one block every REGTEST_BLOCK_EVERY s, default 10, with a collateral refill), and the soak's ledgers A..L and
# deposits (devnet/soak.sh setup, no soak loops) so scenarios find the same names as on the signet.
#
#   devnet/regtest-net.sh up       start everything; first run also mines coins and runs setup
#   devnet/regtest-net.sh down     stop everything (state kept)
#   devnet/regtest-net.sh reset    down, then delete the data dir (fresh chain, fresh keys)
#   devnet/regtest-net.sh status
#   DEVNET=regtest redteam/run-all.sh [--tags ...]     the suite against it
export DEVNET=regtest CLD_CHAIN=regtest
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"
ticker_pid() { cat "$CLD_ROOT/ticker.pid" 2>/dev/null; }
start_ticker() {
  local p; p=$(ticker_pid) && kill -0 "$p" 2>/dev/null && return 0
  # Disputes pledge replacement collateral and red-team runs leave many open: every
  # REGTEST_COLLATERAL_EVERY blocks, refill any node that ran short (soak.sh collateral).
  ( i=0; while sleep "${REGTEST_BLOCK_EVERY:-10}"; do
      mine 1 2>/dev/null; i=$((i+1))
      [ $((i % ${REGTEST_COLLATERAL_EVERY:-12})) -eq 0 ] && "$CLD_SRC/devnet/soak.sh" collateral >>"$CLD_ROOT/collateral.log" 2>&1
    done ) >/dev/null 2>&1 &
  echo $! >"$CLD_ROOT/ticker.pid"
}
up() {
  mkdir -p "$CLD_ROOT" "$SOAK"
  [ -x "$REF_NODE_BIN" ] || { echo "no reference build at $REF_NODE_BIN: CARGO_TARGET_DIR=${DEPOSITS_RUST%/release} cargo build --release -p deposits-node -p deposits-wallet" >&2; exit 1; }
  start_bitcoind || exit 1
  [ "$(bcli getblockcount)" -ge 400 ] || mine 300          # coins for 12 vaults, collateral, scenarios
  start_relay || exit 1; start_esplora || exit 1
  local n pids=(); for n in $(cld_names); do start_cld "$n" & pids+=($!); done; wait "${pids[@]}"   # ~40 s each: in parallel (not a bare wait: the relay is a child too)
  for n in $(cld_names); do cld_running "$n" || { echo "$n did not start" >&2; exit 1; }; done
  for n in $(ref_names); do start_ref "$n" || exit 1; done
  start_ticker
  for n in $(cld_names); do [ -s "$SOAK/pubkey.$n" ] || cld_pubkey "$n" >"$SOAK/pubkey.$n"; done   # scenarios seat any node
  if [ ! -s "$SOAK/deposits.tsv" ]; then
    SOAK_REF_DEPOSITS=${SOAK_REF_DEPOSITS:-2} SOAK_CL_WALLETS=${SOAK_CL_WALLETS:-2} "$CLD_SRC/devnet/soak.sh" setup || exit 1
  fi
  echo "regtest network up: height $(bcli getblockcount), relay $RELAY_URL, $(cld_names | wc -l) cl + $(ref_names | wc -l) reference nodes"
}
down() {
  local n p; p=$(ticker_pid) && kill "$p" 2>/dev/null; rm -f "$CLD_ROOT/ticker.pid"
  for n in $(ref_names); do stop_ref "$n"; done
  for n in $(cld_names); do stop_cld "$n"; done
  stop_relay; p=$(cat "$CLD_ROOT/esplora.pid" 2>/dev/null) && kill "$p" 2>/dev/null; rm -f "$CLD_ROOT/esplora.pid"
  stop_bitcoind; true
}
status() {
  echo "chain: $(bcli getblockcount 2>/dev/null || echo down)   relay: $(relay_running && echo up || echo down)   esplora: $(esplora_running && echo up || echo down)   ticker: $(p=$(ticker_pid) && kill -0 "$p" 2>/dev/null && echo up || echo down)"
  local n; for n in $(cld_names); do printf '%s:%s ' "$n" "$(cld_running "$n" && echo up || echo DOWN)"; done; echo
  for n in $(ref_names); do printf '%s:%s ' "$n" "$(ref_running "$n" && echo up || echo DOWN)"; done; echo
  [ -s "$SOAK/ledgers.tsv" ] && echo "ledgers: $(cut -f1 "$SOAK/ledgers.tsv" | tr '\n' ' ')"
}
case "${1:-}" in
  up) up;; down) down;; status) status;;
  reset) down; case "$CLD_ROOT" in /mnt/lisp/regtest-devnet*|/tmp/*) rm -rf "$CLD_ROOT"; echo "reset $CLD_ROOT";; *) echo "refusing to delete $CLD_ROOT" >&2; exit 1;; esac;;
  *) sed -n '2,15p' "$0"; exit 2;;
esac
