#!/usr/bin/env bash
# devnet/regtest.sh — the end-to-end smoke on a private regtest chain, from
# nothing: bitcoind, the relay, four nodes, the smoke (minus Lightning), and
# teardown.  What CI runs; also the quickest local end-to-end check.
#
#   BITCOIND=/path/bitcoind BITCOIN_CLI=/path/bitcoin-cli devnet/regtest.sh
#   KEEP=1 devnet/regtest.sh     leave everything running for a look
export CLD_CHAIN=regtest
export CLD_ROOT="${CLD_ROOT:-/tmp/cld-regtest}"
# Four cl nodes, no references, on ports clear of the persistent regtest network (devnet/regtest-net.sh).
export REGTEST_CL=4 REGTEST_REFS=0 REGTEST_PORT_BASE=${REGTEST_PORT_BASE:-10200} RELAY_PORT=${RELAY_PORT:-7797} BITCOIN_RPC_PORT=${BITCOIN_RPC_PORT:-18553}
source "$(dirname "$0")/_common.sh"
teardown() {
  local rc=$?
  if [ "${KEEP:-}" != 1 ]; then
    for n in $(cld_names); do stop_cld "$n" >/dev/null; done
    stop_relay; stop_bitcoind
  fi
  if [ $rc -ne 0 ]; then
    for n in $(cld_names); do echo "===== $n log ====="; tail -40 "$(cld_dir "$n")/cld.log" 2>/dev/null; done
    echo "===== relay ====="; tail -20 "$CLD_ROOT/relay.log" 2>/dev/null
  fi
  exit $rc
}
trap teardown EXIT
set -e
rm -rf "$CLD_ROOT"; mkdir -p "$CLD_ROOT"
start_bitcoind && echo "bitcoind regtest at height $(bcli getblockcount)"
start_relay && echo "relay $RELAY_URL"
for n in $(cld_names); do start_cld "$n"; done
CLD_NO_LN=1 "$CLD_SRC/devnet/smoke.sh"
