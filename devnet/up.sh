#!/usr/bin/env bash
# devnet/up.sh — relay + three deposits nodes on the signet devnet.
source "$(dirname "$0")/_common.sh"
pgrep -f "bitcoind -datadir=$BITCOIN_DATADIR" >/dev/null || { echo "bitcoind not running: $SIGNET_ROOT/up.sh first"; exit 1; }
start_relay && echo "relay $RELAY_URL"
for n in $(cld_names); do start_cld "$n"; done
