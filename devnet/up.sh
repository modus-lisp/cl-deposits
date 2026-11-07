#!/usr/bin/env bash
# devnet/up.sh — relay + esplora shim + cld1..cld4 + the reference nodes on the signet devnet.
source "$(dirname "$0")/_common.sh"
pgrep -f "bitcoind -datadir=$BITCOIN_DATADIR" >/dev/null || { echo "bitcoind not running: $SIGNET_ROOT/up.sh first"; exit 1; }
start_relay && echo "relay $RELAY_URL"
start_esplora && echo "esplora shim $ESPLORA_URL"
for n in $(cld_names); do start_cld "$n"; done
for n in $(ref_names); do start_ref "$n" || true; done   # the reference nodes: each from its versioned build (start_ref says if one is missing)
