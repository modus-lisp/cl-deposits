#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
for n in $(cld_names); do stop_cld "$n"; done
for n in $(ref_names); do stop_ref "$n"; done
stop_relay; pkill -f "relay[.]py"; pkill -f "devnet/beacon-relay[.]lisp"; echo "relay stopped"
pkill -f "esplora[.]py" && echo "esplora shim stopped"
[ "${1:-}" = "--wipe" ] && rm -rf "$CLD_ROOT" && echo "wiped $CLD_ROOT"
