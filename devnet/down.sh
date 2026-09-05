#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
for n in $(cld_names); do stop_cld "$n"; done
pkill -f "devnet/relay.py" && echo "relay stopped"
[ "${1:-}" = "--wipe" ] && rm -rf "$CLD_ROOT" && echo "wiped $CLD_ROOT"
