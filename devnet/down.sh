#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
for n in $(cld_names); do stop_cld "$n"; done
pkill -f "relay[.]py" && echo "relay stopped"
pkill -f "esplora[.]py" && echo "esplora shim stopped"
[ "${1:-}" = "--wipe" ] && rm -rf "$CLD_ROOT" && echo "wiped $CLD_ROOT"
