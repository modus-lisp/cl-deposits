#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
echo "height: $(bcli getblockcount 2>/dev/null)   relay: $(relay_running && echo up || echo down)   stored events: $(wc -l < "$RELAY_STORE" 2>/dev/null || echo 0)"
for n in $(cld_names); do
  if cld_running "$n"; then echo "$n: $(cld_ctl "$n" "(:info)")"; else echo "$n: down"; fi
done
