#!/usr/bin/env bash
# devnet/soak-monitor.sh — every SOAK_MONITOR_EVERY seconds: chain height, node liveness and
# RSS, relay store size, every soak ledger's sequence on every cl node (a spread across a
# row is lag or disagreement), fork counts, bot counters, reference WARN/ERROR rates.
# Appends to $SOAK/status.log; the latest snapshot is $SOAK/status.txt.
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; EVERY=${SOAK_MONITOR_EVERY:-300}
rss_kb() { [ -n "$1" ] && ps -o rss= -p "$1" 2>/dev/null | tr -d ' '; }
while true; do
  {
    echo "=== $(date +%FT%T)  height $(bcli getblockcount 2>/dev/null)  relay $(relay_running && echo up || echo DOWN) $(du -m "$RELAY_STORE" 2>/dev/null | cut -f1) MB  bots $(pgrep -fc 'deposit-bot --data-dir')"
    declare -A INFO FORKS
    for n in $(cld_names); do
      if cld_running "$n"; then INFO[$n]=$(cld_ctl "$n" "(:info)" 2>/dev/null); printf '%-5s up   rss %7s KB\n' "$n" "$(rss_kb "$(cld_pid "$n")")"; else echo "$n DOWN"; INFO[$n]=""; fi
    done
    printf '%-8s %-5s' ledger op; for n in $(cld_names); do printf ' %10s' "$n"; done; echo '   (seq/forks per cl node)'
    while IFS=$'\t' read -r name id op _ _; do
      printf '%-8s %-5s' "$name" "$op"
      for n in $(cld_names); do
        if [ -n "${INFO[$n]}" ]; then
          s=$(printf '%s' "${INFO[$n]}" | grep -oE "\(:ID \"$id\" :OWNED [A-Z]+ :SEQ [0-9]+ :QUORUM :[A-Z]+ :MEMBERS [1-9]" | grep -oE ':SEQ [0-9]+' | head -1 | cut -d' ' -f2)
          if [ -n "$s" ]; then f=$(cld_ctl "$n" "(:forks :ledger \"$id\")" 2>/dev/null | grep -o ':OPERATOR' | wc -l); printf ' %7s/%-2s' "$s" "$f"; else printf ' %10s' -; fi
        else printf ' %10s' down; fi
      done; echo
    done <"$SOAK/ledgers.tsv"
    for n in $(ref_names); do
      if ref_running "$n"; then
        lg="$(ref_dir "$n")/node.log"; recent=$(tail -c 3000000 "$lg" | sed 's/\x1b\[[0-9;]*m//g' | awk -v t="$(date -u -d "-$EVERY seconds" +%FT%T)" '$1 > t')
        printf '%-5s up   rss %7s KB   last %ss: WARN %s ERROR %s   log %s MB\n' "$n" "$(rss_kb "$(ref_pid "$n")")" "$EVERY" "$(grep -c ' WARN ' <<<"$recent")" "$(grep -c ' ERROR ' <<<"$recent")" "$(du -m "$lg" | cut -f1)"
        grep -E ' (WARN|ERROR) ' <<<"$recent" | sed -E 's/^[^ ]+ +//' | cut -c1-110 | sort | uniq -c | sort -rn | head -4 | sed 's/^/        /'
      else echo "$n DOWN"; fi
    done
    sent=0; failed=0; back=0; for sw in "$SOAK"/log/swarm-*.log; do [ -f "$sw" ] || continue; sent=$((sent + $(grep -c '→' "$sw"))); failed=$((failed + $(grep -c '✗' "$sw"))); back=$((back + $(grep -c '⧖' "$sw"))); done
    echo "ref bots: sent $sent  failed $failed  inflight-backoff $back"
    ok=0; fl=0; for c in "$SOAK"/clbot-*.counts; do [ -f "$c" ] || continue; read a b <"$c"; ok=$((ok+a)); fl=$((fl+b)); done; echo "cl bots:  ok $ok  fail $fl"
    [ -f "$SOAK/log/chaos.log" ] && echo "chaos: $(tail -1 "$SOAK/log/chaos.log")"
  } >"$SOAK/status.txt.new" 2>&1
  mv "$SOAK/status.txt.new" "$SOAK/status.txt"; cat "$SOAK/status.txt" >>"$SOAK/status.log"
  sleep "$EVERY"
done
