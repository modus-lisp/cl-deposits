#!/usr/bin/env bash
# devnet/soak-hostile.sh — a hostile depositor in the soak (docs/ADVERSARIAL.md §Depositor and wallet).
# Every HOSTILE_EVERY seconds (1200) send one request no honest operator may accept, to a random
# soak ledger, from a fresh key (an operator keeps one deposit per descriptor, so each request
# needs its own), funded with 2000 sats first (soak.sh credit) so the request meets its own rule:
# a malformed descriptor (bad-descriptor), a transfer far over the balance (overdraw), a second
# exit request under an accepted nonce (nonce-reuse): each must be refused; and a 1-msat exit
# (dust-exit), which DEP-20 §3 accepts and holds pending.  Any other outcome is a FINDING in
# $SOAK/log/hostile.log.
# The oracle separately watches that no member accuses the operator over any of them.
# Touch $SOAK/hostile.pause to pause.
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; EVERY=${HOSTILE_EVERY:-1200}
ACTIONS=(${HOSTILE_ACTIONS:-bad-descriptor overdraw dust-exit nonce-reuse})
mkdir -p "$CLD_ROOT/wallets/hostile"
while true; do
  sleep "$EVERY"
  [ -e "$SOAK/hostile.pause" ] && continue
  mapfile -t rows <"$SOAK/ledgers.tsv"; row=${rows[$((RANDOM % ${#rows[@]}))]}
  name=$(cut -f1 <<<"$row"); id=$(cut -f2 <<<"$row"); a=${ACTIONS[$((RANDOM % ${#ACTIONS[@]}))]}
  key="$CLD_ROOT/wallets/hostile/$(date +%s)-$RANDOM.key"
  hw() { (cd "$CLD_SRC" && CL_SOURCE_REGISTRY="$(cld_registry)" CLD_RELAYS="$RELAY_URL" HOSTILE_ADDRESS="$(wcli getnewaddress 2>/dev/null)" HOSTILE_HEIGHT="$(bcli getblockcount)" \
          timeout 300 "${CLD_SBCL:-/usr/bin/sbcl}" --noinform --non-interactive --load devnet/hostile-wallet.lisp -- "$key" "$id" "$1" 2>&1 | grep -E '^\(:ACTION' | tail -1); }
  dep=""
  if [ "$a" != bad-descriptor ]; then   # a funded deposit, so the request meets its own rule and not the balance check
    dep=$(hw open | grep -oE ':DETAIL "[0-9a-f]{32,64}"' | grep -oE '[0-9a-f]{32,64}')
    [ -n "$dep" ] && ! "$CLD_SRC/devnet/soak.sh" credit "$name" "$dep" 2000000 >/dev/null 2>&1 && dep=""
  fi
  out=$(HOSTILE_DEPOSIT="$dep" hw "$a")
  [ -n "$dep" ] && out="$out (funded ${dep:0:8})"
  # DEP-20 §3 accepts a dust exit and keeps it pending (carried to a later rotation, or released by
  # cancel or expiry): the request is not refused, it just never becomes due.  The rest must be refused.
  case "$a:$out" in
    dust-exit:*":REFUSED NIL"*) v=held;;
    dust-exit:*":REFUSED T"*) v=FINDING;;
    *":REFUSED T"*) v=refused;;
    *":REFUSED NIL"*) v=FINDING;;
    *) v=no-answer;;
  esac
  echo "$(date +%FT%T) $v $a on $name: ${out:-(no result line)}" | cut -c1-260
done
