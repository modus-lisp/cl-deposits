#!/usr/bin/env bash
# devnet/soak-rotate.sh — DEP-11 §Quorum Rotation, done from outside for the cl
# operators (the reference operators rotate themselves): every SOAK_ROTATE_EVERY
# seconds, any cl-operated soak ledger within SOAK_ROTATE_MARGIN blocks of its
# quorum_expiry (or past it) is rotated: members re-consent, a fresh reserves
# output is funded from the miner, and a QuorumBegin is appended.  The funding
# outpoint in ledgers.tsv is replaced (credits reference it).
#
# A cl operator that does not rotate loses value-moving operations at expiry
# ("not cosignable at TIER0-POST-EXPIRY") — the soak's first night.  The
# expiry is the SHORTEST member commitment; with a reference member it is
# ~950 blocks, i.e. ~16 h at a block a minute.  Node-side auto-rotation, and a
# rotation that SPENDS the old vault rather than funding a new one, are open.
source "$(dirname "$0")/_common.sh"; source "$CLD_ROOT/soak/env"
SOAK="$CLD_ROOT/soak"; EVERY=${SOAK_ROTATE_EVERY:-600}; MARGIN=${SOAK_ROTATE_MARGIN:-300}
# A rotates to cld4 in place of ref2: ref2 forked A at 81026 (docs/REDTEAM.md
# organic #1) and has treated A as a gap since, so it never re-consents.
PLAN=${SOAK_LEDGER_PLAN:-$(soak_plan)}
# Cached at soak setup: the reference CLI loads the node's whole data dir to print it (minutes on a soaked node).
pubkey_of() { [ -s "$SOAK/pubkey.$1" ] && { cat "$SOAK/pubkey.$1"; return; }; case "$1" in cld*) cld_pubkey "$1";; ref*) ref_pubkey "$1";; esac; }
own_ledger_of() { local v; case "$1" in cld*) v="L${1#cld}";; ref*) v="RL${1#ref}";; esac; echo "${!v}"; }
rotate() {   # rotate NAME ID OPERATOR "m1,m2,m3"
  local name=$1 id=$2 op=$3 members=$4 m r prep addr txid vout
  echo "$(date +%FT%T) rotating $name ($op)"
  for m in ${members//,/ }; do
    r=$(cld_ctl "$op" "(:add-member :ledger \"$id\" :member \"$(pubkey_of "$m")\" :member-ledger \"$(own_ledger_of "$m")\")")
    [[ "$r" == *":STATUS :OK"* ]] || { echo "   $m consent: $r"; return 1; }
  done
  prep=$(cld_ctl "$op" "(:prepare-quorum :ledger \"$id\" :expiry-blocks 4320)"); [[ "$prep" == *":STATUS :OK"* ]] || { echo "   prepare: $prep"; return 1; }
  addr=$(sx "$prep" ":ADDRESS"); txid=$(wcli sendtoaddress "$addr" 0.5) || return 1; mine 3
  vout=$(bcli getrawtransaction "$txid" true | python3 -c "import json,sys; tx=json.load(sys.stdin); print([o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address')=='$addr'][0])")
  sleep 25   # reference members' wallets see the outpoint through the shim on a timer
  r=$(cld_ctl "$op" "(:begin-quorum :ledger \"$id\" :txid \"$txid\" :vout $vout :sats 20000000 :collateral-sats 30000000)")
  [[ "$r" == *":STATUS :OK"* ]] || { echo "   begin-quorum: $r"; return 1; }
  python3 - "$SOAK/ledgers.tsv" "$name" "$txid" "$vout" <<'PY'
import sys; p,name,txid,vout=sys.argv[1:]
rows=[l.rstrip('\n').split('\t') for l in open(p)]
for r in rows:
    if r[0]==name: r[3]=txid; r[4]=vout
open(p,'w').write(''.join('\t'.join(r)+'\n' for r in rows))
PY
  echo "$(date +%FT%T) $name rotated: $(cld_ctl "$op" "(:info)" | grep -oE "\(:ID \"$id\"[^)]*:MEMBERS [1-9][^)]*" | grep -oE ':SEQ [0-9]+|:EXPIRY [0-9]+' | tr '\n' ' ')"
}
declare -A STOOD_DOWN
while true; do
  h=$(bcli getblockcount 2>/dev/null) || { sleep 60; continue; }
  for spec in $PLAN; do
    IFS=: read -r name op members <<<"$spec"; [[ "$op" == cld* ]] || continue
    id=$(awk -F'\t' -v n="$name" '$1==n {print $2}' "$SOAK/ledgers.tsv"); [ -n "$id" ] || continue
    cld_running "$op" || continue
    row=$(cld_ctl "$op" "(:info)" 2>/dev/null | grep -oE "\(:ID \"$id\"[^)]*:MEMBERS [1-9][^)]*" | head -1)
    exp=$(grep -oE ':EXPIRY [0-9]+' <<<"$row" | cut -d' ' -f2); [ -n "$exp" ] || continue
    # A quorum majority that forked this ledger has disputed its operator: custody follows the
    # dispute (DEP-06), the operator stands down, and re-consent can never succeed.
    nm=$(grep -oE ':MEMBERS [0-9]+' <<<"$row" | cut -d' ' -f2); nd=$(grep -oE ':DISPUTED [0-9]+' <<<"$row" | cut -d' ' -f2)
    if [ "${nd:-0}" -gt $(( nm - (nm / 2 + 1) )) ] || grep -qE ':CUSTODY-MOVED "' <<<"$row"; then
      [ -n "${STOOD_DOWN[$name]:-}" ] || echo "$(date +%FT%T) $name: $op stood down ($nd of $nm members disputed it; custody moved: $(grep -oE ':CUSTODY-MOVED [^ ]+' <<<"$row" | cut -d' ' -f2)); not rotating"
      STOOD_DOWN[$name]=1; continue
    fi
    if [ $((exp - h)) -le "$MARGIN" ]; then rotate "$name" "$id" "$op" "$members" || echo "$(date +%FT%T) $name rotation FAILED (height $h, expiry $exp)"; fi
  done
  sleep "$EVERY"
done
