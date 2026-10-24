#!/usr/bin/env bash
# devnet/soak-rotate.sh — DEP-11 §Quorum Rotation, done from outside for the cl
# operators (the reference operators rotate themselves): every SOAK_ROTATE_EVERY
# seconds, any cl-operated soak ledger within SOAK_ROTATE_MARGIN blocks of its
# quorum_expiry (or past it) is rotated: members re-consent, the operator spends
# the old vault into the new reserves, and a QuorumBegin is appended.  The vault
# outpoint in ledgers.tsv is replaced (credits reference it).
#
# A cl operator that does not rotate loses value-moving operations at expiry
# ("not cosignable at TIER0-POST-EXPIRY") — the soak's first night.  The
# expiry is the SHORTEST member commitment; with a reference member it is
# ~950 blocks, i.e. ~16 h at a block a minute.  The rotation spends the old vault
# into the new one (DEP-03, :rotate-vault); node-side auto-rotation is open.
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
  # DEP-03: the rotation spends the old vault into the new one (no fresh funding); a
  # rotation already broadcast but not yet recorded is resumed by :begin-quorum.
  # A rotation recorded already (an earlier pass's begin-quorum outlived its control call)
  # only awaits its rung signatures: :begin-quorum resumes it.
  r=$(cld_ctl "$op" "(:rotate-vault :ledger \"$id\" :expiry-blocks 4320)")
  if [[ "$r" == *":STATUS :OK"* || "$r" == *"already recorded"* ]]; then :
  else echo "   rotate-vault: ${r:-no answer in ${CLD_CTL_TIMEOUT:-60}s}"; return 1; fi
  mine 3
  sleep 25   # reference members' wallets see the outpoint through the shim on a timer
  # begin-quorum cosigns the QuorumBegin, then gathers the rung signatures (up to 90 s): give
  # it the time.  The rung recorded is its :TXID, not the one rotate-vault planned on an older tip.
  r=$(CLD_CTL_TIMEOUT=${SOAK_BEGIN_QUORUM_TIMEOUT:-300} cld_ctl "$op" "(:begin-quorum :ledger \"$id\")")
  [[ "$r" == *":STATUS :OK"* ]] || { echo "   begin-quorum: ${r:-no answer in ${SOAK_BEGIN_QUORUM_TIMEOUT:-300}s (the node may still finish it)}"; return 1; }
  txid=$(sx "$r" ":TXID"); vout=0
  [ -n "$txid" ] || echo "   begin-quorum: QuorumBegin seq $(sx "$r" ":SEQ") recorded; its rungs still await signatures (the node rebroadcasts once signed)"
  [ -n "$txid" ] && python3 - "$SOAK/ledgers.tsv" "$name" "$txid" "$vout" <<'PY'
import sys; p,name,txid,vout=sys.argv[1:]
rows=[l.rstrip('\n').split('\t') for l in open(p)]
for r in rows:
    if r[0]==name: r[3]=txid; r[4]=vout
open(p,'w').write(''.join('\t'.join(r)+'\n' for r in rows))
PY
  # Rotated only if the expiry moved: begin-quorum also answers OK when it resumes a recorded
  # QuorumBegin whose rungs still await signatures, and nothing is spent until they arrive.
  local info new_exp
  info=$(cld_ctl "$op" "(:info)" | grep -oE "\(:ID \"$id\"[^)]*:MEMBERS [1-9][^)]*" | head -1)
  new_exp=$(grep -oE ':EXPIRY [0-9]+' <<<"$info" | cut -d' ' -f2)
  if [ -n "$new_exp" ] && [ "$new_exp" = "${ROT_EXP_BEFORE:-}" ]; then
    echo "$(date +%FT%T) $name: QuorumBegin recorded, rungs still await signatures (expiry ${new_exp}); retrying next pass"
    return 1
  fi
  echo "$(date +%FT%T) $name rotated: $(grep -oE ':SEQ [0-9]+|:EXPIRY [0-9]+' <<<"$info" | tr '\n' ' ')"
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
    if [ $((exp - h)) -le "$MARGIN" ]; then ROT_EXP_BEFORE=$exp rotate "$name" "$id" "$op" "$members" || echo "$(date +%FT%T) $name rotation FAILED (height $h, expiry $exp)"; fi
  done
  sleep "$EVERY"
done
