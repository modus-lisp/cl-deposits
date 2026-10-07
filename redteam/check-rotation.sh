#!/usr/bin/env bash
# redteam/check-rotation.sh — a cl operator's rotation is a real DEP-03 rotation, on chain.
#
# A fresh ledger operated by a cl node with a mixed quorum (one cl member, two reference
# members: the tier-0 majority needs a reference signature) is rotated with :rotate-vault:
# the old vault is spent by the rotation, the QuorumBegin names the rotation's output 0, and
# the new vault is unspent.  Then a leftover check over every ledger each cl node operates:
# for every QuorumBegin after the first, the previous vault is spent by the next one's
# transaction (a vault funded fresh, leaving the old one behind, is reported as a leftover).
# PASS = the rotation lands as above and no rotation made by this code left a prior vault.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
pick OP C1
R1=${R1:-ref6}; R2=${R2:-ref7}
T0=$(date +%s)
# This code, not whatever they started with: the actors, and every cl operator of a soak ledger.
for n in $OP $C1 ${ROTATION_RESTART:-$(awk -F'\t' '$3 ~ /^cld/ {print $3}' "$S/ledgers.tsv" | sort -u)}; do
  cld_running $n || continue; stop_cld $n >/dev/null; start_cld $n >/dev/null &
done; wait
X=$(form_ledger "${REDTEAM_ROT:-ROT$RANDOM}" $OP "" $C1 $R1 $R2) || exit 1
OLD=$(cld_ctl $OP "(:vaults)" | grep -oE "\"$X\" \(\"[0-9a-f]{64}:[0-9]+\"" | grep -oE '[0-9a-f]{64}:[0-9]+')
[ -n "$OLD" ] || fail "no vault recorded for $X"
echo "== ledger $X, vault $OLD"
consent "$X" $OP $C1 $R1 $R2
r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); expect "$r" "rotate-vault"
RT=$(sx "$r" ":TXID"); echo "== rotation $RT ($(sx "$r" ":SATS") sats)"
mine 3 >/dev/null; sleep 20
for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r"; mine 1 >/dev/null; sleep 15; done
expect "$r" "begin-quorum"
[ -z "$(bcli gettxout "${OLD%:*}" "${OLD#*:}")" ] || fail "the old vault $OLD is unspent after the rotation"
spender=$(bcli getrawtransaction "$RT" true | python3 -c "import json,sys; t=json.load(sys.stdin); print(' '.join(f\"{i['txid']}:{i['vout']}\" for i in t['vin']))")
[[ " $spender " == *" $OLD "* ]] || fail "the rotation $RT does not spend the old vault $OLD (it spends $spender)"
NEW=$(cld_ctl $OP "(:vaults)" | grep -oE "\"$X\" \([^)]*\)" | grep -oE '[0-9a-f]{64}:[0-9]+' | tail -1)
[ "$NEW" = "$RT:0" ] || fail "the QuorumBegin names $NEW, not the rotation's output $RT:0"
[ -n "$(bcli gettxout "$RT" 0)" ] || fail "the new vault $RT:0 is not unspent"
signers=$(cld_ctl $C1 "(:log :n 2000)" | grep -c "signing rotation of ${X:0:8}")
echo "   rotation signed: cl member signed $signers; reference successes $(cat "$CLD_ROOT/$R1/node.log" "$CLD_ROOT/$R2/node.log" 2>/dev/null | grep -c "action=rotation_sign, ledger=${X:0:16}.*success=true")"
echo "== mixed-quorum rotation on chain: $OLD -> $RT:0"
# Leftovers: across every cl node's owned ledgers.
leftover=0 legacy=0 checked=0
for n in $(cld_names); do
  cld_running "$n" || continue
  out=$(cld_ctl "$n" "(:vaults)" 2>/dev/null) || continue
  while read -r line; do
    set -- $(grep -oE '[0-9a-f]{64}:[0-9]+' <<<"$line")
    prev=""
    for v in "$@"; do
      if [ -n "$prev" ]; then
        checked=$((checked+1))
        if [ -n "$(bcli gettxout "${prev%:*}" "${prev#*:}")" ]; then
          # Its successor was not a rotation of it.  Recorded since this code took over (T0)?
          bt=$(bcli getrawtransaction "${v%:*}" true 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('blocktime',0))" 2>/dev/null)
          if [ "${bt:-0}" -ge "$T0" ]; then leftover=$((leftover+1)); echo "   LEFTOVER on $n: $prev unspent; its successor $v (since T0) did not spend it"
          else legacy=$((legacy+1)); fi
        fi
      fi
      prev=$v
    done
  done < <(grep -oE '\("[0-9a-f]{64}" \([^)]*\)\)' <<<"$out")
done
echo "   prior vaults checked: $checked; left unspent by a fresh-funded QuorumBegin before this code: $legacy; since: $leftover"
[ $leftover -eq 0 ] || fail "$leftover rotation(s) left a prior vault unspent"
echo "PASS: the cl rotation spent its old vault on chain with a mixed quorum, and no rotation left a prior vault behind."
