#!/usr/bin/env bash
# redteam/attack-soak-fault.sh FAULT — one operator fault on a fresh ledger, judged end to end.
# Written for the live soak (devnet/soak-attackers.sh) but runs anywhere: every actor comes from the
# red-team pool (pick), never a soak operator, and the reference member ($FAULT_REFS, default ref6)
# is a soak node, so live soak state takes part.
#
# Members: M1 M2 M3 (cl, colluders where the fault needs a majority), H (cl, honest) and the
# reference member: five, so Q is valid (DEP-05).
#
#   forge-lock      OP locks a deposit with no depositor witness; M1..M3 cosign blind, so it commits.
#   invalid-credit  OP credits twice the reserves; M1..M3 cosign blind, so it commits.
#   equivocate      OP signs two updates at its tip sequence.  Nobody colludes.
#   PASS for these three = a proof names OP, the vault is confiscated (no member takes the spend
#        for a theft) and the lottery output is claimed by exactly one member.
#
#   omit-commitments     OP credits a deposit declaring no balance commitments (v6/v7: refused).
#   falsify-commitments  OP credits a deposit declaring a balance 1 msat off.  Nobody colludes.
#   PASS for these two = the operation does not commit, and the honest members accuse no one: a
#        refusal to cosign proves nothing (the oracle watches for any proof).
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env" 2>/dev/null
FAULT=${1:?forge-lock|invalid-credit|equivocate|omit-commitments|falsify-commitments}; WAIT=${WAIT:-2400}
source "$(dirname "$0")/_lib.sh"
# Attacker roles (OP and the colluders, which are burned for good) come only from nodes outside the
# soak ($S/soak-nodes, written by devnet/soak-attackers.sh), minted on demand, so no soak member is
# ever made a colluder and loses its collateral to contagion.  The honest member H may be a soak node.
SOAK_NODES=$(cat "$S/soak-nodes" 2>/dev/null | tr '\n' ' ')
REDTEAM_AVOID="${REDTEAM_AVOID:-} $SOAK_NODES" pick OP M1 M2 M3
REDTEAM_AVOID="${REDTEAM_AVOID:-} $OP $M1 $M2 $M3" pick H
REFS=${FAULT_REFS-ref6}
ROW=${REDTEAM_SF:-SF${FAULT:0:2}$RANDOM}
E=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $M1 $M2 $M3 $H $REFS) || exit 1; echo "== ledger $E ($FAULT)"
read -r CTX CVOUT <"$S/redteam-$ROW.outpoint"
D=$(fresh_deposits "$ROW" $OP "$E" 1 | head -1); [ -n "$D" ] || fail "no deposit on the ledger"
VAULT=$(cld_ctl $OP '(:vaults)' | tr '()' '\n\n' | grep -F "\"$E\"" -A1 | grep -oE '[0-9a-f]{64}:[0-9]+' | tail -1)
[ -n "$VAULT" ] || fail "no vault for $E"; VINTX=${VAULT%:*}; VINVOUT=${VAULT#*:}
OPK=$(pubkey_of $OP)
seq_of() { cld_ctl $H "(:info)" | grep -oE "\(:ID \"$E\"[^)]*" | grep -oE ':SEQ [0-9]+' | cut -d' ' -f2; }
S0=$(seq_of)
blind() { for n in $M1 $M2 $M3; do cld_ctl $n "(:adversary :set :cosign-blind $1)" >/dev/null; done; }
cleanup() {
  blind nil; for k in :sign-invalid :omit-commitments :falsify-commitments; do cld_ctl $OP "(:adversary :set $k nil)" >/dev/null 2>&1; done
  # Burned nodes stay up: they are still members of this ledger and of its dispute, and a stopped
  # member cannot answer a challenge of the confiscation it signed (Nov 4: one lapsed unanswered).
}
trap cleanup EXIT

case $FAULT in
  forge-lock)
    blind t; cld_ctl $OP "(:forge-lock :ledger \"$E\" :from \"$D\" :to \"$D\" :msat 1000000)" >/dev/null; sleep 15; blind nil
    taint $OP $M1 $M2 $M3;;
  invalid-credit)
    RES=$(cld_ctl $OP "(:info)" | grep -oE "\(:ID \"$E\"[^)]*" | grep -oE ':RESERVES [0-9]+' | cut -d' ' -f2)
    blind t; cld_ctl $OP "(:adversary :set :sign-invalid t)" >/dev/null
    cld_ctl $OP "(:credit :ledger \"$E\" :deposit \"$D\" :msat $(( ${RES:-25000000000} * 2 )) :txid \"$CTX\" :vout $CVOUT)" >/dev/null
    sleep 15; cld_ctl $OP "(:adversary :set :sign-invalid nil)" >/dev/null; blind nil
    taint $OP $M1 $M2 $M3;;
  equivocate)
    expect "$(cld_ctl $OP "(:equivocate :ledger \"$E\")")" "equivocate"; taint $OP;;
  omit-commitments|falsify-commitments)
    cld_ctl $OP "(:adversary :set :$FAULT t)" >/dev/null
    R=$(cld_ctl $OP "(:credit :ledger \"$E\" :deposit \"$D\" :msat 1000 :txid \"$CTX\" :vout $CVOUT)")
    cld_ctl $OP "(:adversary :set :$FAULT nil)" >/dev/null
    echo "== operator's attempt: $(echo "$R" | cut -c1-200)"
    sleep 30; S1=$(seq_of)
    echo "== $E seq before $S0, after $S1"
    for n in $M1 $M2 $M3 $H; do echo "   $n: $(cld_ctl $n '(:log)' | tr '"' '\n' | grep -E "refused cosign|BALANCE-COMMITMENT|MISSING-BALANCE" | grep -F "${E:0:8}" | tail -1 | cut -c1-150)"; done
    echo "   ${REFS:-no reference}: $(tail -c 5000000 "$(ref_dir ${REFS%% *})/node.log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -F "${E:0:16}" | grep -iE "commitment|refus" | tail -1 | cut -c1-160)"
    [ "${S1:-x}" = "${S0:-y}" ] || fail "the $FAULT credit committed (seq $S0 -> $S1)"
    sleep 60
    for n in $M1 $M2 $M3 $H; do
      cld_ctl $n "(:forks :ledger \"$E\")" | grep -q ':STATE :\(DISPUTED\|ARMED\)' && fail "$n disputed $E over a refused $FAULT"
    done
    echo "PASS: $OP's $FAULT credit on $E was refused (seq stayed $S0) and nobody disputed."
    exit 0;;
  *) fail "unknown fault $FAULT";;
esac
echo "$(date +%s) $FAULT ${E:0:16} ${OPK:2:16} $WAIT" >>"$S/attacks.tsv"   # x-only prefix, as proofs name keys

proven=""; spent=""; claim=""
for i in $(seq 1 $((WAIT / 10))); do
  [ -n "$proven" ] || proven=$(for n in $H $M1; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "NON-CONFORMING|EQUIVOCAT|quivocat|dispute ${E:0:8}" | grep -F "${E:0:8}" | head -1; done | head -1)
  if [ -z "$spent" ] && [ -z "$(bcli gettxout "$VINTX" "$VINVOUT" true 2>/dev/null | head -1)" ]; then
    spent=$(bcli gettxspendingprevout "[{\"txid\":\"$VINTX\",\"vout\":$VINVOUT}]" 2>/dev/null \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)[0].get("spendingtxid","") or "in a block")' 2>/dev/null)
    echo "== vault spent (${spent:-?}) after $((i * 10)) s"
  fi
  if [ -n "$spent" ]; then
    claim=$(for n in $M1 $M2 $M3 $H; do cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F "dispute ${E:0:8}: lottery: won" | head -1 | sed "s/^/$n: /"; done)
    [ -n "$claim" ] && break
    tail -c 3000000 "$(ref_dir ${REFS%% *})/node.log" 2>/dev/null | grep -F "${E:0:16}" | grep -qiE "won the lottery|claim(ed)? .*custody|DisputeAcquire" && { claim="${REFS%% *}: reference"; break; }
  fi
  # On signet the soak's own miner keeps time: mining here too would shorten every window in the soak.
  [ "$CLD_CHAIN" = regtest ] && [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null
  sleep 10
done
echo "== detection: ${proven:-none}"
[ -n "$proven" ] || fail "no honest member detected $OP's $FAULT within ${WAIT}s"
[ -n "$spent" ] || fail "the $FAULT was detected but $E's vault was not confiscated within ${WAIT}s"
for n in $M1 $M2 $M3 $H; do
  cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -E "VAULT SPEND" | grep -qF "${E:0:8}" && fail "$n took the confiscation of $E for a theft"
done
[ -n "$claim" ] || fail "$E's vault was confiscated but no member claimed the lottery within ${WAIT}s"
[ "$(printf '%s\n' "$claim" | grep -c 'lottery: won')" -le 1 ] || fail "more than one member won the lottery"
echo "PASS: $OP's $FAULT on $E was detected, its vault confiscated ($spent) and the lottery claimed (${claim%%:*})."
