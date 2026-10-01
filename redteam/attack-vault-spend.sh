#!/usr/bin/env bash
# redteam/attack-vault-spend.sh — unauthorised vault spend (DEP-06 type 7, docs/MISSING.md).
#
# Detection landed in cl (UnauthorizedVaultSpend, proof discriminant 10): every node that
# replicates the ledger watches its vault outpoint, and a spend no QuorumBegin or confiscation
# accounts for is proved against each signer and slashed on every ledger that signer operates.
# PASS now means the honest minority DETECTED it.  (Before, it demonstrated the gap: no reaction.)
#
# A colluding majority of a ledger's quorum spends the vault's reserves outpoint
# at Tier 0 to an address of theirs — no dispute, no rotation, no confiscation.
# The colluders are the operator (cld1) and three of its cosigners (cld2 cld3
# cld4), a majority of Q = 7.  The honest minority (cld5 cld6 ref6 ref7) sees
# nothing: no watch on the vault outpoint exists in either implementation.
#
# PASS (the finding, not a protocol property): the theft broadcast succeeds and
# no honest node reacts within $WAIT s — no dispute, no fraud proof, no log line
# about the spend.  The script also reports the theft txid and how long the funds
# sat capturable.  REDTEAM_V=name forms a fresh test ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-120}
source "$(dirname "$0")/_lib.sh"
ROW=${REDTEAM_V:-V}   # REFS="" forms a cl-only quorum
V=$(form_ledger "$ROW" cld1 "" cld2 cld3 cld4 cld5 cld6 ${REFS-ref6 ref7}) || exit 1
echo "== V $V (cld1 operates; cld2 cld3 cld4 cld5 cld6 ${REFS-ref6 ref7} cosign)"

# The thieves' destination: cld2's own address (its node key's P2TR).
DEST=$(sx "$(cld_ctl cld2 '(:address)')" ":ADDRESS")
echo "== thieves: cld1 (operator) + cld2 cld3 cld4 cld5 (threshold 5 of 8); destination $DEST"

# Arm the colluders: they will sign each other's theft proposals.
for n in cld2 cld3 cld4 cld5; do expect "$(cld_ctl $n "(:adversary :set :theft-sign t)")"; done

T0=$(date -u +%s)
echo "== spending the vault at Tier 0"
# cld_ctl's 60s timeout is shorter than the daemon's 90s signature-collection window:
# talk to the control port directly with a longer timeout for this one call.
out=$(printf '%s\n' "(:vault-spend :ledger \"$V\" :address \"$DEST\")" | timeout 180 bash -c "exec 3<>/dev/tcp/127.0.0.1/$(cld_port cld1); cat >&3; head -n1 <&3")
echo "$out" | head -2
case "$out" in *":STATUS :OK"*) ;; *) fail "theft failed: $out";; esac
THEFT_TXID=$(sx "$out" ":TXID"); SIGS=$(sx "$out" ":SIGS")
echo "== theft broadcast: $THEFT_TXID ($SIGS signatures) at $(date -u +%H:%M:%S)"

# Confirm it landed on chain.
mine 5
sleep 5
spent=$(bcli gettxout "$THEFT_TXID" 0 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['value'])" 2>/dev/null)
[ -n "$spent" ] && echo "== theft output live on chain: $spent BTC at $THEFT_TXID:0" || echo "== (theft output not found via gettxout — check $THEFT_TXID)"

# What do the honest nodes do?  The watch runs once a minute; the spend needs 3 blocks of grace.
echo "== watching the honest minority (cld6) for ${WAIT}s"
detected=0
for i in $(seq 1 $WAIT); do
  detected=$(cld_ctl cld6 '(:log)' 2>/dev/null | grep -c "VAULT SPEND" || true)
  [ "$detected" -gt 0 ] && break
  sleep 1
done
echo "== cld6 VAULT SPEND log lines: $detected"
sleep 30
for n in cld6; do
  echo "--- $n"; cld_ctl $n '(:log)' 2>/dev/null | grep -E "VAULT SPEND|vault spend|unauthori" | tail -12
done
# Contagion: the signers' other ledgers (L1 L2 L3 L4 L5) should be disputed by cld6's quorums.
disputed=0
for l in "$L1" "$L2" "$L3" "$L4" "$L5"; do
  d=$(cld_ctl cld6 "(:forks :ledger \"$l\")" 2>/dev/null | grep -c ":SEQ" || true)
  [ "$d" -gt 0 ] && disputed=$((disputed + 1))
done
echo "== signer ledgers disputed by cld6: $disputed"

for n in cld2 cld3 cld4 cld5; do cld_ctl $n "(:adversary :set :theft-sign nil)" >/dev/null; done

if [ "$detected" -gt 0 ]; then
  echo "PASS: the honest minority detected the unauthorised vault spend $THEFT_TXID and proved it ($disputed signer ledgers disputed)."
else
  fail "no honest node detected the vault spend $THEFT_TXID within ${WAIT}s"
fi
