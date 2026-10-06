#!/usr/bin/env bash
# redteam/attack-veto-pledge.sh — one armer tries to veto a confiscation by spending its pledge.
#
# A dispute on a fresh ledger V runs to arming.  One member (VC, the adversary
# :spend-pledge) arms and immediately spends the replacement collateral it pledged.
# Under the old DEP-03 rule every cosigner then refused the confiscation and the
# dispute stalled for good (found by ref7 by accident, 2026-10-02).  DEP-03 now
# makes the participant set an eligibility cut: PASS when the confiscation lands
# on chain without VC's veto (VC excluded, or a participant that loses the lottery
# or forfeits as WinnerCollateralDeviation).  FAIL when it never lands.
# Modes ($1): veto (default) — every other member arms honestly; sole — a cl-only quorum where
# the colluders who cosigned the fraud arm but spend their pledges, so one honest armer (H)
# is the only eligible one and must take custody without a draw; reopen — H also spends its
# pledge (nobody is eligible), then stops, and must re-arm with a fresh pledge and take custody.
# REDTEAM_VP=name forms a fresh test ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"
S="$CLD_ROOT/soak"; source "$S/env"; WAIT=${WAIT:-400}
source "$(dirname "$0")/_lib.sh"
MODE=${1:-veto}
pick OP VC C2 C3 C4 H
trap 'disarm :spend-pledge "$VC" $H $C2 $C3 $C4' EXIT
case "$MODE" in sole) ROW=${REDTEAM_VPS:-VPS};; reopen) ROW=${REDTEAM_VPR:-VPR};; *) ROW=${REDTEAM_VP:-VP};; esac
REFS=${REFS-ref6 ref7}
[ "$MODE" = veto ] || REFS=""   # sole/reopen: count the armers exactly
V=$(COLLATERAL_SATS=25000000 RESP=${RESP:-5} form_ledger "$ROW" $OP "" $C2 $C3 $C4 $H $VC $REFS) || exit 1; echo "== V $V"
mapfile -t DEPS < <(fresh_deposits "$ROW" $OP "$V" 1); FROM=${DEPS[0]:-}; [ -n "$FROM" ] || fail "no deposit on V"

# Arm the adversary before the fraud: an honest member disputes (and arms) on sight of it, before a
# switch set afterwards could take effect (veto-pledge-sole, 2026-10-03: VC armed and kept its pledge).
expect "$(cld_ctl $VC "(:adversary :set :spend-pledge t)")"
[ "$MODE" = reopen ] && expect "$(cld_ctl $H "(:adversary :set :spend-pledge t)")"
if [ "$MODE" != veto ]; then   # the colluders who cosigned stay out of the dispute
  # They dispute but spend their pledges, so they are excluded.  As :ignore-fraud they held no
  # fork and never signed: the confiscation lacked its 4 of 5 signers, a majority refusing
  # blocks Tier 0 by design, and that is not what this mode tests (1006 runs).
  for n in $C2 $C3 $C4; do expect "$(cld_ctl $n "(:adversary :set :spend-pledge t)")"; done
fi

# The fraud: $OP locks a depositor's funds with no witness and a majority of members cosign blind:
# $C2..$C4 of the 5-member cl-only quorum (sole/reopen); $C2..$H of the 7 with $REFS (veto),
# leaving $VC and the reference members honest.  With only three blind of seven, the lock never
# reached the 4 cosignatures it needs and nothing was ever disputed.
BLIND="$C2 $C3 $C4"; [ "$MODE" = veto ] && [ -n "$REFS" ] && BLIND="$C2 $C3 $C4 $H"
for n in $BLIND; do expect "$(cld_ctl $n "(:adversary :set :cosign-blind t)")"; done
cld_ctl $OP "(:forge-lock :ledger \"$V\" :from \"$FROM\" :to \"$FROM\" :msat 1000000)" >/dev/null
sleep 10
for n in $BLIND; do cld_ctl $n "(:adversary :set :cosign-blind nil)" >/dev/null; done
taint "$OP" $BLIND   # it committed the fraud; the blind cosigners signed it

echo "== $VC disputes V; it will spend its pledge right after arming"
cld_ctl $VC "(:dispute-enter :ledger \"$V\" :reason \"redteam veto-pledge\")" >/dev/null

# Logs outlive a scenario (an earlier run's "spent our pledge" on $H released it at once): count
# only lines that were not already there when this run started.
OLD=$(for n in $VC $H $C2; do cld_ctl $n '(:log)' 2>/dev/null; done | tr '"' '\n' | grep "adversary: spent our pledge" | sort -u)
fresh() { grep -vxF -f <(printf '%s\n' "${OLD:-@@none@@}"); }
echo "== waiting for the confiscation (up to ${WAIT}s)"
conf=""; spent=""; excluded=""; released=""
for i in $(seq 1 $WAIT); do
  logs=$(for n in $VC $H $C2; do cld_ctl $n '(:log)' 2>/dev/null; done | tr '"' '\n')
  [ -z "$spent" ] && spent=$(echo "$logs" | grep "adversary: spent our pledge" | fresh | head -1)
  [ -z "$excluded" ] && excluded=$(echo "$logs" | grep -m1 "excluded from ${V:0:8}'s lottery")
  conf=$(echo "$logs" | grep -F "dispute ${V:0:8}:" | grep -oE "confiscation [0-9a-f]{64} on chain" | grep -oE '[0-9a-f]{64}' | head -1)
  [ -n "$conf" ] && [ -n "$(bcli getrawtransaction "$conf" 2>/dev/null | head -c1)" ] && break
  conf=""
  # reopen: once the honest armer has spent its pledge too, let it recover and re-arm.
  if [ "$MODE" = reopen ] && [ -z "$released" ] && cld_ctl $H '(:log)' 2>/dev/null | tr '"' '\n' | grep "adversary: spent our pledge" | fresh | grep -q .; then
    mine 2 >/dev/null; cld_ctl $H "(:adversary :set :spend-pledge nil)" >/dev/null; released=1
    echo "  [$i] $H spent its pledge too (nobody eligible); it may now re-arm"
  fi
  [ $((i % 6)) -eq 0 ] && mine 1 >/dev/null
  sleep 5
done
cld_ctl $VC "(:adversary :set :spend-pledge nil)" >/dev/null
taint "$VC"
echo "   pledge spent: ${spent:-not seen}"
echo "   exclusion:    ${excluded:-not logged by cl members}"
for r in $REFS; do grep -h "excluded from the lottery" "$CLD_ROOT/$r/node.log" 2>/dev/null | tail -1 | sed "s/^/   $r: /"; done
[ -n "$spent" ] || fail "the adversary never spent its pledge (did $VC arm with one?)"
[ -n "$conf" ] || fail "no confiscation within ${WAIT}s: a spent pledge still vetoes the dispute"
n_out=$(bcli getrawtransaction "$conf" true 2>/dev/null | grep -c '"scriptPubKey"')
case "$MODE" in
  veto) echo "PASS: the confiscation $conf landed although $VC spent its pledge; one armer can no longer veto.";;
  sole|reopen)
    # A re-arm is logged "re-armed: ..." when the first arm is replaced, or as a plain "armed, pledging"
    # with a coin other than the one spent when the spend overtook the first arm (regtest's 10 s blocks).
    c5=$(cld_ctl $H '(:log)' 2>/dev/null | tr '"' '\n')
    gone=$(echo "$c5" | grep "adversary: spent our pledge" | fresh | grep -oE '[0-9a-f]{64}:[0-9]+' | head -1)
    rearm=$(echo "$c5" | grep -m1 "re-armed")
    [ -z "$rearm" ] && rearm=$(echo "$c5" | grep -F "dispute ${V:0:8}: armed, pledging" | grep -vF "${gone:-none}" | head -1)
    [ "$MODE" = reopen ] && { [ -n "$rearm" ] || fail "$H never re-armed (${rearm:-no log})"; echo "   $rearm"; }
    echo "PASS ($MODE): the confiscation $conf landed with $H the only eligible armer (it takes custody without a draw).";;
esac
