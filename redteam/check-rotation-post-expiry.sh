#!/usr/bin/env bash
# redteam/check-rotation-post-expiry.sh — a rotation past quorum_expiry is allowed, never owed
# (DEP-05 §Cosignature Threshold, DEP-06 §Race; ruled 2026-11-14: "we can allow it, but we can't
# require members to sign"; amended 2026-11-15: under strict-lottery-v8 an expiry dispute ends only
# once the re-establishment's spend of the vault confirms).
#
# A fresh cl ledger, Q=3 (C1, a reference member R1, W), with a short expiry that the chain runs
# past.  Its members dispute the expired quorum.  W declines post-expiry rotations by its own
# policy ((:policy :post-expiry-rotation nil), CLD_REFUSE_POST_EXPIRY_ROTATION).  RUST_EXPECT=sha
# fails the run unless R1 runs that reference build.
#   rescue      : the rotation wins.  The block ticker is paused and C1 and W dispute but hold their
#                 arms (red-team :hold-arm), so nothing can confiscate while the operator
#                 re-establishes with C1, R1 and a recruit C2.  PASS = W declined the seat; while
#                 the QuorumBegin is recorded but its spend unconfirmed every expiry dispute STANDS
#                 (the v8 amendment); once a rung confirms, every one yields (W's, C1's, R1's) and
#                 its pledge lapses; the new quorum (C1 R1 C2) is active with a fresh expiry; no
#                 confiscation; nothing is proved against W.
#   race        : the default arm window, the ticker running: the operator's rotation races the
#                 members' confiscation, and the confiscation wins (regtest 2026-11-15).  PASS = the
#                 vault was confiscated; neither C1 nor R1 yielded its dispute on the recorded
#                 QuorumBegin; R1 revealed its lottery preimage (it kept its stake); and if the
#                 confiscation confirmed before the QuorumBegin was asked for, C1 refused it.
#   confiscated : the confiscation confirms first, then the operator (red-team :rotate-spent-vault,
#                 so it skips its own spent-vault check) asks its members to record a rotation of the
#                 confiscated vault.  PASS = C1 and R1 each log the refusal "the vault's confiscation
#                 confirmed: no rotation of it can be spent", and no QuorumBegin is recorded.
# REDTEAM_PX=name forms a fresh ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
ARM=${1:-rescue}; WAIT=${WAIT:-1200}
pick OP C1 C2 W
log_mark $OP $C1 $C2 $W   # node_log: this run's lines only
R1=${R1:-ref6}
# Each picked node runs the checkout's code (the policy switch, :hold-arm and :rotate-spent-vault
# are new): a pool node may be running, or pinned by its version file to, an older build, so on
# regtest every actor is unpinned and restarted, and checked from /proc.
for n in $OP $C1 $C2 $W; do
  [ "${CLD_CHAIN:-}" = regtest ] && rm -f "$CLD_ROOT/$n/version"
  ( cld_running $n && stop_cld $n >/dev/null; start_cld $n >/dev/null ) &
done; wait
for n in $OP $C1 $C2 $W; do
  b=$(live_build $n) || fail "$n did not come up"
  [ "$(cd "$b" && pwd -P)" = "$(cd "$CLD_SRC" && pwd -P)" ] || fail "$n runs $b, not the checkout $CLD_SRC"
done
echo "== actors $OP $C1 $C2 $W restarted on the checkout ($(git -C "$CLD_SRC" rev-parse --short HEAD))"
RV=$(live_version $R1); echo "== reference member $R1 runs $RV"
[ -z "${RUST_EXPECT:-}" ] || [ "$RV" = "$RUST_EXPECT" ] || fail "$R1 runs $RV, not $RUST_EXPECT"
[ "$ARM" = confiscated ] && export RESP=${RESP:-5}
X=$(FORM_EXPIRY=${FORM_EXPIRY:-40} form_ledger "${REDTEAM_PX:-PX$RANDOM}" $OP "" $C1 $R1 $W) || exit 1
expect "$(cld_ctl $W '(:policy :post-expiry-rotation nil)')" "policy"
TICKER_PAUSED=""
cleanup() {
  cld_ctl $W "(:policy :post-expiry-rotation t)" >/dev/null 2>&1
  disarm :hold-arm $C1 $W; disarm :rotate-spent-vault $OP
  [ -n "$TICKER_PAUSED" ] && ticker_start
}
trap cleanup EXIT
# The ticker is the regtest network's, not ours: restart it outside our process group, which the
# harness kills when the scenario ends (2026-11-15: a ticker restarted inside it died with it).
ticker_start() { setsid -f bash -c "cd '$CLD_SRC' && DEVNET=regtest devnet/regtest-net.sh ticker start" >/dev/null 2>&1; sleep 2; }
# A cl node's own log from time M on (the control port's (:log) reply is not one line per entry).
cllog() { awk -v m="$2" '$1 >= m' "$CLD_ROOT/$1/node.log"; }
info() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$X\" :OWNED [^)]*" | head -1; }
EXP=$(info $OP | grep -oE ':EXPIRY [0-9]+' | cut -d' ' -f2); [ -n "$EXP" ] || fail "no expiry for $X"
VAULT=$(cld_ctl $OP '(:vaults)' | tr '()' '\n\n' | grep -F "\"$X\"" -A1 | grep -oE '[0-9a-f]{64}:[0-9]+' | tail -1)
[ -n "$VAULT" ] || fail "no vault for $X"; VTX=${VAULT%:*}; VVOUT=${VAULT#*:}
echo "== ledger $X (Q=3: $C1 $R1 $W; $W declines post-expiry rotations), expiry $EXP, vault $VAULT ($ARM)"
R1K=$(pubkey_of $R1 | cut -c1-16)
r1log() { sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$R1/node.log" | awk -v m="$1" '$1 >= m'; }
MARK0=$(date -u +%FT%T)

if [ "$ARM" = rescue ]; then
  # Nothing may confiscate while the operator re-establishes: no blocks but the ones we mine, and
  # the cl members dispute without arming (a confiscation needs armed cosigners).
  "$CLD_SRC/devnet/regtest-net.sh" ticker stop >/dev/null; TICKER_PAUSED=1
  arm :hold-arm $C1 $W
fi

# Past expiry: every member disputes the expired quorum.
if [ "$ARM" = rescue ]; then
  while [ "$(bcli getblockcount)" -le "$EXP" ]; do mine 1 >/dev/null; done
else
  while [ "$(bcli getblockcount)" -le $((EXP + 4)) ]; do mine 1 >/dev/null; sleep 1; done
fi
# Keep what :check-expired answered: drive-load 1122-030936 failed with C1 (cld1007) not
# disputing for 180 s, and its fork appeared only after the teardown restart (03:18:12Z vs the
# FAIL at 03:17:08Z) -- with the answer discarded and the node restarted, nothing said why.
declare -A CHKX; for n in $C1 $W; do CHKX[$n]=$(cld_ctl $n '(:check-expired)' 2>&1 | tr '\n' ' ' | cut -c1-300); done
# Each disputant's fork, as C1 sees it (R1 disputes from its own expiry watch).
fork_state() { cld_ctl $C1 "(:forks :ledger \"$X\")" | grep -oE "\(:OPERATOR \"$(pubkey_of $1 | cut -c1-16)\" [^)]*" | grep -oE ':STATE :[A-Z]+' | cut -d: -f3; }
for n in $C1 $W $R1; do
  for i in $(seq 1 60); do [ -n "$(fork_state $n)" ] && break; sleep 3; done
  if [ -z "$(fork_state $n)" ]; then
    echo "== $n :check-expired answered: ${CHKX[$n]:-(not asked)}; at height $(bcli getblockcount), expiry $EXP"
    cld_ctl $n '(:log)' 2>/dev/null | tr '"' '\n' | grep -F -e "${X:0:8}" -e "expired" | tail -8 | sed "s/^/   $n: /"
    cld_ctl $n '(:drive-stats)' 2>/dev/null | cut -c1-400 | sed "s/^/   $n drive-stats: /"
    fail "$n did not dispute the expired quorum (no fork of it on $C1)"
  fi
done
echo "== $C1 $R1 $W disputed the expired quorum at $(bcli getblockcount)"

rotate() {   # the operator's whole rotation; prints the rotation txid, or fails.  ROT_MINE: blocks between plan and record.
  local m r
  for m in $C1 $R1 $C2; do
    r=$(CLD_CTL_TIMEOUT=240 cld_ctl $OP "(:add-member :ledger \"$X\" :member \"$(pubkey_of $m)\" :member-ledger \"$(own_ledger "$m")\")")
    case "$r" in *":STATUS :OK"*) echo "   $m consented" >&2;; *) echo "   $m: $r" >&2; return 1;; esac
  done
  r=$(CLD_CTL_TIMEOUT=240 cld_ctl $OP "(:add-member :ledger \"$X\" :member \"$(pubkey_of $W)\" :member-ledger \"$(own_ledger "$W")\")")
  case "$r" in *":STATUS :OK"*) echo "   $W CONSENTED" >&2; return 2;; *) echo "   $W declined: $r" >&2;; esac
  node_log $W | grep "refused consent" | grep -q "member policy" \
    || { echo "   $W's log has no member-policy refusal of the seat" >&2; return 3; }
  r=$(cld_ctl $OP "(:trim-staged :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) ;; *) echo "   trim: $r" >&2; return 1;; esac
  r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); case "$r" in *":STATUS :OK"*) ;; *) echo "   rotate-vault: $r" >&2; return 1;; esac
  local rt; rt=$(sx "$r" ":TXID")
  [ "${ROT_MINE:-3}" -gt 0 ] && mine "${ROT_MINE:-3}" >/dev/null; sleep 15
  for i in 1 2 3; do r=$(CLD_CTL_TIMEOUT=180 cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r" >&2; [ "${ROT_MINE:-3}" -gt 0 ] && mine 1 >/dev/null; sleep 15; done
  case "$r" in *":STATUS :OK"*) echo "$rt";; *) echo "   begin-quorum: $r" >&2; return 1;; esac
}

case $ARM in
  rescue)
    RT=$(ROT_MINE=0 rotate); rc=$?
    [ $rc = 2 ] && fail "$W consented to a seat its policy declines"
    [ $rc = 3 ] && fail "$W refused the seat, but not by its member policy"
    [ $rc = 0 ] || fail "the post-expiry rotation did not form"
    echo "== rotation $RT recorded; its rungs not yet in a block (tip $(bcli getblockcount))"
    # v8 amendment: recorded but unspent, every expiry dispute stands (R1's expiry watch runs
    # about once a minute: give it two passes).
    sleep 130
    for n in $C1 $W $R1; do
      st=$(fork_state $n); [ "$st" != TOMBSTONED ] || fail "$n yielded while the rotation was recorded but unspent"
      echo "   $n's dispute stands while the rotation is unconfirmed ($st)"
    done
    mine 1 >/dev/null; sleep 5
    [ -z "$(bcli gettxout "$VTX" "$VVOUT" false | head -1)" ] || fail "the old vault $VAULT is unspent after a block"
    sp=$(spender_of "$VTX" "$VVOUT")
    echo "== a rung confirmed at $(bcli getblockcount)"
    mine 2 >/dev/null
    disarm :hold-arm $C1 $W
    ticker_start; TICKER_PAUSED=""
    for n in $C1 $W $R1; do
      st=""
      # A long-lived pool node runs a slow dispute pass (regtest 2026-11-15: W yielded 5 min on).
      for t in $(seq 1 180); do st=$(fork_state $n); [ "$st" = TOMBSTONED ] && break; sleep 5; done
      [ "$st" = TOMBSTONED ] || fail "$n's expiry dispute did not yield within 900 s of the rotation confirming (state ${st:-none})"
      grep -q "$X" "$CLD_ROOT/$n/pledges.sexp" 2>/dev/null && fail "$n still pledges to $X"
      echo "   $n yielded; no pledge left"
    done
    i=$(info $OP); NEW=$(grep -oE ':EXPIRY [0-9]+' <<<"$i" | cut -d' ' -f2); TIP=$(bcli getblockcount)
    grep -q ':MEMBERS 3' <<<"$i" || fail "the new quorum is not three members: $i"
    [ "${NEW:-0}" -gt "$TIP" ] || fail "the new expiry ${NEW:-none} is not past the tip $TIP"
    [ -n "$(bcli gettxout "$RT" 0 | head -1)" ] || echo "   (the old vault was spent by $sp, a higher rung of the rotation's ladder)"
    WK=$(pubkey_of $W | cut -c1-16); WL=$(own_ledger "$W")
    for n in $OP $C1 $C2; do
      node_log $n | grep -iE "against [^ ]*($WK|${WL:0:8})|accused[^ ]* ($WK|${WL:0:8})|VAULT SPEND: ${WL:0:8}" | grep -q . && fail "$n holds a proof against $W"
      cld_ctl $n "(:forks :ledger \"$WL\")" | grep -q ':OPERATOR' && fail "$n has a dispute on $W's own ledger"
    done
    echo "PASS: past expiry the operator re-established with the members that agreed ($C1 $R1 $C2); $W declined by policy and nothing holds that against it; every expiry dispute stood while the rotation was unconfirmed and yielded once it confirmed; no confiscation ($sp spent the vault).";;
  race)
    RT=$(rotate); rc=$?
    echo "== the operator's rotation: rc $rc ${RT:+($RT)}"
    for i in $(seq 1 $((WAIT / 10))); do [ -z "$(bcli gettxout "$VTX" "$VVOUT" false | head -1)" ] && break; sleep 10; done
    [ -z "$(bcli gettxout "$VTX" "$VVOUT" false | head -1)" ] || fail "the vault was not spent in ${WAIT}s"
    sp=$(spender_of "$VTX" "$VVOUT") || fail "the vault $VAULT is spent, but no transaction in the mempool or the last 30 blocks spends it"
    if [ $rc = 0 ] && [ "$sp" = "$RT" ]; then
      echo "PASS (rotation won the race, $RT): see the rescue arm for its checks."; exit 0
    fi
    echo "== the vault went to ${sp:-a confirmed spend} (not the rotation): the confiscation won"
    sleep 120   # its lottery: reveals follow the confiscation's confirmation
    r1log "$MARK0" | grep "Expiry dispute on ${X:0:16}" | grep -q "published DisputeYield" \
      && fail "$R1 yielded its expiry dispute though the confiscation won: $(r1log "$MARK0" | grep "Expiry dispute on ${X:0:16}" | grep -m1 DisputeYield | cut -c1-200)"
    cllog $C1 "$MARK0" | grep "${X:0:8}" | grep -q "quorum re-established" && fail "$C1 yielded on the recorded QuorumBegin"
    r1_revealed() { r1log "$MARK0" | grep -q "Published custody-lottery reveal: ledger=${X:0:16}, member=$R1K"; }
    poll 600 r1_revealed
    rev=$(r1log "$MARK0" | grep -m1 "Published custody-lottery reveal: ledger=${X:0:16}, member=$R1K")
    [ -n "$rev" ] || fail "$R1 published no lottery reveal for $X"
    echo "   $R1: ${rev:0:160}"
    echo "PASS: the confiscation won the race; $R1 and $C1 kept their expiry disputes through the recorded QuorumBegin and $R1 took part in the lottery.";;
  confiscated)
    echo "== waiting for the confiscation to confirm (up to ${WAIT}s)"
    for i in $(seq 1 $((WAIT / 10))); do
      [ -z "$(bcli gettxout "$VTX" "$VVOUT" false | head -1)" ] && break
      mine 1 >/dev/null; sleep 10
    done
    [ -z "$(bcli gettxout "$VTX" "$VVOUT" false | head -1)" ] || fail "the vault was not spent in ${WAIT}s"
    mine 3 >/dev/null; sleep 20
    BEFORE=$(info $OP | grep -oE ':EXPIRY [0-9]+' | cut -d' ' -f2)
    # The operator really asks: :rotate-spent-vault skips its own spent-vault check, so its
    # QuorumBegin over the confiscated vault reaches the members, who must refuse it for that reason.
    arm :rotate-spent-vault $OP
    MARK=$(date -u +%FT%T)
    RT=$(rotate); rc=$?
    disarm :rotate-spent-vault $OP
    AFTER=$(info $OP | grep -oE ':EXPIRY [0-9]+' | cut -d' ' -f2)
    [ $rc = 0 ] && fail "a rotation was recorded over the confiscated vault ($RT)"
    [ "$BEFORE" = "$AFTER" ] || fail "the ledger's expiry moved from $BEFORE to $AFTER: a QuorumBegin was recorded"
    line=$(cllog $C1 "$MARK" | grep "refused cosign" | grep -m1 "no rotation of it can be spent")
    [ -n "$line" ] || fail "$C1 did not refuse the QuorumBegin for the confiscated vault (its log since $MARK has no such refusal)"
    echo "   $C1: $line"
    line=$(r1log "$MARK" | grep -m1 "Refusing cosign: the vault's confiscation confirmed: no rotation of it can be spent")
    [ -n "$line" ] || fail "$R1 did not refuse the QuorumBegin for the confiscated vault (its log since $MARK has no such refusal)"
    echo "   $R1: ${line:0:200}"
    echo "PASS: the confiscation confirmed first; the operator's QuorumBegin over the confiscated vault was refused by $C1 and $R1 for that reason, and no rotation was recorded.";;
  *) fail "arm: rescue | race | confiscated";;
esac
