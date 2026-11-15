#!/usr/bin/env bash
# redteam/check-rotation-post-expiry.sh — a rotation past quorum_expiry is allowed, never owed
# (DEP-05 §Cosignature Threshold, DEP-06 §Race; ruled 2026-11-14: "we can allow it, but we can't
# require members to sign").
#
# A fresh cl ledger, Q=3 (C1, a reference member R1, W), with a short expiry that the chain runs
# past.  Its members dispute the expired quorum.  W declines post-expiry rotations by its own
# policy ((:policy :post-expiry-rotation nil), CLD_REFUSE_POST_EXPIRY_ROTATION).  RUST_EXPECT=sha
# fails the run unless R1 runs that reference build.
#   rescue      : the operator re-establishes with C1, R1 and a recruit C2 before any confiscation.
#                 PASS = W refused the seat (member policy, not a fault), the new quorum
#                 (C1 R1 C2) is active with a fresh expiry, the old vault was spent by the
#                 rotation, every member's expiry dispute yielded (W's, and R1's un-armed one, too)
#                 and its pledge lapsed, no confiscation, and nobody proved anything against W.
#   confiscated : short arm windows (RESP); the confiscation confirms first, then the operator
#                 (red-team :rotate-spent-vault, so it skips its own spent-vault check) asks its
#                 members to record a rotation of the confiscated vault.  PASS = C1 and R1 each log
#                 the refusal "the vault's confiscation confirmed: no rotation of it can be spent",
#                 and no QuorumBegin is recorded.
# REDTEAM_PX=name forms a fresh ledger per run.
source "$(dirname "$0")/../devnet/_common.sh"; S="$CLD_ROOT/soak"; source "$S/env"; source "$(dirname "$0")/_lib.sh"
ARM=${1:-rescue}; WAIT=${WAIT:-1200}
pick OP C1 C2 W
R1=${R1:-ref6}
# Each picked node runs the checkout's code (the policy switch and :rotate-spent-vault are new): a
# pool node may be running, or pinned by its version file to, an older build, so on regtest every
# actor is unpinned and restarted, and checked from /proc.
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
trap 'cld_ctl $W "(:policy :post-expiry-rotation t)" >/dev/null 2>&1' EXIT
info() { cld_ctl "$1" "(:info)" | grep -oE "\(:ID \"$X\" :OWNED [^)]*" | head -1; }
EXP=$(info $OP | grep -oE ':EXPIRY [0-9]+' | cut -d' ' -f2); [ -n "$EXP" ] || fail "no expiry for $X"
VAULT=$(cld_ctl $OP '(:vaults)' | tr '()' '\n\n' | grep -F "\"$X\"" -A1 | grep -oE '[0-9a-f]{64}:[0-9]+' | tail -1)
[ -n "$VAULT" ] || fail "no vault for $X"; VTX=${VAULT%:*}; VVOUT=${VAULT#*:}
echo "== ledger $X (Q=3: $C1 $R1 $W; $W declines post-expiry rotations), expiry $EXP, vault $VAULT ($ARM)"

# Past expiry + the members' grace: every member disputes the expired quorum.
while [ "$(bcli getblockcount)" -le $((EXP + 4)) ]; do mine 1 >/dev/null; sleep 1; done
for n in $C1 $W; do cld_ctl $n '(:check-expired)' >/dev/null; done
# Each disputant's fork, as C1 sees it (R1 disputes from its own expiry watch).
fork_state() { cld_ctl $C1 "(:forks :ledger \"$X\")" | grep -oE "\(:OPERATOR \"$(pubkey_of $1 | cut -c1-16)\" [^)]*" | grep -oE ':STATE :[A-Z]+' | cut -d: -f3; }
for n in $C1 $W $R1; do
  for i in $(seq 1 60); do [ -n "$(fork_state $n)" ] && break; sleep 3; done
  [ -n "$(fork_state $n)" ] || fail "$n did not dispute the expired quorum (no fork of it on $C1)"
done
echo "== $C1 $R1 $W disputed the expired quorum at $(bcli getblockcount)"

rotate() {   # the operator's whole rotation; prints the rotation txid, or fails
  local m r
  for m in $C1 $R1 $C2; do
    r=$(CLD_CTL_TIMEOUT=240 cld_ctl $OP "(:add-member :ledger \"$X\" :member \"$(pubkey_of $m)\" :member-ledger \"$(own_ledger "$m")\")")
    case "$r" in *":STATUS :OK"*) echo "   $m consented" >&2;; *) echo "   $m: $r" >&2; return 1;; esac
  done
  r=$(CLD_CTL_TIMEOUT=240 cld_ctl $OP "(:add-member :ledger \"$X\" :member \"$(pubkey_of $W)\" :member-ledger \"$(own_ledger "$W")\")")
  case "$r" in *"member policy"*) echo "   $W declined the seat: member policy" >&2;; *":STATUS :OK"*) echo "   $W CONSENTED" >&2; return 2;; *) echo "   $W: $r" >&2;; esac
  r=$(cld_ctl $OP "(:trim-staged :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) ;; *) echo "   trim: $r" >&2; return 1;; esac
  r=$(cld_ctl $OP "(:rotate-vault :ledger \"$X\" :expiry-blocks 4320)"); case "$r" in *":STATUS :OK"*) ;; *) echo "   rotate-vault: $r" >&2; return 1;; esac
  local rt; rt=$(sx "$r" ":TXID")
  mine 3 >/dev/null; sleep 15
  for i in 1 2 3; do r=$(cld_ctl $OP "(:begin-quorum :ledger \"$X\")"); case "$r" in *":STATUS :OK"*) break;; esac; echo "   begin-quorum retry $i: $r" >&2; mine 1 >/dev/null; sleep 15; done
  case "$r" in *":STATUS :OK"*) echo "$rt";; *) echo "   begin-quorum: $r" >&2; return 1;; esac
}

case $ARM in
  rescue)
    RT=$(rotate); rc=$?
    [ $rc = 2 ] && fail "$W consented to a seat its policy declines"
    [ $rc = 0 ] || fail "the post-expiry rotation did not form"
    echo "== rotation $RT recorded"
    mine 3 >/dev/null; sleep 20
    i=$(info $OP); NEW=$(grep -oE ':EXPIRY [0-9]+' <<<"$i" | cut -d' ' -f2); TIP=$(bcli getblockcount)
    grep -q ':MEMBERS 3' <<<"$i" || fail "the new quorum is not three members: $i"
    [ "${NEW:-0}" -gt "$TIP" ] || fail "the new expiry ${NEW:-none} is not past the tip $TIP"
    [ -z "$(bcli gettxout "$VTX" "$VVOUT" false | head -1)" ] || fail "the old vault $VAULT is unspent"
    sp=$(bcli gettxspendingprevout "[{\"txid\":\"$VTX\",\"vout\":$VVOUT}]" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0].get("spendingtxid",""))')
    [ -n "$(bcli gettxout "$RT" 0 | head -1)" ] || fail "the new vault $RT:0 is not unspent (old vault spent by $sp)"
    # Every expiry dispute ends: each disputant yields (armed or not) and its pledge lapses.
    for n in $C1 $W $R1; do
      st=""
      for t in $(seq 1 60); do st=$(fork_state $n); [ "$st" = TOMBSTONED ] && break; sleep 5; done
      [ "$st" = TOMBSTONED ] || fail "$n's expiry dispute did not yield (state ${st:-none})"
      grep -q "$X" "$CLD_ROOT/$n/pledges.sexp" 2>/dev/null && fail "$n still pledges to $X"
      echo "   $n yielded; no pledge left"
    done
    # No confiscation: the old vault's spender is the rotation (its new vault RT:0 is unspent above).
    [ "$sp" = "$RT" ] || echo "   (the old vault was spent by $sp, a higher rung of the rotation's ladder)"
    # Nothing against the member that declined.
    WK=$(pubkey_of $W | cut -c1-16); WL=$(own_ledger "$W")
    for n in $OP $C1 $C2; do
      cld_ctl $n '(:log :n 4000)' | grep -iE "against [^ ]*($WK|${WL:0:8})|accused[^ ]* ($WK|${WL:0:8})|VAULT SPEND: ${WL:0:8}" | grep -q . && fail "$n holds a proof against $W"
      cld_ctl $n "(:forks :ledger \"$WL\")" | grep -q ':OPERATOR' && fail "$n has a dispute on $W's own ledger"
    done
    echo "PASS: past expiry the operator re-established with the members that agreed ($C1 $R1 $C2); $W declined by policy and nothing holds that against it; every expiry dispute yielded and no confiscation followed ($RT:0).";;
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
    trap 'cld_ctl $W "(:policy :post-expiry-rotation t)" >/dev/null 2>&1; disarm :rotate-spent-vault $OP' EXIT
    MARK=$(date -u +%FT%T)
    RT=$(rotate); rc=$?
    disarm :rotate-spent-vault $OP
    AFTER=$(info $OP | grep -oE ':EXPIRY [0-9]+' | cut -d' ' -f2)
    [ $rc = 0 ] && fail "a rotation was recorded over the confiscated vault ($RT)"
    [ "$BEFORE" = "$AFTER" ] || fail "the ledger's expiry moved from $BEFORE to $AFTER: a QuorumBegin was recorded"
    line=$(cld_ctl $C1 '(:log :n 4000)' | awk -v m="$MARK" '$1 >= m' | grep "refused cosign" | grep -m1 "confiscation confirmed: no rotation of it can be spent")
    [ -n "$line" ] || fail "$C1 did not refuse the QuorumBegin for the confiscated vault (its log since $MARK has no such refusal)"
    echo "   $C1: $line"
    line=$(sed 's/\x1b\[[0-9;]*m//g' "$CLD_ROOT/$R1/node.log" | awk -v m="$MARK" '$1 >= m' | grep -m1 "Refusing cosign: the vault's confiscation confirmed: no rotation of it can be spent")
    [ -n "$line" ] || fail "$R1 did not refuse the QuorumBegin for the confiscated vault (its log since $MARK has no such refusal)"
    echo "   $R1: ${line:0:200}"; refused=" $C1 $R1"
    echo "PASS: the confiscation confirmed first; the operator's QuorumBegin over the confiscated vault was refused by$refused for that reason, and no rotation was recorded.";;
  *) fail "arm: rescue | confiscated";;
esac
