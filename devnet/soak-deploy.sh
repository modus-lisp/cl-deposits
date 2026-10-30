#!/usr/bin/env bash
# devnet/soak-deploy.sh — stochastic deploys: every node switches to a new build at its own
# uniformly random moment inside a window, so the soak runs mixed versions the whole time and
# converges on the new one by the window's end (the fixed point).
#
#   devnet/soak-deploy.sh adopt <cl-sha> <rust-sha>     # name the builds unversioned nodes already run (no restart)
#   devnet/soak-deploy.sh prepare <cl-sha> <rust-sha>   # make both builds (cl worktree + precompile, Rust release build)
#   devnet/soak-deploy.sh <cl-sha> <rust-sha> [--window 6h] [--seed N] [--nodes a,b,...]
#   devnet/soak-deploy.sh --rollback [--window 6h] [--seed N]   # the last deploy in reverse, same mechanism
#   devnet/soak-deploy.sh --resume                      # continue a persisted plan (after this script was killed)
#   devnet/soak-deploy.sh --status | --pause | --unpause
#
# A node's build is the sha in its data dir's `version` file (devnet/_common.sh: cld_src_of,
# ref_bin_of); a switch writes that file and restarts the node under its restart lock, the same
# lock the chaos loop takes, so chaos restarts keep a node on whatever version it was switched to.
# The plan lives in $SOAK/deploy/plan.tsv (node, from, to, due epoch, state), so a killed deploy
# resumes rather than re-drawing; every switch is logged to $SOAK/log/deploy.log.  At the window's
# end every node must run its target build (checked from /proc, not the version file); any that
# do not are re-driven until they do.
source "$(dirname "$0")/_common.sh"
SOAK="$CLD_ROOT/soak"; D="$SOAK/deploy"; PLAN="$D/plan.tsv"; META="$D/meta"; LOG="$SOAK/log/deploy.log"
mkdir -p "$D" "$SOAK/log"
CL_REPO="${CL_REPO:-$CLD_SRC}"; RUST_REPO="${RUST_REPO:-/home/claude/workspace/deposits-rust}"
log() { echo "$(date +%FT%T) $*" | tee -a "$LOG"; }
die() { echo "soak-deploy: $*" >&2; exit 1; }
dur() { case "$1" in *h) echo $(( ${1%h} * 3600 ));; *m) echo $(( ${1%m} * 60 ));; *s) echo "${1%s}";; *) echo "$1";; esac; }
short() { git -C "$1" rev-parse --short=7 "$2" 2>/dev/null || die "no commit $2 in $1"; }
target_of() { case "$1" in cld*) echo "$CLV";; ref*) echo "$RSV";; esac; }
have_build() { case "$1" in cld*) [ -f "$(cl_build "$2")/bin/cl-deposits.lisp" ];; ref*) [ -x "$(rust_build "$2")/deposits-node" ];; esac; }

prepare() {   # prepare CL-SHA RUST-SHA — immutable builds, side by side
  local c r b src; c=$(short "$CL_REPO" "$1"); r=$(short "$RUST_REPO" "$2")
  src=$(cl_build "$c")
  if [ ! -f "$src/bin/cl-deposits.lisp" ]; then
    git -C "$CL_REPO" worktree add -q --detach "$src" "$c" && (cd "$src" && git submodule update --init --recursive -q) || die "cl worktree $src"
  fi
  ( cd "$src" && CL_SOURCE_REGISTRY="$(cld_registry "$src")" "${CLD_SBCL:-/usr/bin/sbcl}" --noinform --dynamic-space-size 8192 --non-interactive \
      --eval '(require :asdf)' --eval '(handler-bind ((warning (function muffle-warning))) (asdf:load-system "cl-deposits"))' >/dev/null 2>&1 ) \
    || die "cl build $src does not compile"   # compiled once here, not by every node that switches to it
  echo "cl $c: $src"
  b=$(rust_build "$r")
  if [ ! -x "$b/deposits-node" ]; then
    local wt="/mnt/lisp/wt/rust-$r" tgt="/mnt/lisp/cargo-target/$CLD_CHAIN-build-$r"
    [ -d "$wt" ] || { git -C "$RUST_REPO" worktree add -q --detach "$wt" "$r" && (cd "$wt" && git submodule update --init --recursive -q); } || die "rust worktree $wt"
    (cd "$wt" && CARGO_TARGET_DIR="$tgt" cargo build --locked --release -p deposits-node -p deposits-wallet) || die "rust build $r"
    mkdir -p "$b"; cp -p "$tgt/release/deposits-node" "$tgt/release/deposits-wallet" "$b/"; [ -x "$tgt/release/deposit-bot" ] && cp -p "$tgt/release/deposit-bot" "$b/"
  fi
  echo "rust $r: $b"
}

adopt() {   # adopt CL-SHA RUST-SHA — unversioned nodes already run these: record it, restart nothing
  local c r n; c=$1; r=$2
  have_build cld1 "$c" || die "no cl build $c (prepare it first)"; have_build ref2 "$r" || die "no rust build $r"
  for n in $(cld_names) $(ref_names); do
    [ -n "$(node_version "$n")" ] && continue
    case "$n" in cld*) echo "$c";; ref*) echo "$r";; esac >"$(node_dir "$n")/version"
    log "adopt $n $(cat "$(node_dir "$n")/version") (was running $(live_version "$n"))"
  done
}

plan() {   # plan FROM-SPEC — write the schedule: each node draws its own moment in [now, now+window)
  local now n from to; now=$(date +%s)
  : >"$PLAN.new"
  for n in $NODES; do
    from=$(node_version "$n"); to=$(target_of "$n")
    [ "$from" = "$to" ] && [ "$(live_version "$n")" = "$to" ] && continue
    have_build "$n" "$to" || die "no build $to for $n"
    printf '%s\t%s\t%s\n' "$n" "${from:--}" "$to" >>"$PLAN.new"
  done
  python3 - "$PLAN.new" "$now" "$WINDOW" "$SEED" >"$PLAN" <<'EOF'
import random, sys
rows=[l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
now, window, seed = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
rng = random.Random(seed)
for n, frm, to in rows:   # one draw per node, in name order, so a seed reproduces the schedule
    print("\t".join([n, frm, to, str(now + int(rng.random() * window)), "pending"]))
EOF
  rm -f "$PLAN.new"
  printf 'started=%s\nwindow=%s\nseed=%s\ncl=%s\nrust=%s\nkind=%s\n' "$now" "$WINDOW" "$SEED" "$CLV" "$RSV" "$KIND" >"$META"
  log "plan: $KIND cl=$CLV rust=$RSV window=${WINDOW}s seed=$SEED, $(wc -l <"$PLAN") node(s) to switch"
  sort -t$'\t' -k4 -n "$PLAN" | while IFS=$'\t' read -r n f t at s; do log "  $n $f -> $t at $(date -d @"$at" +%FT%T)"; done
}

set_state() { python3 - "$PLAN" "$1" "$2" <<'EOF'
import sys
p, node, state = sys.argv[1:]
rows = [l.rstrip("\n").split("\t") for l in open(p) if l.strip()]
for r in rows:
    if r[0] == node: r[4] = state
open(p + ".tmp", "w").write("".join("\t".join(r) + "\n" for r in rows))
import os; os.replace(p + ".tmp", p)
EOF
}

switch() {   # switch NODE FROM TO — write the version file, restart under the lock, confirm from /proc
  local n=$1 from=$2 to=$3 t0; t0=$(date +%s)
  echo "$to" >"$(node_dir "$n")/version"
  if restart_node "$n" >>"$D/restart.log" 2>&1 </dev/null && [ "$(live_version "$n")" = "$to" ]; then
    log "switch $n $from -> $to ok ($(( $(date +%s) - t0 ))s)"; return 0
  fi
  log "switch $n $from -> $to FAILED (running $(live_version "$n")); see $D/restart.log"; return 1
}

run() {   # drive the plan until every node runs its target: the fixed point
  source "$META"; local end=$(( started + window )) n f t at s tries
  echo $$ >"$D/pid"
  declare -A fails=()
  while true; do
    if [ -f "$D/pause" ]; then sleep 30; continue; fi
    local now; now=$(date +%s)
    while IFS=$'\t' read -r n f t at s; do
      [ "$s" = pending ] || [ "$s" = retry ] || continue
      [ "$now" -ge "$at" ] || continue
      if switch "$n" "$f" "$t"; then set_state "$n" done
      else
        tries=$(( ${fails[$n]:-0} + 1 )); fails[$n]=$tries
        if [ "$tries" -ge 3 ]; then   # keep the node alive on what it ran, and say so
          log "giving up on $n after 3 attempts; back to $f"; [ "$f" = - ] && rm -f "$(node_dir "$n")/version" || echo "$f" >"$(node_dir "$n")/version"
          restart_node "$n" >>"$D/restart.log" 2>&1 </dev/null; set_state "$n" failed
        else set_state "$n" retry; fi
      fi
    done < <(sort -t$'\t' -k4 -n "$PLAN")
    if [ "$now" -ge "$end" ] && ! grep -qP '\t(pending|retry)$' "$PLAN"; then
      # The fixed point is what runs, not what the plan says: re-drive anything that drifted.
      local missed=0
      while IFS=$'\t' read -r n f t at s; do
        [ "$s" = done ] || continue
        if [ "$(live_version "$n")" != "$t" ]; then missed=1; log "fixed point: $n runs $(live_version "$n"), not $t; re-driving"; set_state "$n" retry; fi
      done <"$PLAN"
      if [ "$missed" = 0 ]; then
        log "fixed point reached: $(grep -cP '\tdone$' "$PLAN") switched, $(grep -cP '\tfailed$' "$PLAN") failed"; rm -f "$D/pid"; return 0
      fi
    fi
    sleep 15
  done
}

status() {
  [ -f "$META" ] || { echo "no deploy"; return; }
  source "$META"; local now; now=$(date +%s)
  printf 'deploy (%s) cl=%s rust=%s: %s done, %s pending, %s retry, %s failed; window %s%s%s\n' "$kind" "$cl" "$rust" \
    "$(grep -cP '\tdone$' "$PLAN")" "$(grep -cP '\tpending$' "$PLAN")" "$(grep -cP '\tretry$' "$PLAN")" "$(grep -cP '\tfailed$' "$PLAN")" \
    "$( [ "$now" -lt $((started+window)) ] && echo "ends $(date -d @$((started+window)) +%FT%T)" || echo "ended")" \
    "$( [ -f "$D/pause" ] && echo ', PAUSED')" "$( p=$(cat "$D/pid" 2>/dev/null) && kill -0 "$p" 2>/dev/null && echo ", driver $p" || echo ', no driver')"
  grep -P '\t(pending|retry)$' "$PLAN" | sort -t$'\t' -k4 -n | head -3 | while IFS=$'\t' read -r n f t at s; do echo "  next: $n -> $t at $(date -d @"$at" +%FT%T)"; done
}

detach() { setsid -f nohup "$0" --resume >>"$D/driver.log" 2>&1 </dev/null; sleep 1; echo "driver started; tail -f $LOG"; }

WINDOW=$(dur 6h); SEED=$RANDOM$RANDOM; NODES="$(cld_names | tr '\n' ' ')$(ref_names | tr '\n' ' ')"; KIND=deploy; FG=""
case "${1:-}" in
  adopt)   adopt "$2" "$3"; exit;;
  prepare) prepare "$2" "$3"; exit;;
  --status) status; exit;;
  --pause) touch "$D/pause"; log "paused"; exit;;
  --unpause) rm -f "$D/pause"; log "unpaused"; exit;;
  --resume) [ -f "$PLAN" ] || die "no plan to resume"; p=$(cat "$D/pid" 2>/dev/null) && [ "$p" != $$ ] && kill -0 "$p" 2>/dev/null && die "driver $p already running"
            log "driver resumed (pid $$)"; run; exit;;
  --rollback) shift; KIND=rollback
            [ -f "$PLAN" ] || die "no deploy to roll back"
            while [ $# -gt 0 ]; do case "$1" in --window) WINDOW=$(dur "$2"); shift 2;; --seed) SEED=$2; shift 2;; *) die "unknown $1";; esac; done
            # back to each node's previous build: the plan's from column (nodes that never switched stay)
            source "$META"; CLV=""; RSV=""; NODES=""
            while IFS=$'\t' read -r n f t at s; do [ "$s" = done ] || continue; [ "$f" = - ] && die "$n had no recorded version; adopt first"
              case "$n" in cld*) [ -n "$CLV" ] && [ "$CLV" != "$f" ] && die "cl nodes came from different builds"; CLV=$f;;
                           ref*) [ -n "$RSV" ] && [ "$RSV" != "$f" ] && die "reference nodes came from different builds"; RSV=$f;; esac
              NODES+="$n "; done <"$PLAN"
            [ -n "$NODES" ] || die "nothing switched"
            plan; detach; exit;;
  ""|-*)   sed -n '2,13p' "$0"; exit 2;;
esac
CLV=$(short "$CL_REPO" "$1"); RSV=$(short "$RUST_REPO" "$2"); shift 2
while [ $# -gt 0 ]; do case "$1" in
  --window) WINDOW=$(dur "$2"); shift 2;; --seed) SEED=$2; shift 2;; --nodes) NODES=${2//,/ }; shift 2;;
  --foreground) FG=1; shift;; *) die "unknown $1";; esac; done
p=$(cat "$D/pid" 2>/dev/null) && kill -0 "$p" 2>/dev/null && die "a deploy is running (driver $p); --pause or wait"
plan
[ -n "$FG" ] && { run; exit; }
detach
