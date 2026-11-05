#!/usr/bin/env bash
# inspect/run-all.sh — the offline gate suite: every layer against real vectors.
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd -P)"
SBCL="${SBCL:-sbcl}"
QL="${CLD_QL_SOFTWARE:-$HOME/quicklisp/dists/quicklisp/software}"; [ -d "$QL" ] && QL=" (:tree \"$QL\")" || QL=""   # ahead of ~: see cld_registry in devnet/_common.sh
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$ROOT\")$QL (:tree \"$ROOT/..\") :inherit-configuration)"
pass=0; fail=0; failed=()
run_gate () {
  local name="$1"; shift
  local log="${GATE_LOG_DIR:-/tmp}/cl-deposits-gate-$name.log"; local start=$SECONDS
  if "$@" >"$log" 2>&1; then printf "  %-22s PASS  (%ds)\n" "$name" "$((SECONDS-start))"; pass=$((pass+1))
  else printf "  %-22s FAIL  (%ds)  -> %s\n" "$name" "$((SECONDS-start))" "$log"; fail=$((fail+1)); failed+=("$name"); fi
}
lisp_gate () {  # name, then test files
  local name="$1"; shift
  local args=(--non-interactive --eval '(require :asdf)' --eval '(handler-bind ((warning #'"'"'muffle-warning)) (asdf:load-system "cl-deposits"))'
              --eval "(let ((d (namestring (truename (asdf:system-source-directory \"cl-deposits\"))))) (unless (string= d \"$ROOT/\") (format t \"~&gate loaded cl-deposits from ~a, not $ROOT/~%\" d) (uiop:quit 3)))"
              --load inspect/harness.lisp)
  for f in "$@"; do args+=(--load "$f"); done
  run_gate "$name" "$SBCL" "${args[@]}"
}
# A fresh compile of our own systems must not warn of an undefined variable: one is a stray form
# (Nov 5: a docstring that quoted a phrase with bare double quotes became code, and the soak's
# build raised "variable A is unbound" in the vault-spend verifier while this suite, compiled
# differently, passed).
compile_gate () {
  local out; out=$("$SBCL" --non-interactive --eval '(require :asdf)' --eval '(asdf:load-system "cl-deposits" :force (list "cl-deposits"))' 2>&1)
  if grep -E 'undefined variable: (CL-DEPOSITS|COMMON-LISP:)' <<<"$out"; then return 1; fi
  grep -q 'compilation unit' <<<"$out" || grep -q . <<<"$out"
}
echo "== cl-deposits offline gate suite =="
run_gate compile compile_gate
lisp_gate vectors inspect/update-test.lisp inspect/operation-test.lisp inspect/dep17-test.lisp inspect/dep16-test.lisp inspect/descriptor-test.lisp inspect/reserves-test.lisp inspect/rotation-test.lisp inspect/commitment-test.lisp inspect/lottery-test.lisp
lisp_gate nodes   inspect/update-test.lisp inspect/operation-test.lisp inspect/index-test.lisp inspect/node-test.lisp
lisp_gate property inspect/update-test.lisp inspect/operation-test.lisp inspect/property-test.lisp
lisp_gate chaos    inspect/chaos-test.lisp
lisp_gate restart  inspect/index-test.lisp inspect/restart-test.lisp
echo; echo "$pass passed, $fail failed ${failed[*]:+(${failed[*]})}"
[ "$fail" -eq 0 ]
