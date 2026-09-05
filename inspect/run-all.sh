#!/usr/bin/env bash
# inspect/run-all.sh — the offline gate suite: every layer against real vectors.
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd -P)"
SBCL="${SBCL:-sbcl}"
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$ROOT\") (:tree \"$ROOT/..\") :inherit-configuration)"
pass=0; fail=0; failed=()
run_gate () {
  local name="$1"; shift
  local log="/tmp/cl-deposits-gate-$name.log"; local start=$SECONDS
  if "$@" >"$log" 2>&1; then printf "  %-22s PASS  (%ds)\n" "$name" "$((SECONDS-start))"; pass=$((pass+1))
  else printf "  %-22s FAIL  (%ds)  -> %s\n" "$name" "$((SECONDS-start))" "$log"; fail=$((fail+1)); failed+=("$name"); fi
}
lisp_gate () {  # name, then test files
  local name="$1"; shift
  local args=(--non-interactive --eval '(require :asdf)' --eval '(handler-bind ((warning #'"'"'muffle-warning)) (asdf:load-system "cl-deposits"))' --load inspect/harness.lisp)
  for f in "$@"; do args+=(--load "$f"); done
  run_gate "$name" "$SBCL" "${args[@]}"
}
echo "== cl-deposits offline gate suite =="
lisp_gate vectors inspect/update-test.lisp inspect/operation-test.lisp inspect/dep17-test.lisp inspect/reserves-test.lisp inspect/rotation-test.lisp
echo; echo "$pass passed, $fail failed ${failed[*]:+(${failed[*]})}"
[ "$fail" -eq 0 ]
