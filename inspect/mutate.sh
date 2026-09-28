#!/usr/bin/env bash
# inspect/mutate.sh — apply single-point mutations to the fold and the update
# layer one at a time; a mutant "survives" if the vectors and property gates
# still pass.  Survivors are the tests' blind spots.
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd -P)"; SBCL="${SBCL:-sbcl}"
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$ROOT\") (:tree \"$ROOT/..\") :inherit-configuration)"
export PROPERTY_SEED=31337
OUT="${MUTATE_OUT:-/tmp/cl-deposits-mutants.txt}"; : > "$OUT"
gate() { "$SBCL" --non-interactive --eval '(require :asdf)' --eval '(handler-bind ((warning #'"'"'muffle-warning)) (asdf:load-system "cl-deposits"))' --load inspect/harness.lisp "$@" >/tmp/mutant.log 2>&1; }
ONLY="${MUTATE_ONLY:-}"
run_mutant() {  # name file 'sed-expression'
  local name=$1 file=$2 expr=$3
  if [ -n "$ONLY" ] && ! echo " $ONLY " | grep -q " $name "; then return; fi
  cp "$file" "$file.orig"
  sed -i -E "$expr" "$file"
  if cmp -s "$file" "$file.orig"; then echo "NOOP     $name (pattern did not match)" | tee -a "$OUT"; mv "$file.orig" "$file"; return; fi
  sleep 1; touch "$file"
  local verdict=SURVIVED
  if ! gate --load inspect/update-test.lisp --load inspect/operation-test.lisp --load inspect/dep17-test.lisp --load inspect/reserves-test.lisp --eval '(cl-deposits.test:report)'; then verdict="killed(vectors)";
  elif ! gate --load inspect/update-test.lisp --load inspect/operation-test.lisp --load inspect/property-test.lisp; then verdict="killed(property)";
  elif [ "${MUTATE_FULL:-}" = 1 ] && ! gate --load inspect/update-test.lisp --load inspect/operation-test.lisp --load inspect/node-test.lisp; then verdict="killed(nodes)"; fi
  echo "$verdict  $name" | tee -a "$OUT"
  mv "$file.orig" "$file"; sleep 1; touch "$file"
}
L=src/ledger.lisp; U=src/update.lisp
run_mutant lock-allows-equal            $L 's/\(when \(< \(deposit-available-balance d\) amount\)/(when (< (deposit-available-balance d) (1- amount))/'
run_mutant fulfill-keeps-balance        $L 's/\(setf \(deposit-balance d\) \(max 0 \(- \(deposit-balance d\) amount\)\)\)\)/(setf (deposit-balance d) (deposit-balance d)))/'
run_mutant charge-fixed-nothing         $L 's/\(let \(\(charged \(min \(op:transfer-fees-fixed-msats \(deposit-transfer-fees d\)\) \(deposit-balance d\)\)\)\)/(let ((charged 0))/'
run_mutant duplicate-credit-allowed     $L 's/\(fail :duplicate-credit \(bytes->hex \(f :payment-hash\)\)\)/nil/'
run_mutant close-nonzero-allowed        $L 's/\(when \(plusp \(deposit-balance d\)\) \(fail :non-zero-balance \(deposit-balance d\)\)\)/nil/'
run_mutant majority-off-by-one          $L 's/\(defun majority-threshold \(n\) \(1\+ \(floor n 2\)\)\)/(defun majority-threshold (n) (floor n 2))/'
run_mutant quorum-size-2-allowed        $L "s/\(defparameter \+valid-quorum-sizes\+ '\(3 5 7\)/(defparameter +valid-quorum-sizes+ '(2 3 5 7)/"
run_mutant tier1-offset                 $L 's/\(defparameter \+tier-1-offset\+ 720\)/(defparameter +tier-1-offset+ 721)/'
run_mutant invoice-lock-ignores-fee     $L 's/\(%lock d \(\+ \(f :amount\) fee\)\)/(%lock d (f :amount))/'
run_mutant transfer-complete-no-debit   $L 's/\(setf \(deposit-balance src\) \(max 0 \(- \(deposit-balance src\) \(getf p :amount\)\)\)\)/nil/'
run_mutant transfer-lock-no-check       $L 's/\(when \(< \(deposit-available-balance d\) total\)/(when nil/'
run_mutant sequence-check-off           $L 's/\(unless \(= \(up:update-seq update\) \(1\+ \(ledger-sequence ledger\)\)\)/(unless t/'
run_mutant chain-check-off              $L 's/\(unless \(equalp \(up:update-prev-hash update\) \(ledger-chain-tip ledger\)\)/(unless t/'
run_mutant content-hash-no-cosigs       $U 's/collect \(cat \(cosig-member-ledger-hash c\) \(cosig-signature c\)\)\)\)\)\)/collect (octets))))))/'
run_mutant chain-hash-no-opsig          $U 's/\(sha256 \(cat \(content-hash u\) \(update-operator-sig u\)\)\)\)/(sha256 (content-hash u)))/'
run_mutant cosign-data-no-len           $U 's/\(int->le \(length \(update-message u\)\) 4\) \(update-message u\)\)\)\)$/(update-message u))))/'
run_mutant ledger-id-unsigned           $U 's/\(cat \(int->le \(update-seq u\) 8\) \(update-ledger-id u\)$/(cat (int->le (update-seq u) 8)/'
run_mutant block-height-unsigned        $U 's/^         \(int->le \(update-block-height u\) 4\)$/         (octets)/'
run_mutant operator-digest-no-count     $U 's/\(int->le \(length sigs\) 2\) sigs\)\)/sigs))/'
run_mutant cosigs-unsorted              $U "s/\(sort \(copy-list \(update-cosignatures update\)\) #'bytes< :key #'cosig-pubkey\)/(copy-list (update-cosignatures update))/"
run_mutant cosig-len-unchecked          $U 's/\(unless \(= len 129\)/(unless (= len 0)/'
run_mutant duplicate-cosigner-allowed   $U 's/\(return-from verify-cosignatures \(values nil "duplicate cosigner"\)\)/nil/'
run_mutant threshold-off-by-one         $U 's/\(if \(< \(length seen\) threshold\)/(if (< (1+ (length seen)) threshold)/'
run_mutant xonly-wrong-slice            $U 's/\(defun x-only \(pubkey33\) \(subseq pubkey33 1 33\)\)/(defun x-only (pubkey33) (subseq pubkey33 0 32))/'
run_mutant seq-encoded-le               $U 's/\(cons \+t-seq\+ \(int->be \(update-seq u\) 8\)\)/(cons +t-seq+ (int->le (update-seq u) 8))/'
run_mutant operator-sig-not-verified    $U 's/\(and \(secp:schnorr-verify \(x-only \(update-operator-id u\)\) \(operator-digest u\) \(update-operator-sig u\)\) t\)/t/'
echo "=== summary ==="; grep -c SURVIVED "$OUT"; grep -c killed "$OUT"
