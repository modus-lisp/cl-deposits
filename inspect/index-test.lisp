;;;; inspect/index-test.lisp — loaded before a gate's scenarios: every record's indexes, counts
;;;; and LEDGER-AT are checked against a from-scratch scan of its history as the scenarios run
;;;; (forks, rotations, disputes, restarts).  Checkpoints are made dense so LEDGER-AT replays from
;;;; them, not from genesis.  The gate's REPORT first fails it on any mismatch.
(in-package #:cl-deposits.test)
(setf nd::*verify-indexes* t nd::*verify-every* 7
      nd::*checkpoint-every* 8 nd::*checkpoint-recent* 32 nd::*checkpoint-sparse* 64
      nd::*index-verifications* 0 nd::*index-mismatches* '())
(let ((report #'report))
  (setf (fdefinition 'report)
        (lambda ()
          (with-gate ("indexes: incremental record indexes equal a from-scratch rescan")
            (check (format nil "the scenarios exercised the check (~a verifications)" nd::*index-verifications*)
                   (plusp nd::*index-verifications*))
            (check-equal "no index, count, update-at or ledger-at mismatch"
                         (subseq nd::*index-mismatches* 0 (min 5 (length nd::*index-mismatches*))) '()))
          (funcall report))))
