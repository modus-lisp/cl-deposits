;;;; inspect/history-needs-test.lisp — DEP-06 §Judging a proof, against the shared vector.
;;;;
;;;; inspect/vectors/proof_history_needs.json is shared with deposits-rust
;;;; (deposits-protocol/tests/vectors/) and the spec (vectors/): the history each evidence type
;;;; rests on (FR:PROOF-HISTORY-NEEDS) and, for given replica tips, whether a member acts on a
;;;; proof, holds it until caught up, or refuses it (FR:PROOF-VERDICT).

(in-package #:cl-deposits.test)

(with-gate ("proof history needs and verdicts (shared vector)")
  (let* ((text (with-open-file (in (vector-path "proof_history_needs.json") :external-format :utf-8)
                 (let ((s (make-string (file-length in)))) (subseq s 0 (read-sequence s in)))))
         (cases (gethash "cases" (json-simple:parse text)))
         (rows 0))
    (check "the vector has a case per proof type" (>= (length cases) 13))
    (map nil (lambda (c)
               (let* ((name (gethash "name" c))
                      (proof (fr:json->broadcast (gethash "broadcast" c)))
                      (want (map 'list (lambda (p) (cons (elt p 0) (elt p 1))) (gethash "needs" c)))
                      (got (fr:proof-history-needs proof)))
                 (check-equal (format nil "needs: ~a" name) got want)
                 (map nil (lambda (v)
                            (let* ((tips (gethash "tips" v))
                                   (tip-of (lambda (id) (let ((tip (gethash id tips))) (and (integerp tip) tip))))
                                   (verifies (let ((x (gethash "verifies" v))) (and x (not (eq x :false)) (not (eq x :null)))))
                                   (verdict (fr:proof-verdict want tip-of verifies)))
                              (incf rows)
                              (check-equal (format nil "~a: tips ~a, ~:[fails~;verifies~]" name
                                                   (loop for k being the hash-keys of tips using (hash-value x)
                                                         collect (format nil "~a=~a" (subseq k 0 8) x))
                                                   verifies)
                                           (string-downcase (symbol-name verdict)) (gethash "expect" v))))
                      (gethash "verdicts" c))))
         cases)
    (check-equal "every verdict row was checked" rows 62)))
