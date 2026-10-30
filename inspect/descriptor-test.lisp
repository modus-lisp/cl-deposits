;;;; inspect/descriptor-test.lisp — DEP-16 §Descriptor validity, against the shared vector.
;;;;
;;;; inspect/vectors/descriptor_validity.json is shared with deposits-rust
;;;; (deposits-protocol/tests/vectors/).  A case is valid iff its descriptor passes validity and,
;;;; when max_descriptor_bytes is given, fits within it.

(in-package #:cl-deposits.test)

(with-gate ("descriptor validity (shared vector)")
  (let* ((text (with-open-file (in (vector-path "descriptor_validity.json") :external-format :utf-8)
                 (let ((s (make-string (file-length in)))) (subseq s 0 (read-sequence s in)))))
         (cases (gethash "cases" (json-simple:parse text))))
    (check "the vector has cases" (> (length cases) 50))
    (map nil (lambda (c)
               (let* ((d (sb-ext:octets-to-string (u:hex->bytes (gethash "descriptor_hex" c)) :external-format :utf-8))
                      (max (gethash "max_descriptor_bytes" c))
                      (why (or (d16:descriptor-violation d)
                               (and max (> (length (sb-ext:string-to-octets d :external-format :utf-8)) max)
                                    "over the size cap")))
                      (expected (gethash "valid" c)))
                 (check (gethash "name" c) (eq (null why) (and expected (not (eq expected :false)) t))
                        (format nil "expected valid=~a, got ~s" expected why))))
         cases)))
