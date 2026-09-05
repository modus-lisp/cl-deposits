;;;; inspect/update-test.lisp — DEP-02 against a real ledger.
;;;;
;;;; The vector is the reference implementation's audit fixture: 372 published
;;;; copies of 52 distinct updates (sequence 0..51) of one ledger, including
;;;; republications carrying grown cosignature sets.  Every claim about the hash
;;;; chain and the signatures below is checked against it.

(in-package #:cl-deposits.test)

(with-gate ("tlv")
  (check-equal "bigsize 1 byte" (multiple-value-list (tlv:read-bigsize (hx "fc") 0)) '(252 1))
  (check-equal "bigsize 3 byte" (multiple-value-list (tlv:read-bigsize (hx "fd00fd") 0)) '(253 3))
  (check-signals "bigsize non-minimal" tlv:tlv-error (tlv:read-bigsize (hx "fd00fc") 0))
  (check-bytes "bigsize encode 65536" (tlv:bigsize-bytes 65536) (hx "fe00010000"))
  (check-equal "decode stream" (tlv:decode (hx "000101 0202abcd")) `((0 . ,(hx "01")) (2 . ,(hx "abcd"))))
  (check-signals "out of order" tlv:tlv-error (tlv:decode (hx "0201aa 0001bb")))
  (check-signals "duplicate" tlv:tlv-error (tlv:decode (hx "0001aa 0001bb")))
  (check-signals "overrun" tlv:tlv-error (tlv:decode (hx "0005aa")))
  (check-bytes "encode sorts" (tlv:encode `((2 . ,(hx "abcd")) (0 . ,(hx "01")))) (hx "000101 0202abcd"))
  (check-bytes "base64 roundtrip" (u:base64-decode (u:base64-encode (hx "00ff10"))) (hx "00ff10")))

(defvar *raw* (read-json-string-array (vector-path "ledger_57f60e1dbef339e2.json")))
(defvar *updates* (mapcar (lambda (s) (up:decode-update (u:base64-decode s))) *raw*))

(with-gate ("signed-update: decode and re-encode")
  (check-equal "372 published copies" (length *updates*) 372)
  (check "one ledger" (every (lambda (x) (equalp (up:update-ledger-id x) (up:update-ledger-id (first *updates*)))) *updates*))
  (check "one operator" (every (lambda (x) (equalp (up:update-operator-id x) (up:update-operator-id (first *updates*)))) *updates*))
  (check-equal "sequences 0..51" (sort (remove-duplicates (mapcar #'up:update-seq *updates*)) #'<)
               (loop for i to 51 collect i))
  (check-equal "re-encode is byte-identical (all 372)"
               (loop for raw in *raw* for x in *updates*
                     count (not (equalp (u:base64-decode raw) (up:encode-update x))))
               0)
  (check-equal "cosignature counts" (sort (remove-duplicates (mapcar (lambda (x) (length (up:update-cosignatures x))) *updates*)) #'<)
               '(0 2 3))
  (check "cosignatures arrive sorted by pubkey"
         (every (lambda (x) (equalp (up:update-cosignatures x) (up:sorted-cosignatures x))) *updates*)))

(with-gate ("signed-update: hash chain")
  (let ((tips (make-hash-table :test #'equalp)))
    (dolist (x *updates*) (setf (gethash (up:chain-hash x) tips) x))
    (let ((genesis (remove-if-not (lambda (x) (u:zero-bytes-p (up:update-prev-hash x))) *updates*))
          (unresolved (remove-if (lambda (x) (or (u:zero-bytes-p (up:update-prev-hash x))
                                                 (gethash (up:update-prev-hash x) tips)))
                                 *updates*)))
      (check "genesis copies are all sequence 0" (every (lambda (x) (zerop (up:update-seq x))) genesis))
      (check-equal "14 genesis copies" (length genesis) 14)
      (check-equal "every non-genesis prev_hash resolves to a published chain_hash" (length unresolved) 0)
      (check "each resolves to sequence n-1"
             (every (lambda (x) (or (zerop (up:update-seq x))
                                    (= (up:update-seq (gethash (up:update-prev-hash x) tips)) (1- (up:update-seq x)))))
                    *updates*))
      (check-equal "52 distinct updates among the 372 copies"
                   (length (remove-duplicates *raw* :test #'string=)) 52))))

(with-gate ("signed-update: signatures")
  (let ((versions (make-hash-table)) (cosig-versions (make-hash-table)) (bad-cosigs 0))
    (dolist (x *updates*)
      (incf (gethash (up:verify-operator-signature x) versions 0))
      (dolist (c (up:update-cosignatures x))
        (let ((v (up:verify-cosignature x c)))
          (incf (gethash v cosig-versions 0))
          (unless v (incf bad-cosigs)))))
    (check-equal "every operator signature verifies" (gethash nil versions 0) 0)
    (format t "      operator digest versions: ~{~a=~a~^ ~}~%"
            (loop for k being the hash-keys of versions using (hash-value v) append (list k v)))
    (check-equal "every cosignature verifies" bad-cosigs 0)
    (format t "      cosign digest versions: ~{~a=~a~^ ~}~%"
            (loop for k being the hash-keys of cosig-versions using (hash-value v) append (list k v)))
    (check "verify-cosignatures accepts each update" (every (lambda (x) (up:verify-cosignatures x)) *updates*))
    ;; Mutations must be caught.
    (let* ((x (find-if (lambda (x) (= 2 (length (up:update-cosignatures x)))) *updates*))
           (y (up:decode-update (up:encode-update x))))
      (setf (aref (up:update-message y) 3) (logxor 1 (aref (up:update-message y) 3)))
      (check "flipped message bit breaks operator signature" (null (up:verify-operator-signature y)))
      (check "flipped message bit breaks cosignatures" (not (up:verify-cosignatures y)))
      (let ((z (up:decode-update (up:encode-update x))))
        (setf (up:update-cosignatures z) (list (first (up:update-cosignatures z)) (first (up:update-cosignatures z))))
        (check "duplicate cosigner rejected" (not (up:verify-cosignatures z))))
      (check "threshold enforced" (not (up:verify-cosignatures x :threshold 3)))
      (check "quorum membership enforced"
             (not (up:verify-cosignatures x :quorum (list (up:update-operator-id x))))))))

(with-gate ("signed-update: signing round trip")
  (let* ((op-priv 12345678901234567890) (co-priv 98765432109876543210)
         (op-pub (up:compressed-pubkey op-priv))
         (co-pub (up:compressed-pubkey co-priv))
         (u (up:make-signed-update :operator-id op-pub :ledger-id (u:sha256 (hx "01")) :seq 7
                                   :prev-hash (u:sha256 (hx "02")) :message (hx "00010c")))
         (mlh (u:sha256 (hx "03"))))
    (push (up:sign-cosignature u co-priv co-pub mlh) (up:update-cosignatures u))
    (up:sign-operator u op-priv)
    (check-equal "cosignature verifies as v1" (up:verify-cosignature u (first (up:update-cosignatures u))) :v1)
    (check-equal "operator signature verifies as v1" (up:verify-operator-signature u) :v1)
    (let ((back (up:decode-update (up:encode-update u))))
      (check-bytes "round trip preserves chain hash" (up:chain-hash back) (up:chain-hash u)))))

(report)
