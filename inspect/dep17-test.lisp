;;;; inspect/dep17-test.lisp — DEP-17 operation encoding against the reference
;;;; conformance vector and the fixture ledger's real wallet signatures.

(in-package #:cl-deposits.test)

(defun json-string-field (text key)
  (let* ((k (format nil "\"~a\"" key)) (p (search k text))
         (q (position #\" text :start (+ p (length k) 1)))
         (e (position #\" text :start (1+ q))))
    (subseq text (1+ q) e)))

(with-gate ("dep17: operation preimage matches the reference vector")
  (let* ((text (with-open-file (in (vector-path "calculus/01_pk_valid.json"))
                 (let ((s (make-string (file-length in)))) (subseq s 0 (read-sequence s in)))))
         (expected (hx (json-string-field text "operation_hex")))
         (mine (d17:operation-preimage (make-array 32 :element-type '(unsigned-byte 8))
                                       "spend" '(("amount" . (:int 100))) 0 #xffffffff)))
    (check-bytes "spend{amount:100}, deposit 0, nonce 0, expiry max" mine expected)
    (check-bytes "int is 16-byte BE two's complement" (d17:encode-value '(:int -1))
                 (u:cat (hx "00") (make-array 16 :element-type '(unsigned-byte 8) :initial-element 255)))
    (check-bytes "symbol" (d17:encode-value '(:symbol "ab")) (hx "06 00000002 6162"))
    (check-bytes "list of ints" (d17:encode-value '(:list ((:int 1) (:int 2))))
                 (hx "05 00000002 00 00000000000000000000000000000001 00 00000000000000000000000000000002"))))

(with-gate ("dep17: every depositor signature in the fixture verifies")
  ;; Replay the chain so each lock can be checked against the descriptor of the
  ;; deposit it spends from.
  (let* ((chain (chain-in-order *distinct*)) (ledger (lg:make-ledger))
         (results (make-hash-table :test #'equal)) (hashlocks 0) (bad-hashlocks 0))
    (dolist (x chain)
      (let* ((o (op:decode-operation (up:update-message x))) (type (op:operation-type o)))
        (case type
          ((:invoice-lock :transfer-lock :onchain-lock :deposit-key-rotate)
           (let* ((did (or (op:field o :deposit-id) (op:field o :source-deposit-id)))
                  (d (lg:find-deposit ledger did)))
             (incf (gethash (list type (d17:verify-operation-witness o (lg:deposit-descriptor d) (op:field o :witness)))
                            results 0))))
          (:transfer-complete
           ;; completion_script "sha256(H)": the script witness must carry H's preimage.
           (let* ((p (gethash (op:field o :transfer-id) (lg:ledger-pending-transfers ledger)))
                  (script (getf p :completion-script))
                  (h (and script (search "sha256(" script)
                          (hx (subseq script 7 (position #\) script)))))
                  (w (op:field o :script-witness)))
             (incf hashlocks)
             (unless (and h w (= (length w) 1) (equalp (u:sha256 (first w)) h)) (incf bad-hashlocks)))))
        (lg:apply-update ledger x :check-chain nil)))   ; the v1 fixture: see *distinct*
    (format t "      ~{~a~^ ~}~%" (loop for k being the hash-keys of results using (hash-value v) collect (format nil "~a=~a" k v)))
    (check-equal "InvoiceLock signatures all verify" (gethash '(:invoice-lock :ok) results 0) 10)
    (check-equal "TransferLock signatures all verify" (gethash '(:transfer-lock :ok) results 0) 4)
    (check-equal "no unverifiable depositor signatures"
                 (loop for k being the hash-keys of results using (hash-value v) unless (eq (second k) :ok) sum v) 0)
    (check-equal "TransferComplete witnesses open their sha256 hashlocks" (list hashlocks bad-hashlocks) '(4 0))
    ;; Mutations: amount, nonce, expiry, deposit id each break the signature.
    (let* ((x (find-if (lambda (x) (eq (op:operation-type (op:decode-operation (up:update-message x))) :invoice-lock)) chain))
           (o (op:decode-operation (up:update-message x)))
           (fresh (lg:make-ledger)))
      (dolist (y chain) (when (< (up:update-seq y) (up:update-seq x)) (lg:apply-update fresh y :check-chain nil)))
      (let ((desc (lg:deposit-descriptor (lg:find-deposit fresh (op:field o :deposit-id)))))
        (check-equal "baseline verifies" (d17:verify-operation-witness o desc (op:field o :witness)) :ok)
        (dolist (field '(:amount :nonce :expiry))
          (let ((m (copy-list o)))
            (setf (getf m field) (logxor 1 (getf m field)))
            (check (format nil "changing ~a breaks the signature" field)
                   (null (d17:verify-operation-witness m desc (op:field o :witness))))))
        (let ((m (copy-list o)))
          (remf m :fee)
          (check "dropping the optional fee arg breaks the signature (when present)"
                 (or (null (op:field o :fee)) (null (d17:verify-operation-witness m desc (op:field o :witness))))))))
    ;; Our own signing round-trips through the same verifier.
    (let* ((priv 777777777777777777777) (pub (up:compressed-pubkey priv))
           (o (list :type :invoice-lock :deposit-id (op:deposit-id "x") :amount 5 :payment-id (u:sha256 (hx "01"))
                    :sequence-number 1 :nonce 9 :expiry 100 :witness '())))
      (check-equal "sign-operation verifies under pk(K)"
                   (d17:verify-operation-witness o (format nil "pk(~a)" (u:bytes->hex pub)) (d17:sign-operation o priv))
                   :ok))))

