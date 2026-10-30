;;;; inspect/commitment-test.lisp — DEP-02 §Balance Commitments, against the shared vector.
;;;;
;;;; inspect/vectors/balance_commitments.txt is shared with deposits-rust and generated here
;;;; (CL_DEPOSITS_WRITE_VECTORS=1).  A ledger is built step by step: each step is an operation as a
;;;; wallet or operator first writes it, the same operation after the operator declares its balance
;;;; commitments, and the height of the update that carries it.  Then judge cases: an operation
;;;; judged on the final state under a ruleset, for the commitment verdict alone.

(in-package #:cl-deposits.test)

(defun commitment-did (descriptor) (subseq (u:sha256 (u:ascii->bytes descriptor)) 0 16))

(defun commitment-apply-at (ledger o height seq)
  "Apply O to LEDGER as the update at HEIGHT and SEQ would (exit releases first, DEP-20 §3)."
  (let ((lg:*block-height* height) (lg:*update-seq* seq))
    (unless (eq (op:operation-type o) :quorum-begin) (lg::%release-expired-exits ledger height))
    (lg:apply-operation ledger o)))

(defun commitment-verdict (ledger ruleset hex height seq)
  "ok | mismatch | missing | decode | other: O judged on a copy of LEDGER under RULESET."
  (let ((o (handler-case (op:decode-operation (u:hex->bytes hex)) (error () nil))))
    (if (null o)
        "decode"
        (let ((l (lg:copy-ledger ledger)))
          (setf (lg:ledger-active-ruleset l) ruleset)
          (handler-case (progn (lg:speculate l o height seq) "ok")
            (lg:ledger-error (e)
              (case (lg::ledger-error-kind e)
                (:balance-commitment-mismatch "mismatch")
                (:missing-balance-commitment "missing")
                (t (format nil "other:~a" (lg::ledger-error-kind e))))))))))

(defun commitment-steps ()
  "(height operation) for the shared vector, as first written (no commitments)."
  (let* ((pa (up:compressed-pubkey (tk 717171)))
         (a (commitment-did "pk(commit-a)")) (b (commitment-did "pk(commit-b)")) (c (commitment-did "pk(commit-c)"))
         (d (commitment-did "pk(commit-d)"))
         (h (lambda (s) (u:sha256 (u:ascii->bytes s))))
         (pre1 (funcall h "pre1")) (pre2 (funcall h "pre2")) (pre3 (funcall h "pre3"))
         (spk (u:cat (u:hex->bytes "0014") (subseq (funcall h "exit") 0 20))))
    (list
     (list 100 (list :type :ledger-open :operator-id pa :reserves-id "commitments" :genesis-block 100
                     :reserves-amount 1000000000000 :collateral-amount 100000000000))
     (list 100 (list :type :deposit-open :deposit-id a :descriptor "pk(commit-a)"
                     :transfer-fees (op:make-transfer-fees :fixed-msats 700 :rate-bps 0)))
     (list 100 (list :type :deposit-open :deposit-id b :descriptor "pk(commit-b)"
                     :transfer-fees (op:make-transfer-fees :fixed-msats 1000 :rate-bps 0)))
     (list 101 (list :type :onchain-credit :txid (funcall h "t1") :vout 0 :deposit-id a :amount 5000000 :funding-address "bcrt1qa"))
     (list 101 (list :type :invoice-credit :payment-hash (funcall h "p1") :deposit-id b :amount 3000000 :invoice-id "inv-b" :sequence-number 1))
     (list 102 (list :type :invoice-lock :deposit-id a :amount 400000 :payment-id (u:sha256 pre1) :sequence-number 2
                     :nonce 1 :expiry 1000 :witness '() :timeout-height 200 :fee 1000))
     (list 103 (list :type :invoice-fulfill :deposit-id a :amount 400000 :payment-id (u:sha256 pre1) :sequence-number 3
                     :witness '() :preimage pre1))
     (list 104 (list :type :invoice-lock :deposit-id a :amount 200000 :payment-id (u:sha256 pre2) :sequence-number 4
                     :nonce 2 :expiry 1000 :witness '() :timeout-height 200 :fee 500))
     (list 105 (list :type :invoice-fail :deposit-id a :payment-id (u:sha256 pre2) :sequence-number 5))
     (list 106 (list :type :onchain-lock :deposit-id b :amount 500000 :fee-sats 2000 :destination-address "bcrt1qdest"
                     :withdrawal-id (funcall h "w1") :nonce 3 :expiry 1000 :witness '()))
     (list 107 (list :type :onchain-fulfill :deposit-id b :withdrawal-id (funcall h "w1") :amount 500000 :txid (funcall h "t2")
                     :destination-address "bcrt1qdest"))
     (list 108 (list :type :onchain-lock :deposit-id b :amount 300000 :fee-sats 1500 :destination-address "bcrt1qdest"
                     :withdrawal-id (funcall h "w2") :nonce 4 :expiry 1000 :witness '()))
     (list 109 (list :type :onchain-fail :deposit-id b :withdrawal-id (funcall h "w2")))
     (list 110 (list :type :fee-collect :deposit-id a :amount 2500 :block-height 110))
     (list 111 (list :type :transfer-lock :transfer-nonce (funcall h "n1") :source-deposit-id a :destination-deposit-id b
                     :amount 600000 :fee 3000 :completion-script (format nil "sha256(~a)" (u:bytes->hex (u:sha256 pre3)))
                     :timeout-height 300 :transfer-id (funcall h "x1") :nonce 5 :expiry 1000 :witness '()))
     (list 112 (list :type :transfer-complete :transfer-id (funcall h "x1") :script-witness (list pre3)))
     (list 113 (list :type :transfer-lock :transfer-nonce (funcall h "n2") :source-deposit-id b :destination-deposit-id a
                     :amount 250000 :fee 1000 :completion-script "sha256(00)"
                     :timeout-height 150 :transfer-id (funcall h "x2") :nonce 6 :expiry 1000 :witness '()))
     (list 150 (list :type :transfer-fail :transfer-id (funcall h "x2") :block-hash (funcall h "block 150") :reason 0))
     ;; An exit request locks without a commitment (it is not in the table); its expiry at 160
     ;; releases the lock before the next update's operation, and that update declares the release.
     (list 151 (list :type :exit-request :deposit-id a :amount 1000000 :exit-address spk :expires-at-height 160
                     :nonce 7 :expiry 1000 :witness '()))
     (list 160 (list :type :invoice-credit :payment-hash (funcall h "p2") :deposit-id a :amount 10000 :invoice-id "inv-a" :sequence-number 6))
     (list 161 (list :type :deposit-open :deposit-id c :descriptor "pk(commit-c)"))
     (list 161 (list :type :deposit-close :deposit-id c))
     ;; A deposit opened with no transfer_fees takes DEP-07's default schedule (2 msat + 20 bps):
     ;; its failed transfer keeps the fixed 2 msat (DEP-07 §Fee on Failure).
     (list 161 (list :type :deposit-open :deposit-id d :descriptor "pk(commit-d)"))
     (list 161 (list :type :onchain-credit :txid (funcall h "t3") :vout 0 :deposit-id d :amount 200000 :funding-address "bcrt1qd"))
     (list 161 (list :type :transfer-lock :transfer-nonce (funcall h "n4") :source-deposit-id d :destination-deposit-id a
                     :amount 50000 :fee 102 :completion-script "sha256(00)"
                     :timeout-height 161 :transfer-id (funcall h "x4") :nonce 9 :expiry 1000 :witness '()))
     (list 161 (list :type :transfer-fail :transfer-id (funcall h "x4") :block-hash (funcall h "block 161") :reason 0))
     (list 162 (list :type :transfer-lock :transfer-nonce (funcall h "n3") :source-deposit-id a :destination-deposit-id b
                     :amount 100000 :fee 0 :completion-script (format nil "sha256(~a)" (u:bytes->hex (u:sha256 pre3)))
                     :timeout-height 400 :transfer-id (funcall h "x3") :nonce 8 :expiry 1000 :witness '())))))

(defun commitment-judges (ledger seq)
  "(ruleset height operation-hex verdict) judged on LEDGER, the state after every step."
  (let* ((a (commitment-did "pk(commit-a)"))
         (h (lambda (s) (u:sha256 (u:ascii->bytes s))))
         (credit (list :type :onchain-credit :txid (funcall h "t9") :vout 0 :deposit-id a :amount 1000 :funding-address "bcrt1qa"))
         (filled (lg:fill-balance-commitments ledger credit 170 seq))
         (complete (lg:fill-balance-commitments ledger (list :type :transfer-complete :transfer-id (funcall h "x3")
                                                             :script-witness (list (funcall h "pre3")))
                                                170 seq))
         (enc (lambda (o) (u:bytes->hex (op:encode-operation o))))
         (cases '()))
    (flet ((add (rs o) (push (list rs 170 (funcall enc o) (commitment-verdict ledger rs (funcall enc o) 170 seq)) cases)))
      (dolist (rs '("cltv-offset-v2" "balance-commit-v4" "anchor-ladder-v5" "balance-anchor-v6"))
        (add rs filled)
        (add rs (lg::op-with filled :balance-after (1+ (op:field filled :balance-after))))
        (add rs (lg::op-with filled :locked-after (1+ (op:field filled :locked-after))))
        (add rs credit)
        (add rs complete)
        (add rs (lg::op-with complete :dest-balance-after (1- (op:field complete :dest-balance-after))))
        (add rs (remove-dest complete)))
      ;; A half-present pair is malformed whatever the ruleset.
      (push (list "balance-anchor-v6" 170 (u:bytes->hex (tlv:encode (list (cons 0 (u:octets 35)) (cons 66 (funcall h "t9")) (cons 68 (u:int->be 0 4))
                                                                            (cons 200 a) (cons 2 (u:int->be 1000 8)) (cons 74 (u:ascii->bytes "bcrt1qa"))
                                                                            (cons 223 (u:int->be 5 8)))))
                  "decode")
            cases))
    (nreverse cases)))

(defun remove-dest (o)
  "O without its destination commitment pair."
  (let ((out (list (first o) (second o))))
    (loop for (k v) on (cddr o) by #'cddr
          unless (member k '(:dest-balance-after :dest-locked-after)) do (setf out (append out (list k v))))
    out))

(with-gate ("DEP-02 balance commitments: the shared balance_commitments vector")
  (when (uiop:getenv "CL_DEPOSITS_WRITE_VECTORS")
    (let ((l (lg:make-ledger)) (seq 0))
      (with-open-file (o (vector-path "balance_commitments.txt") :direction :output :if-exists :supersede)
        (format o "# DEP-02 §Balance Commitments (shared cl-deposits / deposits-rust), generated by cl-deposits~%")
        (format o "# (inspect/commitment-test.lisp with CL_DEPOSITS_WRITE_VECTORS).  Each step is applied in order,~%")
        (format o "# starting from an empty ledger, as the update at HEIGHT with the next sequence (0 first):~%")
        (format o "#   step HEIGHT IN OUT   IN as first written, OUT after the operator declares its commitments~%")
        (format o "#                        (the post-update balances, exit releases included); OUT is applied.~%")
        (format o "#   judge RULESET HEIGHT OP VERDICT   OP judged on the final state under RULESET, as the next~%")
        (format o "#                        update: ok | mismatch | missing | decode (commitment verdicts only).~%")
        (loop for (height op) in (commitment-steps)
              do (let ((out (lg:fill-balance-commitments l op height seq)))
                   (format o "step ~a ~a ~a~%" height (u:bytes->hex (op:encode-operation op)) (u:bytes->hex (op:encode-operation out)))
                   (commitment-apply-at l out height seq)
                   (incf seq)))
        (loop for (rs height hex verdict) in (commitment-judges l seq)
              do (format o "judge ~a ~a ~a ~a~%" rs height hex verdict)))))
  (let ((l (lg:make-ledger)) (seq 0) (steps 0) (judges 0) (filled 0))
    (with-open-file (in (vector-path "balance_commitments.txt"))
      (loop for line = (read-line in nil) while line
            unless (or (zerop (length line)) (char= (char line 0) #\#))
              do (let ((w (uiop:split-string line :separator " ")))
                   (cond
                     ((string= (first w) "step")
                      (let* ((height (parse-integer (second w)))
                             (op (op:decode-operation (u:hex->bytes (third w))))
                             (out (lg:fill-balance-commitments l op height seq)))
                        (incf steps)
                        (unless (string= (third w) (fourth w)) (incf filled))
                        (check-equal (format nil "step ~a: the declared commitments" seq)
                                     (u:bytes->hex (op:encode-operation out)) (fourth w))
                        (handler-case (progn (commitment-apply-at l (op:decode-operation (u:hex->bytes (fourth w))) height seq)
                                             (check (format nil "step ~a applies" seq) t))
                          (lg:ledger-error (e) (check (format nil "step ~a applies: ~a" seq e) nil)))
                        (incf seq)))
                     ((string= (first w) "judge")
                      (incf judges)
                      (check-equal (format nil "judge ~a ~a" (second w) (subseq (fourth w) 0 16))
                                   (commitment-verdict l (second w) (fourth w) (parse-integer (third w)) seq)
                                   (fifth w)))))))
    (check-equal "balance_commitments: steps, filled, judges" (list steps filled judges) (list 27 25 29))
    (check-equal "a deposit opened without transfer_fees keeps the default fixed 2 msat on a TransferFail"
                 (lg:deposit-balance (lg:find-deposit l (commitment-did "pk(commit-d)"))) 199998)))
