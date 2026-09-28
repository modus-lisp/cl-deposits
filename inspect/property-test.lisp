;;;; inspect/property-test.lisp — properties of the ledger fold and the update
;;;; codec under seeded random sequences.  The seed is printed; rerun with
;;;; PROPERTY_SEED=<n> to reproduce a failure.

(in-package #:cl-deposits.test)

(defvar *seed* (let ((s (uiop:getenv "PROPERTY_SEED"))) (if s (parse-integer s) (random (expt 2 31) (make-random-state t)))))
(defvar *rs* (sb-ext:seed-random-state *seed*))
(defun rnd (n) (random n *rs*))
(defun rbytes (n) (let ((a (make-array n :element-type '(unsigned-byte 8)))) (dotimes (i n a) (setf (aref a i) (rnd 256)))))
(defun pick (list) (nth (rnd (length list)) list))

(format t "      property seed ~a~%" *seed*)
(defvar *diagnose* t)

;;; A model that tracks what the fold must conserve.
(defstruct model (credited 0) (spent 0) (fees 0) (booked 0) (open '()) (closed '()))
;;; FEES = fees debited from balances; BOOKED = fees the ledger records (the
;;; TransferComplete fee is booked but never debited — reference semantics).

(defun run-random-sequence (steps)
  "Apply STEPS random operations; return (values ledger model history) where
   HISTORY is the list of (op . outcome) with outcome :ok or the error kind."
  (let* ((ledger (lg:make-ledger)) (m (make-model)) (history '())
         (deposits (loop for i below 3 collect (op:deposit-id (format nil "pk(~a)" (u:bytes->hex (up:compressed-pubkey (+ 1000 i)))))))
         (pending-invoices '()) (pending-withdrawals '()) (pending-transfers '()) (n 0))
    (lg:apply-operation ledger (list :type :ledger-open :operator-id (up:compressed-pubkey 7) :reserves-id "g" :genesis-block 0
                                     :reserves-amount (* 1000 1000000) :collateral-amount 0))
    (dolist (d deposits)
      (lg:apply-operation ledger (list :type :deposit-open :deposit-id d :descriptor (u:bytes->hex d) :receive-requires-sig nil
                                       :transfer-fees (op:make-transfer-fees :fixed-msats (rnd 50) :rate-bps 0)))
      (push d (model-open m)))
    (flet ((try (o &key on-ok)
             (let* ((ob0 (lg:total-obligations ledger)) (f0 (lg:ledger-fees-accumulated ledger))
                    (mc0 (model-credited m)) (ms0 (model-spent m)) (mf0 (model-fees m)) (mb0 (model-booked m))
                    (outcome (handler-case (progn (lg:apply-operation ledger o) (when on-ok (funcall on-ok)) :ok)
                               (lg:ledger-error (e) (lg::ledger-error-kind e)))))
               (when (and (eq outcome :ok) *diagnose*)
                 (let ((fold-d (- (lg:total-obligations ledger) ob0)) (fold-f (- (lg:ledger-fees-accumulated ledger) f0))
                       (model-d (- (- (model-credited m) mc0) (- (model-spent m) ms0) (- (model-fees m) mf0))) (model-f (+ (- (model-fees m) mf0) (- (model-booked m) mb0))))
                   (unless (and (= fold-d model-d) (= fold-f model-f))
                     (format t "      MISMATCH ~a: fold obligations ~a fees ~a | model obligations ~a fees ~a~%" (op:operation-type o) fold-d fold-f model-d model-f)
                     (setf *diagnose* nil))))
               (push (cons o outcome) history)
               outcome))
           (dep () (pick deposits))
           (fixed (d) (op:transfer-fees-fixed-msats (lg:deposit-transfer-fees (lg:find-deposit ledger d)))))
      (dotimes (step steps)
        (incf n)
        (case (rnd 11)
          (0 (let ((d (dep)) (amt (1+ (rnd 100000))))
               (try (list :type :onchain-credit :txid (rbytes 32) :vout 0 :deposit-id d :amount amt :funding-address "x")
                    :on-ok (lambda () (incf (model-credited m) amt)))))
          (1 (let ((d (dep)) (amt (1+ (rnd 100000))) (h (rbytes 32)))
               (try (list :type :invoice-credit :payment-hash h :deposit-id d :amount amt :invoice-id "i" :sequence-number n)
                    :on-ok (lambda () (incf (model-credited m) amt)))))
          (2 (let ((d (dep)) (amt (1+ (rnd 60000))) (fee (rnd 100)) (pid (rbytes 32)))
               (try (list :type :invoice-lock :deposit-id d :amount amt :payment-id pid :sequence-number n :nonce n :expiry 1000 :witness '() :fee fee)
                    :on-ok (lambda () (push (list pid d amt fee) pending-invoices)))))
          (3 (when pending-invoices
               (destructuring-bind (pid d amt fee) (pick pending-invoices)
                 (try (list :type :invoice-fulfill :deposit-id d :amount amt :payment-id pid :sequence-number n :witness '() :preimage (rbytes 32))
                      :on-ok (lambda () (incf (model-spent m) amt) (incf (model-fees m) fee) (setf pending-invoices (remove pid pending-invoices :key #'first)))))))
          (4 (when pending-invoices
               (destructuring-bind (pid d amt fee) (pick pending-invoices)
                 (declare (ignore amt fee))
                 (let ((charged (min (fixed d) (lg:deposit-balance (lg:find-deposit ledger d)))))
                   (try (list :type :invoice-fail :deposit-id d :payment-id pid :sequence-number n)
                        :on-ok (lambda () (incf (model-fees m) charged) (setf pending-invoices (remove pid pending-invoices :key #'first))))))))
          (5 (let ((d (dep)) (amt (1+ (rnd 60000))) (fee (rnd 500)) (wid (rbytes 32)))
               (try (list :type :onchain-lock :deposit-id d :amount amt :fee-sats fee :destination-address "tb1q" :withdrawal-id wid :nonce n :expiry 1000 :witness '())
                    :on-ok (lambda () (push (list wid d amt fee) pending-withdrawals)))))
          (6 (when pending-withdrawals
               (destructuring-bind (wid d amt fee) (pick pending-withdrawals)
                 (if (zerop (rnd 2))
                     (try (list :type :onchain-fulfill :deposit-id d :withdrawal-id wid :amount amt :txid (rbytes 32) :destination-address "tb1q")
                          :on-ok (lambda () (incf (model-spent m) (+ amt fee)) (setf pending-withdrawals (remove wid pending-withdrawals :key #'first))))
                     (let ((charged (min (fixed d) (lg:deposit-balance (lg:find-deposit ledger d)))))
                       (try (list :type :onchain-fail :deposit-id d :withdrawal-id wid)
                            :on-ok (lambda () (incf (model-fees m) charged) (setf pending-withdrawals (remove wid pending-withdrawals :key #'first)))))))))
          (7 (let* ((src (dep)) (dst (dep)) (amt (1+ (rnd 60000))) (fee (rnd 100)) (tid (rbytes 32)))
               (try (list :type :transfer-lock :transfer-nonce (rbytes 32) :source-deposit-id src :destination-deposit-id dst :amount amt :fee fee
                          :completion-script "sha256(00)" :timeout-height 100 :transfer-id tid :nonce n :expiry 1000 :witness '())
                    :on-ok (lambda () (push (list tid src dst amt fee) pending-transfers)))))
          (8 (when pending-transfers
               (destructuring-bind (tid src dst amt fee) (pick pending-transfers)
                 (declare (ignore src dst amt))
                 (if (zerop (rnd 2))
                     (try (list :type :transfer-complete :transfer-id tid :script-witness (list (rbytes 32)))
                          ;; Reference semantics: the fee is booked as revenue but never leaves the
                          ;; sender's balance (see UPSTREAM-NOTES); obligations are unchanged.
                          :on-ok (lambda () (incf (model-booked m) fee) (setf pending-transfers (remove tid pending-transfers :key #'first))))
                     (let ((charged (min (fixed (second (find tid pending-transfers :key #'first))) (lg:deposit-balance (lg:find-deposit ledger (second (find tid pending-transfers :key #'first)))))))
                       (try (list :type :transfer-fail :transfer-id tid :block-hash (rbytes 32) :reason 0)
                            :on-ok (lambda () (incf (model-fees m) charged) (setf pending-transfers (remove tid pending-transfers :key #'first)))))))))
          (9 (let* ((d (dep)) (bal (lg:deposit-balance (lg:find-deposit ledger d)))
                    ;; A conforming operator never collects from locked funds (the fold would
                    ;; let it, and obligations would then drift — see the quirk check below).
                    (amt (min (rnd 2000) (lg:deposit-available-balance (lg:find-deposit ledger d)))))
               ;; Reference semantics: the full amount is booked even when the balance
               ;; only covered part of it (see UPSTREAM-NOTES).
               (try (list :type :fee-collect :deposit-id d :amount amt :block-height 10)
                    :on-ok (lambda () (incf (model-fees m) (min amt bal)) (incf (model-booked m) (- amt (min amt bal)))))))
          (10 (let ((d (dep)))
                (try (list :type :fee-change :deposit-id d :new-fees (op:make-fees :annualized-msats 1 :annualized-bps 1 :frequency-blocks 1) :effective-block 5)))))))
    (values ledger m (reverse history))))

(defun invariants-hold-p (ledger m)
  "Every deposit sane, and obligations == credited - spent - fees (for closed-form fees)."
  (and (loop for d being the hash-values of (lg:ledger-deposits ledger)
             always (and (>= (lg:deposit-balance d) 0) (<= (lg:deposit-locked-balance d) (lg:deposit-balance d))))
       (= (lg:total-obligations ledger) (- (model-credited m) (model-spent m) (model-fees m)))
       (= (lg:ledger-fees-accumulated ledger) (+ (model-fees m) (model-booked m)))
       (<= (lg:total-obligations ledger) (lg:ledger-reserves-amount ledger))))

(with-gate ("property: the ledger fold conserves value under random operation sequences")
  (let ((failures 0) (applied 0) (refused 0) (kinds (make-hash-table)))
    (dotimes (run 40)
      (multiple-value-bind (ledger m history) (run-random-sequence 60)
        (loop for (nil . outcome) in history do (if (eq outcome :ok) (incf applied) (progn (incf refused) (incf (gethash outcome kinds 0)))))
        (unless (invariants-hold-p ledger m)
          (incf failures)
          (format t "      run ~a broke invariants: obligations ~a credited ~a spent ~a fees ~a/~a~%" run (lg:total-obligations ledger)
                  (model-credited m) (model-spent m) (model-fees m) (lg:ledger-fees-accumulated ledger)))))
    (format t "      ~a operations applied, ~a refused (~{~a=~a~^ ~})~%" applied refused
            (loop for k being the hash-keys of kinds using (hash-value v) append (list k v)))
    (check-equal "40 runs x 60 steps: invariants hold after every run" failures 0)
    (check "the generator exercises refusals too" (> refused 50))
    (check "every rejection is a typed ledger error" (loop for k being the hash-keys of kinds always (keywordp k)))))

(with-gate ("reference quirk: FeeCollect from locked funds lets a later completion mint obligations")
  ;; Documented in UPSTREAM-NOTES: FeeCollect uses saturating subtraction on the
  ;; whole balance, ignoring locked_balance.  Our fold mirrors it.
  (let* ((l (lg:make-ledger)) (d (op:deposit-id "q")))
    (lg:apply-operation l (list :type :ledger-open :operator-id (up:compressed-pubkey 7) :reserves-id "g" :genesis-block 0 :reserves-amount 1000000000 :collateral-amount 0))
    (lg:apply-operation l (list :type :deposit-open :deposit-id d :descriptor "q" :receive-requires-sig nil))
    (lg:apply-operation l (list :type :onchain-credit :txid (rbytes 32) :vout 0 :deposit-id d :amount 1000 :funding-address "x"))
    (lg:apply-operation l (list :type :invoice-lock :deposit-id d :amount 800 :payment-id (rbytes 32) :sequence-number 1 :nonce 1 :expiry 9 :witness '() :fee 0))
    (lg:apply-operation l (list :type :fee-collect :deposit-id d :amount 900 :block-height 1))
    (check-equal "the fold lets FeeCollect take locked funds (balance 100 < locked 800)"
                 (list (lg:deposit-balance (lg:find-deposit l d)) (lg:deposit-locked-balance (lg:find-deposit l d))) '(100 800))
    (check "locked > balance: the invariant a conforming ledger keeps is already broken"
           (> (lg:deposit-locked-balance (lg:find-deposit l d)) (lg:deposit-balance (lg:find-deposit l d))))))

(with-gate ("property: replay is deterministic and errors leave state untouched")
  (let ((bad 0))
    (dotimes (run 20)
      (multiple-value-bind (ledger m history) (run-random-sequence 40)
        (declare (ignore m))
        ;; Replaying only the accepted operations must reproduce the same state.
        (let ((again (lg:make-ledger)))
          (lg:apply-operation again (list :type :ledger-open :operator-id (up:compressed-pubkey 7) :reserves-id "g" :genesis-block 0 :reserves-amount (* 1000 1000000) :collateral-amount 0))
          (dolist (d (loop for i below 3 collect (op:deposit-id (format nil "pk(~a)" (u:bytes->hex (up:compressed-pubkey (+ 1000 i)))))))
            (unless (gethash d (lg:ledger-deposits again))
              (let ((orig (gethash d (lg:ledger-deposits ledger))))
                (lg:apply-operation again (list :type :deposit-open :deposit-id d :descriptor (u:bytes->hex d) :receive-requires-sig nil
                                                :transfer-fees (if orig (lg:deposit-transfer-fees orig) (op:make-transfer-fees)))))))
          (loop for (o . outcome) in history
                do (if (eq outcome :ok)
                       (lg:apply-operation again o)
                       ;; a refused op must be refused again, and change nothing
                       (let ((before (lg:total-obligations again)) (fees (lg:ledger-fees-accumulated again)))
                         (handler-case (progn (lg:apply-operation again o) (incf bad)) (lg:ledger-error () nil))
                         (unless (and (= before (lg:total-obligations again)) (= fees (lg:ledger-fees-accumulated again))) (incf bad)))))
          (unless (and (= (lg:total-obligations again) (lg:total-obligations ledger))
                       (= (lg:ledger-fees-accumulated again) (lg:ledger-fees-accumulated ledger))
                       (loop for d being the hash-values of (lg:ledger-deposits ledger)
                             always (let ((e (gethash (lg:deposit-id d) (lg:ledger-deposits again))))
                                      (and e (= (lg:deposit-balance d) (lg:deposit-balance e)) (= (lg:deposit-locked-balance d) (lg:deposit-locked-balance e))))))
            (incf bad)))))
    (check-equal "20 runs: replay matches, refusals are stable and side-effect free" bad 0)))

(with-gate ("property: signed-update codec and hash chain under random inputs")
  (let ((bad 0))
    (dotimes (i 200)
      (let* ((cosigs (loop repeat (rnd 4) collect (up:make-cosignature :pubkey (up:compressed-pubkey (+ 5000 (rnd 1000))) :signature (rbytes 64) :member-ledger-hash (rbytes 32))))
             (u (up:make-signed-update :operator-id (up:compressed-pubkey 77) :ledger-id (rbytes 32) :seq (rnd 100000) :prev-hash (rbytes 32)
                                       :message (rbytes (1+ (rnd 300))) :block-height (rnd 2) :block-hash (if (zerop (rnd 2)) (rbytes 32) (make-array 32 :element-type '(unsigned-byte 8)))
                                       :operator-sig (rbytes 64) :cosignatures (remove-duplicates cosigs :key #'up:cosig-pubkey :test #'equalp)))
             (bytes (up:encode-update u))
             (back (up:decode-update bytes)))
        (unless (equalp (up:encode-update back) bytes) (incf bad))
        (unless (equalp (up:chain-hash back) (up:chain-hash u)) (incf bad))
        ;; any single bit flip in the encoding changes the chain hash or fails to decode
        (let ((flipped (copy-seq bytes)) (k (rnd (length bytes))))
          (setf (aref flipped k) (logxor 1 (aref flipped k)))
          (handler-case (let* ((f (up:decode-update flipped))
                               ;; v2: every field but the keys (operator_id and cosigner pubkeys,
                               ;; which the signatures cover) is in the chain hash
                               (hashed (lambda (x) (list (up:update-seq x) (up:update-ledger-id x) (up:update-block-height x) (up:update-block-hash x)
                                                         (up:update-prev-hash x) (up:update-message x) (up:update-operator-sig x)
                                                         (mapcar (lambda (c) (u:cat (up:cosig-member-ledger-hash c) (up:cosig-signature c))) (up:sorted-cosignatures x)))))
                               (hashed-part-same (equalp (funcall hashed f) (funcall hashed u))))
                          (if hashed-part-same
                              (unless (equalp (up:chain-hash f) (up:chain-hash u)) (incf bad))
                              (when (equalp (up:chain-hash f) (up:chain-hash u)) (incf bad))))
            (error () nil)))))
    (check-equal "200 random updates: encode/decode identity, chain hash stable, bit flips detected" bad 0)))

(report)
