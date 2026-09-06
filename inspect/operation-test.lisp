;;;; inspect/operation-test.lisp — operations and the ledger fold, against the fixture.

(in-package #:cl-deposits.test)

(defvar *distinct* (remove-duplicates *updates* :test #'equalp :key #'up:encode-update))

(with-gate ("operations: decode and re-encode every fixture operation")
  (check-equal "52 distinct updates" (length *distinct*) 52)
  (let ((types (make-hash-table)))
    (dolist (x *distinct*)
      (let ((o (op:decode-operation (up:update-message x))))
        (incf (gethash (op:operation-type o) types 0))))
    (format t "      ~{~a=~a~^ ~}~%" (loop for k being the hash-keys of types using (hash-value v) append (list k v))))
  (check-equal "byte-identical re-encode for all 52"
               (loop for x in *distinct*
                     count (not (equalp (op:encode-operation (op:decode-operation (up:update-message x)))
                                        (up:update-message x))))
               0)
  (check-signals "unknown discriminant rejected" op:op-error (op:decode-operation (hx "0001ff")))
  (check-signals "missing required field rejected" op:op-error (op:decode-operation (hx "000101")))
  (check-signals "unknown even tag rejected" op:op-error
    (op:encode-operation (op:decode-operation (u:cat (hx "00013c") (hx "6401aa")))))
  (check "unknown odd tag passes through"
         (equalp (op:encode-operation (op:decode-operation (u:cat (hx "00013c") (hx "6501aa"))))
                 (u:cat (hx "00013c") (hx "6501aa")))))

(with-gate ("operations: fixture semantics cross-checks")
  ;; Genesis: the ledger id in every update equals the id derived from LedgerOpen.
  (let* ((genesis (find 0 *distinct* :key #'up:update-seq))
         (o (op:decode-operation (up:update-message genesis))))
    (check-equal "genesis is LedgerOpen" (op:operation-type o) :ledger-open)
    (check-bytes "ledger_id = SHA256(operator || reserves_id || genesis_block_le)"
                 (op:compute-ledger-id (op:field o :operator-id) (op:field o :reserves-id) (op:field o :genesis-block))
                 (up:update-ledger-id genesis))
    (check-bytes "LedgerOpen operator_id is the signing operator" (op:field o :operator-id) (up:update-operator-id genesis)))
  ;; Every DepositOpen's id is the first 16 bytes of SHA256(descriptor).
  (let ((opens (loop for x in *distinct*
                     for o = (op:decode-operation (up:update-message x))
                     when (eq (op:operation-type o) :deposit-open) collect o)))
    (check "deposit_id = SHA256(descriptor)[0..16] for every DepositOpen"
           (and opens (every (lambda (o) (equalp (op:field o :deposit-id) (op:deposit-id (op:field o :descriptor)))) opens)))
    (format t "      descriptors: ~{~a~^ | ~}~%" (mapcar (lambda (o) (op:field o :descriptor)) (subseq opens 0 (min 2 (length opens)))))))

(defun chain-in-order (updates)
  "Follow prev_hash from genesis; returns the list in sequence order."
  (let ((by-prev (make-hash-table :test #'equalp)))
    (dolist (x updates) (setf (gethash (up:update-prev-hash x) by-prev) x))
    (loop for x = (gethash (make-array 32 :element-type '(unsigned-byte 8)) by-prev)
            then (gethash (up:chain-hash x) by-prev)
          while x collect x)))

(with-gate ("ledger: replay the fixture chain")
  (let* ((chain (chain-in-order *distinct*))
         (ledger (lg:make-ledger))
         (errors '()))
    (check-equal "chain walks all 52 updates in order" (mapcar #'up:update-seq chain) (loop for i to 51 collect i))
    (dolist (x chain)
      (handler-case (lg:apply-update ledger x)
        (error (e) (push (format nil "seq ~a: ~a" (up:update-seq x) e) errors))))
    (check-equal "every update applies without error" (reverse errors) '())
    (check-equal "sequence at tip" (lg:ledger-sequence ledger) 51)
    (check-bytes "chain tip is the last chain_hash" (lg:ledger-chain-tip ledger) (up:chain-hash (car (last chain))))
    (check-bytes "ledger id" (lg:ledger-id ledger) (up:update-ledger-id (first chain)))
    (check-equal "quorum active" (lg:ledger-quorum-state ledger) :active)
    (check-equal "three quorum members" (length (lg:ledger-quorum-members ledger)) 3)
    (check "obligations within reserves" (<= (lg:total-obligations ledger) (lg:ledger-reserves-amount ledger))
           (format nil "~a > ~a" (lg:total-obligations ledger) (lg:ledger-reserves-amount ledger)))
    (check "no negative or over-locked balances"
           (loop for d being the hash-values of (lg:ledger-deposits ledger)
                 always (and (>= (lg:deposit-balance d) 0) (<= (lg:deposit-locked-balance d) (lg:deposit-balance d)))))
    (format t "      deposits ~a  obligations ~a msat  reserves ~a  collateral ~a  fees ~a  open locks ~a  pending transfers ~a~%"
            (hash-table-count (lg:ledger-deposits ledger)) (lg:total-obligations ledger)
            (lg:ledger-reserves-amount ledger) (lg:ledger-collateral-amount ledger) (lg:ledger-fees-accumulated ledger)
            (hash-table-count (lg:ledger-open-invoice-locks ledger)) (hash-table-count (lg:ledger-pending-transfers ledger)))
    ;; Chain checks bite.
    (let ((fresh (lg:make-ledger)))
      (check-signals "out-of-sequence update rejected" lg:ledger-error (lg:apply-update fresh (second chain)))
      (lg:apply-update fresh (first chain))
      (let ((forged (up:decode-update (up:encode-update (second chain)))))
        (setf (aref (up:update-prev-hash forged) 0) (logxor 1 (aref (up:update-prev-hash forged) 0)))
        (check-signals "broken prev_hash rejected" lg:ledger-error (lg:apply-update fresh forged))))
    ;; DEP-05 cosign rule against the real ledger: after QuorumBegin, every
    ;; update carries a majority of the active members' cosignatures, and all
    ;; cosigners are members.
    (let* ((replay (lg:make-ledger)) (violations '()) (seen-begin nil))
      (dolist (x chain)
        (let ((o (op:decode-operation (up:update-message x))))
          (when (and seen-begin (not (eq (op:operation-type o) :quorum-begin)))
            (let ((members (mapcar #'lg:member-pubkey (lg:ledger-quorum-members replay))))
              (multiple-value-bind (ok why)
                  (up:verify-cosignatures x :quorum members :threshold (lg:majority-threshold (length members)))
                (unless ok (push (format nil "seq ~a ~a: ~a" (up:update-seq x) (op:operation-type o) why) violations)))))
          (lg:apply-update replay x)
          (when (eq (op:operation-type o) :quorum-begin)
            (setf seen-begin t)
            (multiple-value-bind (ok why)
                (up:verify-cosignatures x :quorum (mapcar #'lg:member-pubkey (lg:ledger-quorum-members replay))
                                          :threshold (lg:majority-threshold (length (lg:ledger-quorum-members replay))))
              (unless ok (push (format nil "seq ~a quorum-begin: ~a" (up:update-seq x) why) violations))))))
      (check-equal "post-QuorumBegin updates carry a member majority" (reverse violations) '()))))


(with-gate ("ledger rules at their boundaries (mutation survivors)")
  (flet ((fresh () (let ((l (lg:make-ledger)) (d (op:deposit-id "b")))
                     (lg:apply-operation l (list :type :ledger-open :operator-id (up:compressed-pubkey 7) :reserves-id "g" :genesis-block 0 :reserves-amount 100000000 :collateral-amount 0))
                     (lg:apply-operation l (list :type :deposit-open :deposit-id d :descriptor "b" :receive-requires-sig nil))
                     (lg:apply-operation l (list :type :onchain-credit :txid (u:sha256 (hx "01")) :vout 0 :deposit-id d :amount 1000 :funding-address "x"))
                     (values l d))))
    (multiple-value-bind (l d) (fresh)
      (check "lock exactly the available balance succeeds"
             (progn (lg:apply-operation l (list :type :invoice-lock :deposit-id d :amount 1000 :payment-id (u:sha256 (hx "02")) :sequence-number 1 :nonce 1 :expiry 9 :witness '())) t))
      (check-equal "nothing available after" (lg:deposit-available-balance (lg:find-deposit l d)) 0))
    (multiple-value-bind (l d) (fresh)
      (check-signals "lock one more than available is refused" lg:ledger-error
        (lg:apply-operation l (list :type :invoice-lock :deposit-id d :amount 1001 :payment-id (u:sha256 (hx "02")) :sequence-number 1 :nonce 1 :expiry 9 :witness '()))))
    (multiple-value-bind (l d) (fresh)
      (check-signals "lock amount + fee beyond available is refused (fee counts)" lg:ledger-error
        (lg:apply-operation l (list :type :invoice-lock :deposit-id d :amount 1000 :payment-id (u:sha256 (hx "02")) :sequence-number 1 :nonce 1 :expiry 9 :witness '() :fee 1))))
    (multiple-value-bind (l d) (fresh)
      (lg:apply-operation l (list :type :invoice-credit :payment-hash (u:sha256 (hx "03")) :deposit-id d :amount 5 :invoice-id "i" :sequence-number 1))
      (check-signals "the same payment hash cannot be credited twice" lg:ledger-error
        (lg:apply-operation l (list :type :invoice-credit :payment-hash (u:sha256 (hx "03")) :deposit-id d :amount 5 :invoice-id "i" :sequence-number 2))))
    (multiple-value-bind (l d) (fresh)
      (check-signals "closing a funded deposit is refused" lg:ledger-error (lg:apply-operation l (list :type :deposit-close :deposit-id d)))
      (lg:apply-operation l (list :type :fee-collect :deposit-id d :amount 1000 :block-height 1))
      (check "closing an empty deposit succeeds" (progn (lg:apply-operation l (list :type :deposit-close :deposit-id d)) t)))
    (check-equal "majority thresholds" (mapcar #'lg:majority-threshold '(1 2 3 4 5 7)) '(1 2 2 3 3 4))
    (check-equal "valid quorum sizes are exactly 3, 5, 7" lg:+valid-quorum-sizes+ '(3 5 7))
    (let ((l (lg:make-ledger)))
      (setf (lg:ledger-quorum-expiry l) 1000)
      (check-equal "lifecycle tiers at their edges"
                   (mapcar (lambda (h) (lg:lifecycle-tier l h)) '(999 1000 1719 1720 5031 5032 9063 9064))
                   '(:tier0 :tier0-post-expiry :tier0-post-expiry :tier1 :tier1 :tier2 :tier2 :tier3)))
    ;; sequence continuity is enforced on apply-update
    (let* ((chain (chain-in-order *distinct*)) (l (lg:make-ledger)))
      (lg:apply-update l (first chain))
      (check-signals "skipping a sequence is refused" lg:ledger-error (lg:apply-update l (third chain))))
    ;; cosignatures are canonicalised on encode even when supplied unsorted
    (let* ((x (find-if (lambda (x) (= 2 (length (up:update-cosignatures x)))) *distinct*))
           (y (up:decode-update (up:encode-update x))))
      (setf (up:update-cosignatures y) (reverse (up:update-cosignatures y)))
      (check-bytes "unsorted cosignatures encode to the canonical (sorted) bytes" (up:encode-update y) (up:encode-update x))
      (check-bytes "and hash the same" (up:content-hash y) (up:content-hash x)))))

(with-gate ("sequence continuity is checked independently of the hash chain")
  (let* ((priv 424242) (pub (up:compressed-pubkey priv)) (lid (u:sha256 (hx "1d")))
         (genesis (up:make-signed-update :operator-id pub :ledger-id lid :seq 0 :prev-hash (make-array 32 :element-type '(unsigned-byte 8))
                                         :message (op:encode-operation (list :type :ledger-open :operator-id pub :reserves-id "g" :genesis-block 0 :reserves-amount 1 :collateral-amount 0))))
         (l (lg:make-ledger)))
    (up:sign-operator genesis priv)
    (lg:apply-update l genesis)
    ;; correct prev_hash, wrong sequence: only the sequence rule can refuse this
    (let ((skip (up:make-signed-update :operator-id pub :ledger-id lid :seq 5 :prev-hash (up:chain-hash genesis)
                                       :message (op:encode-operation (list :type :fee-change :deposit-id (op:deposit-id "x") :new-fees (op:make-fees) :effective-block 1)))))
      (up:sign-operator skip priv)
      (check-signals "seq 5 after seq 0 is refused even though it chains" lg:ledger-error (lg:apply-update l skip)))))
