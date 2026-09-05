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

(report)
