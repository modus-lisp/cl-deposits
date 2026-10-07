;;;; src/ledger.lisp — the ledger state machine (DEP-05 accounting).
;;;;
;;;; What a cosigner replicates and what a wallet audits: fold the operations of
;;;; a chain, in order, into balances.  APPLY-OPERATION mirrors the reference
;;;; implementation's apply semantics field for field; APPLY-UPDATE adds the
;;;; chain checks around it (sequence, prev_hash continuity) and advances the tip.
;;;;
;;;; Deliberately NOT here yet: conformance checking (who may sign what, when),
;;;; which is a separate layer over this pure fold.

(defpackage #:cl-deposits.ledger
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:op #:cl-deposits.operation) (#:up #:cl-deposits.update)
                    (#:tr #:cl-consensus.taproot-script))
  (:export #:ledger #:make-ledger #:ledger-error
           #:ledger-id #:ledger-genesis-block #:ledger-operator-key #:ledger-reserves-key
           #:ledger-reserves-amount #:ledger-collateral-amount #:ledger-quorum-state
           #:ledger-quorum-members #:ledger-next-quorum-members #:ledger-quorum-expiry
           #:ledger-deposits #:ledger-pending-transfers #:ledger-open-invoice-locks
           #:ledger-pending-withdrawals #:ledger-credited-payments #:ledger-fees-accumulated
           #:ledger-sequence #:ledger-chain-tip #:ledger-joined-quorums #:ledger-dispute-state
           #:ledger-active-ruleset #:ledger-pending-exits #:ledger-vault-current-p #:due-exits #:+exit-cutoff-margin+
           #:exit-dust-msats #:*update-seq* #:ledger-reference-feerate #:rotation-feerate #:exit-cost
           #:ledger-dormancy-notice #:dormancy-spin-outs #:dormancy-amount-msats #:deposit-last-signed-activity
           #:pk-key-path-spk #:dormancy-cost
           #:deposit #:deposit-id #:deposit-descriptor #:deposit-balance #:deposit-locked-balance
           #:deposit-fees #:deposit-transfer-fees #:deposit-available-balance #:deposit-seen-nonces
           #:deposit-opened-at-block #:deposit-last-activity-block #:deposit-last-received-block #:*block-height*
           #:collateral-floor-bps #:collateral-meets-floor-p #:+min-collateral-bps-floor+ #:quorum-member #:member-pubkey #:member-ledger-id #:member-membership-until #:member-dispute-response-blocks
           #:apply-operation #:apply-update #:total-obligations #:find-deposit
           #:majority-threshold #:+valid-quorum-sizes+ #:+rulesets+ #:+supported-rulesets+ #:cosign-requirement #:lifecycle-tier #:establishment-p #:replay #:copy-ledger))
(in-package #:cl-deposits.ledger)

(define-condition ledger-error (error)
  ((kind :initarg :kind :reader ledger-error-kind)
   (detail :initarg :detail :initform nil :reader detail))
  (:report (lambda (c s) (format s "ledger: ~a~@[ (~a)~]" (ledger-error-kind c) (detail c)))))

(defun fail (kind &optional detail) (error 'ledger-error :kind kind :detail detail))

;; The registered rulesets.  All share the cltv-offset-v2 reserves cascade (tier-1
;; minority ceil(n/2) - 1); fee-cap-v3 and balance-commit-v4 add off-chain op rules
;; this implementation does not enforce, so it advertises only cltv-offset-v2.
(defparameter +rulesets+ '("cltv-offset-v2" "fee-cap-v3" "balance-commit-v4"))
(defparameter +supported-rulesets+ '("cltv-offset-v2"))

(defparameter +valid-quorum-sizes+ '(3 5 7)
  "DEP-03 §Pre-release policy cap: odd for clean majorities, >= 3 for redundancy, <= 7.")

(defstruct deposit
  id descriptor (balance 0) (locked-balance 0)
  (fees (op:make-fees)) (transfer-fees (op:make-transfer-fees))
  (receive-requires-sig nil) fee-change-after-blocks fee-change-notice-blocks fee-change-limit-bps
  (opened-at-block 0) pending-fee-change (last-fee-assessment 0)
  (last-activity-block 0) (last-received-block 0)
  (last-signed-activity 0)                     ; DEP-20 §8: latest depositor-signed op's height
  (seen-nonces '()))

(defun deposit-available-balance (d) (max 0 (- (deposit-balance d) (deposit-locked-balance d))))

(defstruct (quorum-member (:conc-name member-))
  pubkey (ledger-id "") min-fee-bps min-fee-fixed max-fee-period membership-until min-collateral-bps
  dispute-response-blocks dispute-arm-blocks service-response-blocks max-transfer-timeout-blocks
  max-descriptor-bytes compensation-bps compensation-deposit-id compensation-frequency-blocks
  dormancy-blocks dormancy-notice-blocks
  member-response)

(defstruct (ledger (:constructor %make-ledger) (:copier nil))   ; COPY-LEDGER is the deep copy below
  id (genesis-block 0) operator-key (reserves-key "")
  (reserves-amount 0) (collateral-amount 0)
  (quorum-state :pre-quorum) (quorum-members '()) (next-quorum-members '()) quorum-expiry
  (active-ruleset nil)
  (deposits (make-hash-table :test #'equalp))
  (pending-transfers (make-hash-table :test #'equalp))
  (open-invoice-locks (make-hash-table :test #'equalp))
  (pending-withdrawals (make-hash-table :test #'equalp))
  (credited-payments (make-hash-table :test #'equalp))
  (fees-accumulated 0)
  (sequence -1)                     ; sequence of the last applied update; -1 = empty
  (chain-tip (make-array 32 :element-type '(unsigned-byte 8)))
  (joined-quorums '())
  (dispute-state :normal)
  ;; DEP-20 §3: request id (chain_hash of the ExitRequest update) -> plist
  (pending-exits (make-hash-table :test #'equalp))
  (vault-current-p nil)             ; a QuorumBegin vault the next QuorumBegin rotates
  (reference-feerate nil)           ; the governing QuorumBegin's reference_feerate_sat_vb (DEP-03)
  (dormancy-blocks 26280) (dormancy-notice-blocks 2016)   ; DEP-20 §8, from the promoted members
  (dormancy-notice nil))            ; outstanding DormancyNotice: (:height h :rotation-height r)

(defun make-ledger () (%make-ledger))

(defun find-deposit (ledger id)
  (or (gethash id (ledger-deposits ledger)) (fail :deposit-not-found (bytes->hex id))))

(defun total-obligations (ledger)
  (loop for d being the hash-values of (ledger-deposits ledger) sum (deposit-balance d)))

(defun majority-threshold (n) (1+ (floor n 2)))

(defun %credit (d amount) (incf (deposit-balance d) amount))
(defun %check-obligation-room (ledger amount)
  "DEP-05: refuse a credit that would push total obligations above reserves.
   Pre-quorum ledgers (reserves 0, no QuorumBegin yet) are exempt: nothing is
   bonded and nothing can be cosigned on them anyway."
  (when (and (plusp (ledger-reserves-amount ledger))
             (> (+ (total-obligations ledger) amount) (ledger-reserves-amount ledger)))
    (fail :over-obligation (format nil "credit ~a would take obligations ~a over reserves ~a"
                                   amount (total-obligations ledger) (ledger-reserves-amount ledger)))))
(defun %lock (d amount)
  (when (< (deposit-available-balance d) amount)
    (fail :insufficient-balance (format nil "available ~a, need ~a" (deposit-available-balance d) amount)))
  (incf (deposit-locked-balance d) amount))
(defun %unlock (d amount) (setf (deposit-locked-balance d) (max 0 (- (deposit-locked-balance d) amount))))
(defun %fulfill (d amount)
  (%unlock d amount)
  (setf (deposit-balance d) (max 0 (- (deposit-balance d) amount))))
(defun %charge-fixed (ledger d)
  "On a failed lock the deposit pays its fixed transfer fee, capped at its balance."
  (let ((charged (min (op:transfer-fees-fixed-msats (deposit-transfer-fees d)) (deposit-balance d))))
    (decf (deposit-balance d) charged)
    (incf (ledger-fees-accumulated ledger) charged)))

(defvar *block-height* 0 "The block height of the update being applied (for descriptor snapshots).")
(defvar *update-seq* 0 "The sequence of the update being applied.")

(defparameter +exit-cutoff-margin+ 144 "DEP-20 §3 exit_cutoff_margin_blocks (DEP-11 default).")
(defparameter exit-dust-msats 330000 "DEP-20 §3: requests below 330 sats are carried, not settled.")

(defun rotation-feerate (ledger)
  "DEP-03: the governing QuorumBegin's reference feerate, or 2 sat/vB when none is recorded."
  (or (ledger-reference-feerate ledger) 2))

(defun exit-cost (address feerate)
  "DEP-20 §3: an exit output's own marginal cost, feerate x (9 + len(spk)) sats."
  (* feerate (+ 9 (length address))))

(defun dormancy-amount-msats (ledger)
  "DEP-20 §8: 10 x 34 vB x the governing feerate, in msat."
  (* 10 34 (rotation-feerate ledger) 1000))

(defun pk-key-path-spk (descriptor)
  "DEP-20 §8: a pk(K) deposit's address, the key-path P2TR with K's x-only key internal; else NIL."
  (let ((start (search "pk(" descriptor)))
    (when (and start (= start 0) (= (length descriptor) 70) (char= (char descriptor 69) #\)))
      (let ((k (ignore-errors (hex->bytes (subseq descriptor 3 69)))))
        (and k (= (length k) 33) (member (aref k 0) '(2 3))
             (values (tr::taproot-output-spk-from-root (subseq k 1 33) (make-array 0 :element-type '(unsigned-byte 8)))))))))

(defun dormancy-cost (ledger) "An addressable spin-out's output cost, sats." (* (rotation-feerate ledger) (+ 9 34)))

(defun dormancy-spin-outs (ledger cutoff)
  "DEP-20 §8.2: if a rotating QuorumBegin with exit_cutoff_height CUTOFF consumes the outstanding notice, the
   addressable bucket deposits at or above the floor, ascending deposit id, as
   ((deposit-id balance spk) ...); else NIL."
  (let ((n (ledger-dormancy-notice ledger)))
    (when (and n (ledger-vault-current-p ledger) (>= cutoff (getf n :rotation-height)))
      (let ((bound (- (getf n :height) (ledger-dormancy-blocks ledger))) (floor-msat (dormancy-amount-msats ledger))
            (pending (let ((h (make-hash-table :test #'equalp)))
                       (maphash (lambda (k e) (declare (ignore k)) (setf (gethash (getf e :deposit-id) h) t)) (ledger-pending-exits ledger))
                       h))
            (out '()))
        (maphash (lambda (id d)
                   (let ((spk (pk-key-path-spk (deposit-descriptor d))))
                     (when (and spk (plusp (deposit-balance d)) (zerop (deposit-locked-balance d))
                                (not (gethash id pending))
                                (<= (deposit-last-signed-activity d) bound)
                                (>= (deposit-balance d) floor-msat))
                       (push (list id (deposit-balance d) spk) out))))
                 (ledger-deposits ledger))
        (sort out #'bytes< :key #'first)))))

(defun due-exits (ledger height cutoff)
  "DEP-20 §3 due set: pending requests appended at block_height <= CUTOFF whose output clears the
   330-sat floor after its own cost, unexpired, in append order, as a list of (id . plist)."
  (let ((due '()) (f (rotation-feerate ledger)))
    (maphash (lambda (id e)
               (when (and (<= (getf e :block-height) cutoff)
                          (>= (- (floor (getf e :amount) 1000) (exit-cost (getf e :exit-address) f)) 330)
                          (or (null (getf e :expires-at)) (> (getf e :expires-at) cutoff)))
                 (push (cons id e) due)))
             (ledger-pending-exits ledger))
    (sort due #'< :key (lambda (c) (getf (cdr c) :seq)))))

(defun %release-expired-exits (ledger height)
  (let ((gone '()))
    (maphash (lambda (id e) (when (and (getf e :expires-at) (<= (getf e :expires-at) height)) (push (cons id e) gone)))
             (ledger-pending-exits ledger))
    (loop for (id . e) in gone
          do (let ((d (gethash (getf e :deposit-id) (ledger-deposits ledger))))
               (when d (%unlock d (getf e :amount))))
             (remhash id (ledger-pending-exits ledger)))))

(defun %settle-exits (ledger o)
  "DEP-20 §3 settlement on a QuorumBegin: EXIT-OUTPUTS must be exactly the due set (rotating
   QuorumBegins only); each entry's deposit is debited and its request removed."
  (let* ((entries (op:field o :exit-outputs))
         (h *block-height*)
         (cutoff (or (op:field o :exit-cutoff-height) (- h +exit-cutoff-margin+))))
    (unless (ledger-vault-current-p ledger)
      (when entries (fail :exit-outputs "a QuorumBegin with no current vault settles no exits"))
      (return-from %settle-exits))
    (unless (<= (- h +exit-cutoff-margin+) cutoff h)
      (fail :exit-cutoff (format nil "cutoff ~a outside [~a, ~a]" cutoff (- h +exit-cutoff-margin+) h)))
    (let ((due (due-exits ledger h cutoff)))
      (unless (= (length due) (length entries))
        (fail :exit-outputs (format nil "~a due exits, ~a settled" (length due) (length entries))))
      (loop for (id . e) in due for (dep amount vout) in entries for i from 1
            do (unless (and (equalp dep (getf e :deposit-id)) (= amount (getf e :amount)) (= vout i))
                 (fail :exit-outputs (format nil "entry ~a does not match due request ~a" i (bytes->hex id))))
               (let ((d (find-deposit ledger dep)))
                 (%unlock d amount)
                 (setf (deposit-balance d) (max 0 (- (deposit-balance d) amount))))
               (remhash id (ledger-pending-exits ledger))))))

(defun %touch (ledger o)
  "Record activity heights on the deposits an operation moves."
  (dolist (name '(:deposit-id :source-deposit-id))
    (let ((d (and (op:field o name) (gethash (op:field o name) (ledger-deposits ledger)))))
      (when d (setf (deposit-last-activity-block d) *block-height*))))
  (when (member (op:operation-type o) '(:invoice-credit :onchain-credit))
    (let ((d (gethash (op:field o :deposit-id) (ledger-deposits ledger))))
      (when d (setf (deposit-last-received-block d) *block-height*))))
  ;; DEP-20 §8 signed activity: depositor-signed operations only.
  (let ((spender (case (op:operation-type o)
                   ((:invoice-lock :onchain-lock :deposit-key-rotate :exit-request :exit-cancel) (op:field o :deposit-id))
                   (:transfer-lock (op:field o :source-deposit-id)))))
    (when spender
      (let ((d (gethash spender (ledger-deposits ledger))))
        (when d (setf (deposit-last-signed-activity d) *block-height*))))))

(defun apply-operation (ledger o)
  "Fold one operation into LEDGER, or signal LEDGER-ERROR leaving it untouched
   in the ways that matter (callers replaying a chain treat any error as fatal)."
  (prog1 (%apply-operation ledger o) (%touch ledger o)))

(defun %apply-operation (ledger o)
  (flet ((f (name) (op:field o name)))
    (ecase (op:operation-type o)
      (:ledger-open
       (setf (ledger-operator-key ledger) (f :operator-id)
             (ledger-reserves-key ledger) (f :reserves-id)
             (ledger-genesis-block ledger) (f :genesis-block)
             (ledger-id ledger) (op:compute-ledger-id (f :operator-id) (f :reserves-id) (f :genesis-block))
             (ledger-reserves-amount ledger) (f :reserves-amount)
             (ledger-collateral-amount ledger) (f :collateral-amount)))
      (:quorum-begin
       (let* ((declared (f :quorum-members))
              (promoted (remove-if-not (lambda (m) (member (member-pubkey m) declared :test #'equalp))
                                       (ledger-next-quorum-members ledger))))
         ;; DEP-03 pre-release size policy, enforced by every validator.
         (unless (member (length declared) +valid-quorum-sizes+)
           (fail :quorum-size-invalid (format nil "Q=~a not in ~a" (length declared) +valid-quorum-sizes+)))
         (unless (member (f :protocol-version) +rulesets+ :test #'equal)
           (fail :unknown-ruleset (format nil "QuorumBegin protocol_version ~s is not a known ruleset" (f :protocol-version))))
         ;; DEP-05 "Collateral floor": collateral is at least the strictest member's share of
         ;; the vault, never below 20%.  Collateral is a floor, not a cap on credits.
         (let ((floor (collateral-floor-bps promoted)))
           (unless (collateral-meets-floor-p (f :amount) (f :collateral-amount) floor)
             (fail :collateral-below-floor
                   (format nil "collateral ~a is below ~a bps of the vault (reserves ~a)" (f :collateral-amount) floor (f :amount)))))
         (let* ((cutoff (or (op:field o :exit-cutoff-height) (- *block-height* +exit-cutoff-margin+)))
                (spins (dormancy-spin-outs ledger cutoff))
                (nexits (length (op:field o :exit-outputs))))
           (%settle-exits ledger o)
           (let ((entries (op:field o :dormancy-outputs)))
             (unless (and (= (length spins) (length entries))
                          (loop for (id bal) in spins for (eid eamt vout) in entries for j from 1
                                always (and (equalp id eid) (= bal eamt) (= vout (+ nexits j)))))
               (fail :dormancy-outputs (format nil "~a spin-outs due, ~a recorded or mismatched" (length spins) (length entries))))
             (loop for (id) in spins do (setf (deposit-balance (find-deposit ledger id)) 0))
             (when (and (ledger-dormancy-notice ledger) (ledger-vault-current-p ledger)
                        (>= cutoff (getf (ledger-dormancy-notice ledger) :rotation-height)))
               (setf (ledger-dormancy-notice ledger) nil))))
         (%release-expired-exits ledger *block-height*)   ; after settlement (DEP-20 §3 Expiry)
         (setf (ledger-reference-feerate ledger) (f :reference-feerate)
               ;; DEP-20 §8: the largest declared value applies; the default only when none is declared.
               (ledger-dormancy-blocks ledger) (let ((v (remove nil (mapcar #'member-dormancy-blocks promoted))))
                                                 (if v (reduce #'max v) 26280))
               (ledger-dormancy-notice-blocks ledger) (let ((v (remove nil (mapcar #'member-dormancy-notice-blocks promoted))))
                                                        (if v (reduce #'max v) 2016)))
         (setf (ledger-next-quorum-members ledger) '()
               (ledger-vault-current-p ledger) t
               (ledger-reserves-key ledger) (f :reserves-id)
               (ledger-reserves-amount ledger) (f :amount)
               (ledger-collateral-amount ledger) (f :collateral-amount)
               (ledger-quorum-expiry ledger) (f :quorum-expiry)
               (ledger-active-ruleset ledger) (f :protocol-version)
               (ledger-quorum-members ledger) promoted
               (ledger-quorum-state ledger) :active)))
      (:deposit-open
       (let ((id (f :deposit-id)))
         (when (gethash id (ledger-deposits ledger)) (fail :deposit-exists))
         (let ((d (make-deposit :id id :descriptor (f :descriptor) :opened-at-block *block-height*
                                :last-activity-block *block-height* :last-signed-activity *block-height*)))
           (when (f :fees) (setf (deposit-fees d) (f :fees)))
           (when (f :transfer-fees) (setf (deposit-transfer-fees d) (f :transfer-fees)))
           (setf (deposit-receive-requires-sig d) (f :receive-requires-sig)
                 (deposit-fee-change-after-blocks d) (f :fee-change-after-blocks)
                 (deposit-fee-change-notice-blocks d) (f :fee-change-notice-blocks)
                 (deposit-fee-change-limit-bps d) (f :fee-change-limit-bps))
           (setf (gethash id (ledger-deposits ledger)) d))))
      (:deposit-close
       (let ((d (find-deposit ledger (f :deposit-id))))
         (when (plusp (deposit-balance d)) (fail :non-zero-balance (deposit-balance d)))
         (remhash (f :deposit-id) (ledger-deposits ledger))))
      (:fee-change
       (let ((d (gethash (f :deposit-id) (ledger-deposits ledger))))
         (when d (setf (deposit-pending-fee-change d) (cons (f :new-fees) (f :effective-block))))))
      (:deposit-key-rotate
       (let ((d (gethash (f :deposit-id) (ledger-deposits ledger))))
         (when d
           (setf (deposit-descriptor d) (f :new-descriptor))
           (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d)))))
      (:invoice-credit
       (when (gethash (f :payment-hash) (ledger-credited-payments ledger))
         (fail :duplicate-credit (bytes->hex (f :payment-hash))))
       (let ((d (find-deposit ledger (f :deposit-id))))
         (%credit d (f :amount))
         (setf (gethash (f :payment-hash) (ledger-credited-payments ledger)) t)))
      (:invoice-lock
       (let* ((d (find-deposit ledger (f :deposit-id))) (fee (or (f :fee) 0)))
         (%lock d (+ (f :amount) fee))
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (setf (gethash (f :payment-id) (ledger-open-invoice-locks ledger))
               (list :deposit-id (f :deposit-id) :amount (f :amount) :fee fee
                     :lock-sequence (f :sequence-number) :timeout-height (f :timeout-height)))))
      (:invoice-fail
       (let* ((lock (gethash (f :payment-id) (ledger-open-invoice-locks ledger)))
              (d (find-deposit ledger (f :deposit-id))))
         (%unlock d (+ (or (getf lock :amount) 0) (or (getf lock :fee) 0)))
         (%charge-fixed ledger d)
         (remhash (f :payment-id) (ledger-open-invoice-locks ledger))))
      (:invoice-fulfill
       (let* ((lock (gethash (f :payment-id) (ledger-open-invoice-locks ledger)))
              (fee (or (getf lock :fee) 0))
              (d (find-deposit ledger (f :deposit-id))))
         (%fulfill d (+ (f :amount) fee))
         (remhash (f :payment-id) (ledger-open-invoice-locks ledger))
         (incf (ledger-fees-accumulated ledger) fee)))
      (:onchain-credit
       ;; DEP-05 §Obligation Limits: total obligations (the sum of balances) must
       ;; not exceed the reserves amount.  Unchecked until the red team read this
       ;; arm (docs/REDTEAM.md #1): a cl cosigner would sign an operator crediting
       ;; itself any amount.  (The reference additionally caps by collateral.)
       (%check-obligation-room ledger (f :amount))
       (%credit (find-deposit ledger (f :deposit-id)) (f :amount)))
      (:onchain-lock
       (let ((d (find-deposit ledger (f :deposit-id))))
         (%lock d (+ (f :amount) (f :fee-sats)))
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (setf (gethash (f :withdrawal-id) (ledger-pending-withdrawals ledger))
               (list :deposit-id (f :deposit-id) :amount (f :amount) :fee-sats (f :fee-sats)
                     :destination-address (f :destination-address)))))
      (:onchain-fail
       (find-deposit ledger (f :deposit-id))
       (let ((p (gethash (f :withdrawal-id) (ledger-pending-withdrawals ledger))))
         (remhash (f :withdrawal-id) (ledger-pending-withdrawals ledger))
         (when p
           (let ((d (gethash (getf p :deposit-id) (ledger-deposits ledger))))
             (when d
               (%unlock d (+ (getf p :amount) (getf p :fee-sats)))
               (%charge-fixed ledger d))))))
      (:onchain-fulfill
       (find-deposit ledger (f :deposit-id))
       (let ((p (gethash (f :withdrawal-id) (ledger-pending-withdrawals ledger))))
         (remhash (f :withdrawal-id) (ledger-pending-withdrawals ledger))
         (when p
           (let ((d (gethash (getf p :deposit-id) (ledger-deposits ledger))))
             (when d (%fulfill d (+ (getf p :amount) (getf p :fee-sats))))))))
      (:fee-collect
       (let ((d (gethash (f :deposit-id) (ledger-deposits ledger))))
         (when d
           (let ((pending (deposit-pending-fee-change d)))
             (when (and pending (>= (f :block-height) (cdr pending)))
               (setf (deposit-fees d) (car pending) (deposit-pending-fee-change d) nil)))
           (setf (deposit-balance d) (max 0 (- (deposit-balance d) (f :amount)))
                 (deposit-last-fee-assessment d) (f :block-height))
           (incf (ledger-fees-accumulated ledger) (f :amount)))))
      (:quorum-add-member
       (let ((m (make-quorum-member :pubkey (f :quorum-member) :ledger-id (f :member-ledger-id)
                             :min-fee-bps (f :min-fee-bps) :min-fee-fixed (f :min-fee-fixed)
                             :max-fee-period (f :max-fee-period) :membership-until (f :membership-until)
                             :dispute-response-blocks (f :dispute-response-blocks)
                             :dispute-arm-blocks (f :dispute-arm-blocks)
                             :service-response-blocks (f :service-response-blocks)
                             :max-transfer-timeout-blocks (f :max-transfer-timeout-blocks)
                             :max-descriptor-bytes (f :max-descriptor-bytes)
                             :compensation-bps (f :compensation-bps)
                             :compensation-deposit-id (f :compensation-deposit-id)
                             :compensation-frequency-blocks (f :compensation-frequency-blocks)
                             :min-collateral-bps (f :min-collateral-bps)
                             :dormancy-blocks (f :dormancy-blocks) :dormancy-notice-blocks (f :dormancy-notice-blocks)
                             :member-response (f :member-response))))
         (setf (ledger-next-quorum-members ledger)
               (append (remove (f :quorum-member) (ledger-next-quorum-members ledger)
                               :key #'member-pubkey :test #'equalp)
                       (list m)))))
      (:quorum-remove-member
       (setf (ledger-next-quorum-members ledger)
             (remove (f :quorum-member) (ledger-next-quorum-members ledger) :key #'member-pubkey :test #'equalp)))
      (:quorum-upgrade (setf (ledger-active-ruleset ledger) (f :new-protocol-version)))
      (:quorum-join
       (let ((existing (find-if (lambda (j) (and (equalp (getf j :operator-id) (f :operator-id))
                                                 (string= (getf j :ledger-id) (f :ledger-id))))
                                (ledger-joined-quorums ledger))))
         (if existing
             (setf (getf existing :membership-expires) (f :membership-expires))
             (push (list :operator-id (f :operator-id) :ledger-id (f :ledger-id)
                         :membership-expires (f :membership-expires)
                         :joined-at-sequence (1+ (ledger-sequence ledger)))
                   (ledger-joined-quorums ledger)))))
      (:ledger-close nil)
      (:dispute-enter (setf (ledger-dispute-state ledger) :disputed))
      (:dispute-armed (setf (ledger-dispute-state ledger) :armed))
      (:dispute-acquire (setf (ledger-operator-key ledger) (f :new-custodian)
                              (ledger-vault-current-p ledger) nil (ledger-dormancy-notice ledger) nil
                              (ledger-dispute-state ledger) :normal))
      (:dormancy-notice
       (when (ledger-dormancy-notice ledger) (fail :dormancy-notice "a notice is already outstanding"))
       (unless (>= (f :rotation-height) (+ *block-height* (ledger-dormancy-notice-blocks ledger)))
         (fail :dormancy-notice (format nil "rotation_height ~a is less than ~a blocks ahead" (f :rotation-height)
                                        (ledger-dormancy-notice-blocks ledger))))
       (setf (ledger-dormancy-notice ledger) (list :height *block-height* :rotation-height (f :rotation-height))))
      (:exit-request
       (let ((d (find-deposit ledger (f :deposit-id))))
         (unless (plusp (f :amount)) (fail :exit-amount "zero"))
         (%lock d (f :amount))
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (setf (gethash (sha256 (op:encode-operation o)) (ledger-pending-exits ledger))
               (list :deposit-id (f :deposit-id) :amount (f :amount) :exit-address (f :exit-address)
                     :expires-at (f :expires-at-height) :block-height *block-height* :seq *update-seq*))))
      (:exit-cancel
       (let* ((d (find-deposit ledger (f :deposit-id)))
              (e (gethash (f :exit-request-id) (ledger-pending-exits ledger))))
         (unless (and e (equalp (getf e :deposit-id) (f :deposit-id)))
           (fail :exit-cancel "names no pending exit request of this deposit"))
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (%unlock d (getf e :amount))
         (remhash (f :exit-request-id) (ledger-pending-exits ledger))))
      (:dispute-yield (setf (ledger-dispute-state ledger) :tombstoned))
      (:transfer-lock
       (let* ((d (find-deposit ledger (f :source-deposit-id)))
              (total (+ (f :amount) (f :fee))))
         (when (< (deposit-available-balance d) total)
           (fail :insufficient-balance (format nil "available ~a, need ~a" (deposit-available-balance d) total)))
         (incf (deposit-locked-balance d) total)
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (setf (gethash (f :transfer-id) (ledger-pending-transfers ledger))
               (list :source (f :source-deposit-id) :destination (f :destination-deposit-id)
                     :amount (f :amount) :fee (f :fee) :completion-script (f :completion-script)
                     :timeout-height (f :timeout-height) :transfer-nonce (f :transfer-nonce)))))
      (:transfer-complete
       (let ((p (gethash (f :transfer-id) (ledger-pending-transfers ledger))))
         (remhash (f :transfer-id) (ledger-pending-transfers ledger))
         (when p
           (let ((src (gethash (getf p :source) (ledger-deposits ledger)))
                 (dst (gethash (getf p :destination) (ledger-deposits ledger)))
                 (total (+ (getf p :amount) (getf p :fee))))
             (when src
               (%unlock src total)
               (setf (deposit-balance src) (max 0 (- (deposit-balance src) (getf p :amount)))))
             (when dst (%credit dst (getf p :amount)))
             (incf (ledger-fees-accumulated ledger) (getf p :fee))))))
      (:transfer-fail
       (let ((p (gethash (f :transfer-id) (ledger-pending-transfers ledger))))
         (remhash (f :transfer-id) (ledger-pending-transfers ledger))
         (when p
           (let ((src (gethash (getf p :source) (ledger-deposits ledger))))
             (when src
               (%unlock src (+ (getf p :amount) (getf p :fee)))
               (%charge-fixed ledger src))))))
      (:delivery-embed nil)
      (:batch (fail :unsupported "batch")))
    ledger))

(defun apply-update (ledger update &key (check-chain t))
  "Apply a signed update: it must be the next sequence and chain to our tip."
  (when check-chain
    (unless (= (up:update-seq update) (1+ (ledger-sequence ledger)))
      (fail :sequence (format nil "expected ~a, got ~a" (1+ (ledger-sequence ledger)) (up:update-seq update))))
    (unless (equalp (up:update-prev-hash update) (ledger-chain-tip ledger))
      (fail :chain-break (format nil "at sequence ~a" (up:update-seq update)))))
  (let ((*block-height* (up:update-block-height update))
        (*update-seq* (up:update-seq update)))
    (let ((o (op:decode-operation (up:update-message update))))
      (unless (eq (op:operation-type o) :quorum-begin) (%release-expired-exits ledger *block-height*))
      (apply-operation ledger o)))
  (setf (ledger-sequence ledger) (up:update-seq update)
        (ledger-chain-tip ledger) (up:chain-hash update))
  ledger)

;;; ---------------------------------------------------------------------------
;;; DEP-05 §Lifecycle: how many cosignatures an operation needs at a height.

(defparameter +tier-1-offset+ 720)
(defparameter +tier-2-offset+ 4032)
(defparameter +tier-3-offset+ 8064)

(defun establishment-p (op)
  (member (cl-deposits.operation:operation-type op) '(:quorum-add-member :quorum-remove-member :quorum-begin)))

(defconstant +min-collateral-bps-floor+ 2000 "DEP-05: no quorum lets collateral fall below 20% of the vault.")

(defun collateral-floor-bps (members)
  "The strictest member's min_collateral_bps, never below +min-collateral-bps-floor+."
  (reduce #'max (remove nil (mapcar #'member-min-collateral-bps members)) :initial-value +min-collateral-bps-floor+))

(defun collateral-meets-floor-p (reserves collateral floor-bps)
  (>= (* collateral 10000) (* floor-bps (+ reserves collateral))))

(defun lifecycle-tier (ledger height)
  (let ((expiry (ledger-quorum-expiry ledger)))
    (cond ((null expiry) :tier0)
          ((< height expiry) :tier0)
          ((< height (+ expiry +tier-1-offset+)) :tier0-post-expiry)
          ((< height (+ expiry +tier-2-offset+)) :tier1)
          ((< height (+ expiry +tier-3-offset+)) :tier2)
          (t :tier3))))

(defun cosign-requirement (ledger op height)
  "(values required-sigs signers tier operator-alone-p allowed-p).  SIGNERS is the
   member list the signatures must come from: the active quorum, or for the
   first QuorumBegin the staged set."
  (let* ((active (ledger-quorum-members ledger))
         (staged (ledger-next-quorum-members ledger))
         (signers (cond (active active)
                        ((and staged (eq (cl-deposits.operation:operation-type op) :quorum-begin)) staged)
                        (t nil))))
    (when (null signers)
      (return-from cosign-requirement (values 0 '() :tier0 nil t)))
    (let* ((n (length signers)) (majority (majority-threshold n)) (minority (max 1 (1- (ceiling n 2))))
           (tier (if (member (ledger-active-ruleset ledger) +rulesets+ :test #'string=)
                     (lifecycle-tier ledger height)
                     :tier0)))
      (cond ((eq tier :tier0) (values majority signers tier nil t))
            ((not (establishment-p op)) (values 0 signers tier nil nil))
            ((eq tier :tier0-post-expiry) (values majority signers tier nil t))
            ((eq tier :tier1) (values minority signers tier nil t))
            ((eq tier :tier2) (values 1 signers tier nil t))
            (t (values 0 signers tier t t))))))

(defun replay (updates)
  "A fresh ledger folded from UPDATES in order."
  (let ((l (make-ledger))) (dolist (u updates l) (apply-update l u))))

(defun deep-copy (x)
  "Structures, lists, hash tables and general vectors are copied; strings, byte
   vectors and atoms are shared (nothing mutates them)."
  (typecase x
    (cons (loop for tail = x then (cdr tail)
                collect (deep-copy (car tail)) into acc
                while (consp (cdr tail))
                finally (return (if (null (cdr tail)) acc (nconc acc (deep-copy (cdr tail)))))))
    (hash-table (let ((h (make-hash-table :test (hash-table-test x) :size (hash-table-count x))))
                  (maphash (lambda (k v) (setf (gethash k h) (deep-copy v))) x) h))
    (string x)
    ((array (unsigned-byte 8)) x)
    ((and vector (not simple-array)) (map 'vector #'deep-copy x))
    (simple-vector (map 'simple-vector #'deep-copy x))
    (structure-object (let ((c (copy-structure x)))
                        (dolist (slot (sb-mop:class-slots (class-of c)) c)
                          (let ((n (sb-mop:slot-definition-name slot)))
                            (setf (slot-value c n) (deep-copy (slot-value c n)))))))
    (t x)))

(defun copy-ledger (ledger)
  "A private copy to try an operation on.  Replaying the history from genesis
   was the old way and cost O(sequence) per operation and per cosign: at
   sequence 1400 the operator of a busy ledger spent its whole worker on it."
  (deep-copy ledger))
