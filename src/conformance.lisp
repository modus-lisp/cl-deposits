;;;; src/conformance.lisp — DEP-16 conformance: what a depositor's signature allows.
;;;;
;;;; The fold (ledger.lisp) keeps the books; it does not know who may move a
;;;; deposit.  An operation that spends or re-keys a deposit carries the
;;;; depositor's witness, a nonce and an expiry, and three rules decide whether
;;;; it may apply at a height:
;;;;
;;;;   ExpiryPassed  expiry < height: the signature is past its validity window
;;;;   NonceReplay   the deposit saw this nonce with an expiry still >= height
;;;;   Unauthorized  the witness does not satisfy the deposit's descriptor
;;;;
;;;; (the reference: deposits-protocol ledger_state check_conformance).  These
;;;; are ledger rules, not operator courtesy.  Until they were checked here, cl
;;;; cosigners and replicas never ran them: a cl operator could lock a deposit
;;;; with no witness at all, or replay a depositor's signed lock, and its cl
;;;; members cosigned it.

(defpackage #:cl-deposits.conformance
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:op #:cl-deposits.operation) (#:lg #:cl-deposits.ledger)
                    (#:d16 #:cl-deposits.dep16) (#:d17 #:cl-deposits.dep17))
  (:export #:violation #:authorized-p #:nonce-verdict #:operation-deposit-id #:signed-sighash
           #:descriptor-refusal))
(in-package #:cl-deposits.conformance)

(defun field (o name) (ignore-errors (op:field o name)))

(defun snapshot (d height)
  (d16:make-snapshot :balance (lg:deposit-balance d)
                     :blocks-since-activity (max 0 (- height (lg:deposit-last-activity-block d)))
                     :blocks-since-open (max 0 (- height (lg:deposit-opened-at-block d)))
                     :blocks-since-received (max 0 (- height (lg:deposit-last-received-block d)))
                     :height height))

(defun authorized-p (o d height)
  "Does deposit D's descriptor authorize operation O with O's witness, at HEIGHT?"
  (let ((desc (lg:deposit-descriptor d)) (witness (field o :witness)))
    (if (d17:descriptor-key desc)
        (eq :ok (d17:verify-operation-witness o desc witness))
        (multiple-value-bind (id type args nonce expiry) (d17:operation->dep16 o)
          (and id
               (let ((descriptor (handler-case (d16:parse-descriptor desc)
                                   ;; an unparseable descriptor authorizes nothing (as in the reference)
                                   (d16:eval-error () (return-from authorized-p nil))))
                     (op (d16:make-operation :deposit-id id :op-type type :args args :nonce nonce :expiry expiry)))
                 (handler-case (d16:evaluate descriptor op (snapshot d height) (d16:witness-from-stack witness descriptor op))
                   (d16:eval-error () nil))))))))

(defun operator-violation (ledger o)
  "DEP-07 FeeCollect, which no depositor signs: the cadence the depositor accepted
   (FeeWindowNotElapsed) and the one-period assessment cap (FeeExceedsAssessment), both read
   from the pre-state deposit.  The cap is a rule of every ruleset (DEP-07, FINDINGS L6)."
  (when (eq (op:operation-type o) :fee-collect)
    (let ((d (gethash (field o :deposit-id) (lg:ledger-deposits ledger))))
      (when d
        (let ((next (+ (lg:deposit-last-fee-assessment d) (op:fees-frequency-blocks (lg:deposit-fees d))))
              (due (lg:fees-due d (field o :block-height))))
          (cond ((< (field o :block-height) next)
                 (format nil "FeeWindowNotElapsed: block ~a is before ~a" (field o :block-height) next))
                ((> (field o :amount) due)
                 (format nil "FeeExceedsAssessment: collected ~a, at most ~a due" (field o :amount) due))))))))

(defun violation (ledger o height)
  "NIL when operation O conforms at HEIGHT on LEDGER (its state before O), else
   a string naming the broken rule.  Depositor-signed operations: expiry, nonce and witness;
   FeeCollect: DEP-07's window and cap.  The fold judges everything else, including an unknown
   deposit and the operator-only transfer and invoice settlements."
  (or (operator-violation ledger o) (depositor-violation ledger o height)))

(defun depositor-violation (ledger o height)
  (when (d17:operation->dep16 o)
    (let* ((d (ignore-errors (lg:find-deposit ledger (or (field o :source-deposit-id) (field o :deposit-id)))))
           (nonce (field o :nonce)) (expiry (field o :expiry)))
      (cond ((null d) nil)
            ((and expiry (< expiry height)) (format nil "ExpiryPassed: expiry ~a is below height ~a" expiry height))
            ((and nonce (some (lambda (seen) (and (eql (car seen) nonce) (cdr seen) (>= (cdr seen) height)))
                              (lg:deposit-seen-nonces d)))
             (format nil "NonceReplay: nonce ~a" nonce))
            ((not (authorized-p o d height)) "Unauthorized: the depositor's witness does not authorize this operation")))))

;;; DEP-16 §Descriptor validity.  Grounds for a member to refuse a cosignature and for an operator
;;; not to propose, never to convict: the descriptor is the depositor's own, and cl admitted
;;; invalid ones before the shared vector existed (inspect/vectors/descriptor_validity.json).
;;; The reference is deposits-protocol ledger_state check_conformance (UnparseableDescriptor,
;;; DescriptorTooLarge), which proves_non_conformance excludes.

(defun descriptor-refusal (ledger o)
  "NIL, or why a DepositOpen or DepositKeyRotate O may not be cosigned on LEDGER: its descriptor
   is invalid, or longer than the smallest max_descriptor_bytes a quorum member declared."
  (let ((text (case (op:operation-type o)
                (:deposit-open (field o :descriptor))
                (:deposit-key-rotate (field o :new-descriptor)))))
    (when text
      (or (let ((v (d16:descriptor-violation text)))
            (when v (format nil "UnparseableDescriptor: ~a" v)))
          (let ((caps (remove nil (mapcar #'lg::member-max-descriptor-bytes (lg:ledger-quorum-members ledger))))
                (len (length (sb-ext:string-to-octets text :external-format :utf-8))))
            (when (and caps (> len (reduce #'min caps)))
              (format nil "DescriptorTooLarge: ~a bytes, at most ~a" len (reduce #'min caps))))))))

;;; DEP-17 §duplicate delivery: what an operator does with a request whose operation reuses
;;; a nonce.  Pinned by inspect/vectors/nonce_delivery.json, shared with deposits-rust.

(defun nonce-verdict (accepted nonce expiry sighash height)
  "ACCEPTED is the deposit's accepted operations as (nonce expiry sighash) lists.  Returns
   :EXPIRED (expiry below HEIGHT), :DUPLICATE (the accepted operation with this nonce, still
   within its expiry, has this SIGHASH: the same operation delivered again), :REPLAY (a different
   operation reusing a live nonce) or :ACCEPT.  A lower nonce than the last is accepted."
  (let ((live (remove-if-not (lambda (a) (and (eql (first a) nonce) (>= (second a) height))) accepted)))
    (cond ((< expiry height) :expired)
          ((find sighash live :key #'third :test #'equalp) :duplicate)
          (live :replay)
          (t :accept))))

(defun operation-deposit-id (o)
  "The deposit a depositor-signed operation is signed for."
  (or (field o :source-deposit-id) (field o :deposit-id)))

(defun signed-sighash (o)
  "The DEP-17 operation sighash O's depositor signs, or NIL for operations no depositor signs."
  (multiple-value-bind (id type args nonce expiry) (d17:operation->dep16 o)
    (when id (d17:operation-sighash (d17:operation-preimage id type args nonce expiry)))))
