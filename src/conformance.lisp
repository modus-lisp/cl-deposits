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
  (:export #:violation #:authorized-p))
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
               (let ((descriptor (d16:parse-descriptor desc))
                     (op (d16:make-operation :deposit-id id :op-type type :args args :nonce nonce :expiry expiry)))
                 (handler-case (d16:evaluate descriptor op (snapshot d height) (d16:witness-from-stack witness descriptor op))
                   (d16:eval-error () nil))))))))

(defun violation (ledger o height)
  "NIL when operation O conforms at HEIGHT on LEDGER (its state before O), else
   a string naming the broken rule.  Operations no depositor signs conform here;
   the fold judges everything else, including an unknown deposit."
  (when (d17:operation->dep16 o)
    (let* ((d (ignore-errors (lg:find-deposit ledger (or (field o :source-deposit-id) (field o :deposit-id)))))
           (nonce (field o :nonce)) (expiry (field o :expiry)))
      (cond ((null d) nil)
            ((and expiry (< expiry height)) (format nil "ExpiryPassed: expiry ~a is below height ~a" expiry height))
            ((and nonce (some (lambda (seen) (and (eql (car seen) nonce) (cdr seen) (>= (cdr seen) height)))
                              (lg:deposit-seen-nonces d)))
             (format nil "NonceReplay: nonce ~a" nonce))
            ((not (authorized-p o d height)) "Unauthorized: the depositor's witness does not authorize this operation")))))
