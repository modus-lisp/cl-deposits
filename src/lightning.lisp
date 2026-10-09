;;;; src/lightning.lisp — the Lightning rail (DEP-10, legacy deterrence receive).
;;;;
;;;; A wallet asks its operator for an invoice; the operator's Lightning node
;;;; mints it; a quorum member cosigns an attestation binding (ledger, payment
;;;; hash, deposit, amount) so that a paid-but-uncredited invoice is provable
;;;; fraud; when the node reports the payment settled, the operator appends
;;;; InvoiceCredit.  The Lightning node here is a cl-payments daemon, reached
;;;; over its control socket — or a mock, for the gate.

(defpackage #:cl-deposits.lightning
  (:use #:cl #:cl-deposits.util)
  (:export #:ln-make-invoice #:ln-invoice-status #:ln-pay #:ln-payment-status #:clp-backend #:make-clp-backend
           #:mock-ln #:make-mock-ln #:mock-ln-settle #:mock-ln-external-invoice #:invoice-cosign-message
           #:invoice-payment-hash #:invoice-amount-msat #:ln-refused #:mock-ln-hold #:mock-ln-resolve))
(in-package #:cl-deposits.lightning)

(defgeneric ln-make-invoice (backend amount-msat description)
  (:documentation "(values bolt11 payment-hash32)"))
(defgeneric ln-invoice-status (backend payment-hash)
  (:documentation "(values :paid|:unpaid|:unknown received-msat-or-nil)"))
(defgeneric ln-pay (backend bolt11 &key amount-msat height)
  (:documentation "Start paying; returns the payment hash."))
(defgeneric ln-payment-status (backend payment-hash)
  (:documentation "(values :pending|:succeeded|:failed preimage-or-nil).  :failed only
   when the backend says the payment definitively failed; anything it cannot
   vouch for (unknown, error, in flight) is :pending, because releasing a lock on a
   payment that may still settle pays it twice."))

(define-condition ln-refused (error)
  ((reason :initarg :reason :reader ln-refused-reason))
  (:report (lambda (c s) (format s "the Lightning node refused to send: ~a" (ln-refused-reason c))))
  (:documentation "The backend declined BEFORE offering any HTLC: nothing was sent."))

(defun invoice-payment-hash (bolt11)
  "The payment hash a BOLT #11 invoice commits to.  Mock invoices end in it."
  (if (and (> (length bolt11) 70) (string= "lnmock" (subseq bolt11 0 6)))
      (hex->bytes (subseq bolt11 (- (length bolt11) 64)))
      (cl-deposits.lightning.decode:payment-hash bolt11)))

(defun invoice-amount-msat (bolt11)
  "The amount an invoice asks for, in msat, or NIL for an amountless invoice."
  (if (and (> (length bolt11) 70) (string= "lnmock" (subseq bolt11 0 6)))
      (let ((digits (subseq bolt11 7 (- (length bolt11) 64))))
        (and (plusp (length digits)) (every #'digit-char-p digits) (parse-integer digits)))
      (cl-deposits.lightning.decode:invoice-amount-msat bolt11)))

(defun invoice-cosign-message (ledger-id-hex payment-hash deposit-id amount-msat signer-ledger-hash)
  "deposits_protocol::invoice_cosign_signing_message: a tagged hash over
   ledger_id (hex ascii) || payment_hash || deposit_id || amount_le64 || signer's ledger hash."
  (tagged-hash "deposits/invoice_cosign"
               (ascii->bytes ledger-id-hex) payment-hash deposit-id (int->le amount-msat 8) signer-ledger-hash))

;;; cl-payments over its control socket: one s-expression per line.

(defstruct (clp-backend (:constructor %make-clp-backend)) host port)
(defun make-clp-backend (host port) (%make-clp-backend :host host :port port))

(defun clp-call (backend form)
  (let ((sock (usocket:socket-connect (clp-backend-host backend) (clp-backend-port backend))))
    (unwind-protect
         (let ((s (usocket:socket-stream sock)))
           (write-line form s) (finish-output s)
           (let ((line (read-line s nil nil)))
             (and line (let ((*read-eval* nil)) (read-from-string line)))))
      (usocket:socket-close sock))))

(defmethod ln-make-invoice ((b clp-backend) amount-msat description)
  (let ((r (clp-call b (let ((*print-pretty* nil))
                         (format nil "(:invoice :amount-msat ~d :description ~s)" amount-msat (or description ""))))))
    (unless (eq (getf r :status) :ok) (error "cl-payments refused the invoice: ~s" r))
    (values (getf r :bolt11) (hex->bytes (getf r :payment-hash)))))

(defmethod ln-pay ((b clp-backend) bolt11 &key amount-msat height)
  (let ((r (clp-call b (let ((*print-pretty* nil))
                         (format nil "(:pay :bolt11 ~s~@[ :amount-msat ~d~]~@[ :height ~d~])" bolt11 amount-msat height)))))
    ;; A reply that is not :pending is cl-payments declining before it offered an
    ;; HTLC (it answers :pending once one is out).  No reply at all is NOT a
    ;; refusal: the payment may be in flight, so that is an ordinary error.
    (unless (member (getf r :status) '(:pending :ok))
      (if r (error 'ln-refused :reason (princ-to-string r)) (error "no reply from cl-payments to :pay")))
    (hex->bytes (getf r :payment-hash))))

(defmethod ln-payment-status ((b clp-backend) payment-hash)
  (let ((r (clp-call b (format nil "(:payment-status :payment-hash ~s)" (bytes->hex payment-hash)))))
    (case (getf r :status)
      ((:succeeded :complete :completed :paid)
       (values :succeeded (let ((p (getf r :preimage))) (and (stringp p) (hex->bytes p)))))
      (:failed (values :failed nil))
      (t (values :pending nil)))))

(defmethod ln-invoice-status ((b clp-backend) payment-hash)
  (let ((r (clp-call b (format nil "(:invoice-status :payment-hash ~s)" (bytes->hex payment-hash)))))
    (values (case (getf r :status) (:paid :paid) (:unknown :unknown) (t :unpaid))
            (let ((m (getf r :received-msat))) (and (integerp m) m)))))

;;; A mock for the gate.

(defstruct (mock-ln (:constructor make-mock-ln)) (invoices (make-hash-table :test #'equalp)) (paid (make-hash-table :test #'equalp)))

(defmethod ln-make-invoice ((b mock-ln) amount-msat description)
  (declare (ignore description))
  (let* ((preimage (with-open-file (in "/dev/urandom" :element-type '(unsigned-byte 8))
                     (let ((a (make-array 32 :element-type '(unsigned-byte 8)))) (read-sequence a in) a)))
         (hash (sha256 preimage)))
    (setf (gethash hash (mock-ln-invoices b)) amount-msat)
    (values (format nil "lnmock1~a~a" amount-msat (bytes->hex hash)) hash)))

(defmethod ln-invoice-status ((b mock-ln) payment-hash)
  (let ((paid (gethash payment-hash (mock-ln-paid b))))
    (cond (paid (values :paid (if (integerp paid) paid (gethash payment-hash (mock-ln-invoices b)))))
          ((gethash payment-hash (mock-ln-invoices b)) :unpaid)
          (t :unknown))))

(defun mock-ln-settle (b payment-hash &optional received-msat)
  "Mark an invoice paid; RECEIVED-MSAT (default: the invoiced amount) is what arrived."
  (setf (gethash payment-hash (mock-ln-paid b)) (or received-msat t)))

;;; Paying with the mock: an "external" invoice is one whose preimage the mock
;;; knows; paying it succeeds and yields the preimage.  Anything else fails.
(defvar *mock-external* (make-hash-table :test #'equalp))   ; payment hash -> preimage
(defun mock-ln-external-invoice (b amount-msat)
  (declare (ignore b))
  (let* ((preimage (with-open-file (in "/dev/urandom" :element-type '(unsigned-byte 8))
                     (let ((a (make-array 32 :element-type '(unsigned-byte 8)))) (read-sequence a in) a)))
         (hash (sha256 preimage)))
    (setf (gethash hash *mock-external*) preimage)
    (values (format nil "lnmock1~a~a" amount-msat (bytes->hex hash)) hash preimage)))
(defmethod ln-pay ((b mock-ln) bolt11 &key amount-msat height)
  (declare (ignore amount-msat height))
  (hex->bytes (subseq bolt11 (- (length bolt11) 64))))
(defvar *mock-held* (make-hash-table :test #'equalp)
  "payment hash -> :pending, or (:succeeded . preimage) / :failed once resolved.")
(defun mock-ln-hold (payment-hash) (setf (gethash payment-hash *mock-held*) :pending))
(defun mock-ln-resolve (payment-hash outcome)
  "OUTCOME is :failed, or :succeeded (the preimage comes from *mock-external*)."
  (setf (gethash payment-hash *mock-held*) outcome))
(defmethod ln-payment-status ((b mock-ln) payment-hash)
  (let ((held (gethash payment-hash *mock-held*))
        (p (gethash payment-hash *mock-external*)))
    (cond ((eq held :pending) (values :pending nil))
          ((eq held :failed) (values :failed nil))
          (p (values :succeeded p))
          (t (values :failed nil)))))
