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
  (:export #:ln-make-invoice #:ln-invoice-status #:clp-backend #:make-clp-backend
           #:mock-ln #:make-mock-ln #:mock-ln-settle #:invoice-cosign-message))
(in-package #:cl-deposits.lightning)

(defgeneric ln-make-invoice (backend amount-msat description)
  (:documentation "(values bolt11 payment-hash32)"))
(defgeneric ln-invoice-status (backend payment-hash)
  (:documentation ":paid, :unpaid, or :unknown"))

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

(defmethod ln-invoice-status ((b clp-backend) payment-hash)
  (let ((r (clp-call b (format nil "(:invoice-status :payment-hash ~s)" (bytes->hex payment-hash)))))
    (case (getf r :status) (:paid :paid) (:unknown :unknown) (t :unpaid))))

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
  (cond ((gethash payment-hash (mock-ln-paid b)) :paid)
        ((gethash payment-hash (mock-ln-invoices b)) :unpaid)
        (t :unknown)))

(defun mock-ln-settle (b payment-hash) (setf (gethash payment-hash (mock-ln-paid b)) t))
