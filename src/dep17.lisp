;;;; src/dep17.lisp — DEP-17 canonical encodings (the part a wallet signs).
;;;;
;;;; A deposit's descriptor authorizes OPERATIONS; the signature a wallet puts
;;;; in an InvoiceLock/OnchainLock/TransferLock witness commits to the canonical
;;;; bytes of that operation, domain-separated by deposit id and bounded by a
;;;; nonce and an expiry height.  Getting one byte of this wrong means every
;;;; real wallet's signature fails here, so it is checked against the reference
;;;; conformance vectors and against the signatures in the fixture ledger.
;;;;
;;;;   operation_preimage = 0x01 || deposit_id(32) || symbol op_type
;;;;                        || list<(symbol name, value)> args (sorted by name)
;;;;                        || u64 nonce || u32 expiry
;;;;   operation_sighash  = tagged_hash("dep17/operation", operation_preimage)

(defpackage #:cl-deposits.dep17
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:op #:cl-deposits.operation) (#:secp #:secp256k1-fast)
                    (#:schnorr #:secp256k1-fast.schnorr))
  (:export #:encode-value #:operation-preimage #:operation-sighash
           #:operation->dep16 #:pad-deposit-id #:descriptor-key
           #:verify-operation-witness #:sign-operation #:parse-pubkey #:ecdsa-compact-verify))
(in-package #:cl-deposits.dep17)

;;; Values are tagged: (:int n) (:key bytes33) (:hash fn digest) (:bytes b)
;;; (:path (i...)) (:list (v...)) (:symbol "s").

(defun put-u32 (n) (int->be n 4))

(defun put-bytes (b)
  "u32 length, then the bytes."
  (cat (put-u32 (length b)) b))

(defun put-int (n)
  "16-byte big-endian two's complement."
  (int->be (ldb (byte 128 0) n) 16))

(defun encode-value (v)
  (ecase (first v)
    (:int (cat (octets 0) (put-int (second v))))
    (:key (cat (octets 1) (put-bytes (second v))))
    (:hash (cat (octets 2) (octets (ecase (second v) (:sha256 0) (:hash256 1) (:ripemd160 2) (:hash160 3)))
                (third v)))
    (:bytes (cat (octets 3) (put-bytes (second v))))
    (:path (apply #'cat (octets 4) (put-u32 (length (second v))) (mapcar #'put-u32 (second v))))
    (:list (apply #'cat (octets 5) (put-u32 (length (second v))) (mapcar #'encode-value (second v))))
    (:symbol (cat (octets 6) (put-bytes (ascii->bytes (second v)))))))

(defun operation-preimage (deposit-id32 op-type args nonce expiry)
  "ARGS is an alist of (name-string . value); it is sorted here."
  (apply #'cat (octets 1) deposit-id32 (put-bytes (ascii->bytes op-type))
         (put-u32 (length args))
         (append (loop for (name . value) in (sort (copy-list args) #'string< :key #'car)
                       collect (cat (put-bytes (ascii->bytes name)) (encode-value value)))
                 (list (int->be nonce 8) (int->be expiry 4)))))

(defun operation-sighash (preimage)
  (tagged-hash "dep17/operation" preimage))

(defun pad-deposit-id (id16)
  (cat id16 (make-array 16 :element-type '(unsigned-byte 8))))

(defun operation->dep16 (o)
  "The dep-16 operation a ledger operation is authorized as: (values deposit-id32
   op-type args nonce expiry), or NIL for operations no depositor signs."
  (flet ((f (name) (op:field o name)))
    (case (op:operation-type o)
      (:invoice-lock
       (values (pad-deposit-id (f :deposit-id)) "spend"
               (append `(("amount" . (:int ,(f :amount))) ("kind" . (:symbol "invoice"))
                         ("payment_id" . (:bytes ,(f :payment-id))))
                       (when (f :fee) `(("fee" . (:int ,(f :fee))))))
               (f :nonce) (f :expiry)))
      (:onchain-lock
       (values (pad-deposit-id (f :deposit-id)) "spend"
               `(("amount" . (:int ,(f :amount)))
                 ("destination" . (:bytes ,(ascii->bytes (f :destination-address))))
                 ("fee" . (:int ,(f :fee-sats))) ("kind" . (:symbol "onchain"))
                 ("withdrawal_id" . (:bytes ,(f :withdrawal-id))))
               (f :nonce) (f :expiry)))
      (:transfer-lock
       (values (pad-deposit-id (f :source-deposit-id)) "spend"
               `(("amount" . (:int ,(f :amount)))
                 ("completion_script" . (:bytes ,(ascii->bytes (f :completion-script))))
                 ("destination_deposit_id" . (:bytes ,(f :destination-deposit-id)))
                 ("fee" . (:int ,(f :fee))) ("kind" . (:symbol "transfer"))
                 ("transfer_nonce" . (:bytes ,(f :transfer-nonce)))
                 ("transfer_id" . (:bytes ,(f :transfer-id)))
                 ("timeout_height" . (:int ,(f :timeout-height))))
               (f :nonce) (f :expiry)))
      (:deposit-key-rotate
       (values (pad-deposit-id (f :deposit-id)) "update"
               `(("sub_op" . (:symbol "replace"))
                 ("new_descriptor_source" . (:bytes ,(ascii->bytes (f :new-descriptor)))))
               (f :nonce) (f :expiry)))
      (:transfer-complete
       (values (f :transfer-id) "transfer_release"
               `(("transfer_id" . (:bytes ,(f :transfer-id)))) 0 #xffffffff))
      (t nil))))

;;; ---------------------------------------------------------------------------
;;; pk(K) descriptors and ECDSA witnesses.  The full descriptor calculus is
;;; the next layer; this is the case every real deposit in the fixture uses.

(defun descriptor-key (descriptor)
  "The compressed key of a plain pk(<hex>) descriptor, or NIL."
  (let ((start (search "pk(" descriptor)))
    (when (and start (= start 0))
      (let ((end (position #\) descriptor)))
        (when (and end (= (- end 3) 66))
          (hex->bytes (subseq descriptor 3 end)))))))

(defun parse-pubkey (b)
  (unless (and (= (length b) 33) (member (aref b 0) '(2 3))) (error "bad compressed pubkey"))
  (secp:secp-init)
  (let* ((x (be->int b :start 1))
         (even (or (schnorr:lift-x x) (error "pubkey not on curve"))))
    (if (= (aref b 0) 2) even (cons x (- secp:*secp256k1-p* (cdr even))))))

(defun ecdsa-compact-verify (pubkey33 msg32 sig64)
  (and (= (length sig64) 64)
       (secp:ecdsa-verify (parse-pubkey pubkey33) msg32 (be->int sig64 :end 32) (be->int sig64 :start 32))))

(defun verify-operation-witness (o descriptor witness)
  "For a pk(K) deposit: does the witness's single element sign the operation's
   DEP-17 sighash under K?  Returns :ok, :unsigned-kind (operation carries no
   depositor signature), or NIL."
  (multiple-value-bind (id type args nonce expiry) (operation->dep16 o)
    (cond ((null id) :unsigned-kind)
          (t (let ((key (descriptor-key descriptor)))
               (and key witness (= (length witness) 1)
                    (ecdsa-compact-verify key (operation-sighash (operation-preimage id type args nonce expiry))
                                          (first witness))
                    :ok))))))

(defun sign-operation (o privkey-int)
  "A one-element witness: the compact ECDSA signature over the operation's sighash."
  (multiple-value-bind (id type args nonce expiry) (operation->dep16 o)
    (unless id (error "operation ~a is not depositor-signed" (op:operation-type o)))
    (multiple-value-bind (r s) (secp:ecdsa-sign-raw privkey-int (operation-sighash (operation-preimage id type args nonce expiry)))
      (list (cat (int->be r 32) (int->be s 32))))))
