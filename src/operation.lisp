;;;; src/operation.lisp — DEP-02 ledger operations.
;;;;
;;;; The inner TLV of a SignedLedgerUpdate.  Record 0 is the discriminant; the
;;;; rest are the operation's fields, whose tag numbers are shared across
;;;; operations (tag 2 is always "amount") except where two operations reuse a
;;;; number for different things (288/290: nonce/expiry on deposit ops,
;;;; member_response/member_signature on QuorumAddMember), which is why the
;;;; field table is per operation.
;;;;
;;;; An operation is a plist: (:type :invoice-lock :deposit-id #(...) :amount 5 ...).
;;;; Absent optional fields are simply absent — not NIL — so that
;;;; (encode (decode bytes)) reproduces bytes exactly, which the fixture gate
;;;; checks for every operation of a real ledger.

(defpackage #:cl-deposits.operation
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:tlv #:cl-deposits.tlv))
  (:export #:decode-operation #:encode-operation #:operation-type #:field
           #:op-error #:discriminant #:type-of-discriminant
           #:deposit-id #:compute-ledger-id #:*operations*
           #:fees #:transfer-fees #:make-fees #:make-transfer-fees
           #:fees-annualized-msats #:fees-annualized-bps #:fees-frequency-blocks
           #:transfer-fees-fixed-msats #:transfer-fees-rate-bps
           #:member-ref #:make-member-ref #:member-ref-pubkey #:member-ref-ledger-id))
(in-package #:cl-deposits.operation)

(define-condition op-error (error)
  ((detail :initarg :detail :reader detail))
  (:report (lambda (c s) (format s "operation: ~a" (detail c)))))

(defstruct fees (annualized-msats 0) (annualized-bps 0) (frequency-blocks 0))
(defstruct transfer-fees (fixed-msats 0) (rate-bps 0))
(defstruct member-ref pubkey (ledger-id ""))

;;; ---------------------------------------------------------------------------
;;; The field table.  (name tag kind [:optional])

(defparameter *operations*
  '((1 :ledger-open
     (:operator-id 56 :pubkey) (:reserves-id 58 :string) (:genesis-block 96 :u32)
     (:reserves-amount 62 :u64) (:collateral-amount 88 :u64))
    (12 :quorum-begin
     (:reserves-id 58 :string) (:spending-txid 90 :bytes32) (:new-outpoint-txid 84 :bytes32)
     (:new-outpoint-vout 92 :u32) (:amount 2 :u64) (:quorum-expiry 86 :u32)
     (:ledger-hash 42 :bytes32) (:quorum-members 6 :pubkeys) (:collateral-amount 88 :u64)
     (:quorum-member-ledger-ids 276 :ledger-ids :optional) (:protocol-version 286 :string :optional)
     (:exit-cutoff-height 278 :u32 :optional) (:exit-outputs 280 :exit-outputs :optional))
    (20 :deposit-open
     (:deposit-id 200 :deposit-id) (:descriptor 202 :string) (:fees 12 :fees :optional)
     (:transfer-fees 226 :transfer-fees :optional) (:payment-hash 14 :bytes32 :optional)
     (:invoice 16 :string :optional) (:cosigner-guarantee-signature 18 :bytes64 :optional)
     (:receive-requires-sig 232 :bool :optional) (:fee-change-after-blocks 244 :u32 :optional)
     (:fee-change-notice-blocks 246 :u32 :optional) (:fee-change-limit-bps 248 :u16 :optional)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (21 :deposit-close
     (:deposit-id 200 :deposit-id) (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (22 :fee-change
     (:deposit-id 200 :deposit-id) (:new-fees 20 :fees) (:effective-block 250 :u32))
    (23 :deposit-key-rotate
     (:deposit-id 200 :deposit-id) (:new-descriptor 208 :string) (:nonce 288 :u64) (:expiry 290 :u32)
     (:witness 204 :witness))
    (30 :invoice-credit
     (:payment-hash 14 :bytes32) (:deposit-id 200 :deposit-id) (:amount 2 :u64) (:invoice-id 26 :string)
     (:sequence-number 28 :u64) (:wallet-authorization 296 :bytes64 :optional)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (31 :invoice-lock
     (:deposit-id 200 :deposit-id) (:amount 2 :u64) (:payment-id 30 :bytes32) (:sequence-number 28 :u64)
     (:nonce 288 :u64) (:expiry 290 :u32) (:witness 204 :witness) (:timeout-height 219 :u32 :optional)
     (:fee 221 :u64 :optional) (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (32 :invoice-fail
     (:deposit-id 200 :deposit-id) (:payment-id 30 :bytes32) (:sequence-number 28 :u64)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (33 :invoice-fulfill
     (:deposit-id 200 :deposit-id) (:amount 2 :u64) (:payment-id 30 :bytes32) (:sequence-number 28 :u64)
     (:witness 204 :witness) (:preimage 34 :bytes32)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (35 :onchain-credit
     (:txid 66 :bytes32) (:vout 68 :u32) (:deposit-id 200 :deposit-id) (:amount 2 :u64)
     (:funding-address 74 :string) (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (36 :onchain-lock
     (:deposit-id 200 :deposit-id) (:amount 2 :u64) (:fee-sats 12 :u64) (:destination-address 70 :string)
     (:withdrawal-id 72 :bytes32) (:nonce 288 :u64) (:expiry 290 :u32) (:witness 204 :witness)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (37 :onchain-fail
     (:deposit-id 200 :deposit-id) (:withdrawal-id 72 :bytes32)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (38 :onchain-fulfill
     (:deposit-id 200 :deposit-id) (:withdrawal-id 72 :bytes32) (:amount 2 :u64) (:txid 66 :bytes32)
     (:destination-address 70 :string) (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (43 :quorum-add-member
     (:quorum-member 44 :pubkey) (:quorum-member-signature 46 :bytes64) (:member-ledger-id 114 :string)
     (:min-fee-bps 234 :u16 :optional) (:min-fee-fixed 236 :u64 :optional) (:max-fee-period 238 :u32 :optional)
     (:membership-until 242 :u32 :optional) (:dispute-response-blocks 252 :u32 :optional)
     (:dispute-arm-blocks 254 :u32 :optional) (:service-response-blocks 256 :u32 :optional)
     (:max-transfer-timeout-blocks 258 :u32 :optional) (:max-descriptor-bytes 262 :u32 :optional)
     (:compensation-bps 264 :u16 :optional) (:compensation-deposit-id 266 :deposit-id :optional)
     (:compensation-frequency-blocks 268 :u32 :optional) (:min-collateral-bps 314 :u16 :optional)
     (:member-response 288 :bytes :optional)
     (:member-signature 290 :bytes64 :optional))
    (44 :quorum-remove-member (:quorum-member 44 :pubkey) (:operator-signature 48 :bytes64))
    (45 :quorum-upgrade (:new-protocol-version 286 :string))
    (46 :quorum-join (:operator-id 56 :pubkey) (:ledger-id 58 :string) (:membership-expires 82 :u32))
    (50 :fee-collect
     (:deposit-id 200 :deposit-id) (:amount 2 :u64) (:block-height 36 :u32)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (54 :dispute-enter
     (:last-valid-sequence 102 :u64) (:reason 100 :string) (:anchor-block-hash 292 :bytes32 :optional)
     (:anchor-block-height 294 :u32 :optional))
    (55 :dispute-acquire
     (:new-custodian 108 :pubkey) (:claim-txid 110 :bytes32) (:new-reserves-address 120 :string))
    (56 :dispute-yield)
    (57 :dispute-armed
     (:armed-block 118 :u32) (:commitment-hash 112 :bytes20) (:target-reserves 122 :string)
     (:replacement-collateral-txid 280 :bytes32 :optional) (:replacement-collateral-vout 282 :u32 :optional)
     (:replacement-collateral-amount 284 :u64 :optional))
    (60 :ledger-close)
    (70 :transfer-lock
     (:transfer-nonce 210 :bytes32) (:source-deposit-id 212 :deposit-id) (:destination-deposit-id 214 :deposit-id)
     (:amount 2 :u64) (:fee 12 :u64) (:completion-script 216 :string) (:timeout-height 218 :u32)
     (:transfer-id 220 :bytes32) (:nonce 288 :u64) (:expiry 290 :u32) (:witness 204 :witness)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (71 :transfer-complete
     (:transfer-id 220 :bytes32) (:script-witness 224 :witness)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional)
     (:dest-balance-after 227 :u64 :optional) (:dest-locked-after 229 :u64 :optional))
    (72 :transfer-fail
     (:transfer-id 220 :bytes32) (:block-hash 222 :bytes32) (:reason 228 :u8)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (80 :delivery-embed
     (:request-hash 270 :bytes32) (:target-ledger-id 272 :bytes32) (:target-operator 274 :pubkey))
    (90 :batch (:ops 298 :bytes))
    (100 :exit-request
     (:deposit-id 200 :deposit-id) (:amount 2 :u64) (:exit-address 300 :bytes)
     (:expires-at-height 302 :u32 :optional) (:nonce 288 :u64) (:expiry 290 :u32) (:witness 204 :witness)
     (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))
    (101 :exit-cancel
     (:deposit-id 200 :deposit-id) (:exit-request-id 304 :bytes32) (:nonce 288 :u64) (:expiry 290 :u32)
     (:witness 204 :witness) (:balance-after 223 :u64 :optional) (:locked-after 225 :u64 :optional))))

(defun discriminant (type)
  (or (first (find type *operations* :key #'second))
      (error 'op-error :detail (format nil "unknown operation type ~s" type))))

(defun type-of-discriminant (d)
  (second (or (assoc d *operations*) (error 'op-error :detail (format nil "unknown discriminant ~a" d)))))

(defun operation-type (op) (getf op :type))
(defun field (op name) (getf op name))

;;; ---------------------------------------------------------------------------
;;; Ids

(defun deposit-id (descriptor)
  "A deposit is identified by the first 16 bytes of SHA256 of its descriptor text."
  (subseq (sha256 (ascii->bytes descriptor)) 0 16))

(defun compute-ledger-id (operator-id33 reserves-id genesis-block)
  "SHA256(operator_pubkey || reserves_id_utf8 || genesis_block_le32)."
  (sha256 (cat operator-id33 (ascii->bytes reserves-id) (int->le genesis-block 4))))

;;; ---------------------------------------------------------------------------
;;; Field kinds

(defun %fixed (bytes len name)
  (unless (= (length bytes) len)
    (error 'op-error :detail (format nil "~a: expected ~a bytes, got ~a" name len (length bytes))))
  bytes)

(defun %int (bytes size name)
  (be->int (%fixed bytes size name)))

(defun decode-witness (bytes)
  (multiple-value-bind (n pos) (tlv:read-bigsize bytes 0)
    (let ((stack '()))
      (dotimes (i n)
        (multiple-value-bind (len p) (tlv:read-bigsize bytes pos)
          (when (> (+ p len) (length bytes)) (error 'op-error :detail "truncated witness"))
          (push (subseq bytes p (+ p len)) stack)
          (setf pos (+ p len))))
      (unless (= pos (length bytes)) (error 'op-error :detail "trailing bytes in witness"))
      (nreverse stack))))

(defun encode-witness (stack)
  (apply #'cat (tlv:bigsize-bytes (length stack))
         (loop for e in stack collect (cat (tlv:bigsize-bytes (length e)) e))))

(defun decode-fees (bytes)
  (let ((a (tlv:decode bytes)))
    (make-fees :annualized-msats (be->int (tlv:field a 0))
               :annualized-bps (be->int (tlv:field a 2))
               :frequency-blocks (be->int (tlv:field a 4)))))

(defun encode-fees (f)
  (tlv:encode `((0 . ,(int->be (fees-annualized-msats f) 8))
                (2 . ,(int->be (fees-annualized-bps f) 2))
                (4 . ,(int->be (fees-frequency-blocks f) 4)))))

(defun decode-transfer-fees (bytes)
  (let ((a (tlv:decode bytes)))
    (make-transfer-fees :fixed-msats (be->int (tlv:field a 0)) :rate-bps (be->int (tlv:field a 2)))))

(defun encode-transfer-fees (f)
  (tlv:encode `((0 . ,(int->be (transfer-fees-fixed-msats f) 8))
                (2 . ,(int->be (transfer-fees-rate-bps f) 2)))))

(defun decode-pubkeys (bytes)
  (unless (zerop (mod (length bytes) 33)) (error 'op-error :detail "pubkey list not a multiple of 33"))
  (loop for i from 0 below (length bytes) by 33 collect (subseq bytes i (+ i 33))))

(defun decode-ledger-ids (bytes)
  "u8 length-prefixed UTF-8 strings, back to back."
  (let ((pos 0) (out '()))
    (loop while (< pos (length bytes))
          do (let ((len (aref bytes pos)))
               (when (> (+ pos 1 len) (length bytes)) (error 'op-error :detail "truncated ledger id list"))
               (push (bytes->ascii (subseq bytes (1+ pos) (+ pos 1 len))) out)
               (incf pos (1+ len))))
    (nreverse out)))

(defun encode-ledger-ids (ids)
  (apply #'cat (loop for id in ids collect (cat (octets (length id)) (ascii->bytes id)))))

(defun decode-exit-outputs (bytes)
  "DEP-02 type 280: repeated deposit_id(16) || amount_msats(8) || vout(4), as ((id amount vout) ...)."
  (unless (zerop (mod (length bytes) 28)) (error 'op-error :detail "exit_outputs not a multiple of 28"))
  (loop for i from 0 below (length bytes) by 28
        collect (list (subseq bytes i (+ i 16)) (be->int bytes :start (+ i 16) :end (+ i 24))
                      (be->int bytes :start (+ i 24) :end (+ i 28)))))

(defun encode-exit-outputs (entries)
  (apply #'cat (loop for (id amount vout) in entries collect (cat id (int->be amount 8) (int->be vout 4)))))

(defun decode-kind (kind bytes name)
  (ecase kind
    (:u8 (%int bytes 1 name)) (:u16 (%int bytes 2 name)) (:u32 (%int bytes 4 name)) (:u64 (%int bytes 8 name))
    (:bool (let ((b (%int bytes 1 name))) (unless (<= b 1) (error 'op-error :detail "bool not 0/1")) (= b 1)))
    (:bytes bytes) (:bytes20 (%fixed bytes 20 name)) (:bytes32 (%fixed bytes 32 name)) (:bytes64 (%fixed bytes 64 name))
    (:pubkey (%fixed bytes 33 name)) (:deposit-id (%fixed bytes 16 name))
    (:string (bytes->ascii bytes))
    (:witness (decode-witness bytes)) (:fees (decode-fees bytes)) (:transfer-fees (decode-transfer-fees bytes))
    (:pubkeys (decode-pubkeys bytes)) (:ledger-ids (decode-ledger-ids bytes))
    (:exit-outputs (decode-exit-outputs bytes))))

(defun encode-kind (kind value)
  (ecase kind
    (:u8 (int->be value 1)) (:u16 (int->be value 2)) (:u32 (int->be value 4)) (:u64 (int->be value 8))
    (:bool (octets (if value 1 0)))
    ((:bytes :bytes20 :bytes32 :bytes64 :pubkey :deposit-id) value)
    (:string (ascii->bytes value))
    (:witness (encode-witness value)) (:fees (encode-fees value)) (:transfer-fees (encode-transfer-fees value))
    (:pubkeys (apply #'cat value)) (:ledger-ids (encode-ledger-ids value))
    (:exit-outputs (encode-exit-outputs value))))

;;; ---------------------------------------------------------------------------

(defun decode-operation (bytes)
  (let* ((a (tlv:decode bytes))
         (d (tlv:field a 0)))
    (unless (and d (= (length d) 1)) (error 'op-error :detail "missing discriminant"))
    (let* ((entry (or (assoc (aref d 0) *operations*)
                      (error 'op-error :detail (format nil "unknown discriminant ~a" (aref d 0)))))
           (op (list :type (second entry)))
           (known (list 0)))
      (loop for (name tag kind . flags) in (cddr entry)
            do (push tag known)
               (let ((v (tlv:field a tag)))
                 (cond (v (setf op (append op (list name (decode-kind kind v name)))))
                       ((member :optional flags))
                       (t (error 'op-error :detail (format nil "~a: missing ~a (tag ~a)" (second entry) name tag))))))
      ;; Unknown odd tags are permitted (forward compatibility); unknown even tags are not.
      (dolist (rec a)
        (unless (member (car rec) known)
          (when (evenp (car rec))
            (error 'op-error :detail (format nil "~a: unknown even tag ~a" (second entry) (car rec))))
          (setf op (append op (list (car rec) (cdr rec))))))
      op)))

(defun encode-operation (op)
  (let* ((type (operation-type op))
         (entry (or (find type *operations* :key #'second)
                    (error 'op-error :detail (format nil "unknown operation type ~s" type))))
         (records (list (cons 0 (octets (first entry))))))
    (loop for (name tag kind . flags) in (cddr entry)
          do (let ((cell (member name op)))
               (cond (cell (push (cons tag (encode-kind kind (second cell))) records))
                     ((member :optional flags))
                     (t (error 'op-error :detail (format nil "~a: missing ~a" type name))))))
    ;; pass-through unknown odd tags (stored under their integer key)
    (loop for (k v) on op by #'cddr
          when (integerp k) do (push (cons k v) records))
    (tlv:encode records)))
