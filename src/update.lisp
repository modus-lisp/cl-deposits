;;;; src/update.lisp — DEP-02 SignedLedgerUpdate.
;;;;
;;;; The unit of a ledger: one operation, sequenced and chained to its
;;;; predecessor by hash, cosigned by quorum members, then signed by the
;;;; operator.  This file knows nothing about what the operation MEANS — only
;;;; its bytes, its place in the chain, and who vouched for it.
;;;;
;;;; Hash chain (verified byte-for-byte against the reference implementation's
;;;; audit fixture, inspect/vectors/ledger_57f60e1dbef339e2.json):
;;;;
;;;;   content_hash = SHA256(seq_le8 || prev_hash || message
;;;;                         || for each cosignature, sorted by pubkey:
;;;;                              member_ledger_hash || cosign_signature)
;;;;   chain_hash   = SHA256(content_hash || operator_signature)
;;;;
;;;; and the next update's prev_hash is this one's chain_hash.  Note the
;;;; consequence: the cosignature SET is part of the chain.  An operator who
;;;; republishes an update with more cosignatures has not changed its
;;;; successor's prev_hash — the successor chains to whichever set the operator
;;;; hashed at publish time — so a verifier must resolve prev_hash against the
;;;; copy it actually chains to, not "the latest copy of sequence n".

(defpackage #:cl-deposits.update
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:tlv #:cl-deposits.tlv) (#:secp #:secp256k1-fast.schnorr)
                    (#:ec #:secp256k1-fast))
  (:export #:signed-update #:make-signed-update #:signed-update-p
           #:update-operator-id #:update-ledger-id #:update-seq #:update-prev-hash
           #:update-message #:update-block-height #:update-block-hash
           #:update-operator-sig #:update-cosignatures
           #:cosignature #:make-cosignature #:cosig-pubkey #:cosig-signature
           #:cosig-member-ledger-hash
           #:decode-update #:encode-update #:sorted-cosignatures
           #:content-hash #:chain-hash
           #:cosign-digest #:operator-digest
           #:verify-operator-signature #:verify-cosignature #:verify-cosignatures
           #:x-only #:compressed-pubkey #:sign-cosignature #:sign-operator
           #:+cosign-tag+ #:+operator-tag+ #:encode-cosignatures-for-test))
(in-package #:cl-deposits.update)

;;; Outer TLV tags (DEP-02 §Signed Update Format).
(defconstant +t-operator-id+ 0)
(defconstant +t-ledger-id+ 2)
(defconstant +t-seq+ 4)
(defconstant +t-prev-hash+ 6)
(defconstant +t-message+ 8)
(defconstant +t-block-height+ 10)
(defconstant +t-block-hash+ 12)
(defconstant +t-cosigner-pubkey+ 14)     ; legacy single cosigner
(defconstant +t-member-ledger-hash+ 16)  ; legacy
(defconstant +t-cosign-signature+ 18)    ; legacy
(defconstant +t-operator-signature+ 20)
(defconstant +t-cosignatures+ 22)

(defparameter +cosign-tag+ "deposits/cosign/v1")
(defparameter +operator-tag+ "deposits/operator-update/v1")

(defstruct (cosignature (:conc-name cosig-))
  (pubkey nil :type (or null octets))             ; 33-byte compressed
  (signature nil :type (or null octets))          ; 64-byte BIP-340
  (member-ledger-hash nil :type (or null octets))) ; 32: the member's own ledger tip

(defstruct (signed-update (:conc-name update-))
  operator-id ledger-id (seq 0) prev-hash message
  (block-height 0) block-hash
  operator-sig
  (cosignatures '()))

(defun x-only (pubkey33) (subseq pubkey33 1 33))

(defun compressed-pubkey (privkey-int)
  "33-byte SEC compressed public key: 02/03 by y parity, then x."
  (ec:secp-init)
  (let ((pt (ec:secp-pubkey privkey-int)))
    (cat (octets (if (evenp (ec:secp-y pt)) 2 3)) (int->be (ec:secp-x pt) 32))))

(defun sorted-cosignatures (update)
  (sort (copy-list (update-cosignatures update)) #'bytes< :key #'cosig-pubkey))

;;; ---------------------------------------------------------------------------
;;; Wire

(defun %expect (bytes len what)
  (unless (and bytes (= (length bytes) len))
    (error 'tlv:tlv-error :detail (format nil "~a must be ~a bytes" what len)))
  bytes)

(defun decode-cosignatures (bytes)
  "Tag 22: a sequence of (u16 BE entry_len=129 || pubkey33 || sig64 || member_ledger_hash32)."
  (let ((pos 0) (out '()))
    (loop while (< pos (length bytes))
          do (let ((len (be->int bytes :start pos :end (+ pos 2))))
               (unless (= len 129)
                 (error 'tlv:tlv-error :detail (format nil "cosignature entry length ~a" len)))
               (when (> (+ pos 2 len) (length bytes))
                 (error 'tlv:tlv-error :detail "truncated cosignature list"))
               (let ((e (+ pos 2)))
                 (push (make-cosignature :pubkey (subseq bytes e (+ e 33))
                                         :signature (subseq bytes (+ e 33) (+ e 97))
                                         :member-ledger-hash (subseq bytes (+ e 97) (+ e 129)))
                       out))
               (incf pos (+ 2 len))))
    (nreverse out)))

(defun encode-cosignatures-for-test (u) (encode-cosignatures (sorted-cosignatures u)))

(defun encode-cosignatures (cosigs)
  (apply #'cat (loop for c in cosigs
                     collect (cat (int->be 129 2) (cosig-pubkey c) (cosig-signature c)
                                  (cosig-member-ledger-hash c)))))

(defun decode-update (bytes)
  (let* ((a (tlv:decode bytes))
         (f (lambda (type) (tlv:field a type)))
         (cosigs (funcall f +t-cosignatures+))
         (legacy-sig (funcall f +t-cosign-signature+)))
    (make-signed-update
     :operator-id (%expect (funcall f +t-operator-id+) 33 "operator_id")
     :ledger-id (%expect (funcall f +t-ledger-id+) 32 "ledger_id")
     :seq (be->int (%expect (funcall f +t-seq+) 8 "sequence_number"))
     :prev-hash (%expect (funcall f +t-prev-hash+) 32 "previous_hash")
     :message (or (funcall f +t-message+) (error 'tlv:tlv-error :detail "no message"))
     :block-height (let ((h (funcall f +t-block-height+))) (if h (be->int (%expect h 4 "block_height")) 0))
     :block-hash (let ((h (funcall f +t-block-hash+))) (if h (%expect h 32 "block_hash") (make-array 32 :element-type '(unsigned-byte 8))))
     :operator-sig (%expect (funcall f +t-operator-signature+) 64 "operator_signature")
     :cosignatures (cond (cosigs (decode-cosignatures cosigs))
                         ((and legacy-sig (not (zero-bytes-p legacy-sig)))
                          (list (make-cosignature
                                 :pubkey (funcall f +t-cosigner-pubkey+)
                                 :signature legacy-sig
                                 :member-ledger-hash (or (funcall f +t-member-ledger-hash+)
                                                         (make-array 32 :element-type '(unsigned-byte 8))))))
                         (t '())))))

(defun encode-update (u)
  "The canonical bytes, as the reference encoder writes them: block fields
   omitted when zero, cosignatures under tag 22 sorted by pubkey."
  (tlv:encode
   (append
    (list (cons +t-operator-id+ (update-operator-id u))
          (cons +t-ledger-id+ (update-ledger-id u))
          (cons +t-seq+ (int->be (update-seq u) 8))
          (cons +t-prev-hash+ (update-prev-hash u))
          (cons +t-message+ (update-message u)))
    (unless (zerop (update-block-height u))
      (list (cons +t-block-height+ (int->be (update-block-height u) 4))))
    (unless (or (null (update-block-hash u)) (zero-bytes-p (update-block-hash u)))
      (list (cons +t-block-hash+ (update-block-hash u))))
    (when (update-operator-sig u)
      (list (cons +t-operator-signature+ (update-operator-sig u))))
    (when (update-cosignatures u)
      (list (cons +t-cosignatures+ (encode-cosignatures (sorted-cosignatures u))))))))

;;; ---------------------------------------------------------------------------
;;; Hash chain

(defun content-hash (u)
  (sha256 (apply #'cat (int->le (update-seq u) 8) (update-prev-hash u) (update-message u)
                 (loop for c in (sorted-cosignatures u)
                       collect (cat (cosig-member-ledger-hash c) (cosig-signature c))))))

(defun chain-hash (u)
  "What the NEXT update's prev_hash must equal."
  (sha256 (cat (content-hash u) (update-operator-sig u))))

;;; ---------------------------------------------------------------------------
;;; Signing digests
;;;
;;; Two generations exist in the wild.  v1 is the canonical one going forward:
;;; a tagged hash with a length-prefixed message.  The legacy forms are what
;;; older reference nodes signed; verification accepts them, signing never
;;; produces them.

(defun cosign-data (u)
  (cat (int->le (update-seq u) 8) (update-prev-hash u) (update-message u)))

(defun cosign-digest (u member-ledger-hash &key (version :v1))
  (ecase version
    (:v1 (tagged-hash +cosign-tag+
                      (int->le (update-seq u) 8) (update-prev-hash u)
                      (int->le (length (update-message u)) 4) (update-message u)
                      member-ledger-hash))
    (:legacy (tagged-hash "deposits/cosign" (cosign-data u) member-ledger-hash))))

(defun operator-digest (u &key (version :v1))
  (let ((sigs (mapcar #'cosig-signature (sorted-cosignatures u))))
    (ecase version
      (:v1 (apply #'tagged-hash +operator-tag+
                  (int->le (update-seq u) 8) (update-prev-hash u)
                  (int->le (length (update-message u)) 4) (update-message u)
                  (int->le (length sigs) 2) sigs))
      ;; Legacy A: SHA256(cosign_data || each cosign signature)
      (:legacy-a (sha256 (apply #'cat (cosign-data u)
                                (or sigs (list (make-array 64 :element-type '(unsigned-byte 8)))))))
      ;; Legacy B: pre-c57d7e0d genesis form, SHA256(seq_le || prev || content_hash || message)
      (:legacy-b (sha256 (cat (int->le (update-seq u) 8) (update-prev-hash u)
                              (content-hash u) (update-message u)))))))

(defun verify-operator-signature (u)
  "The digest version the operator's signature verifies under, or NIL."
  (let ((pk (x-only (update-operator-id u))) (sig (update-operator-sig u)))
    (loop for v in '(:v1 :legacy-a :legacy-b)
          when (secp:schnorr-verify pk (operator-digest u :version v) sig)
            return v)))

(defun verify-cosignature (u cosig)
  "The digest version this cosignature verifies under, or NIL."
  (let ((pk (x-only (cosig-pubkey cosig))))
    (loop for v in '(:v1 :legacy)
          when (secp:schnorr-verify pk (cosign-digest u (cosig-member-ledger-hash cosig) :version v)
                                    (cosig-signature cosig))
            return v)))

(defun verify-cosignatures (u &key quorum (threshold 0))
  "Every cosignature must verify, come from a distinct pubkey, and (when QUORUM
   is given) belong to it.  Returns (values ok-p reason)."
  (let ((seen '()))
    (dolist (c (update-cosignatures u))
      (when (member (cosig-pubkey c) seen :test #'equalp)
        (return-from verify-cosignatures (values nil "duplicate cosigner")))
      (push (cosig-pubkey c) seen)
      (when (and quorum (not (member (cosig-pubkey c) quorum :test #'equalp)))
        (return-from verify-cosignatures (values nil "cosigner not in quorum")))
      (unless (verify-cosignature u c)
        (return-from verify-cosignatures (values nil "bad cosignature"))))
    (if (< (length seen) threshold)
        (values nil (format nil "~a of ~a cosignatures" (length seen) threshold))
        (values t nil))))

;;; ---------------------------------------------------------------------------
;;; Signing (v1 only)

(defun sign-cosignature (u privkey-int pubkey33 member-ledger-hash &key aux)
  (make-cosignature :pubkey pubkey33
                    :signature (secp:schnorr-sign privkey-int (cosign-digest u member-ledger-hash)
                                                  (or aux (make-array 32 :element-type '(unsigned-byte 8))))
                    :member-ledger-hash member-ledger-hash))

(defun sign-operator (u privkey-int &key aux)
  "Sets and returns the operator signature over the update's cosignatures as they stand."
  (setf (update-operator-sig u)
        (secp:schnorr-sign privkey-int (operator-digest u)
                           (or aux (make-array 32 :element-type '(unsigned-byte 8))))))
