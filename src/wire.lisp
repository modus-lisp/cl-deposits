;;;; src/wire.lisp — DEP-04 events: how ledger data rides on Nostr.
;;;;
;;;; Kind 9100  ledger update    content = base64(SignedLedgerUpdate TLV)
;;;;                             tags d=<ledger_id hex[0..16]> n=<seq> t=<disc> i=<deposit id>...
;;;; Kind 20101 request          content = JSON params; tags l=<ledger_id hex> action=<name>
;;;; Kind 20102 response         content = JSON {success,result,error}; tags e=<request id> l=<ledger_id>
;;;; Kind 39100 advertisement    content = JSON; tags d=<ledger_id hex> n=<network> o=<operator pubkey>
;;;;
;;;; Only construction and parsing live here; nothing touches a socket.

(defpackage #:cl-deposits.wire
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:up #:cl-deposits.update) (#:op #:cl-deposits.operation)
                    (#:ev #:cl-nostr.event) (#:k #:cl-nostr.keys) (#:jzon #:com.inuoe.jzon))
  (:export #:+kind-update+ #:+kind-request+ #:+kind-response+ #:+kind-advertisement+
           #:+kind-fraud-proof+ #:+kind-lottery-reveal+ #:fraud-event #:reveal-event #:reveal-message
           #:event-member #:event-d-tag
           #:nostr-keypair #:update-event #:event->update #:ledger-tag
           #:request-event #:response-event #:advertisement-event
           #:event-action #:event-ledger-id #:event-request-id #:parse-json #:json
           #:jget #:json-object #:affected-deposit-ids #:hex-of #:even-y-privkey))
(in-package #:cl-deposits.wire)

(defconstant +kind-update+ 9100)
(defconstant +kind-request+ 20101)
(defconstant +kind-response+ 20102)
(defconstant +kind-advertisement+ 39100)
(defconstant +kind-fraud-proof+ 9101)
(defconstant +kind-lottery-reveal+ 9106)

;;; ---------------------------------------------------------------------------
;;; Keys.  A node's protocol key is also its Nostr key.  Nostr sees only the
;;; x coordinate, and the reference rebuilds a compressed key from it with an
;;; 02 prefix — so protocol keys must have even Y to be one identity on both
;;; layers.  EVEN-Y-PRIVKEY negates a private key whose public Y is odd.

(defun even-y-privkey (priv)
  (secp256k1-fast:secp-init)
  (let ((pt (secp256k1-fast:secp-pubkey priv)))
    (if (evenp (secp256k1-fast:secp-y pt)) priv (- secp256k1-fast:*secp256k1-n* priv))))

(defun nostr-keypair (priv) (k:keypair-from-secret (int->be priv 32)))

(defun hex-of (bytes) (bytes->hex bytes))

;;; ---------------------------------------------------------------------------
;;; JSON helpers (jzon: objects are hash tables with string keys).

(defun json-object (&rest kvs)
  "(json-object \"a\" 1 \"b\" \"x\") -> hash table.  NIL values are omitted."
  (let ((ht (make-hash-table :test #'equal)))
    (loop for (key value) on kvs by #'cddr
          when value do (setf (gethash key ht) value))
    ht))

(defun json (object) (jzon:stringify object))
(defun parse-json (string) (jzon:parse string))
(defun jget (object &rest keys)
  (let ((o object))
    (dolist (key keys o)
      (setf o (and (hash-table-p o) (gethash key o))))))

;;; ---------------------------------------------------------------------------
;;; Kind 9100

(defun ledger-tag (ledger-id) (subseq (bytes->hex ledger-id) 0 16))

(defun affected-deposit-ids (o)
  (remove nil (list (op:field o :deposit-id) (op:field o :source-deposit-id) (op:field o :destination-deposit-id))))

(defun update-event (keypair update &key created-at)
  (let* ((o (op:decode-operation (up:update-message update)))
         (tags (append (list (list "d" (ledger-tag (up:update-ledger-id update)))
                             (list "n" (princ-to-string (up:update-seq update)))
                             (list "t" (princ-to-string (op:discriminant (op:operation-type o)))))
                       (mapcar (lambda (id) (list "i" (bytes->hex id))) (affected-deposit-ids o))
                       (when (eq (op:operation-type o) :invoice-credit)
                         (list (list "payment_hash" (bytes->hex (op:field o :payment-hash))))))))
    (ev:build-event keypair +kind-update+ (base64-encode (up:encode-update update))
                    :tags tags :created-at (or created-at (ev::now)))))

(defun event->update (event)
  "Decode a Kind 9100 event's content; the caller verifies signatures."
  (up:decode-update (base64-decode (ev:event-content event))))

;;; ---------------------------------------------------------------------------
;;; Kinds 20101 / 20102

(defun request-event (keypair ledger-id-hex action params &key (extra-tags '()))
  (ev:build-event keypair +kind-request+ (json params)
                  :tags (append (list (list "l" ledger-id-hex) (list "action" action)) extra-tags)))

(defun response-event (keypair request-id ledger-id-hex success &key result error)
  (let ((body (json-object "result" result "error" error)))
    (setf (gethash "success" body) (and success t))   ; jzon: T -> true, NIL -> false
    (ev:build-event keypair +kind-response+ (json body)
                    :tags (list (list "e" request-id) (list "l" ledger-id-hex)))))

(defun event-action (event) (ev:first-tag-value event "action"))
(defun event-ledger-id (event) (ev:first-tag-value event "l"))
(defun event-request-id (event) (ev:first-tag-value event "e"))

;;; ---------------------------------------------------------------------------
;;; Kind 39100

(defun advertisement-event (keypair ad &key (network "signet"))
  "AD is a hash table (json-object) with at least ledger_id and operator_pubkey."
  (ev:build-event keypair +kind-advertisement+ (json ad)
                  :tags (list (list "d" (gethash "ledger_id" ad)) (list "n" network)
                              (list "o" (gethash "operator_pubkey" ad)))))

;;; ---------------------------------------------------------------------------
;;; Kind 9101 (fraud broadcast, JSON) and Kind 9106 (custody lottery reveal)

(defun fraud-event (keypair ledger-id-hex accused-hex broadcast-json)
  (ev:build-event keypair +kind-fraud-proof+ (json broadcast-json)
                  :tags (list (list "d" (subseq ledger-id-hex 0 16)) (list "p" (subseq accused-hex 2)))))

(defun reveal-message (ledger-id-hex preimage)
  "sha256(\"CustodyLotteryReveal:\" || ledger_id_hex || 0x00 || preimage)"
  (sha256 (cat (ascii->bytes "CustodyLotteryReveal:") (ascii->bytes ledger-id-hex) (octets 0) preimage)))

(defun reveal-event (keypair member-pubkey-hex ledger-id-hex preimage signature64)
  (ev:build-event keypair +kind-lottery-reveal+
                  (json (json-object "member_pubkey" member-pubkey-hex "ledger_id" ledger-id-hex
                                     "preimage_hex" (bytes->hex preimage) "signature" (bytes->hex signature64)))
                  :tags (list (list "l" ledger-id-hex) (list "member" member-pubkey-hex))))

(defun event-member (event) (ev:first-tag-value event "member"))
(defun event-d-tag (event) (ev:first-tag-value event "d"))
