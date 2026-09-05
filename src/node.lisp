;;;; src/node.lisp — a Deposits node: operator of its own ledgers, cosigning
;;;; member of others', and the counterparty wallets talk to.
;;;;
;;;; One NODE holds one protocol key.  For each ledger it knows it keeps a
;;;; RECORD: the folded state, the full update history (what the fixture
;;;; format is: a list of signed updates), and whether it is ours.  Everything
;;;; arrives and leaves through a BUS (in-process for the gate, Nostr relays
;;;; for the devnet), as DEP-04 events built in wire.lisp.
;;;;
;;;; Message flows implemented here, all matching the reference node's request
;;;; and response fields:
;;;;   operator  -> members : cosign_update {sequence_number, cosign_data_hex,
;;;;                          content_hash_hex} ; reply {cosign_signature_hex,
;;;;                          cosigner_pubkey, sequence_number, member_ledger_hash_hex}
;;;;   operator  -> member  : consent_request {operator_pubkey, operator_ledger_id,
;;;;                          ledger_history[], chosen_ruleset, terms...} ; reply
;;;;                          {status CONSENT_GRANTED, consent_signature,
;;;;                          membership_expires, member_response, member_signature}
;;;;   wallet    -> operator: deposit_open, balance_query, transfer_lock,
;;;;                          transfer_complete, onchain_credit (devnet helper)

(defpackage #:cl-deposits.node
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:up #:cl-deposits.update) (#:op #:cl-deposits.operation)
                    (#:lg #:cl-deposits.ledger) (#:d17 #:cl-deposits.dep17)
                    (#:rs #:cl-deposits.reserves) (#:w #:cl-deposits.wire)
                    (#:bus #:cl-deposits.bus) (#:ev #:cl-nostr.event) (#:flt #:cl-nostr.filter)
                    (#:k #:cl-nostr.keys) (#:tlv #:cl-deposits.tlv)
                    (#:schnorr #:secp256k1-fast.schnorr))
  (:export #:node #:make-node #:node-pubkey #:node-pubkey-hex #:node-ledgers #:node-log
           #:record #:record-ledger #:record-history #:record-owned-p #:record-id-hex #:record-reserves
           #:find-record #:own-ledger
           #:open-ledger #:append-operation #:add-member #:prepare-quorum #:begin-quorum #:credit-onchain
           #:node-chain-fn #:node-min-confs #:node-data-dir #:record-pinned #:height #:tip
           #:node-error #:request #:wallet #:make-wallet #:wallet-pubkey #:wallet-request
           #:wallet-open-deposit #:wallet-balance #:wallet-transfer #:wallet-complete-transfer
           #:save-record #:load-record #:*cosign-timeout*))
(in-package #:cl-deposits.node)

(define-condition node-error (error)
  ((detail :initarg :detail :reader detail))
  (:report (lambda (c s) (format s "node: ~a" (detail c)))))
(defun fail (fmt &rest args) (error 'node-error :detail (apply #'format nil fmt args)))

(defparameter *cosign-timeout* 10 "Seconds to wait for a cosignature quorum.")

(defstruct record
  id-hex ledger (history '()) owned-p reserves
  pinned)                                      ; (reserves . expiry) prepared for the next QuorumBegin

(defstruct (node (:constructor %make-node))
  priv pubkey pubkey-hex keypair bus network
  (ledgers (make-hash-table :test #'equal))    ; ledger id hex -> record
  (pending (make-hash-table :test #'equal))    ; request event id -> waiter
  (lock (bt:make-lock "node"))
  (height-fn (lambda () 0))
  (log '())
  data-dir
  (inbox '()) (inbox-lock (bt:make-lock "inbox")) (inbox-cv (bt:make-condition-variable)) (worker nil)
  (chain-fn nil)                               ; (lambda (txid vout)) -> plist :value-sats :confirmations, or NIL
  (min-confs 1)
  (member-ledger-hex nil))                     ; our own ledger used for QuorumJoin / member_ledger_hash

(defun log! (node fmt &rest args)
  (push (apply #'format nil fmt args) (node-log node)))

(defun make-node (&key priv bus (network "signet") height-fn data-dir chain-fn (min-confs 1))
  (let* ((priv (w:even-y-privkey priv))
         (pub (up:compressed-pubkey priv))
         (node (%make-node :priv priv :pubkey pub :pubkey-hex (bytes->hex pub)
                           :keypair (w:nostr-keypair priv) :bus bus :network network
                           :height-fn (or height-fn (lambda () 0)) :data-dir data-dir
                           :chain-fn chain-fn :min-confs min-confs)))
    ;; On a real relay, events arrive on the reader thread.  Responses are
    ;; consumed inline (they only wake a waiter); requests and updates go to a
    ;; worker, because handling a request may itself wait for responses.
    (when (bus:bus-async-p bus)
      (setf (node-worker node)
            (bt:make-thread (lambda () (worker-loop node)) :name "cld-worker")))
    (bus:bus-subscribe bus (flt:make-filter :kinds (list w:+kind-update+ w:+kind-request+ w:+kind-response+))
                       (lambda (event)
                         (if (and (node-worker node) (/= (ev:event-kind event) w:+kind-response+))
                             (enqueue node event)
                             (handle-event node event))))
    node))

(defun enqueue (node event)
  (bt:with-lock-held ((node-inbox-lock node))
    (setf (node-inbox node) (append (node-inbox node) (list event)))
    (bt:condition-notify (node-inbox-cv node))))

(defun worker-loop (node)
  (loop
    (let ((event (bt:with-lock-held ((node-inbox-lock node))
                   (loop until (node-inbox node) do (bt:condition-wait (node-inbox-cv node) (node-inbox-lock node)))
                   (pop (node-inbox node)))))
      (handle-event node event))))

(defun height (node) (funcall (node-height-fn node)))
(defun find-record (node id-hex) (gethash id-hex (node-ledgers node)))
(defun own-ledger (node) (and (node-member-ledger-hex node) (find-record node (node-member-ledger-hex node))))
(defun tip (rec) (car (record-history rec)))
(defun x-hex (pubkey33) (bytes->hex (up:x-only pubkey33)))

;;; ---------------------------------------------------------------------------
;;; Waiting for responses

(defstruct waiter (lock (bt:make-lock)) (cv (bt:make-condition-variable)) (responses '()) (done nil) want)

(defun wait-for (node request-id want &key (timeout *cosign-timeout*))
  "Block until WANT responses (or DONE) for REQUEST-ID, or TIMEOUT.  Returns the responses."
  (let ((wt (gethash request-id (node-pending node))))
    (bt:with-lock-held ((waiter-lock wt))
      (loop with deadline = (+ (get-internal-real-time) (* timeout internal-time-units-per-second))
            until (or (waiter-done wt) (>= (length (waiter-responses wt)) want)
                      (> (get-internal-real-time) deadline))
            do (bt:condition-wait (waiter-cv wt) (waiter-lock wt) :timeout 0.2)))
    (remhash request-id (node-pending node))
    (reverse (waiter-responses wt))))

(defun send-request (node ledger-id-hex action params &key (want 1) (timeout *cosign-timeout*) extra-tags)
  "Publish a Kind 20101 request and collect WANT Kind 20102 responses."
  (let ((event (w:request-event (node-keypair node) ledger-id-hex action params :extra-tags extra-tags)))
    (setf (gethash (ev:event-id event) (node-pending node)) (make-waiter :want want))
    (bus:bus-publish (node-bus node) event)
    (wait-for node (ev:event-id event) want :timeout timeout)))

(defun respond (node request success &key result error)
  (bus:bus-publish (node-bus node)
                   (w:response-event (node-keypair node) (ev:event-id request) (w:event-ledger-id request) success
                                     :result result :error error)))

;;; ---------------------------------------------------------------------------
;;; Building and publishing our own updates

(defun new-update (node rec op &key (height (height node)))
  (let ((t0 (tip rec)))
    (up:make-signed-update :operator-id (node-pubkey node) :ledger-id (hex->bytes (record-id-hex rec))
                           :seq (if t0 (1+ (up:update-seq t0)) 0)
                           :prev-hash (if t0 (up:chain-hash t0) (make-array 32 :element-type '(unsigned-byte 8)))
                           :message (op:encode-operation op) :block-height height)))

(defun commit-update (node rec update)
  "Operator-sign, apply, record, publish, persist.  The update's cosignatures
   must already be in place."
  (up:sign-operator update (node-priv node))
  (lg:apply-update (record-ledger rec) update)       ; signals ledger-error if invalid
  (push update (record-history rec))
  (bus:bus-publish (node-bus node) (w:update-event (node-keypair node) update))
  (save-record node rec)
  update)

(defun solicit-cosignatures (node rec update signers required)
  "Ask the quorum; return when REQUIRED valid cosignatures are in the update."
  (let* ((params (w:json-object "sequence_number" (up:update-seq update)
                                "cosign_data_hex" (bytes->hex (up::cosign-data update))
                                "content_hash_hex" (bytes->hex (up:content-hash update))
                                "message_type" 32769))
         (responses (send-request node (record-id-hex rec) "cosign_update" params :want required)))
    (dolist (r responses)
      (let ((res (w:jget r "result")))
        (when (and (w:jget r "success") res)
          (let* ((pk (hex->bytes (w:jget res "cosigner_pubkey")))
                 (c (up:make-cosignature :pubkey pk
                                         :signature (hex->bytes (w:jget res "cosign_signature_hex"))
                                         :member-ledger-hash (hex->bytes (w:jget res "member_ledger_hash_hex")))))
            (when (and (member pk signers :key #'lg:member-pubkey :test #'equalp)
                       (up:verify-cosignature update c)
                       (not (member pk (up:update-cosignatures update) :key #'up:cosig-pubkey :test #'equalp)))
              (push c (up:update-cosignatures update)))))))
    (when (< (length (up:update-cosignatures update)) required)
      (fail "only ~a of ~a cosignatures for seq ~a" (length (up:update-cosignatures update)) required (up:update-seq update)))
    update))

(defun append-operation (node rec op &key (height (height node)))
  "The operator's one entry point: chain OP onto REC's ledger with whatever
   cosignatures DEP-05 requires at HEIGHT."
  (unless (record-owned-p rec) (fail "not our ledger"))
  ;; Would it apply?  Check on a replay before asking anyone to cosign it.
  (lg:apply-operation (lg:replay (reverse (record-history rec))) op)
  (let ((update (new-update node rec op :height height)))
    (multiple-value-bind (required signers tier operator-alone allowed)
        (lg:cosign-requirement (record-ledger rec) op height)
      (declare (ignore operator-alone))
      (unless allowed (fail "~a not cosignable at ~a" (op:operation-type op) tier))
      (when (plusp required) (solicit-cosignatures node rec update signers required)))
    (commit-update node rec update)))

(defun open-ledger (node &key reserves-id (genesis-block (height node)) (reserves 0) (collateral 0))
  "Genesis: LedgerOpen at sequence 0.  Returns the record."
  (let* ((id (op:compute-ledger-id (node-pubkey node) reserves-id genesis-block))
         (rec (make-record :id-hex (bytes->hex id) :ledger (lg:make-ledger) :owned-p t)))
    (setf (gethash (record-id-hex rec) (node-ledgers node)) rec)
    (unless (node-member-ledger-hex node) (setf (node-member-ledger-hex node) (record-id-hex rec)))
    (commit-update node rec (new-update node rec (list :type :ledger-open :operator-id (node-pubkey node)
                                                       :reserves-id reserves-id :genesis-block genesis-block
                                                       :reserves-amount reserves :collateral-amount collateral)))
    rec))

;;; ---------------------------------------------------------------------------
;;; Quorum formation (operator side)

(defun member-terms->plist (res)
  (list :min-fee-bps (w:jget res "min_fee_bps") :min-fee-fixed (w:jget res "min_fee_fixed")
        :max-fee-period (w:jget res "max_fee_period") :membership-until (w:jget res "membership_expires")))

(defun add-member (node rec member-pubkey &key (membership-blocks 4320) (ruleset "cltv-offset-v2") (min-fee-bps 0) (min-fee-fixed 0) (max-fee-period 2016))
  "Ask MEMBER-PUBKEY to join REC's quorum; on consent, stage them with QuorumAddMember."
  (let* ((until (+ (height node) membership-blocks))
         (params (w:json-object "operator_pubkey" (node-pubkey-hex node) "operator_ledger_id" (record-id-hex rec)
                                "ledger_history" (coerce (mapcar (lambda (u) (base64-encode (up:encode-update u)))
                                                                 (reverse (record-history rec))) 'vector)
                                "chosen_ruleset" ruleset "min_fee_bps" min-fee-bps "min_fee_fixed" min-fee-fixed
                                "max_fee_period" max-fee-period "membership_until" until))
         (responses (send-request node (record-id-hex rec) "consent_request" params
                                  :extra-tags (list (list "p" (x-hex member-pubkey)))))
         (r (find-if (lambda (r) (equal (gethash "responder" r) (x-hex member-pubkey))) responses)))
    (unless (and r (w:jget r "success")) (fail "member ~a did not consent" (subseq (bytes->hex member-pubkey) 0 8)))
    (let* ((res (w:jget r "result"))
           (consent (hex->bytes (w:jget res "consent_signature"))))
      ;; The consent covers sha256("COLLATERAL_CONSENT" || operator pubkey || ledger id hex).
      (unless (schnorr:schnorr-verify (up:x-only member-pubkey)
                                      (sha256 (cat (ascii->bytes "COLLATERAL_CONSENT") (node-pubkey node)
                                                   (ascii->bytes (record-id-hex rec))))
                                      consent)
        (fail "bad consent signature"))
      (append-operation node rec
                        (%strip-nil-fields
                                (list :type :quorum-add-member :quorum-member member-pubkey
                                      :quorum-member-signature consent
                                      :member-ledger-id (w:jget res "member_ledger_id")
                                      :min-fee-bps min-fee-bps :min-fee-fixed min-fee-fixed :max-fee-period max-fee-period
                                      :membership-until (w:jget res "membership_expires")
                                      :member-response (let ((b (w:jget res "member_response"))) (and b (base64-decode b)))
                                      :member-signature (let ((h (w:jget res "member_signature"))) (and h (hex->bytes h)))))))))

(defun %strip-nil-fields (plist)
  (loop for (k v) on plist by #'cddr when v append (list k v)))

(defun prepare-quorum (node rec &key (ruleset "cltv-offset-v2") (expiry-blocks 4320))
  "Build (and pin) the reserves output the next QuorumBegin will point at, so
   it can be funded on chain first.  Returns the reserves."
  (let* ((staged (lg:ledger-next-quorum-members (record-ledger rec)))
         (expiry (+ (height node) expiry-blocks))
         (reserves (rs:build-reserves :operator (node-pubkey node) :members (mapcar #'lg:member-pubkey staged)
                                      :ledger-hash (up:chain-hash (tip rec)) :quorum-expiry expiry
                                      :ruleset ruleset :network (intern (string-upcase (node-network node)) :keyword))))
    (when (null staged) (fail "no staged members"))
    (setf (record-pinned rec) (cons reserves expiry))
    reserves))

(defun begin-quorum (node rec &key funding-txid funding-vout amount-msats collateral-msats
                                   (ruleset "cltv-offset-v2") (expiry-blocks 4320) (spending-txid funding-txid))
  "Promote the staged members: chain a QuorumBegin pointing at the on-chain
   outpoint funding the reserves output prepared by PREPARE-QUORUM (or built
   now).  Returns (values update reserves)."
  (let* ((ledger (record-ledger rec))
         (staged (lg:ledger-next-quorum-members ledger))
         (members (mapcar #'lg:member-pubkey staged))
         (pinned (or (record-pinned rec) (progn (prepare-quorum node rec :ruleset ruleset :expiry-blocks expiry-blocks)
                                                 (record-pinned rec))))
         (reserves (car pinned)) (expiry (cdr pinned)))
    (unless (equalp (rs:reserves-ledger-hash reserves) (up:chain-hash (tip rec)))
      (fail "ledger moved since the reserves were prepared; prepare again"))
    (let* ((op (list :type :quorum-begin :reserves-id (rs:reserves-address reserves)
                   :spending-txid spending-txid :new-outpoint-txid funding-txid :new-outpoint-vout funding-vout
                   :amount amount-msats :quorum-expiry expiry :ledger-hash (up:chain-hash (tip rec))
                   :quorum-members members :collateral-amount collateral-msats
                   :quorum-member-ledger-ids (mapcar #'lg:member-ledger-id staged)
                   :protocol-version ruleset))
           (update (append-operation node rec op)))
      (setf (record-reserves rec) reserves (record-pinned rec) nil)
      (values update reserves))))

(defun credit-onchain (node rec deposit-id amount-msats &key txid (vout 0) (funding-address ""))
  (append-operation node rec (list :type :onchain-credit :txid txid :vout vout :deposit-id deposit-id
                                   :amount amount-msats :funding-address funding-address)))

;;; ---------------------------------------------------------------------------
;;; Inbound: dispatch

(defun handle-event (node event)
  (handler-case
      (case (ev:event-kind event)
        (#.w:+kind-response+ (handle-response node event))
        (#.w:+kind-request+ (unless (string= (ev:event-pubkey event) (k:public-hex (node-keypair node)))
                              (handle-request node event)))
        (#.w:+kind-update+ (unless (string= (ev:event-pubkey event) (k:public-hex (node-keypair node)))
                             (handle-update node event))))
    (error (e) (log! node "event ~a: ~a" (subseq (ev:event-id event) 0 8) e))))

(defun handle-response (node event)
  (let ((wt (gethash (w:event-request-id event) (node-pending node))))
    (when wt
      (bt:with-lock-held ((waiter-lock wt))
        (push (w:parse-json (ev:event-content event)) (waiter-responses wt))
        ;; carry the responder's pubkey alongside
        (setf (gethash "responder" (car (waiter-responses wt))) (ev:event-pubkey event))
        (bt:condition-notify (waiter-cv wt))))))

(defun handle-request (node event)
  (let ((action (w:event-action event)) (params (w:parse-json (ev:event-content event))))
    (cond ((string= action "cosign_update") (handle-cosign node event params))
          ((string= action "consent_request") (handle-consent node event params))
          (t (let ((rec (find-record node (w:event-ledger-id event))))
               (when (and rec (record-owned-p rec))
                 (handle-wallet-request node rec event action params)))))))

;;; ---------------------------------------------------------------------------
;;; Inbound: another operator's published update (we replicate ledgers we cosign)

(defun handle-update (node event)
  (let* ((update (w:event->update event))
         (rec (find-record node (bytes->hex (up:update-ledger-id update)))))
    (when (and rec (not (record-owned-p rec)))
      (accept-update node rec update))))

(defun accept-update (node rec update)
  "Validate an operator's update against our replica and apply it."
  (let ((ledger (record-ledger rec)) (op (op:decode-operation (up:update-message update))))
    (unless (up:verify-operator-signature update) (fail "bad operator signature at seq ~a" (up:update-seq update)))
    (when (<= (up:update-seq update) (lg:ledger-sequence ledger)) (return-from accept-update :echo))
    (multiple-value-bind (required signers tier operator-alone allowed)
        (lg:cosign-requirement ledger op (up:update-block-height update))
      (declare (ignore tier operator-alone))
      (unless allowed (fail "uncosignable operation at seq ~a" (up:update-seq update)))
      (when (plusp required)
        (multiple-value-bind (ok why)
            (up:verify-cosignatures update :quorum (mapcar #'lg:member-pubkey signers) :threshold required)
          (unless ok (fail "seq ~a: ~a" (up:update-seq update) why)))))
    (lg:apply-update ledger update)
    (push update (record-history rec))
    (save-record node rec)
    :applied))

;;; ---------------------------------------------------------------------------
;;; Inbound: cosign_update (we are a quorum member of this ledger)

(defun member-ledger-hash (node)
  "The content hash of our own ledger's latest update — what we vouch with."
  (let ((own (own-ledger node)))
    (if (and own (tip own)) (up:content-hash (tip own)) (make-array 32 :element-type '(unsigned-byte 8)))))

(defun handle-cosign (node event params)
  (let* ((rec (find-record node (w:event-ledger-id event)))
         (data (hex->bytes (w:jget params "cosign_data_hex")))
         (seq (w:jget params "sequence_number")))
    (cond
      ((or (null rec) (record-owned-p rec)) nil)      ; not a ledger we replicate
      ((< (length data) 40) (respond node event nil :error "malformed cosign_data"))
      (t
       (let* ((ledger (record-ledger rec))
              (prev (subseq data 8 40)) (message (subseq data 40))
              (candidate (up:make-signed-update :operator-id (lg:ledger-operator-key ledger)
                                                :ledger-id (hex->bytes (record-id-hex rec))
                                                :seq seq :prev-hash prev :message message)))
         (handler-case
             (progn
               (unless (= seq (1+ (lg:ledger-sequence ledger)))
                 (fail "expected seq ~a" (1+ (lg:ledger-sequence ledger))))
               (unless (equalp prev (lg:ledger-chain-tip ledger)) (fail "chain mismatch: not our tip"))
               (let ((o (op:decode-operation message)))
                 ;; Speculative apply on a fresh replica: the op must be valid on our state.
                 (lg:apply-operation (lg:replay (reverse (record-history rec))) o)
                 (multiple-value-bind (required signers tier operator-alone allowed)
                     (lg:cosign-requirement ledger o (height node))
                   (declare (ignore required signers tier operator-alone))
                   (unless allowed (fail "not cosignable at this height")))
                 (when (eq (op:operation-type o) :quorum-begin) (check-reserves-outpoint node o)))
               (let* ((mlh (member-ledger-hash node))
                      (c (up:sign-cosignature candidate (node-priv node) (node-pubkey node) mlh)))
                 (log! node "cosigned ~a seq ~a" (subseq (record-id-hex rec) 0 8) seq)
                 (respond node event t
                          :result (w:json-object "cosign_signature_hex" (bytes->hex (up:cosig-signature c))
                                                 "cosigner_pubkey" (node-pubkey-hex node)
                                                 "sequence_number" seq
                                                 "member_ledger_hash_hex" (bytes->hex mlh)))))
           (error (e) (log! node "refused cosign seq ~a: ~a" seq e)
             (respond node event nil :error (princ-to-string e)))))))))

;;; ---------------------------------------------------------------------------
;;; Inbound: consent_request (an operator wants us in their quorum)

(defun handle-consent (node event params)
  ;; Addressed to one member: the p tag names them.
  (let ((to (ev:first-tag-value event "p")))
    (unless (and to (string= to (k:public-hex (node-keypair node))))
      (return-from handle-consent nil)))
  (let* ((their-id (w:jget params "operator_ledger_id"))
         (operator (hex->bytes (w:jget params "operator_pubkey")))
         (history (map 'list (lambda (b64) (up:decode-update (base64-decode b64))) (w:jget params "ledger_history"))))
    (unless (own-ledger node) (return-from handle-consent (respond node event nil :error "no ledger of our own")))
    (handler-case
        (let ((rec (or (find-record node their-id) (make-record :id-hex their-id :ledger (lg:make-ledger)))))
          ;; Bootstrap / catch up the replica from the piggybacked history.
          (dolist (u history)
            (when (> (up:update-seq u) (lg:ledger-sequence (record-ledger rec)))
              (accept-update node rec u)))
          (unless (equalp (lg:ledger-operator-key (record-ledger rec)) operator) (fail "history is not this operator's"))
          (setf (gethash their-id (node-ledgers node)) rec)
          (let* ((until (w:jget params "membership_until"))
                 (consent (schnorr:schnorr-sign (node-priv node)
                                                (sha256 (cat (ascii->bytes "COLLATERAL_CONSENT") operator (ascii->bytes their-id)))
                                                (random-aux)))
                 (blob (member-response-blob node operator their-id (w:jget params "chosen_ruleset") until params))
                 (blob-sig (schnorr:schnorr-sign (node-priv node) (tagged-hash "deposits/quorum-member-response/v1" blob) (random-aux))))
            ;; Record the membership on OUR ledger.
            (append-operation node (own-ledger node)
                              (list :type :quorum-join :operator-id operator :ledger-id their-id :membership-expires until))
            (respond node event t
                     :result (w:json-object "status" "CONSENT_GRANTED" "consent_signature" (bytes->hex consent)
                                            "membership_expires" until "member_ledger_id" (node-member-ledger-hex node)
                                            "member_response" (base64-encode blob) "member_signature" (bytes->hex blob-sig)))))
      (error (e) (log! node "refused consent: ~a" e) (respond node event nil :error (princ-to-string e))))))

(defun check-reserves-outpoint (node o)
  "DEP-03: a cosigner verifies the QuorumBegin outpoint against its own chain
   view — exists, unspent, value = (reserves + collateral)/1000 sats, confirmed."
  (when (node-chain-fn node)
    (let* ((info (funcall (node-chain-fn node) (op:field o :new-outpoint-txid) (op:field o :new-outpoint-vout)))
           (want (floor (+ (op:field o :amount) (op:field o :collateral-amount)) 1000)))
      (unless info (fail "reserves outpoint not found or spent"))
      (unless (= (getf info :value-sats) want) (fail "reserves outpoint value ~a != ~a" (getf info :value-sats) want))
      (unless (>= (getf info :confirmations) (node-min-confs node)) (fail "reserves outpoint has ~a confirmations" (getf info :confirmations))))))

(defun random-aux ()
  "32 bytes from the OS.  CL's RANDOM is deterministic in a fresh image — three
   daemons once started with the same key because of it."
  (with-open-file (in "/dev/urandom" :element-type '(unsigned-byte 8))
    (let ((a (make-array 32 :element-type '(unsigned-byte 8)))) (read-sequence a in) a)))

(defun member-response-blob (node operator their-id ruleset until params)
  "QuorumMemberResponse TLV (deposits-protocol/src/types/quorum_member_response.rs)."
  (tlv:encode
   (remove nil
           (list (cons 1 (int->be 1 2)) (cons 2 (node-pubkey node)) (cons 3 operator)
                 (cons 4 (ascii->bytes their-id)) (cons 5 (ascii->bytes (or ruleset "cltv-offset-v2")))
                 (cons 6 (ascii->bytes (node-member-ledger-hex node)))
                 (cons 7 (apply #'cat (mapcar (lambda (s) (cat (octets (length s)) (ascii->bytes s)))
                                              '("legacy" "cltv-offset-literal" "cltv-offset-v2" "fee-cap-v3" "balance-commit-v4"))))
                 (let ((v (w:jget params "min_fee_bps"))) (and v (cons 10 (int->be v 2))))
                 (let ((v (w:jget params "min_fee_fixed"))) (and v (cons 11 (int->be v 8))))
                 (let ((v (w:jget params "max_fee_period"))) (and v (cons 12 (int->be v 4))))
                 (and until (cons 13 (int->be until 4)))))))

;;; ---------------------------------------------------------------------------
;;; Inbound: wallet requests (we are the operator)

(defun handle-wallet-request (node rec event action params)
  (handler-case
      (cond
        ((string= action "deposit_open")
         (let* ((descriptor (w:jget params "descriptor"))
                (id (op:deposit-id descriptor)))
           (append-operation node rec (list :type :deposit-open :deposit-id id :descriptor descriptor
                                            :fees (op:make-fees :annualized-msats (or (w:jget params "annualized_msats") 0)
                                                                :annualized-bps (or (w:jget params "annualized_bps") 0)
                                                                :frequency-blocks (or (w:jget params "frequency_blocks") 2016))
                                            :receive-requires-sig nil))
           (respond node event t :result (w:json-object "deposit_id" (bytes->hex id)))))
        ((string= action "balance_query")
         (let ((d (lg:find-deposit (record-ledger rec) (hex->bytes (w:jget params "deposit_id")))))
           (respond node event t :result (w:json-object "balance_msats" (lg:deposit-balance d)
                                                        "locked_msats" (lg:deposit-locked-balance d)
                                                        "sequence" (lg:ledger-sequence (record-ledger rec))))))
        ((string= action "transfer_lock")
         (let* ((o (op:decode-operation (base64-decode (w:jget params "operation"))))
                (src (lg:find-deposit (record-ledger rec) (op:field o :source-deposit-id))))
           (unless (eq (op:operation-type o) :transfer-lock) (fail "not a TransferLock"))
           (unless (eq :ok (d17:verify-operation-witness o (lg:deposit-descriptor src) (op:field o :witness)))
             (fail "witness does not authorize this operation"))
           (when (> (height node) (op:field o :expiry)) (fail "operation expired"))
           (when (member (cons (op:field o :nonce) (op:field o :expiry)) (lg:deposit-seen-nonces src) :test #'equal)
             (fail "nonce replayed"))
           (append-operation node rec o)
           (respond node event t :result (w:json-object "transfer_id" (bytes->hex (op:field o :transfer-id))))))
        ((string= action "transfer_complete")
         (let* ((o (op:decode-operation (base64-decode (w:jget params "operation"))))
                (pending (gethash (op:field o :transfer-id) (lg:ledger-pending-transfers (record-ledger rec)))))
           (unless pending (fail "no such transfer"))
           (let* ((script (getf pending :completion-script))
                  (h (and (search "sha256(" script) (hex->bytes (subseq script 7 (position #\) script)))))
                  (wit (op:field o :script-witness)))
             (unless (and h wit (= 1 (length wit)) (equalp (sha256 (first wit)) h)) (fail "hashlock not satisfied")))
           (append-operation node rec o)
           (respond node event t :result (w:json-object "transfer_id" (bytes->hex (op:field o :transfer-id))))))
        (t (respond node event nil :error (format nil "unknown action ~a" action))))
    (error (e) (respond node event nil :error (princ-to-string e)))))

;;; ---------------------------------------------------------------------------
;;; Wallet: a key, a bus, and the requests it can make

(defstruct (wallet (:constructor %make-wallet)) priv pubkey keypair bus (pending (make-hash-table :test #'equal)) (nonce 0))

(defun make-wallet (&key priv bus)
  (let* ((priv (w:even-y-privkey priv))
         (wal (%make-wallet :priv priv :pubkey (up:compressed-pubkey priv) :keypair (w:nostr-keypair priv) :bus bus)))
    (bus:bus-subscribe bus (flt:make-filter :kinds (list w:+kind-response+))
                       (lambda (event)
                         (let ((wt (gethash (w:event-request-id event) (wallet-pending wal))))
                           (when wt (bt:with-lock-held ((waiter-lock wt))
                                      (push (w:parse-json (ev:event-content event)) (waiter-responses wt))
                                      (bt:condition-notify (waiter-cv wt)))))))
    wal))

(defun wallet-request (wal ledger-id-hex action params &key (timeout *cosign-timeout*))
  "Send a request; return (values success result error)."
  (let* ((event (w:request-event (wallet-keypair wal) ledger-id-hex action params))
         (wt (make-waiter :want 1)))
    (setf (gethash (ev:event-id event) (wallet-pending wal)) wt)
    (bus:bus-publish (wallet-bus wal) event)
    (bt:with-lock-held ((waiter-lock wt))
      (loop with deadline = (+ (get-internal-real-time) (* timeout internal-time-units-per-second))
            until (or (waiter-responses wt) (> (get-internal-real-time) deadline))
            do (bt:condition-wait (waiter-cv wt) (waiter-lock wt) :timeout 0.2)))
    (remhash (ev:event-id event) (wallet-pending wal))
    (let ((r (first (waiter-responses wt))))
      (if r (values (w:jget r "success") (w:jget r "result") (w:jget r "error")) (values nil nil "timeout")))))

(defun wallet-descriptor (wal) (format nil "pk(~a)" (bytes->hex (wallet-pubkey wal))))

(defun wallet-open-deposit (wal ledger-id-hex)
  (multiple-value-bind (ok res err) (wallet-request wal ledger-id-hex "deposit_open" (w:json-object "descriptor" (wallet-descriptor wal)))
    (unless ok (fail "deposit_open: ~a" err))
    (hex->bytes (w:jget res "deposit_id"))))

(defun wallet-balance (wal ledger-id-hex deposit-id)
  (multiple-value-bind (ok res err) (wallet-request wal ledger-id-hex "balance_query" (w:json-object "deposit_id" (bytes->hex deposit-id)))
    (unless ok (fail "balance_query: ~a" err))
    (values (w:jget res "balance_msats") (w:jget res "locked_msats"))))

(defun wallet-transfer (wal ledger-id-hex from to amount-msats &key (fee 0) preimage (timeout-blocks 144) (height 0))
  "Lock AMOUNT from deposit FROM to deposit TO behind sha256(PREIMAGE).  Returns (values transfer-id preimage)."
  (let* ((preimage (or preimage (random-aux)))
         (transfer-nonce (random-aux))
         (transfer-id (sha256 (cat transfer-nonce from to)))
         (o (list :type :transfer-lock :transfer-nonce transfer-nonce :source-deposit-id from :destination-deposit-id to
                  :amount amount-msats :fee fee :completion-script (format nil "sha256(~a)" (bytes->hex (sha256 preimage)))
                  :timeout-height (+ height timeout-blocks) :transfer-id transfer-id
                  :nonce (incf (wallet-nonce wal)) :expiry (+ height 144) :witness '())))
    (setf (getf o :witness) (d17:sign-operation o (wallet-priv wal)))
    (multiple-value-bind (ok res err)
        (wallet-request wal ledger-id-hex "transfer_lock" (w:json-object "operation" (base64-encode (op:encode-operation o))))
      (declare (ignore res))
      (unless ok (fail "transfer_lock: ~a" err))
      (values transfer-id preimage))))

(defun wallet-complete-transfer (wal ledger-id-hex transfer-id preimage)
  (let ((o (list :type :transfer-complete :transfer-id transfer-id :script-witness (list preimage))))
    (multiple-value-bind (ok res err)
        (wallet-request wal ledger-id-hex "transfer_complete" (w:json-object "operation" (base64-encode (op:encode-operation o))))
      (declare (ignore res))
      (unless ok (fail "transfer_complete: ~a" err))
      t)))

;;; ---------------------------------------------------------------------------
;;; Persistence: the fixture format — a JSON array of base64 updates, oldest first.

(defun save-record (node rec)
  (when (node-data-dir node)
    (ensure-directories-exist (node-data-dir node))
    (with-open-file (out (merge-pathnames (format nil "ledger_~a.json" (subseq (record-id-hex rec) 0 16)) (node-data-dir node))
                         :direction :output :if-exists :supersede)
      (format out "[~{~s~^,~%~}]~%" (mapcar (lambda (u) (base64-encode (up:encode-update u))) (reverse (record-history rec)))))))

(defun load-record (node path &key owned-p)
  "Rebuild a record from a saved (or fixture) file, validating as we go."
  (let* ((text (with-open-file (in path) (let ((s (make-string (file-length in)))) (subseq s 0 (read-sequence s in)))))
         (updates (loop with pos = 0
                        for start = (position #\" text :start pos) while start
                        collect (let ((end (position #\" text :start (1+ start))))
                                  (setf pos (1+ end))
                                  (up:decode-update (base64-decode (subseq text (1+ start) end))))))
         (first (first updates))
         (rec (make-record :id-hex (bytes->hex (up:update-ledger-id first)) :ledger (lg:make-ledger) :owned-p owned-p)))
    (dolist (u updates)
      (if owned-p
          (progn (lg:apply-update (record-ledger rec) u) (push u (record-history rec)))
          (accept-update node rec u)))
    (setf (gethash (record-id-hex rec) (node-ledgers node)) rec)
    rec))
