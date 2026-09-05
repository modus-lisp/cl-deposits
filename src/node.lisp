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
                    (#:k #:cl-nostr.keys) (#:tlv #:cl-deposits.tlv) (#:ln #:cl-deposits.lightning)
                    (#:fr #:cl-deposits.fraud) (#:lot #:cl-deposits.lottery) (#:rot #:cl-deposits.rotation)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire)
                    (#:schnorr #:secp256k1-fast.schnorr))
  (:export #:node #:make-node #:node-pubkey #:node-pubkey-hex #:node-ledgers #:node-log
           #:record #:record-ledger #:record-history #:record-owned-p #:record-id-hex #:record-reserves
           #:find-record #:own-ledger
           #:open-ledger #:append-operation #:add-member #:prepare-quorum #:begin-quorum #:credit-onchain
           #:node-chain-fn #:node-min-confs #:node-data-dir #:record-pinned #:height #:tip
           #:node-error #:request #:wallet #:make-wallet #:wallet-pubkey #:wallet-request
           #:wallet-open-deposit #:wallet-balance #:wallet-transfer #:wallet-complete-transfer
           #:wallet-make-invoice #:credit-paid-invoices #:start-invoice-poller #:node-ln #:node-invoices
           #:enter-dispute #:arm-dispute #:fork-key #:find-fork #:forks-of #:armers-of #:disputed-reserves
           #:build-confiscation #:confiscate #:publish-reveal #:reveals-of #:claim-or-yield #:node-broadcast-fn
           #:node-broadcasts #:broadcast-fraud #:record-fork-p #:record-preimage #:record-lottery #:record-confiscation
           #:node-height-of-block #:equivocate
           #:save-record #:load-record #:*cosign-timeout*))
(in-package #:cl-deposits.node)

(define-condition node-error (error)
  ((detail :initarg :detail :reader detail))
  (:report (lambda (c s) (format s "node: ~a" (detail c)))))
(defun fail (fmt &rest args) (error 'node-error :detail (apply #'format nil fmt args)))

(defparameter *cosign-timeout* 10 "Seconds to wait for a cosignature quorum.")

(defstruct record
  id-hex ledger (history '()) owned-p reserves
  pinned                                       ; (reserves . expiry) prepared for the next QuorumBegin
  fork-p fork-of fork-operator                 ; a dispute fork: of which ledger, signed by whom
  preimage lottery confiscation)               ; our lottery secret; the built lottery; the confiscation tx

(defstruct (node (:constructor %make-node))
  priv pubkey pubkey-hex keypair bus network
  (ledgers (make-hash-table :test #'equal))    ; ledger id hex -> record
  (pending (make-hash-table :test #'equal))    ; request event id -> waiter
  (lock (bt:make-lock "node"))
  (height-fn (lambda () 0))
  (log '())
  data-dir
  (inbox '()) (inbox-lock (bt:make-lock "inbox")) (inbox-cv (bt:make-condition-variable)) (worker nil)
  (ln nil)                                     ; a cl-deposits.lightning backend, or NIL
  (broadcast-fn nil)                           ; (lambda (tx-bytes)) -> txid or NIL; NIL = collect only
  (broadcasts '())                             ; what we would have broadcast (newest first)
  (height-of-block nil)                        ; (lambda (hash32)) -> height or NIL (fraud-proof anchors)
  (reveals (make-hash-table :test #'equal))    ; ledger id hex -> alist (member-pubkey33 . preimage)
  (relays '())                                 ; relay URLs, for advertisements
  (invoices (make-hash-table :test #'equalp))  ; payment hash -> plist (:rec :deposit-id :amount :bolt11)
  (chain-fn nil)                               ; (lambda (txid vout)) -> plist :value-sats :confirmations, or NIL
  (min-confs 1)
  (member-ledger-hex nil))                     ; our own ledger used for QuorumJoin / member_ledger_hash

(defun log! (node fmt &rest args)
  ;; One line per entry: the control socket is line-oriented.
  (push (substitute #\Space #\Newline (apply #'format nil fmt args)) (node-log node)))

(defun make-node (&key priv bus (network "signet") height-fn data-dir chain-fn (min-confs 1) ln relays broadcast-fn height-of-block)
  (let* ((priv (w:even-y-privkey priv))
         (pub (up:compressed-pubkey priv))
         (node (%make-node :priv priv :pubkey pub :pubkey-hex (bytes->hex pub)
                           :keypair (w:nostr-keypair priv) :bus bus :network network
                           :height-fn (or height-fn (lambda () 0)) :data-dir data-dir
                           :chain-fn chain-fn :min-confs min-confs :ln ln :relays relays
                           :broadcast-fn broadcast-fn :height-of-block height-of-block)))
    ;; On a real relay, events arrive on the reader thread.  Responses are
    ;; consumed inline (they only wake a waiter); requests and updates go to a
    ;; worker, because handling a request may itself wait for responses.
    (when (bus:bus-async-p bus)
      (setf (node-worker node)
            (bt:make-thread (lambda () (worker-loop node)) :name "cld-worker")))
    (bus:bus-subscribe bus (flt:make-filter :kinds (list w:+kind-update+ w:+kind-request+ w:+kind-response+
                                                        w:+kind-fraud-proof+ w:+kind-lottery-reveal+))
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

(defun add-member (node rec member-pubkey &key member-ledger-id (membership-blocks 4320) (ruleset "cltv-offset-v2") (min-fee-bps 0) (min-fee-fixed 0) (max-fee-period 2016))
  "Ask MEMBER-PUBKEY to join REC's quorum; on consent, stage them with QuorumAddMember.
   The request is addressed (tag l) to MEMBER-LEDGER-ID — the member's own ledger —
   as the reference does; its nodes only answer requests for ledgers they operate."
  (let* ((until (+ (height node) membership-blocks))
         (params (w:json-object "operator_pubkey" (node-pubkey-hex node) "operator_ledger_id" (record-id-hex rec)
                                "ledger_history" (coerce (mapcar (lambda (u) (base64-encode (up:encode-update u)))
                                                                 (reverse (record-history rec))) 'vector)
                                "chosen_ruleset" ruleset "min_fee_bps" min-fee-bps "min_fee_fixed" min-fee-fixed
                                "max_fee_period" max-fee-period "membership_until" until))
         (responses (send-request node (or member-ledger-id (record-id-hex rec)) "consent_request" params
                                  :extra-tags (list (list "p" (x-hex member-pubkey)))))
         (consent-ok (lambda (r)
                       ;; The reference signs Nostr events with a per-host delegate key, so
                       ;; the event pubkey says nothing; the consent signature does.
                       (let ((res (w:jget r "result")))
                         (and (w:jget r "success") res (w:jget res "consent_signature")
                              (schnorr:schnorr-verify (up:x-only member-pubkey)
                                                      (sha256 (cat (ascii->bytes "COLLATERAL_CONSENT") (node-pubkey node)
                                                                   (ascii->bytes (record-id-hex rec))))
                                                      (hex->bytes (w:jget res "consent_signature")))))))
         (r (find-if consent-ok responses)))
    (unless r (fail "member ~a did not consent" (subseq (bytes->hex member-pubkey) 0 8)))
    (let* ((res (w:jget r "result"))
           (consent (hex->bytes (w:jget res "consent_signature"))))
      (append-operation node rec
                        (%strip-nil-fields
                                (list :type :quorum-add-member :quorum-member member-pubkey
                                      :quorum-member-signature consent
                                      :member-ledger-id (or (w:jget res "member_ledger_id") member-ledger-id "")
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
         ;; DEP-05: quorum_expiry is the shortest member commitment.
         (commitments (remove nil (mapcar #'lg:member-membership-until staged)))
         (expiry (reduce #'min commitments :initial-value (+ (height node) expiry-blocks)))
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
                             (handle-update node event)))
        (#.w:+kind-fraud-proof+ (handle-fraud node event))
        (#.w:+kind-lottery-reveal+ (handle-reveal node event)))
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
          ((string= action "confiscation_sign") (handle-confiscation-sign node event params))
          ((string= action "consent_request") (handle-consent node event params))
          ((string= action "cosign_invoice") (handle-cosign-invoice node event params))
          (t (let ((rec (find-record node (w:event-ledger-id event))))
               (when (and rec (record-owned-p rec))
                 (handle-wallet-request node rec event action params)))))))

;;; ---------------------------------------------------------------------------
;;; Inbound: another operator's published update (we replicate ledgers we cosign)

(defun handle-update (node event)
  (let* ((update (w:event->update event))
         (id (bytes->hex (up:update-ledger-id update)))
         (rec (find-record node id))
         (signer (up:update-operator-id update)))
    (when rec
      (cond
        ;; The operator's own chain.
        ((and (not (record-owned-p rec)) (equalp signer (lg:ledger-operator-key (record-ledger rec))))
         (accept-update node rec update))
        ;; A quorum member's dispute fork (or its continuation).
        ((not (equalp signer (node-pubkey node)))
         (let ((fork (find-fork node id signer))
               (o (op:decode-operation (up:update-message update))))
           (cond (fork (accept-update node fork update))
                 ((and (eq (op:operation-type o) :dispute-enter)
                       (member signer (lg:ledger-quorum-members (record-ledger rec)) :key #'lg:member-pubkey :test #'equalp))
                  (let ((fork (make-fork node rec (op:field o :last-valid-sequence) signer)))
                    (accept-update node fork update)
                    (log! node "fork of ~a by ~a at seq ~a" (subseq id 0 8) (subseq (bytes->hex signer) 0 8) (op:field o :last-valid-sequence)))))))))))

(defun accept-update (node rec update)
  "Validate an operator's update against our replica and apply it."
  (let ((ledger (record-ledger rec)) (op (op:decode-operation (up:update-message update))))
    (unless (up:verify-operator-signature update) (fail "bad operator signature at seq ~a" (up:update-seq update)))
    (when (and (record-fork-p rec) (not (equalp (up:update-operator-id update) (record-fork-operator rec))))
      (fail "fork update not signed by the fork's operator"))
    (when (<= (up:update-seq update) (lg:ledger-sequence ledger))
      ;; Same sequence, different content, validly signed by the operator: equivocation.
      (let ((ours (find (up:update-seq update) (record-history rec) :key #'up:update-seq)))
        (when (and ours (not (record-fork-p rec))
                   (not (equalp (up:content-hash ours) (up:content-hash update)))
                   (member (node-pubkey node) (lg:ledger-quorum-members ledger) :key #'lg:member-pubkey :test #'equalp))
          (log! node "EQUIVOCATION on ~a at seq ~a" (subseq (record-id-hex rec) 0 8) (up:update-seq update))
          (broadcast-fraud node (fr:make-equivocation-proof (up:update-operator-id update) (up:update-ledger-id update) ours update))))
      (return-from accept-update :echo))
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
  ;; For us if the l tag names a ledger we operate (the reference's addressing),
  ;; or the p tag names our key.
  (let* ((to (ev:first-tag-value event "p"))
         (l (w:event-ledger-id event))
         (ours (and l (find-record node l))))
    (unless (or (and ours (record-owned-p ours))
                (and to (string= to (k:public-hex (node-keypair node)))))
      (return-from handle-consent nil))
    (when (and ours (record-owned-p ours)) (setf (node-member-ledger-hex node) l)))
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
          (let* ((until (let ((u (w:jget params "membership_until"))) (if (integerp u) u (+ (height node) 4320))))
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
    (let* ((info (funcall (node-chain-fn node) (op:field o :new-outpoint-txid) (op:field o :new-outpoint-vout)))   ; internal-order bytes
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
                 (and (integerp until) (cons 13 (int->be until 4)))))))

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
         (let ((d (lg:find-deposit (record-ledger rec) (deposit-id-param params))))
           (respond node event t :result (w:json-object "deposit_id" (bytes->hex (lg:deposit-id d))
                                                        "balance_msats" (lg:deposit-balance d)
                                                        "locked_msats" (lg:deposit-locked-balance d)
                                                        "available_msats" (lg:deposit-available-balance d)
                                                        "balance" (lg:deposit-balance d)
                                                        "locked_balance" (lg:deposit-locked-balance d)
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
        ((string= action "make_invoice") (handle-make-invoice node rec event params))
        (t (respond node event nil :error (format nil "unknown action ~a" action))))
    (error (e) (respond node event nil :error (princ-to-string e)))))

;;; ---------------------------------------------------------------------------
;;; Lightning: make_invoice (operator), cosign_invoice (member), crediting

(defun tip-content-hash (rec)
  (if (tip rec) (up:content-hash (tip rec)) (make-array 32 :element-type '(unsigned-byte 8))))

(defun deposit-id-param (params)
  "Wallets name a deposit by id or by descriptor (the reference wallet sends the descriptor)."
  (cond ((w:jget params "deposit_id") (hex->bytes (w:jget params "deposit_id")))
        ((w:jget params "descriptor") (op:deposit-id (w:jget params "descriptor")))
        (t (fail "deposit_id or descriptor required"))))

(defun handle-make-invoice (node rec event params)
  (unless (node-ln node) (fail "no lightning node"))
  (let* ((amount (or (w:jget params "amount_msats") (let ((s (w:jget params "amount_sats"))) (and s (* 1000 s)))
                     (fail "amount_msats required")))
         (deposit-id (deposit-id-param params))
         (ledger (record-ledger rec)))
    (lg:find-deposit ledger deposit-id)
    (unless (<= (+ (lg:total-obligations ledger) amount) (lg:ledger-reserves-amount ledger))
      (fail "invoice would exceed reserves"))
    (multiple-value-bind (bolt11 hash) (ln:ln-make-invoice (node-ln node) amount (w:jget params "description"))
      (setf (gethash hash (node-invoices node)) (list :rec rec :deposit-id deposit-id :amount amount :bolt11 bolt11))
      (let* ((operator-hash (tip-content-hash rec))
             (operator-sig (schnorr:schnorr-sign (node-priv node)
                                                 (ln:invoice-cosign-message (record-id-hex rec) hash deposit-id amount operator-hash)
                                                 (random-aux)))
             (result (w:json-object "invoice" bolt11 "amount_msat" amount "amount_sats" (floor amount 1000)
                                    "deposit_id" (bytes->hex deposit-id) "payment_hash" (bytes->hex hash)
                                    "operator_pubkey" (node-pubkey-hex node)
                                    "operator_ledger_hash" (bytes->hex operator-hash)
                                    "operator_signature" (bytes->hex operator-sig))))
        (when (eq (lg:ledger-quorum-state ledger) :active)
          (let* ((members (lg:ledger-quorum-members ledger))
                 (responses (send-request node (record-id-hex rec) "cosign_invoice"
                                          (w:json-object "payment_hash" (bytes->hex hash) "deposit_id" (bytes->hex deposit-id)
                                                         "amount_msat" amount "invoice" bolt11)))
                 (good (find-if (lambda (r)
                                  (let ((res (w:jget r "result")))
                                    (and (w:jget r "success") res
                                         (let ((pk (hex->bytes (w:jget res "cosigner_pubkey"))))
                                           (and (member pk members :key #'lg:member-pubkey :test #'equalp)
                                                (schnorr:schnorr-verify
                                                 (up:x-only pk)
                                                 (ln:invoice-cosign-message (record-id-hex rec) hash deposit-id amount
                                                                            (hex->bytes (w:jget res "cosigner_ledger_hash")))
                                                 (hex->bytes (w:jget res "cosign_signature"))))))))
                                responses)))
            (unless good (fail "no quorum member cosigned the invoice"))
            (let ((res (w:jget good "result")))
              (setf (gethash "cosign_required" result) t
                    (gethash "cosigner_pubkey" result) (w:jget res "cosigner_pubkey")
                    (gethash "cosigner_ledger_hash" result) (w:jget res "cosigner_ledger_hash")
                    (gethash "cosign_signature" result) (w:jget res "cosign_signature")))))
        (respond node event t :result result)))))

(defun handle-cosign-invoice (node event params)
  (let ((rec (find-record node (w:event-ledger-id event))))
    (when (and rec (not (record-owned-p rec)))
      (handler-case
          (let* ((hash (hex->bytes (w:jget params "payment_hash")))
                 (deposit-id (hex->bytes (w:jget params "deposit_id")))
                 (amount (w:jget params "amount_msat"))
                 (ledger (record-ledger rec)))
            (lg:find-deposit ledger deposit-id)
            (unless (<= (+ (lg:total-obligations ledger) amount) (lg:ledger-reserves-amount ledger))
              (fail "invoice would exceed reserves"))
            (let* ((mlh (member-ledger-hash node))
                   (sig (schnorr:schnorr-sign (node-priv node)
                                              (ln:invoice-cosign-message (record-id-hex rec) hash deposit-id amount mlh)
                                              (random-aux))))
              (respond node event t :result (w:json-object "cosign_signature" (bytes->hex sig)
                                                           "cosigner_pubkey" (node-pubkey-hex node)
                                                           "cosigner_ledger_hash" (bytes->hex mlh)))))
        (error (e) (respond node event nil :error (princ-to-string e)))))))

(defun credit-paid-invoices (node)
  "Ask the Lightning node about every outstanding invoice; credit the paid ones.
   Returns the payment hashes credited."
  (let ((credited '()))
    (when (node-ln node)
      (loop for hash being the hash-keys of (node-invoices node) using (hash-value inv)
            when (eq :paid (ln:ln-invoice-status (node-ln node) hash))
              do (handler-case
                     (let ((rec (getf inv :rec)))
                       (append-operation node rec
                                         (list :type :invoice-credit :payment-hash hash :deposit-id (getf inv :deposit-id)
                                               :amount (getf inv :amount)
                                               :invoice-id (format nil "bolt11:~a" (subseq (getf inv :bolt11) 0 (min 32 (length (getf inv :bolt11)))))
                                               :sequence-number (1+ (lg:ledger-sequence (record-ledger rec)))))
                       (push hash credited)
                       (remhash hash (node-invoices node)))
                   (error (e) (log! node "credit ~a: ~a" (subseq (bytes->hex hash) 0 8) e)))))
    credited))

(defun start-invoice-poller (node &key (interval 3))
  (bt:make-thread (lambda () (loop (sleep interval) (ignore-errors (credit-paid-invoices node)))) :name "cld-invoices"))

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

;;; Wallet: receive over Lightning

(defun wallet-make-invoice (wal ledger-id-hex deposit-id amount-msat &key description operator-pubkey)
  "Ask the operator for an invoice; verify the attestation signatures it and a
   cosigner put on (ledger, payment hash, deposit, amount).  Returns
   (values bolt11 payment-hash attestation)."
  (multiple-value-bind (ok res err)
      (wallet-request wal ledger-id-hex "make_invoice"
                      (w:json-object "amount_msats" amount-msat "deposit_id" (bytes->hex deposit-id) "description" description))
    (unless ok (fail "make_invoice: ~a" err))
    (let* ((hash (hex->bytes (w:jget res "payment_hash")))
           (op-pk (hex->bytes (w:jget res "operator_pubkey"))))
      (when (and operator-pubkey (not (equalp op-pk operator-pubkey))) (fail "invoice attested by the wrong operator"))
      (unless (= (w:jget res "amount_msat") amount-msat) (fail "amount mismatch"))
      (unless (schnorr:schnorr-verify (up:x-only op-pk)
                                      (ln:invoice-cosign-message ledger-id-hex hash deposit-id amount-msat
                                                                 (hex->bytes (w:jget res "operator_ledger_hash")))
                                      (hex->bytes (w:jget res "operator_signature")))
        (fail "operator invoice attestation does not verify"))
      (when (w:jget res "cosign_signature")
        (unless (schnorr:schnorr-verify (up:x-only (hex->bytes (w:jget res "cosigner_pubkey")))
                                        (ln:invoice-cosign-message ledger-id-hex hash deposit-id amount-msat
                                                                   (hex->bytes (w:jget res "cosigner_ledger_hash")))
                                        (hex->bytes (w:jget res "cosign_signature")))
          (fail "cosigner invoice attestation does not verify")))
      (values (w:jget res "invoice") hash res))))

;;; ---------------------------------------------------------------------------
;;; Disputes (DEP-06): forks, arming, confiscation, reveal, claim

(defun fork-key (id-hex operator33) (format nil "~a:fork:~a" id-hex (subseq (bytes->hex operator33) 0 16)))
(defun find-fork (node id-hex operator33) (gethash (fork-key id-hex operator33) (node-ledgers node)))
(defun forks-of (node id-hex)
  (loop for rec being the hash-values of (node-ledgers node)
        when (and (record-fork-p rec) (string= (record-fork-of rec) id-hex)) collect rec))

(defun make-fork (node rec last-valid-seq operator33)
  "A fork of REC's ledger from LAST-VALID-SEQ, operated by OPERATOR33: the
   truncated history replayed, quorum cleared (the reference does the same,
   so fork operations need no cosignatures)."
  (let* ((history (remove-if (lambda (u) (> (up:update-seq u) last-valid-seq)) (reverse (record-history rec))))
         (ledger (lg:replay history))
         (fork (make-record :id-hex (record-id-hex rec) :ledger ledger :history (reverse history)
                            :owned-p (equalp operator33 (node-pubkey node))
                            :fork-p t :fork-of (record-id-hex rec) :fork-operator operator33)))
    (setf (lg:ledger-quorum-members ledger) '() (lg:ledger-next-quorum-members ledger) '())
    (setf (gethash (fork-key (record-id-hex rec) operator33) (node-ledgers node)) fork)
    fork))

(defun enter-dispute (node rec last-valid-seq &key (reason "fraud") anchor-block-hash anchor-block-height)
  "We are a quorum member of REC's ledger and have grounds: fork it and publish DisputeEnter."
  (let ((fork (or (find-fork node (record-id-hex rec) (node-pubkey node))
                  (make-fork node rec last-valid-seq (node-pubkey node)))))
    (commit-update node fork (new-update node fork (%strip-nil-fields
                                                    (list :type :dispute-enter :last-valid-sequence last-valid-seq :reason reason
                                                          :anchor-block-hash anchor-block-hash :anchor-block-height anchor-block-height))))
    fork))

(defun dispute-lottery-n (rec)
  "N disputants = the latest QuorumBegin's members minus the original operator."
  (length (recovery-voters rec)))

(defun recovery-voters (rec)
  "x-only keys of the latest QuorumBegin's members other than the original operator."
  (let ((operator nil) (members '()))
    (dolist (u (reverse (record-history rec)))
      (let ((o (op:decode-operation (up:update-message u))))
        (case (op:operation-type o)
          (:ledger-open (setf operator (op:field o :operator-id)))
          (:quorum-begin (setf members (op:field o :quorum-members))))))
    (mapcar #'up:x-only (remove operator members :test #'equalp))))

(defun our-target-address (node)
  (cl-consensus.encoding:segwit-encode (rs:hrp-for (intern (string-upcase (node-network node)) :keyword)) 1
                                       (subseq (lot:key-path-spk (up:x-only (node-pubkey node))) 2)))

(defun arm-dispute (node fork &key seed replacement)
  "Commit to our lottery preimage on our fork.  REPLACEMENT is (txid vout sats) or NIL."
  (let* ((n (dispute-lottery-n fork))
         (preimage (lot:derive-preimage (or seed (random-aux)) n)))
    (setf (record-preimage fork) preimage)
    (commit-update node fork (new-update node fork (%strip-nil-fields
                                                    (list :type :dispute-armed :armed-block (height node)
                                                          :commitment-hash (lot:commitment-of preimage)
                                                          :target-reserves (our-target-address node)
                                                          :replacement-collateral-txid (first replacement)
                                                          :replacement-collateral-vout (second replacement)
                                                          :replacement-collateral-amount (third replacement)))))
    preimage))

(defun armers-of (node id-hex)
  "Every DisputeArmed we have seen on any fork of the ledger: (pubkey33 commitment target)."
  (loop for fork in (forks-of node id-hex)
        append (loop for u in (record-history fork)
                     for o = (op:decode-operation (up:update-message u))
                     when (eq (op:operation-type o) :dispute-armed)
                       collect (list (up:update-operator-id u) (op:field o :commitment-hash) (op:field o :target-reserves)))))

(defun disputed-reserves (rec)
  "From the latest QuorumBegin: (values reserves-struct txid vout sats operator33)."
  (let ((operator nil) (qb nil))
    (dolist (u (reverse (record-history rec)))
      (let ((o (op:decode-operation (up:update-message u))))
        (case (op:operation-type o)
          (:ledger-open (setf operator (op:field o :operator-id)))
          (:quorum-begin (setf qb o)))))
    (unless qb (fail "no QuorumBegin"))
    (values (rs:build-reserves :operator operator :members (op:field qb :quorum-members)
                               :ledger-hash (op:field qb :ledger-hash) :quorum-expiry (op:field qb :quorum-expiry)
                               :ruleset (or (op:field qb :protocol-version) "cltv-offset-v2")
                               :network (intern (string-upcase (or (and (string= "bc" (subseq (op:field qb :reserves-id) 0 2)) "mainnet") "signet")) :keyword))
            (op:field qb :new-outpoint-txid) (op:field qb :new-outpoint-vout)
            (floor (+ (op:field qb :amount) (op:field qb :collateral-amount)) 1000)
            operator)))

(defun build-confiscation (node id-hex &key respectful (fee 1000))
  "The confiscation transaction for a disputed ledger, from public state only,
   so every cosigner rebuilds the same one.  Returns (values tx lottery prevouts reserves)."
  (let* ((base (or (find-record node id-hex) (fail "unknown ledger")))
         (armers (sort (copy-list (armers-of node id-hex)) #'bytes< :key #'first))
         (voters (recovery-voters base))
         (threshold (lg:majority-threshold (length voters)))
         (participants (loop for (pk c target) in armers collect (lot:make-participant :pubkey (up:x-only pk) :commitment c :target target)))
         (lottery (lot:build-lottery participants voters threshold :network (intern (string-upcase (node-network node)) :keyword))))
    (when (< (length participants) 2) (fail "fewer than two armers"))
    (multiple-value-bind (reserves txid vout sats operator) (disputed-reserves base)
      (let* ((outs (lot:confiscation-outputs (lot:lottery-spk lottery) sats fee :respectful respectful
                                             :obligations-sats (floor (lg:total-obligations (record-ledger base)) 1000)
                                             :operator-pubkey33 operator))
             (tx (btx:parse-tx (bw:make-reader
                                (btx:serialize-tx
                                 (btx:make-tx :version 2 :locktime 0 :segwit-p t
                                              :inputs (list (btx:make-txin :prev-hash txid :prev-index vout :script (octets) :sequence rot:+sequence-rbf+))
                                              :outputs (loop for (spk . v) in outs collect (btx:make-txout :value v :script spk))
                                              :witnesses (list nil)))))))
        (values tx lottery (vector (cons sats (rs:reserves-spk reserves))) reserves)))))

(defun confiscation-sighash (tx prevouts reserves) (rot:tier-sighash tx 0 prevouts (first (rs:reserves-leaves reserves))))

(defun confiscate (node id-hex &key respectful (fee 1000))
  "Build the confiscation, gather the recovery quorum's tier-0 signatures over
   the relay (confiscation_sign), assemble, and broadcast.  Returns (values tx lottery)."
  (multiple-value-bind (tx lottery prevouts reserves) (build-confiscation node id-hex :respectful respectful :fee fee)
    (let* ((sighash (confiscation-sighash tx prevouts reserves))
           (tier (first (rs:reserves-tiers reserves)))
           (keys (rs:tier-keys tier))
           (ours (schnorr:schnorr-sign (node-priv node) sighash (random-aux)))
           (sigs (list (cons (up:x-only (node-pubkey node)) ours)))
           (responses (send-request node id-hex "confiscation_sign"
                                    (w:json-object "sighash" (bytes->hex sighash) "respectful" (and respectful t) "fee_sats" fee
                                                   "tx_hex" (bytes->hex (btx:serialize-tx tx)))
                                    :want (1- (length (recovery-voters (find-record node id-hex)))) :timeout 20)))
      (dolist (r responses)
        (let ((res (w:jget r "result")))
          (unless (w:jget r "success") (log! node "confiscation_sign refused: ~a" (w:jget r "error")))
          (when (and (w:jget r "success") res)
            (let ((pk (up:x-only (hex->bytes (w:jget res "signer")))) (sig (hex->bytes (w:jget res "signature"))))
              (when (and (member pk keys :test #'equalp) (schnorr:schnorr-verify pk sighash sig)
                         (not (assoc pk sigs :test #'equalp)))
                (push (cons pk sig) sigs))))))
      (when (< (length sigs) (rs:tier-threshold tier)) (fail "only ~a of ~a confiscation signatures" (length sigs) (rs:tier-threshold tier)))
      (let* ((ordered (mapcar (lambda (k) (cdr (assoc k sigs :test #'equalp))) keys))
             (signed (rot:attach-tier-witness tx 0 reserves 0 ordered)))
        (unless (rot:verify-spend signed 0 prevouts) (fail "assembled confiscation does not verify"))
        (broadcast node signed)
        (dolist (fork (forks-of node id-hex)) (setf (record-lottery fork) lottery (record-confiscation fork) signed))
        (values signed lottery)))))

(defun broadcast (node tx)
  (push tx (node-broadcasts node))
  (when (node-broadcast-fn node) (funcall (node-broadcast-fn node) (btx:serialize-tx tx))))

(defun handle-confiscation-sign (node event params)
  "A recovery-quorum member: rebuild the confiscation from public state, sign
   only if the proposer's sighash is exactly ours."
  (let ((id (w:event-ledger-id event)))
    (handler-case
        (progn
          (unless (find-fork node id (node-pubkey node)) (fail "not armed for this dispute"))
          (multiple-value-bind (tx lottery prevouts reserves)
              (build-confiscation node id :respectful (w:jget params "respectful") :fee (w:jget params "fee_sats"))
            (declare (ignore tx))
            (let ((expected (confiscation-sighash (btx:parse-tx (bw:make-reader (hex->bytes (w:jget params "tx_hex")))) prevouts reserves)))
              (unless (equalp expected (hex->bytes (w:jget params "sighash"))) (fail "sighash is not for the confiscation we expect"))
              (dolist (fork (forks-of node id)) (setf (record-lottery fork) lottery))
              (respond node event t :result (w:json-object "signer" (node-pubkey-hex node)
                                                           "signature" (bytes->hex (schnorr:schnorr-sign (node-priv node) expected (random-aux))))))))
      (error (e) (log! node "refused confiscation_sign: ~a" e) (respond node event nil :error (princ-to-string e))))))

(defun publish-reveal (node id-hex)
  (let* ((fork (or (find-fork node id-hex (node-pubkey node)) (fail "no fork")))
         (preimage (or (record-preimage fork) (fail "not armed")))
         (sig (schnorr:schnorr-sign (node-priv node) (w:reveal-message id-hex preimage) (random-aux))))
    (note-reveal node id-hex (node-pubkey node) preimage)
    (bus:bus-publish (node-bus node) (w:reveal-event (node-keypair node) (node-pubkey-hex node) id-hex preimage sig))))

(defun note-reveal (node id-hex member33 preimage)
  (let ((alist (gethash id-hex (node-reveals node))))
    (unless (assoc member33 alist :test #'equalp)
      (setf (gethash id-hex (node-reveals node)) (cons (cons member33 preimage) alist)))))

(defun handle-reveal (node event)
  (let* ((j (w:parse-json (ev:event-content event)))
         (id (w:jget j "ledger_id")) (member (hex->bytes (w:jget j "member_pubkey")))
         (preimage (hex->bytes (w:jget j "preimage_hex"))) (sig (hex->bytes (w:jget j "signature"))))
    (when (and (find-record node id)
               (schnorr:schnorr-verify (up:x-only member) (w:reveal-message id preimage) sig)
               (find (lot:commitment-of preimage) (armers-of node id) :key #'second :test #'equalp))
      (note-reveal node id member preimage))))

(defun reveals-of (node id-hex) (gethash id-hex (node-reveals node)))

(defun claim-or-yield (node id-hex &key confiscation-txid (fee 400))
  "With every preimage in: the script-selected winner claims the lottery output
   and takes custody (DisputeAcquire); everyone else yields.  Returns
   (values :won-or-:yielded claim-tx)."
  (let* ((fork (or (find-fork node id-hex (node-pubkey node)) (fail "no fork")))
         (lottery (or (record-lottery fork) (fail "no lottery built")))
         (participants (lot:lottery-participants lottery))
         (reveals (reveals-of node id-hex))
         (preimages (mapcar (lambda (p) (or (cdr (find (lot:participant-pubkey p) reveals :key (lambda (r) (up:x-only (car r))) :test #'equalp))
                                            (fail "missing a reveal")))
                            participants))
         (winner (lot:calculate-winner preimages))
         (winner-pk (lot:participant-pubkey (nth winner participants))))
    (if (equalp winner-pk (up:x-only (node-pubkey node)))
        (let* ((conf (record-confiscation fork))
               (txid (or confiscation-txid (and conf (btx:tx-txid conf)) (fail "no confiscation tx")))
               (amount (btx:txout-value (first (btx:tx-outputs conf))))
               (target (lot:participant-target (nth winner participants)))
               (spk (multiple-value-bind (witver program)
                        (cl-consensus.encoding:segwit-decode target (rs:hrp-for (intern (string-upcase (node-network node)) :keyword)))
                      (cat (octets (if (zerop witver) 0 (+ #x50 witver)) (length program)) program)))
               (tx (btx:parse-tx (bw:make-reader
                                  (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t
                                                                 :inputs (list (btx:make-txin :prev-hash txid :prev-index 0 :script (octets) :sequence rot:+sequence-rbf+))
                                                                 :outputs (list (btx:make-txout :value (- amount fee) :script spk))
                                                                 :witnesses (list nil))))))
               (prevouts (vector (cons amount (lot:lottery-spk lottery))))
               (sig (schnorr:schnorr-sign (node-priv node) (rot:tier-sighash tx 0 prevouts (first (lot:lottery-leaves lottery))) (random-aux)))
               (signed (btx:parse-tx (bw:make-reader
                                      (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t :inputs (btx:tx-inputs tx) :outputs (btx:tx-outputs tx)
                                                                     :witnesses (list (lot:claim-witness lottery sig preimages))))))))
          (unless (rot:verify-spend signed 0 prevouts) (fail "claim does not verify"))
          (broadcast node signed)
          (commit-update node fork (new-update node fork (list :type :dispute-acquire :new-custodian (node-pubkey node)
                                                               :claim-txid (btx:tx-txid signed) :new-reserves-address target)))
          (values :won signed))
        (progn (commit-update node fork (new-update node fork (list :type :dispute-yield)))
               (values :yielded nil)))))

;;; Testing only: the operator publishes a conflicting update at its current tip
;;; sequence, so members can be seen catching it.

(defun equivocate (node rec)
  (let* ((last (tip rec))
         (o (op:decode-operation (up:update-message last)))
         (u (up:make-signed-update :operator-id (node-pubkey node) :ledger-id (hex->bytes (record-id-hex rec))
                                   :seq (up:update-seq last) :prev-hash (up:update-prev-hash last)
                                   :message (op:encode-operation (append (list :type :onchain-credit :txid (random-aux) :vout 0
                                                                               :deposit-id (or (op:field o :deposit-id) (make-array 16 :element-type '(unsigned-byte 8)))
                                                                               :amount 1 :funding-address "equivocation")))
                                   :block-height (up:update-block-height last))))
    (up:sign-operator u (node-priv node))
    (bus:bus-publish (node-bus node) (w:update-event (node-keypair node) u))
    u))

;;; Fraud broadcasts (Kind 9101): verify, and if we are a member, dispute.

(defun broadcast-fraud (node proof)
  (bus:bus-publish (node-bus node) (w:fraud-event (node-keypair node) (getf proof :ledger-id) (getf proof :accused) (fr:broadcast->json proof))))

(defun handle-fraud (node event)
  (let* ((proof (fr:json->broadcast (w:parse-json (ev:event-content event))))
         (id (getf proof :ledger-id))
         (rec (find-record node id)))
    (when (and rec (not (record-owned-p rec))
               (member (node-pubkey node) (lg:ledger-quorum-members (record-ledger rec)) :key #'lg:member-pubkey :test #'equalp)
               (not (find-fork node id (node-pubkey node))))
      (multiple-value-bind (ok why)
          (fr:verify-proof proof :history (reverse (record-history rec)) :height-of-block (node-height-of-block node))
        (if ok
            (let ((last-valid (min (lg:ledger-sequence (record-ledger rec))
                                   (case (getf proof :type)
                                     ((:equivocation :non-conforming-update) (1- (getf (getf proof :evidence) (if (eq (getf proof :type) :equivocation) :sequence :fault-sequence))))
                                     (t (lg:ledger-sequence (record-ledger rec)))))))
              (log! node "fraud proof ~a on ~a verified: disputing from seq ~a" (getf proof :type) (subseq id 0 8) last-valid)
              (enter-dispute node rec last-valid :reason (string-downcase (symbol-name (getf proof :type)))))
            (log! node "fraud proof rejected: ~a" why))))))

;;; ---------------------------------------------------------------------------
;;; Persistence: the fixture format — a JSON array of base64 updates, oldest first.

(defun record-file-name (rec)
  (if (record-fork-p rec)
      (format nil "ledger_~a_fork_~a.json" (subseq (record-id-hex rec) 0 16) (subseq (bytes->hex (record-fork-operator rec)) 0 16))
      (format nil "ledger_~a.json" (subseq (record-id-hex rec) 0 16))))

(defun save-record (node rec)
  (when (node-data-dir node)
    (ensure-directories-exist (node-data-dir node))
    (with-open-file (out (merge-pathnames (record-file-name rec) (node-data-dir node))
                         :direction :output :if-exists :supersede)
      (format out "[~{~s~^,~%~}]~%" (mapcar (lambda (u) (base64-encode (up:encode-update u))) (reverse (record-history rec)))))))

(defun load-record (node path &key owned-p)
  "Rebuild a record from a saved (or fixture) file, validating as we go.  A
   fork file (ledger_<id>_fork_<op>.json) becomes a fork record of its base,
   which must already be loaded."
  (let* ((text (with-open-file (in path) (let ((s (make-string (file-length in)))) (subseq s 0 (read-sequence s in)))))
         (updates (loop with pos = 0
                        for start = (position #\" text :start pos) while start
                        collect (let ((end (position #\" text :start (1+ start))))
                                  (setf pos (1+ end))
                                  (up:decode-update (base64-decode (subseq text (1+ start) end))))))
         (first (first updates))
         (id-hex (bytes->hex (up:update-ledger-id first)))
         (fork-p (search "_fork_" (file-namestring path)))
         (rec (if fork-p
                  (let* ((base (or (find-record node id-hex) (fail "fork file before its base ledger")))
                         (divergence (or (position-if (lambda (u) (not (equalp (up:update-operator-id u) (lg:ledger-operator-key (record-ledger base))))) updates)
                                         (fail "fork file with no fork updates")))
                         (operator (up:update-operator-id (nth divergence updates))))
                    (make-fork node base (1- (up:update-seq (nth divergence updates))) operator))
                  (make-record :id-hex id-hex :ledger (lg:make-ledger) :owned-p owned-p))))
    (dolist (u updates)
      (when (> (up:update-seq u) (lg:ledger-sequence (record-ledger rec)))
        (if (and (record-owned-p rec) (not fork-p))
            (progn (lg:apply-update (record-ledger rec) u) (push u (record-history rec)))
            (accept-update node rec u))))
    (unless fork-p (setf (gethash (record-id-hex rec) (node-ledgers node)) rec))
    rec))
