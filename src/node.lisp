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
                    (#:d16 #:cl-deposits.dep16)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire)
                    (#:schnorr #:secp256k1-fast.schnorr))
  (:export #:node #:make-node #:node-pubkey #:node-pubkey-hex #:node-ledgers #:node-log
           #:record #:record-ledger #:record-history #:record-owned-p #:record-id-hex #:record-reserves
           #:find-record #:own-ledger
           #:open-ledger #:append-operation #:add-member #:prepare-quorum #:begin-quorum #:credit-onchain
           #:node-chain-fn #:node-min-confs #:node-data-dir #:record-pinned #:height #:tip
           #:node-error #:request #:wallet #:make-wallet #:wallet-pubkey #:wallet-request
           #:wallet-open-deposit #:wallet-balance #:wallet-transfer #:wallet-complete-transfer
           #:wallet-make-invoice #:wallet-pay-invoice #:credit-paid-invoices #:start-invoice-poller #:node-ln #:node-invoices
           #:enter-dispute #:arm-dispute #:fork-key #:find-fork #:forks-of #:armers-of #:disputed-reserves
           #:build-confiscation #:confiscate #:publish-reveal #:reveals-of #:claim-or-yield #:node-broadcast-fn
           #:node-broadcasts #:broadcast-fraud #:record-fork-p #:record-preimage #:record-lottery #:record-confiscation
           #:node-height-of-block #:equivocate
           #:check-expired-quorums #:collateral-floor-sats #:follow-ledger #:wallet-escalate #:node-ignore-actions #:wallet-request-hash #:wallet-lock-to
           #:node-hooks #:add-hook #:wallet-pending-lock #:completion-satisfied-p #:node-busy
           #:save-record #:load-record #:load-data-dir #:stop-node #:lottery-seed #:*cosign-timeout* #:inbox-depths #:catch-up #:catch-up-all #:fail-expired-transfers #:start-transfer-timeout-poller #:node-adversary
           #:dispute-expired-quorums #:start-expiry-watch #:*expiry-grace-blocks*
           #:required-replacement-sats #:pledge-collateral #:release-pledges #:our-utxos #:node-pledges
           #:drive-disputes #:dispute-arm-closes #:outpoint-key #:save-pledges))
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
  last-event-id                                ; Nostr id of the last update we published
  (persisted 0)                                ; how many history entries the file on disk holds (append-only save)
  (append-lock (bt:make-lock "append"))        ; one append at a time per owned ledger, cosign wait included
  preimage lottery confiscation)               ; our lottery secret; the built lottery; the confiscation tx

(defstruct (node (:constructor %make-node))
  priv pubkey pubkey-hex keypair bus network
  (ledgers (make-hash-table :test #'equal :synchronized t))    ; ledger id hex -> record (both lanes add records)
  (pending (make-hash-table :test #'equal))    ; request event id -> waiter
  (lock (bt:make-lock "node"))
  (height-fn (lambda () 0))
  (log '())
  data-dir
  (inbox '()) (inbox-lock (bt:make-lock "inbox")) (inbox-cv (bt:make-condition-variable)) (worker nil) (busy nil)
  ;; The replica lane: other operators' updates and their cosign requests, in
  ;; arrival order.  Neither ever waits on anyone, but an operator request does
  ;; (up to 3 rounds of *cosign-timeout*), and every node here is both an
  ;; operator and a cosigner.  On one queue the four cl nodes convoy: each sits
  ;; in wait-for while the others' cosign requests age behind it, and under load
  ;; no operator ever completes a round (the soak's 50% failure rate).  Cosigns
  ;; alone on the lane are not enough: a cosigner whose replica is behind
  ;; refuses ("expected seq N"), so the updates it chains onto must arrive on the
  ;; same lane ahead of it.  Owned ledgers are never replicas, so the two lanes
  ;; mutate disjoint records.
  (fast-inbox '()) (fast-lock (bt:make-lock "cosign-inbox")) (fast-cv (bt:make-condition-variable)) (fast-worker nil)
  (subscription nil)                           ; our bus handler, so STOP-NODE can remove it
  (seen (make-hash-table :test #'equal)) (seen-order '())   ; event ids already handled (relays redeliver)
  (not-ours (make-hash-table :test #'equal :synchronized t))   ; ledger id -> retry-after, for refollow-if-member
  (ln nil)                                     ; a cl-deposits.lightning backend, or NIL
  (broadcast-fn nil)                           ; (lambda (tx-bytes)) -> txid or NIL; NIL = collect only
  (broadcasts '())                             ; what we would have broadcast (newest first)
  (height-of-block nil)                        ; (lambda (hash32)) -> height or NIL (fraud-proof anchors)
  (block-hash-fn nil)                          ; (lambda (height)) -> hash32 or NIL (TransferFail anchors)
  (reveals (make-hash-table :test #'equal))    ; ledger id hex -> alist (member-pubkey33 . preimage)
  (relays '())                                 ; relay URLs, for advertisements
  (ignore-actions '())                         ; testing: wallet actions the operator silently drops
  (adversary '())                              ; red team (docs/REDTEAM.md): plist of misbehaviours this node performs on purpose
  (hooks '())                                  ; (lambda (rec update op)) called after every accepted/committed update
  (invoices (make-hash-table :test #'equalp))  ; payment hash -> plist (:rec :deposit-id :amount :bolt11)
  (chain-fn nil)                               ; (lambda (txid vout)) -> plist :value-sats :confirmations, or NIL
  (utxos-fn nil)                               ; (lambda (address)) -> list of plists :txid :vout :sats :confirmations
  (pledges (make-hash-table :test #'equal :synchronized t))   ; "txidhex:vout" -> ledger id hex we pledged it to
  (dispute-notes (make-hash-table :test #'equal))   ; ledger id -> the last dispute-driver state we logged
  (min-confs 1)
  (member-ledger-hex nil))                     ; our own ledger used for QuorumJoin / member_ledger_hash

(defun log! (node fmt &rest args)
  ;; One line per entry: the control socket is line-oriented.
  (push (substitute #\Space #\Newline (apply #'format nil fmt args)) (node-log node)))

(defun add-hook (node fn) (push fn (node-hooks node)))
(defun extra-actions (node)
  "Actions registered by roles layered on the node (couriers), addressed to us by p tag."
  (or (get (intern (node-pubkey-hex node) :keyword) 'actions)
      (setf (get (intern (node-pubkey-hex node) :keyword) 'actions) (make-hash-table :test #'equal))))
(defun run-hooks (node rec update)
  (let ((o (op:decode-operation (up:update-message update))))
    (dolist (h (node-hooks node)) (handler-case (funcall h rec update o) (error (e) (log! node "hook: ~a" e))))))

(defun make-node (&key priv bus (network "signet") height-fn data-dir chain-fn utxos-fn (min-confs 1) ln relays broadcast-fn height-of-block block-hash-fn)
  (let* ((priv (w:even-y-privkey priv))
         (pub (up:compressed-pubkey priv))
         (node (%make-node :priv priv :pubkey pub :pubkey-hex (bytes->hex pub)
                           :keypair (w:nostr-keypair priv) :bus bus :network network
                           :height-fn (or height-fn (lambda () 0)) :data-dir data-dir
                           :chain-fn chain-fn :utxos-fn utxos-fn :min-confs min-confs :ln ln :relays relays
                           :broadcast-fn broadcast-fn :height-of-block height-of-block :block-hash-fn block-hash-fn)))
    ;; On a real relay, events arrive on the reader thread.  Responses are
    ;; consumed inline (they only wake a waiter); requests and updates go to a
    ;; worker, because handling a request may itself wait for responses.
    (when (bus:bus-async-p bus)
      (setf (node-worker node)
            (bt:make-thread (lambda () (worker-loop node)) :name "cld-worker"))
      (setf (node-fast-worker node)
            (bt:make-thread (lambda () (fast-worker-loop node)) :name "cld-cosigner"))
      (when (typep bus 'bus:chaos-bus)
        (bus:bus-add-idle-hook bus (lambda () (and (null (node-inbox node)) (not (node-busy node)))))))
    (setf (node-subscription node)
          ;; SINCE a minute ago: the relay would otherwise replay its whole store
          ;; (tens of thousands of events) into this subscription at every start;
          ;; anything we missed while down, catch-up fetches per ledger on demand.
          (bus:bus-subscribe bus (flt:make-filter :kinds (list w:+kind-update+ w:+kind-request+ w:+kind-response+
                                                              w:+kind-fraud-proof+ w:+kind-lottery-reveal+)
                                                  :since (if (bus:bus-async-p bus) (- (get-universal-time) 2208988800 60) nil))
                             (lambda (event)
                               (cond ((or (null (node-worker node)) (= (ev:event-kind event) w:+kind-response+))
                                      (handle-event node event))
                                     ((or (= (ev:event-kind event) w:+kind-update+)
                                          (and (= (ev:event-kind event) w:+kind-request+)
                                               (equal (w:event-action event) "cosign_update")))
                                      (enqueue-fast node event))
                                     (t (enqueue node event))))))
    node))

(defun stop-node (node)
  "Leave the bus and stop the worker: what a process exit does, for tests that
   then rebuild the node from its data dir."
  (bus:bus-unsubscribe (node-bus node) (node-subscription node))
  (when (node-worker node) (ignore-errors (bt:destroy-thread (node-worker node))) (setf (node-worker node) nil))
  (when (node-fast-worker node) (ignore-errors (bt:destroy-thread (node-fast-worker node))) (setf (node-fast-worker node) nil))
  node)

(defun enqueue (node event)
  (bt:with-lock-held ((node-inbox-lock node))
    (setf (node-inbox node) (append (node-inbox node) (list event)))
    (bt:condition-notify (node-inbox-cv node))))

(defun worker-loop (node)
  (loop
    (let ((event (bt:with-lock-held ((node-inbox-lock node))
                   (loop until (node-inbox node) do (bt:condition-wait (node-inbox-cv node) (node-inbox-lock node)))
                   (setf (node-busy node) t)
                   (pop (node-inbox node)))))
      (unwind-protect (handle-event node event) (setf (node-busy node) nil)))))

(defun enqueue-fast (node event)
  (bt:with-lock-held ((node-fast-lock node))
    (setf (node-fast-inbox node) (append (node-fast-inbox node) (list event)))
    (bt:condition-notify (node-fast-cv node))))

(defun fast-worker-loop (node)
  ;; Replicas are applied and read here only; the main worker mutates owned
  ;; records.  What the two share (the seen table, the ledgers table) is locked.
  (loop
    (let ((event (bt:with-lock-held ((node-fast-lock node))
                   (loop until (node-fast-inbox node) do (bt:condition-wait (node-fast-cv node) (node-fast-lock node)))
                   (pop (node-fast-inbox node)))))
      (handle-event node event))))

(defun inbox-depths (node)
  "(:inbox N :cosign-inbox N) — how far behind the two lanes are."
  (list :inbox (length (node-inbox node)) :cosign-inbox (length (node-fast-inbox node))))

(defun height (node) (funcall (node-height-fn node)))
(defun find-record (node id-hex) (gethash id-hex (node-ledgers node)))
(defun own-ledger (node) (and (node-member-ledger-hex node) (find-record node (node-member-ledger-hex node))))
(defun tip (rec) (car (record-history rec)))
(defun x-hex (pubkey33) (bytes->hex (up:x-only pubkey33)))

;;; ---------------------------------------------------------------------------
;;; Waiting for responses

(defstruct waiter (lock (bt:make-lock)) (cv (bt:make-condition-variable)) (responses '()) (done nil) want (successes-only nil) (ids '()) (counts nil))

(defun waiter-count (wt)
  (cond ((waiter-counts wt) (count-if (waiter-counts wt) (waiter-responses wt)))
        ((waiter-successes-only wt) (count-if (lambda (r) (w:jget r "success")) (waiter-responses wt)))
        (t (length (waiter-responses wt)))))

(defun wait-for (node request-id want &key (timeout *cosign-timeout*))
  "Block until WANT responses (or DONE) for REQUEST-ID, or TIMEOUT.  Returns the responses."
  (let ((wt (gethash request-id (node-pending node))))
    (bt:with-lock-held ((waiter-lock wt))
      (loop with deadline = (+ (get-internal-real-time) (* timeout internal-time-units-per-second))
            until (or (waiter-done wt) (>= (waiter-count wt) want)
                      (> (get-internal-real-time) deadline))
            do (bt:condition-wait (waiter-cv wt) (waiter-lock wt) :timeout 0.2)))
    (remhash request-id (node-pending node))
    (reverse (waiter-responses wt))))

(defun send-request (node ledger-id-hex action params &key (want 1) (timeout *cosign-timeout*) extra-tags successes-only counts)
  "Publish a Kind 20101 request and collect WANT Kind 20102 responses (successful
   ones when SUCCESSES-ONLY; those satisfying COUNTS when given)."
  (let ((event (w:request-event (node-keypair node) ledger-id-hex action params :extra-tags extra-tags)))
    (setf (gethash (ev:event-id event) (node-pending node)) (make-waiter :want want :successes-only successes-only :counts counts))
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
  (setf (record-last-event-id rec) (ev:event-id (bus:bus-publish (node-bus node) (w:update-event (node-keypair node) update))))
  (save-record node rec)
  (run-hooks node rec update)
  update)

(defun solicit-cosignatures (node rec update signers required)
  "Ask the quorum; return when REQUIRED valid cosignatures are in the update."
  (let* ((params (w:json-object "sequence_number" (up:update-seq update)
                                "cosign_data_hex" (bytes->hex (up::cosign-data update))
                                "content_hash_hex" (bytes->hex (up:content-hash update))
                                "message_type" 32769
                                "fork_operator" (and (record-fork-p rec) (bytes->hex (record-fork-operator rec)))))
         (attempt 0))
    (flet ((collect (responses)
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
                       (push c (up:update-cosignatures update)))))))))
      ;; A member may still be applying the update this one chains onto (relays
      ;; reorder); ask again after a pause before giving up.
      (loop do (collect (send-request node (record-id-hex rec) "cosign_update" params
                                      :want (- required (length (up:update-cosignatures update)))
                                      :counts (lambda (r) (let ((res (w:jget r "result")))
                                                            (and (w:jget r "success") res
                                                                 (member (hex->bytes (w:jget res "cosigner_pubkey")) signers :key #'lg:member-pubkey :test #'equalp))))
                                      :timeout (if (zerop attempt) *cosign-timeout* 3)))
               (incf attempt)
            until (or (>= (length (up:update-cosignatures update)) required) (>= attempt 3))
            do (sleep 0.3)))
    (when (< (length (up:update-cosignatures update)) required)
      (fail "only ~a of ~a cosignatures for seq ~a" (length (up:update-cosignatures update)) required (up:update-seq update)))
    update))

(defun append-operation (node rec op &key (height (height node)))
  "The operator's one entry point: chain OP onto REC's ledger with whatever
   cosignatures DEP-05 requires at HEIGHT."
  (unless (record-owned-p rec) (fail "not our ledger"))
  ;; Serialised per ledger, cosign round included: the control socket (a
  ;; rotation's QuorumAddMember) and the worker (a wallet's transfer) both
  ;; append here, and an update built from a tip that moved during its own
  ;; cosign round commits as "SEQUENCE (expected N+1, got N)".  Under steady
  ;; traffic a rotation never won that race and only succeeded post-expiry,
  ;; when value-moving operations were being refused and nothing competed.
  (bt:with-lock-held ((record-append-lock rec))
    ;; Would it apply?  Check on a copy before asking anyone to cosign it.
    ;; ADVERSARY :sign-invalid — an operator that asks its quorum to cosign an
    ;; operation its own validator rejects (red team #1).
    (unless (getf (node-adversary node) :sign-invalid)
      (lg:apply-operation (lg:copy-ledger (record-ledger rec)) op))
    (let ((update (new-update node rec op :height height)))
      (multiple-value-bind (required signers tier operator-alone allowed)
          (lg:cosign-requirement (record-ledger rec) op height)
        (declare (ignore operator-alone))
        (unless allowed (fail "~a not cosignable at ~a" (op:operation-type op) tier))
        (when (plusp required) (solicit-cosignatures node rec update signers required)))
      (commit-update node rec update))))

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

(defparameter +consent-timeout+ 60 "Seconds to wait for a member's consent.")
(defparameter +consent-history-limit+ 40
  "How much of the history a consent request carries: the reference's nostr client drops any
   event over 70 KB (~70 updates), and it needs LedgerOpen; the rest is gap-filled from the relay.")

(defun add-member (node rec member-pubkey &key member-ledger-id (membership-blocks 4320) (ruleset "cltv-offset-v2") (min-fee-bps 0) (min-fee-fixed 0) (max-fee-period 2016))
  "Ask MEMBER-PUBKEY to join REC's quorum; on consent, stage them with QuorumAddMember.
   The request is addressed (tag l) to MEMBER-LEDGER-ID — the member's own ledger —
   as the reference does; its nodes only answer requests for ledgers they operate."
  (let* ((until (+ (height node) membership-blocks))
         ;; Only a PREFIX of the history rides along.  At 46k updates the whole
         ;; of it is ~60 MB of base64 in one event — no relay carries that.  The
         ;; reference member insists on seeing LedgerOpen (it validates the
         ;; ledger id from it) and gap-fills the rest itself; ours catches up
         ;; from the relay to `ledger_sequence`.
         (params (w:json-object "operator_pubkey" (node-pubkey-hex node) "operator_ledger_id" (record-id-hex rec)
                                "ledger_history" (coerce (let ((h (reverse (record-history rec))))
                                                           (mapcar (lambda (u) (base64-encode (up:encode-update u)))
                                                                   (subseq h 0 (min (length h) +consent-history-limit+))))
                                                         'vector)
                                "ledger_sequence" (lg:ledger-sequence (record-ledger rec))
                                "chosen_ruleset" ruleset "min_fee_bps" min-fee-bps "min_fee_fixed" min-fee-fixed
                                "max_fee_period" max-fee-period "membership_until" until))
         ;; A member validates (the reference imports and gap-fills) before it
         ;; answers: allow it well beyond a cosign round.
         (responses (send-request node (or member-ledger-id (record-id-hex rec)) "consent_request" params
                                  :timeout +consent-timeout+
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
    ;; The QuorumBegin's ledger_hash is a state ANCHOR committed in the reserves
    ;; script, not a chain link (the reference: "a state anchor, not a chain
    ;; link"), so it is the tip the reserves were prepared on.  Requiring the tip
    ;; not to have moved meant a ledger under traffic — funding needs three
    ;; confirmations — never rotated until it expired and went quiet.  What must
    ;; still hold is that the reserves were built for the quorum being promoted.
    (unless (equalp (rs:reserves-members reserves) members)
      (fail "staged members changed since the reserves were prepared; prepare again"))
    (let* ((op (list :type :quorum-begin :reserves-id (rs:reserves-address reserves)
                   :spending-txid spending-txid :new-outpoint-txid funding-txid :new-outpoint-vout funding-vout
                   :amount amount-msats :quorum-expiry expiry :ledger-hash (rs:reserves-ledger-hash reserves)
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

(defun seen-before-p (node event)
  "T if this event id was handled already; remembers the last 5000 ids."
  (let ((id (ev:event-id event)))
    (bt:with-lock-held ((node-lock node))
      (if (gethash id (node-seen node))
          t
          (progn (setf (gethash id (node-seen node)) t)
                 (push id (node-seen-order node))
                 (when (> (length (node-seen-order node)) 5000)
                   (remhash (car (last (node-seen-order node))) (node-seen node))
                   (setf (node-seen-order node) (butlast (node-seen-order node))))
                 nil)))))

(defun handle-event (node event)
  (when (and (/= (ev:event-kind event) w:+kind-response+) (seen-before-p node event))
    (return-from handle-event nil))
  (handler-case
      (case (ev:event-kind event)
        (#.w:+kind-response+ (handle-response node event))
        (#.w:+kind-request+ (unless (string= (ev:event-pubkey event) (k:public-hex (node-keypair node)))
                              (handle-request node event)))
        (#.w:+kind-update+ (unless (string= (ev:event-pubkey event) (k:public-hex (node-keypair node)))
                             (handle-update node event)))
        (#.w:+kind-fraud-proof+ (handle-fraud node event))
        (#.w:+kind-lottery-reveal+ (handle-reveal node event)))
    (error (e) (log! node "event ~a (kind ~a from ~a): ~a" (subseq (ev:event-id event) 0 8) (ev:event-kind event) (subseq (ev:event-pubkey event) 0 8) e))))

(defun handle-response (node event)
  (let ((wt (gethash (w:event-request-id event) (node-pending node))))
    (when wt
      (bt:with-lock-held ((waiter-lock wt))
        ;; relays redeliver: one response per event id
        (when (member (ev:event-id event) (waiter-ids wt) :test #'string=) (return-from handle-response nil))
        (push (ev:event-id event) (waiter-ids wt))
        (push (w:parse-json (ev:event-content event)) (waiter-responses wt))
        ;; carry the responder's pubkey alongside
        (setf (gethash "responder" (car (waiter-responses wt))) (ev:event-pubkey event))
        (bt:condition-notify (waiter-cv wt))))))

(defun handle-request (node event)
  ;; Addressed requests (a "p" tag) for someone else are not ours: the reference
  ;; CLI talks to its own daemon this way, encrypted, over the same relay.
  (let ((to (ev:first-tag-value event "p")))
    (when (and to (string/= to (k:public-hex (node-keypair node))))
      (return-from handle-request nil)))
  (let ((action (w:event-action event)) (params (w:parse-json (ev:event-content event))))
    (cond ((and (ev:first-tag-value event "p") (string= (ev:first-tag-value event "p") (k:public-hex (node-keypair node)))
                (gethash action (extra-actions node)))
           (funcall (gethash action (extra-actions node)) event params))
          ((string= action "cosign_update") (handle-cosign node event params))
          ((string= action "confiscation_sign") (handle-confiscation-sign node event params))
          ((string= action "lottery_reveal") (handle-lottery-reveal-request node event params))
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
         (when (and (not (record-fork-p rec)) (> (up:update-seq update) (1+ (lg:ledger-sequence (record-ledger rec)))))
           (catch-up node rec))
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
    (run-hooks node rec update)
    :applied))

;;; Following a ledger we are not a member of (couriers, watchers): bootstrap a
;;; replica from what the relays hold, then keep it current like any replica.

(defun ledger-updates-from-relays (node id-hex &key from to)
  "Updates the relays hold for ID-HEX, deduplicated, in sequence order — all of
   them, or just sequences FROM..TO (the `n` tag every update event carries).
   A gap is usually one or two updates; fetching a 6000-update history to fill
   it took 3 s a time and put the replica lane into a spiral."
  (let ((events (bus:bus-fetch (node-bus node)
                               (flt:make-filter :kinds (list w:+kind-update+)
                                                :tags (append (list (cons "d" (list (subseq id-hex 0 16))))
                                                              (when (and from to)
                                                                (list (cons "n" (loop for i from from to to collect (princ-to-string i))))))))))
    ;; Dedup through a hash table: REMOVE-DUPLICATES on a 6000-update list was
    ;; quadratic in EQUALP on 300-byte vectors and took minutes per ledger.
    (let ((seen (make-hash-table :test #'equalp)) (out '()))
      (dolist (e events)
        (let* ((u (w:event->update e)) (k (up:encode-update u)))
          (when (and (string= (bytes->hex (up:update-ledger-id u)) id-hex) (not (gethash k seen)))
            (setf (gethash k seen) t) (push u out))))
      (sort out #'< :key #'up:update-seq))))

(defun catch-up (node rec)
  "A replica that missed an update (a restart, a relay that dropped us) can never
   apply another: every later one fails 'expected seq N'.  Fetch the operator's
   chain past our sequence and apply it in order.  Returns how many applied."
  (let ((ledger (record-ledger rec)) (n 0) (from (lg:ledger-sequence (record-ledger rec))) (window 200))
    ;; Windows of WINDOW sequences past our tip, until a window adds nothing.
    (loop
      (let* ((lo (1+ (lg:ledger-sequence ledger))) (hi (+ lo window -1)) (applied 0)
             (updates (handler-case (ledger-updates-from-relays node (record-id-hex rec) :from lo :to hi)
                        (error (e) (log! node "catch-up on ~a: fetch failed: ~a" (subseq (record-id-hex rec) 0 8) e) '()))))
        (dolist (u updates)
          (when (and (= (up:update-seq u) (1+ (lg:ledger-sequence ledger)))
                     (equalp (up:update-operator-id u) (lg:ledger-operator-key ledger)))
            (handler-case (when (eq (accept-update node rec u) :applied) (incf n) (incf applied))
              (error (e) (log! node "catch-up on ~a stopped at seq ~a: ~a" (subseq (record-id-hex rec) 0 8) (up:update-seq u) e)
                (return)))))
        (when (zerop applied) (return))))
    (when (plusp n) (log! node "caught up ~a from seq ~a to ~a" (subseq (record-id-hex rec) 0 8) from (lg:ledger-sequence ledger)))
    n))

(defun catch-up-all (node)
  "At startup: every replica we cosign, before the first cosign request arrives."
  (loop for rec being the hash-values of (node-ledgers node)
        unless (or (record-owned-p rec) (record-fork-p rec))
          do (ignore-errors (catch-up node rec))))

(defun quorum-names-us-p (node id-hex)
  "Cheap membership pre-check from the relay: the newest QuorumBegin (update
   events carry the operation discriminant as their `t` tag) names the active
   quorum.  NIL also when the relay has none."
  (let* ((events (bus:bus-fetch (node-bus node)
                                (flt:make-filter :kinds (list w:+kind-update+)
                                                 :tags (list (cons "d" (list (subseq id-hex 0 16)))
                                                             (cons "t" (list (princ-to-string (op:discriminant :quorum-begin)))))
                                                 :limit 1)))
         (u (and events (w:event->update (first events))))
         (o (and u (op:decode-operation (up:update-message u)))))
    (and o (member (node-pubkey node) (op:field o :quorum-members) :test #'equalp) t)))

(defvar *deferred-saves* nil "When a list, SAVE-RECORD queues the record here instead of writing.")
(defvar *verify-on-load* (let ((v (uiop:getenv "CLD_VERIFY_ON_LOAD"))) (and v (plusp (length v)) (not (string= v "0"))))
  "Re-verify every signature when loading our own data dir (default: trust it).")

(defun refollow-if-member (node id-hex)
  "Rebuild ID-HEX from the relay if its quorum names us; else remember it as not
   ours for six hours.  NIL when not ours or not reconstructible.  The rebuild
   used to run FIRST — every signature verified and a file write per update
   for a 90k-update ledger, then discarded because we were not a member, then
   again ten minutes later: the replica lane spent its life on it."
  (let ((until (gethash id-hex (node-not-ours node))))
    (when (and until (< (get-universal-time) until)) (return-from refollow-if-member nil)))
  (unless (handler-case (quorum-names-us-p node id-hex) (error () nil))
    (setf (gethash id-hex (node-not-ours node)) (+ (get-universal-time) 21600))
    (return-from refollow-if-member nil))
  (handler-case
      (let* ((rec (let ((*deferred-saves* (list nil))) (follow-ledger node id-hex)))   ; one write at the end, below
             (l (record-ledger rec)))
        (if (or (member (node-pubkey node) (lg:ledger-quorum-members l) :key #'lg:member-pubkey :test #'equalp)
                (member (node-pubkey node) (lg:ledger-next-quorum-members l) :key #'lg:member-pubkey :test #'equalp))
            (progn (log! node "rebuilt our replica of ~a from the relay (seq ~a)" (subseq id-hex 0 8) (lg:ledger-sequence l))
                   (remhash id-hex (node-not-ours node)) (save-record node rec) rec)
            (progn (remhash id-hex (node-ledgers node))
                   (let ((f (merge-pathnames (record-file-name rec) (node-data-dir node)))) (when (probe-file f) (delete-file f)))
                   nil)))
    (error (e) (log! node "cannot follow ~a: ~a" (subseq id-hex 0 8) e) nil)))

(defun follow-ledger (node id-hex)
  (or (find-record node id-hex)
      (let* ((updates (ledger-updates-from-relays node id-hex))
             (rec (make-record :id-hex id-hex :ledger (lg:make-ledger))))
        (dolist (u updates) (accept-update node rec u))
        (setf (gethash id-hex (node-ledgers node)) rec)
        rec)))

;;; ---------------------------------------------------------------------------
;;; Inbound: cosign_update (we are a quorum member of this ledger)

(defun member-ledger-hash (node)
  "The content hash of our own ledger's latest update — what we vouch with."
  (let ((own (own-ledger node)))
    (if (and own (tip own)) (up:content-hash (tip own)) (make-array 32 :element-type '(unsigned-byte 8)))))

(defun handle-cosign (node event params)
  (let* ((rec (let ((fo (w:jget params "fork_operator")))
                (if fo
                    (find-fork node (w:event-ledger-id event) (hex->bytes fo))
                    (or (find-record node (w:event-ledger-id event))
                        ;; A ledger we do not hold — perhaps a replica we LOST (see
                        ;; save-record).  Rebuild it from the relay; keep it only if
                        ;; its quorum names us, and cosign again from here on.
                        (refollow-if-member node (w:event-ledger-id event))))))
         (data (hex->bytes (w:jget params "cosign_data_hex")))
         (seq (w:jget params "sequence_number")))
    (cond
      ((or (null rec) (record-owned-p rec)) nil)      ; not a ledger we replicate
      ;; Only a member (or a staged member, for the QuorumBegin that promotes it) answers.
      ((not (let ((l (record-ledger rec)))
              (or (member (node-pubkey node) (lg:ledger-quorum-members l) :key #'lg:member-pubkey :test #'equalp)
                  (member (node-pubkey node) (lg:ledger-next-quorum-members l) :key #'lg:member-pubkey :test #'equalp))))
       nil)
      ((< (length data) 40) (respond node event nil :error "malformed cosign_data"))
      (t
       (let* ((ledger (record-ledger rec))
              (prev (subseq data 8 40)) (message (subseq data 40))
              (candidate (up:make-signed-update :operator-id (lg:ledger-operator-key ledger)
                                                :ledger-id (hex->bytes (record-id-hex rec))
                                                :seq seq :prev-hash prev :message message)))
         (handler-case
             (progn
               (when (and (> seq (1+ (lg:ledger-sequence ledger))) (not (record-fork-p rec)))
                 (catch-up node rec))
               (unless (= seq (1+ (lg:ledger-sequence ledger)))
                 (fail "expected seq ~a" (1+ (lg:ledger-sequence ledger))))
               (unless (equalp prev (lg:ledger-chain-tip ledger)) (fail "chain mismatch: not our tip"))
               (let ((o (op:decode-operation message)))
                 ;; Speculative apply on a fresh replica: the op must be valid on our state.
                 ;; ADVERSARY :cosign-blind — a member that signs whatever chains (red team #1).
                 (unless (getf (node-adversary node) :cosign-blind)
                   (lg:apply-operation (lg:copy-ledger (record-ledger rec)) o))
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
        (let* ((genesis-operator (if history (up:update-operator-id (first history)) operator))
               (forked (not (equalp genesis-operator operator)))
               (div (and forked (position-if (lambda (u) (equalp (up:update-operator-id u) operator)) history)))
               (base (or (find-record node their-id)
                         ;; No replica yet: build it from the history's base prefix,
                         ;; or — no history sent (a long ledger) — from the relay.
                         (if history
                             (let ((b (make-record :id-hex their-id :ledger (lg:make-ledger))))
                               (dolist (u (if forked (subseq history 0 div) history)) (accept-update node b u))
                               (setf (gethash their-id (node-ledgers node)) b)
                               b)
                             (follow-ledger node their-id))))
               (rec (if (not forked)
                        base
                        ;; A dispute winner re-establishing on its fork: find or build the fork.
                        (or (find-fork node their-id operator)
                            (progn (unless div (fail "history has no fork by this operator"))
                                   (make-fork node base (1- (up:update-seq (nth div history))) operator))))))
          ;; Catch up from the piggybacked history, or from the relay when none came.
          (dolist (u history)
            (when (> (up:update-seq u) (lg:ledger-sequence (record-ledger rec)))
              (accept-update node rec u)))
          (let ((want (w:jget params "ledger_sequence")))
            (when (and (integerp want) (> want (lg:ledger-sequence (record-ledger rec))) (not (record-fork-p rec)))
              (catch-up node rec)))
          (unless (equalp (lg:ledger-operator-key (record-ledger rec)) operator) (fail "history is not this operator's"))
          (unless (record-fork-p rec) (setf (gethash their-id (node-ledgers node)) rec))
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
  (when (member action (node-ignore-actions node) :test #'string=)
    (log! node "ignoring ~a (test switch)" action)
    (return-from handle-wallet-request nil))
  (handler-case
      (cond
        ((string= action "delivery_embed")
         ;; DEP-12: a wallet asks us (a quorum member) to anchor its unanswered request.
         (let ((h (hex->bytes (w:jget params "request_hash")))
               (target (hex->bytes (w:jget params "target_ledger_id")))
               (operator (hex->bytes (w:jget params "target_operator"))))
           (unless (= (length h) 32) (fail "request_hash must be 32 bytes"))
           (append-operation node rec (list :type :delivery-embed :request-hash h :target-ledger-id target :target-operator operator))
           (respond node event t :result (w:json-object "ledger_id" (record-id-hex rec)
                                                        "event_id" (record-last-event-id rec)
                                                        "sequence" (lg:ledger-sequence (record-ledger rec))
                                                        "tip_hash" (bytes->hex (lg:ledger-chain-tip (record-ledger rec)))
                                                        "request_hash" (bytes->hex h)))))
        ((string= action "deposit_open")
         (let* ((descriptor (w:jget params "descriptor"))
                (id (op:deposit-id descriptor)))
           (unless (d17:descriptor-key descriptor) (d16:parse-descriptor descriptor))   ; must be a descriptor we can evaluate
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
         (let* ((o (transfer-lock-from-request params))
                (src (lg:find-deposit (record-ledger rec) (op:field o :source-deposit-id))))
           (unless (eq (op:operation-type o) :transfer-lock) (fail "not a TransferLock"))
           (unless (authorized-p node rec o src (op:field o :witness)) (fail "witness does not authorize this operation"))
           (when (> (height node) (op:field o :expiry)) (fail "operation expired"))
           (when (member (cons (op:field o :nonce) (op:field o :expiry)) (lg:deposit-seen-nonces src) :test #'equal)
             (fail "nonce replayed"))
           (append-operation node rec o)
           (respond node event t :result (w:json-object "transfer_id" (bytes->hex (op:field o :transfer-id))))))
        ((string= action "transfer_complete")
         (let* ((o (if (w:jget params "operation")
                       (op:decode-operation (base64-decode (w:jget params "operation")))
                       (list :type :transfer-complete :transfer-id (hex->bytes (w:jget params "transfer_id"))
                             :script-witness (list (hex->bytes (or (w:jget params "preimage") (w:jget params "scalar") (fail "preimage required")))))))
                (pending (gethash (op:field o :transfer-id) (lg:ledger-pending-transfers (record-ledger rec)))))
           (unless pending (fail "no such transfer"))
           (unless (completion-satisfied-p (getf pending :completion-script) (op:field o :script-witness))
             (fail "completion script not satisfied"))
           (append-operation node rec o)
           (respond node event t :result (w:json-object "transfer_id" (bytes->hex (op:field o :transfer-id))))))
        ((string= action "make_invoice") (handle-make-invoice node rec event params))
        ((string= action "pay_invoice") (handle-pay-invoice node rec event params))
        (t (respond node event nil :error (format nil "unknown action ~a" action))))
    (error (e) (respond node event nil :error (princ-to-string e)))))

;;; Authorization: pk(K) deposits take the direct ECDSA path; anything else is
;;; a DEP-16 descriptor evaluated against the deposit's state snapshot.

(defun deposit-snapshot (node ledger d)
  (let ((h (height node)))
    (d16:make-snapshot :balance (lg:deposit-balance d)
                       :blocks-since-activity (max 0 (- h (lg:deposit-last-activity-block d)))
                       :blocks-since-open (max 0 (- h (lg:deposit-opened-at-block d)))
                       :blocks-since-received (max 0 (- h (lg:deposit-last-received-block d)))
                       :height h)
    ))

(defun authorized-p (node rec o d witness)
  "Does deposit D's descriptor authorize operation O with WITNESS (a stack)?"
  (let ((desc (lg:deposit-descriptor d)))
    (if (d17:descriptor-key desc)
        (eq :ok (d17:verify-operation-witness o desc witness))
        (multiple-value-bind (id type args nonce expiry) (d17:operation->dep16 o)
          (and id
               (let ((descriptor (d16:parse-descriptor desc))
                     (op (d16:make-operation :deposit-id id :op-type type :args args :nonce nonce :expiry expiry)))
                 (handler-case (d16:evaluate descriptor op (deposit-snapshot node (record-ledger rec) d)
                                             (d16:witness-from-stack witness descriptor op))
                   (d16:eval-error (e) (log! node "descriptor evaluation: ~a" e) nil))))))))

;;; Requests in the reference wallet's shape (field by field, signature = witness)

(defun witness-from-json (v)
  "A DescriptorWitness as the reference serialises it: {\"stack\": [...]}, a bare
   array, or a single hex signature; elements as hex strings or byte arrays."
  (let ((stack (cond ((hash-table-p v) (gethash "stack" v)) (t v))))
    (cond ((stringp stack) (list (hex->bytes stack)))
          ((vectorp stack) (map 'list (lambda (e) (if (stringp e) (hex->bytes e) (coerce (map 'list #'identity e) 'octets))) stack))
          (t '()))))

(defun transfer-lock-from-request (params)
  (if (w:jget params "operation")
      (op:decode-operation (base64-decode (w:jget params "operation")))
      (list :type :transfer-lock
            :transfer-nonce (hex->bytes (w:jget params "transfer_nonce"))
            :source-deposit-id (hex->bytes (w:jget params "source_deposit_id"))
            :destination-deposit-id (hex->bytes (w:jget params "destination_deposit_id"))
            :amount (w:jget params "amount") :fee (or (w:jget params "fee") 0)
            :completion-script (w:jget params "completion_script") :timeout-height (w:jget params "timeout_height")
            :transfer-id (hex->bytes (w:jget params "transfer_id"))
            :nonce (w:jget params "op_nonce") :expiry (w:jget params "op_expiry")
            :witness (or (witness-from-json (w:jget params "witness"))
                         (list (hex->bytes (or (w:jget params "signature") (fail "signature required"))))))))

;;; ---------------------------------------------------------------------------
;;; Lightning: pay_invoice (DEP-10 pay).  InvoiceLock on the deposit, pay through
;;; the node's Lightning backend, then InvoiceFulfill with the preimage or
;;; InvoiceFail.

(defun handle-pay-invoice (node rec event params)
  (unless (node-ln node) (fail "no lightning node"))
  (let* ((deposit-id (deposit-id-param params))
         (bolt11 (w:jget params "invoice"))
         (hash (or (and (w:jget params "payment_hash") (hex->bytes (w:jget params "payment_hash"))) (ln:invoice-payment-hash bolt11)))
         (amount (w:jget params "amount_msats"))
         (fee (or (w:jget params "fee_msats") 0))
         (o (if (w:jget params "operation")
                (op:decode-operation (base64-decode (w:jget params "operation")))
                (list :type :invoice-lock :deposit-id deposit-id :amount amount :payment-id hash
                      :sequence-number (1+ (lg:ledger-sequence (record-ledger rec)))
                      :nonce (w:jget params "nonce") :expiry (w:jget params "expiry") :fee fee
                      :witness (witness-from-json (w:jget params "witness")))))
         (d (lg:find-deposit (record-ledger rec) (op:field o :deposit-id))))
    (unless (equalp (ln:invoice-payment-hash bolt11) (op:field o :payment-id)) (fail "payment_hash does not match the invoice"))
    (unless (authorized-p node rec o d (op:field o :witness)) (fail "witness does not authorize this lock"))
    (when (> (height node) (op:field o :expiry)) (fail "operation expired"))
    (append-operation node rec o)
    ;; Pay, then settle the lock either way.
    (let ((outcome :failed) (preimage nil))
      (handler-case
          (progn (ln:ln-pay (node-ln node) bolt11 :amount-msat (op:field o :amount) :height (height node))
                 (loop repeat 60
                       do (multiple-value-bind (st pre) (ln:ln-payment-status (node-ln node) (op:field o :payment-id))
                            (case st (:succeeded (setf outcome :succeeded preimage pre) (return))
                                     (:failed (return))
                                     (t (sleep 0.5))))))
        (error (e) (log! node "pay failed: ~a" e)))
      (if (and (eq outcome :succeeded) preimage (equalp (sha256 preimage) (op:field o :payment-id)))
          (progn
            (append-operation node rec (list :type :invoice-fulfill :deposit-id (op:field o :deposit-id) :amount (op:field o :amount)
                                             :payment-id (op:field o :payment-id) :sequence-number (1+ (lg:ledger-sequence (record-ledger rec)))
                                             :witness (op:field o :witness) :preimage preimage))
            (respond node event t :result (w:json-object "payment_id" (bytes->hex (op:field o :payment-id))
                                                         "deposit_id" (bytes->hex (op:field o :deposit-id))
                                                         "amount_msat" (op:field o :amount) "preimage" (bytes->hex preimage)
                                                         "status" "succeeded")))
          (progn
            (append-operation node rec (list :type :invoice-fail :deposit-id (op:field o :deposit-id) :payment-id (op:field o :payment-id)
                                             :sequence-number (1+ (lg:ledger-sequence (record-ledger rec)))))
            (respond node event nil :error "payment failed; lock released"))))))

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

(defun fail-expired-transfers (node &key (per-ledger 20))
  "DEP-11 §Transfer Timeout: on every ledger we operate, append TransferFail
   for each pending transfer whose timeout_height has passed.  Never done
   before this: after two days of a soak nearly every sat on our ledgers sat
   locked behind a completion that had timed out, and every update we signed
   past those heights was provable non-conformance.  Bounded per pass so a
   backlog does not monopolise the ledger's append lock."
  (let ((h (height node)) (n 0))
    (when (plusp h)
      (loop for rec being the hash-values of (node-ledgers node)
            when (and (record-owned-p rec) (not (record-fork-p rec)))
              do (let ((expired '()))
                   (maphash (lambda (tid p) (let ((th (getf p :timeout-height)))
                                              (when (and (integerp th) (>= h th)) (push tid expired))))
                            (lg:ledger-pending-transfers (record-ledger rec)))
                   (dolist (tid (subseq expired 0 (min per-ledger (length expired))))
                     (handler-case
                         (progn (append-operation node rec (list :type :transfer-fail :transfer-id tid
                                                                 :block-hash (or (and (node-block-hash-fn node) (funcall (node-block-hash-fn node) h))
                                                                                 (make-array 32 :element-type '(unsigned-byte 8)))
                                                                 :reason 1))
                                (incf n))
                       (error (e) (log! node "transfer-fail on ~a: ~a" (subseq (record-id-hex rec) 0 8) e) (return)))))))
    (when (plusp n) (log! node "failed ~a expired transfer~:p at height ~a" n h))
    n))

(defun start-transfer-timeout-poller (node &key (interval 30))
  (bt:make-thread (lambda () (loop (sleep interval) (ignore-errors (fail-expired-transfers node)))) :name "cld-timeouts"))

;;; DEP-19 / DEP-11: a quorum member disputes an operator who let the quorum
;;; lapse.  CHECK-EXPIRED-QUORUMS was only reachable from the control socket,
;;; so no cl member ever noticed an expired quorum by itself: on the soak a
;;; reference-operated ledger sat hours past quorum_expiry, still appending,
;;; with no dispute from either implementation (docs/REDTEAM.md claim #4).
(defparameter *expiry-grace-blocks* 3
  "Blocks past quorum_expiry before a member disputes: room for a QuorumBegin
   still propagating, so a rotation that just made it is not mistaken for a lapse.")

(defun relay-tip-seq (node id-hex operator33)
  "The highest sequence among the newest updates the relays hold for ID-HEX from
   its OPERATOR33 (members' forks share the ledger's tag), or NIL."
  (loop for e in (bus:bus-fetch (node-bus node)
                                (flt:make-filter :kinds (list w:+kind-update+) :limit 20
                                                 :tags (list (cons "d" (list (subseq id-hex 0 16))))))
        for u = (ignore-errors (w:event->update e))
        when (and u (string= (bytes->hex (up:update-ledger-id u)) id-hex) (equalp (up:update-operator-id u) operator33))
          maximize (up:update-seq u)))

(defun dispute-expired-quorums (node &key (grace *expiry-grace-blocks*))
  "Dispute every quorum we sit on that is past expiry — judged only on a replica
   that is current.  One that missed its QuorumBegin shows the old expiry and
   would accuse an operator who rotated: on the soak cld1, just restarted, held
   ledger D at 127572 of 138728, a rotation at 128928 never reached, and
   disputed it.  A replica behind the relay is left alone (the replica lane
   catches it up; catching up here raced that lane).  Returns the ids disputed."
  (let ((h (height node)))
    (when (plusp h)
      (let* ((stale (loop for rec being the hash-values of (node-ledgers node)
                          when (expired-quorum-p node rec h grace)
                            when (let ((tip (ignore-errors (relay-tip-seq node (record-id-hex rec) (lg:ledger-operator-key (record-ledger rec))))))
                                   (and tip (> tip (lg:ledger-sequence (record-ledger rec)))))
                              collect (record-id-hex rec)))
             (disputed (check-expired-quorums node :grace grace :skip stale
                                                   :anchor-block-hash (and (node-block-hash-fn node) (funcall (node-block-hash-fn node) h)))))
        (dolist (id stale) (note-dispute node id "quorum looks expired but our replica is behind the relay: not judging"))
        (dolist (id disputed) (log! node "quorum expired on ~a at height ~a: disputed" (subseq id 0 8) h))
        disputed))))

;;; The member's side of a dispute, driven to the end (DEP-06): arm with pledged
;;; collateral, propose the confiscation once the arm window closes, reveal once
;;; it is on chain, claim or yield once every reveal is in.  Until now each step
;;; was a control-socket command, so a cl member's dispute stopped at DisputeEnter.

(defparameter *default-dispute-arm-blocks* 6
  "The arm window when no member's QuorumAddMember terms name one.  The
   reference neither sets nor enforces dispute_arm_blocks; this is our policy.")
(defparameter *proposer-grace-blocks* 3
  "Blocks the lowest-keyed armer has to propose before the others do too.")

(defun fork-op (fork type)
  "FORK's most recent update of operation TYPE, and its decoded operation."
  (let ((u (find type (record-history fork) :key (lambda (u) (op:operation-type (op:decode-operation (up:update-message u)))))))
    (and u (values u (op:decode-operation (up:update-message u))))))

(defun dispute-arm-closes (node base)
  "The block the arm window closes: the earliest DisputeEnter on any fork of
   BASE's ledger plus the members' dispute_arm_blocks (the longest named)."
  (let ((entered (loop for f in (forks-of node (record-id-hex base))
                       for (u o) = (multiple-value-list (fork-op f :dispute-enter))
                       when u minimize (or (op:field o :anchor-block-height) (up:update-block-height u))))
        ;; No member names one (the reference never sets dispute_arm_blocks): ours.
        (window (let ((named (loop for m in (lg:ledger-quorum-members (record-ledger base))
                                   for b = (lg::member-dispute-arm-blocks m) when (and b (plusp b)) collect b)))
                  (if named (reduce #'max named) *default-dispute-arm-blocks*))))
    (and entered (+ entered window))))

(defun confiscation-on-chain (node id-hex)
  "The confiscation of ID-HEX whose lottery output is in the UTXO set (we
   proposed or signed it, or it rebuilds from public state), or NIL.  Reserves
   that are merely spent prove nothing: a stranded rotation spends them too."
  (when (node-chain-fn node)
    (let ((known (loop for f in (forks-of node id-hex) thereis (record-confiscation f))))
      (or (and known (funcall (node-chain-fn node) (btx:tx-txid known) 0) known)
          (loop for ti below (length (rs:reserves-tiers (disputed-reserves node (find-record node id-hex))))
                for tx = (ignore-errors (build-confiscation node id-hex :tier-index ti))
                when (and tx (funcall (node-chain-fn node) (btx:tx-txid tx) 0)) return tx)))))

(defun note-dispute (node id-hex fmt &rest args)
  "Log a dispute's state only when it changes: a stuck dispute is retried every
   pass and would otherwise fill the log."
  (let ((line (apply #'format nil fmt args)))
    (unless (equal line (gethash id-hex (node-dispute-notes node)))
      (setf (gethash id-hex (node-dispute-notes node)) line)
      (log! node "dispute ~a: ~a" (subseq id-hex 0 8) line))))

(defun expiry-reason-p (reason)
  "A DisputeEnter for a lapsed quorum, in either spelling we ever wrote."
  (and (stringp reason) (string= (substitute #\_ #\- reason) "quorum_expired")))

(defun drive-dispute (node fork)
  (let* ((id (record-id-hex fork)) (base (find-record node id)) (h (height node)))
    (multiple-value-bind (enter enter-op) (fork-op fork :dispute-enter)
      (unless (and base enter) (return-from drive-dispute nil))
      (when (or (fork-op fork :dispute-acquire) (fork-op fork :dispute-yield))
        (when (loop for v being the hash-values of (node-pledges node) thereis (equal v id)) (release-pledges node id))
        (return-from drive-dispute (note-dispute node id "concluded")))
      ;; A quorum_expired dispute whose operator has since re-established the quorum
      ;; (or that we opened on a stale replica): stand down, unless it is already
      ;; confiscated.
      (let ((expiry (lg:ledger-quorum-expiry (record-ledger base))))
        (when (and (expiry-reason-p (op:field enter-op :reason)) expiry (<= h (+ expiry *expiry-grace-blocks*))
                   (not (confiscation-on-chain node id)))
          (commit-update node fork (new-update node fork (list :type :dispute-yield)))
          (release-pledges node id)
          (return-from drive-dispute (note-dispute node id "quorum re-established (expiry ~a); yielded" expiry))))
      (let ((conf (confiscation-on-chain node id))
            (reserves-spent (multiple-value-bind (r txid vout) (disputed-reserves node base)
                              (declare (ignore r))
                              (and (node-chain-fn node) (null (funcall (node-chain-fn node) txid vout))))))
        (cond
          ;; Nothing left to confiscate (a stranded rotation spent it): arming would
          ;; only tie up a pledge.
          ((and reserves-spent (not conf))
           (note-dispute node id "reserves spent, but not by a confiscation we can rebuild"))
          ((null (fork-op fork :dispute-armed))
           (let ((p (pledge-collateral node id)))
             (if p
                 (progn (arm-dispute node fork :replacement p)
                        (note-dispute node id "armed, pledging ~a:~a (~a sats)" (txid-hex (first p)) (second p) (third p)))
                 (note-dispute node id "waiting for collateral (~a sats)" (required-replacement-sats base)))))
          (conf
           (if (not (assoc (node-pubkey node) (reveals-of node id) :test #'equalp))
               (progn (publish-reveal node id)
                      (note-dispute node id "confiscation ~a on chain; revealed" (txid-hex (btx:tx-txid conf))))
               (handler-case (let ((outcome (claim-or-yield node id :confiscation-txid (btx:tx-txid conf))))
                               (release-pledges node id)
                               (note-dispute node id "lottery: ~(~a~)" outcome))
                 (error (e) (note-dispute node id "waiting to claim: ~a" e)))))
          (t
           (let ((closes (dispute-arm-closes node base))
                 (armers (sort (mapcar #'first (armers-of node id)) #'bytes<)))
             (cond ((< (length armers) 2) (note-dispute node id "armed; waiting for a second armer"))
                   ((< h closes) (note-dispute node id "armed; arm window closes at ~a" closes))
                   ((or (equalp (first armers) (node-pubkey node)) (>= h (+ closes *proposer-grace-blocks*)))
                    (handler-case
                        (let ((tx (confiscate node id :respectful (expiry-reason-p (op:field enter-op :reason)))))
                          (note-dispute node id "proposed confiscation ~a" (txid-hex (btx:tx-txid tx))))
                      (error (e) (note-dispute node id "confiscation not yet: ~a" e))))
                   (t (note-dispute node id "armed; another armer proposes first"))))))))))

(defun drive-disputes (node)
  (loop for rec in (loop for r being the hash-values of (node-ledgers node)
                         when (and (record-fork-p r) (record-owned-p r)) collect r)
        do (handler-case (drive-dispute node rec)
             (error (e) (note-dispute node (record-id-hex rec) "error: ~a" e)))))

(defun start-expiry-watch (node &key (interval 60))
  (bt:make-thread (lambda () (loop (sleep interval)
                                   (ignore-errors (dispute-expired-quorums node))
                                   (ignore-errors (drive-disputes node))))
                  :name "cld-expiry"))

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
                                      (unless (member (ev:event-id event) (waiter-ids wt) :test #'string=)
                                        (push (ev:event-id event) (waiter-ids wt))
                                        (push (w:parse-json (ev:event-content event)) (waiter-responses wt))
                                        (bt:condition-notify (waiter-cv wt))))))))
    wal))

(defun wallet-request (wal ledger-id-hex action params &key (timeout *cosign-timeout*) extra-tags)
  "Send a request; return (values success result error request-hash)."
  (let* ((event (w:request-event (wallet-keypair wal) ledger-id-hex action params :extra-tags extra-tags))
         (wt (make-waiter :want 1)))
    (setf (gethash (ev:event-id event) (wallet-pending wal)) wt)
    (bus:bus-publish (wallet-bus wal) event)
    (bt:with-lock-held ((waiter-lock wt))
      (loop with deadline = (+ (get-internal-real-time) (* timeout internal-time-units-per-second))
            until (or (waiter-responses wt) (> (get-internal-real-time) deadline))
            do (bt:condition-wait (waiter-cv wt) (waiter-lock wt) :timeout 0.2)))
    (remhash (ev:event-id event) (wallet-pending wal))
    (let ((r (first (waiter-responses wt))) (h (sha256 (ascii->bytes (ev:event-content event)))))
      (if r (values (w:jget r "success") (w:jget r "result") (w:jget r "error") h) (values nil nil "timeout" h)))))

(defun wallet-request-hash (wal ledger-id-hex action params)
  "The request hash DEP-12 anchors: SHA256 of the signed request's content."
  (declare (ignore wal ledger-id-hex action))
  (sha256 (ascii->bytes (w:json params))))

(defun wallet-descriptor (wal) (format nil "pk(~a)" (bytes->hex (wallet-pubkey wal))))

(defun wallet-open-deposit (wal ledger-id-hex &key descriptor)
  (multiple-value-bind (ok res err) (wallet-request wal ledger-id-hex "deposit_open" (w:json-object "descriptor" (or descriptor (wallet-descriptor wal))))
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
        ;; Both shapes: our operator takes the encoded operation; the reference
        ;; operator wants the fields (and a 64-byte "signature" for the witness).
        (wallet-request wal ledger-id-hex "transfer_lock"
                        (w:json-object "operation" (base64-encode (op:encode-operation o))
                                       "transfer_nonce" (bytes->hex transfer-nonce)
                                       "source_deposit_id" (bytes->hex from) "destination_deposit_id" (bytes->hex to)
                                       "amount" amount-msats "fee" fee
                                       "completion_script" (getf o :completion-script) "timeout_height" (getf o :timeout-height)
                                       "transfer_id" (bytes->hex transfer-id)
                                       "op_nonce" (getf o :nonce) "op_expiry" (getf o :expiry)
                                       "signature" (bytes->hex (first (getf o :witness)))))
      (declare (ignore res))
      (unless ok (fail "transfer_lock: ~a" err))
      (values transfer-id preimage))))

(defun wallet-complete-transfer (wal ledger-id-hex transfer-id preimage)
  (let ((o (list :type :transfer-complete :transfer-id transfer-id :script-witness (list preimage))))
    (multiple-value-bind (ok res err)
        (wallet-request wal ledger-id-hex "transfer_complete"
                        (w:json-object "operation" (base64-encode (op:encode-operation o))
                                       "transfer_id" (bytes->hex transfer-id) "preimage" (bytes->hex preimage)))
      (declare (ignore res))
      (unless ok (fail "transfer_complete: ~a" err))
      t)))

;;; Wallet: pay a Lightning invoice from a deposit

(defun wallet-pay-invoice (wal ledger-id-hex deposit-id bolt11 amount-msat &key (fee 0) (height 0))
  "InvoiceLock signed by us; the operator pays and settles.  Returns (values ok preimage error)."
  (let* ((hash (ln:invoice-payment-hash bolt11))
         (o (list :type :invoice-lock :deposit-id deposit-id :amount amount-msat :payment-id hash :sequence-number 0
                  :nonce (incf (wallet-nonce wal)) :expiry (+ height 144) :fee fee :witness '())))
    (setf (getf o :witness) (d17:sign-operation o (wallet-priv wal)))
    (multiple-value-bind (ok res err)
        (wallet-request wal ledger-id-hex "pay_invoice"
                        (w:json-object "descriptor" (wallet-descriptor wal) "invoice" bolt11 "payment_hash" (bytes->hex hash)
                                       "amount_msats" amount-msat "fee_msats" fee "nonce" (op:field o :nonce) "expiry" (op:field o :expiry)
                                       "witness" (w:json-object "stack" (coerce (mapcar #'bytes->hex (op:field o :witness)) 'vector)))
                        :timeout 40)
      (values ok (and ok (hex->bytes (w:jget res "preimage"))) err))))

;;; Completion scripts (DEP-09/13): sha256(H) opened by a preimage, pointlock(P)
;;; opened by the scalar s with s*G = P.

(defun completion-satisfied-p (script witness)
  (let ((arg (and (position #\( script) (position #\) script) (subseq script (1+ (position #\( script)) (position #\) script)))))
    (and witness (= 1 (length witness)) arg
         (cond ((search "sha256(" script) (equalp (sha256 (first witness)) (hex->bytes arg)))
               ((search "pointlock(" script)
                (let ((s (be->int (first witness))))
                  (and (= 32 (length (first witness))) (< 0 s secp256k1-fast:*secp256k1-n*)
                       (equalp (up:compressed-pubkey s) (hex->bytes arg)))))
               (t nil)))))

;;; Wallet: DEP-12 escalation through a quorum member

(defun wallet-escalate (wal member-ledger-hex request-hash target-ledger-hex target-operator-hex)
  "Ask a quorum member to anchor our unanswered request on its ledger.
   Returns the member's reply (sequence, tip_hash)."
  (multiple-value-bind (ok res err)
      (wallet-request wal member-ledger-hex "delivery_embed"
                      (w:json-object "request_hash" (bytes->hex request-hash) "target_ledger_id" target-ledger-hex
                                     "target_operator" target-operator-hex))
    (unless ok (fail "delivery_embed: ~a" err))
    res))

(defun wallet-lock-to (wal ledger-id-hex from to amount-msats hash &key (fee 0) (timeout-blocks 144) (height 0) point)
  "A TransferLock behind an externally chosen sha256 HASH, or a POINT (33 bytes)
   for a PTLC leg.  Returns the transfer id."
  (let* ((transfer-nonce (random-aux))
         (transfer-id (sha256 (cat transfer-nonce from to)))
         (o (list :type :transfer-lock :transfer-nonce transfer-nonce :source-deposit-id from :destination-deposit-id to
                  :amount amount-msats :fee fee
                  :completion-script (if point (format nil "pointlock(~a)" (bytes->hex point)) (format nil "sha256(~a)" (bytes->hex hash)))
                  :timeout-height (+ height timeout-blocks) :transfer-id transfer-id
                  :nonce (incf (wallet-nonce wal)) :expiry (+ height 144) :witness '())))
    (setf (getf o :witness) (d17:sign-operation o (wallet-priv wal)))
    (multiple-value-bind (ok res err)
        (wallet-request wal ledger-id-hex "transfer_lock" (w:json-object "operation" (base64-encode (op:encode-operation o))))
      (declare (ignore res))
      (unless ok (fail "transfer_lock: ~a" err))
      transfer-id)))

(defun wallet-pending-lock (node ledger-id-hex hash to-deposit &key point)
  "In a followed/replicated ledger, the pending TransferLock to TO-DEPOSIT behind HASH (or POINT), or NIL."
  (let ((rec (find-record node ledger-id-hex))
        (script (if point (format nil "pointlock(~a)" (bytes->hex point)) (format nil "sha256(~a)" (bytes->hex hash)))))
    (when rec
      (loop for tid being the hash-keys of (lg:ledger-pending-transfers (record-ledger rec)) using (hash-value p)
            when (and (equalp (getf p :destination) to-deposit) (string= (getf p :completion-script) script))
              return (list :transfer-id tid :amount (getf p :amount) :timeout-height (getf p :timeout-height) :source (getf p :source))))))

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

(defun lottery-seed (node id-hex)
  "Our lottery seed for a dispute on ID-HEX, derived from the node key so a
   restarted node recovers the preimage it committed to."
  (sha256 (cat (ascii->bytes "deposits/cl/lottery-seed/v1") (int->be (node-priv node) 32) (hex->bytes id-hex))))

(defun arm-dispute (node fork &key seed replacement)
  "Commit to our lottery preimage on our fork.  REPLACEMENT is (txid vout sats) or NIL."
  (let* ((n (dispute-lottery-n fork))
         (preimage (lot:derive-preimage (or seed (lottery-seed node (record-id-hex fork))) n)))
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
                       collect (list (up:update-operator-id u) (op:field o :commitment-hash) (op:field o :target-reserves)
                                     (and (op:field o :replacement-collateral-txid)
                                          (list (op:field o :replacement-collateral-txid) (op:field o :replacement-collateral-vout)
                                                (op:field o :replacement-collateral-amount)))))))

(defun collateral-floor-sats (base &key (claim-fee 400))
  "DEP-06: obligations x the ledger's collateral ratio, plus the claim fee."
  (let* ((l (record-ledger base))
         (obligations (floor (lg:total-obligations l) 1000))
         (ratio (if (plusp (lg:ledger-reserves-amount l)) (/ (lg:ledger-collateral-amount l) (lg:ledger-reserves-amount l)) 0)))
    (+ (ceiling (* obligations ratio)) claim-fee)))

(defun check-armer-collateral (node base armers)
  "Every armer that declared replacement collateral must have declared enough,
   and (when we have a chain view) it must exist, be unspent and confirmed."
  (let ((floor-sats (collateral-floor-sats base)))
    (loop for entry in armers
          for pk = (first entry) for coll = (fourth entry)
          do (when coll
               (destructuring-bind (txid vout sats) coll
                 (when (< sats floor-sats) (fail "armer ~a declared ~a sats, below the floor ~a" (subseq (bytes->hex pk) 0 8) sats floor-sats))
                 (when (node-chain-fn node)
                   (let ((info (funcall (node-chain-fn node) txid vout)))
                     (unless info (fail "armer ~a's collateral outpoint not found or spent" (subseq (bytes->hex pk) 0 8)))
                     (when (< (getf info :value-sats) sats) (fail "armer ~a's collateral outpoint is smaller than declared" (subseq (bytes->hex pk) 0 8)))
                     (when (< (getf info :confirmations) (node-min-confs node)) (fail "armer ~a's collateral is unconfirmed" (subseq (bytes->hex pk) 0 8))))))))))

(defun disputed-reserves (node rec)
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
                               :network (intern (string-upcase (node-network node)) :keyword))
            (op:field qb :new-outpoint-txid) (op:field qb :new-outpoint-vout)
            (floor (+ (op:field qb :amount) (op:field qb :collateral-amount)) 1000)
            operator)))

(defun confiscation-tier (reserves h)
  "The reserves tier a confiscation signs at height H: the lowest threshold whose
   CLTV has passed, never the operator's tie-breaker tier.  DEP-06 §Phase 2: a
   strict majority at Tier 0, a minority from quorum_expiry + 720, one member
   from + 4032.  Always signing Tier 0 meant a quorum short of a majority of
   armers could not confiscate even after the minority leaf opened."
  (let ((best 0))
    (loop for tier in (rs:reserves-tiers reserves) for i from 0
          when (and (not (rs:tier-tie-breaker-p tier)) (<= (rs:tier-locktime tier) h)
                    (< (rs:tier-threshold tier) (rs:tier-threshold (nth best (rs:reserves-tiers reserves)))))
            do (setf best i))
    best))

(defun build-confiscation (node id-hex &key respectful (fee 1000) tier-index)
  "The confiscation transaction for a disputed ledger, from public state only,
   so every cosigner rebuilds the same one.  It spends the reserves through
   TIER-INDEX (default: the tier open at our height), its nLockTime that tier's
   CLTV.  Returns (values tx lottery prevouts reserves tier-index)."
  (let* ((base (or (find-record node id-hex) (fail "unknown ledger")))
         (armers (sort (copy-list (armers-of node id-hex)) #'bytes< :key #'first))
         (voters (recovery-voters base))
         (threshold (lg:majority-threshold (length voters)))
         (participants (loop for (pk c target nil) in armers collect (lot:make-participant :pubkey (up:x-only pk) :commitment c :target target)))
         (lottery (lot:build-lottery participants voters threshold :network (intern (string-upcase (node-network node)) :keyword))))
    (when (< (length participants) 2) (fail "fewer than two armers"))
    (check-armer-collateral node base armers)
    (multiple-value-bind (reserves txid vout sats operator) (disputed-reserves node base)
      (let* ((tier-index (or tier-index (confiscation-tier reserves (height node))))
             (locktime (rs:tier-locktime (nth tier-index (rs:reserves-tiers reserves))))
             (outs (lot:confiscation-outputs (lot:lottery-spk lottery) sats fee :respectful respectful
                                             :obligations-sats (floor (lg:total-obligations (record-ledger base)) 1000)
                                             :operator-pubkey33 operator))
             (tx (btx:parse-tx (bw:make-reader
                                (btx:serialize-tx
                                 (btx:make-tx :version 2 :locktime locktime :segwit-p t
                                              :inputs (list (btx:make-txin :prev-hash txid :prev-index vout :script (octets) :sequence rot:+sequence-rbf+))
                                              :outputs (loop for (spk . v) in outs collect (btx:make-txout :value v :script spk))
                                              :witnesses (list nil)))))))
        (values tx lottery (vector (cons sats (rs:reserves-spk reserves))) reserves tier-index)))))

(defun confiscation-sighash (tx prevouts reserves &optional (tier-index 0))
  (rot:tier-sighash tx 0 prevouts (nth tier-index (rs:reserves-leaves reserves))))

(defun confiscate (node id-hex &key respectful (fee 1000))
  "Build the confiscation, gather the recovery quorum's tier-0 signatures over
   the relay (confiscation_sign), assemble, and broadcast.  Returns (values tx lottery)."
  (multiple-value-bind (tx lottery prevouts reserves tier-index) (build-confiscation node id-hex :respectful respectful :fee fee)
    (let* ((sighash (confiscation-sighash tx prevouts reserves tier-index))
           (tier (nth tier-index (rs:reserves-tiers reserves)))
           (keys (rs:tier-keys tier))
           (ours (schnorr:schnorr-sign (node-priv node) sighash (random-aux)))
           (sigs (list (cons (up:x-only (node-pubkey node)) ours)))
           (responses (send-request node id-hex "confiscation_sign"
                                    ;; The reference's field names: sighash, unsigned_tx, last_valid_sequence.
                                    (w:json-object "sighash" (bytes->hex sighash) "respectful" (and respectful t) "fee_sats" fee
                                                   "tier_index" tier-index
                                                   "unsigned_tx" (bytes->hex (btx:serialize-tx tx))
                                                   "last_valid_sequence" (lg:ledger-sequence (record-ledger (or (find-fork node id-hex (node-pubkey node)) (find-record node id-hex)))))
                                    :want (1- (rs:tier-threshold tier)) :timeout 20 :successes-only t)))
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
             (signed (rot:attach-tier-witness tx 0 reserves tier-index ordered)))
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
    (unless (find-fork node id (node-pubkey node))
      (log! node "confiscation_sign for ~a from ~a: we hold no fork, not answering" (subseq id 0 8) (subseq (ev:event-pubkey event) 0 8))
      (return-from handle-confiscation-sign nil))   ; not a disputant: not ours to answer
    (handler-case
        (let* ((proposed (btx:parse-tx (bw:make-reader (hex->bytes (or (w:jget params "unsigned_tx") (w:jget params "tx_hex") (fail "no unsigned_tx"))))))
               (outputs-total (reduce #'+ (btx:tx-outputs proposed) :key #'btx:txout-value))
               ;; The reference sends neither fee nor shape: read both off the proposed tx.
               (fee (or (w:jget params "fee_sats")
                        (- (nth-value 3 (disputed-reserves node (or (find-record node id) (fail "unknown ledger")))) outputs-total)))
               (respectful (let ((r (w:jget params "respectful"))) (if (eq r nil) (> (length (btx:tx-outputs proposed)) 1) r))))
          (multiple-value-bind (tx lottery prevouts reserves tier-index)
              ;; The proposer names its tier (the reference's `tier_index`; else the
              ;; one whose CLTV is the proposed nLockTime).  It must be open at our height.
              (let* ((reserves (disputed-reserves node (or (find-record node id) (fail "unknown ledger"))))
                     (tiers (rs:reserves-tiers reserves))
                     (ti (or (w:jget params "tier_index")
                             (position (btx:tx-locktime proposed) tiers :key #'rs:tier-locktime)
                             (fail "no tier has CLTV ~a" (btx:tx-locktime proposed)))))
                (unless (and (integerp ti) (< -1 ti (length tiers))) (fail "tier_index ~a out of range" ti))
                (when (rs:tier-tie-breaker-p (nth ti tiers)) (fail "the operator's tier is not a confiscation tier"))
                (when (> (rs:tier-locktime (nth ti tiers)) (height node))
                  (fail "tier ~a opens at ~a, we are at ~a" ti (rs:tier-locktime (nth ti tiers)) (height node)))
                (build-confiscation node id :respectful respectful :fee fee :tier-index ti))
            (let ((expected (confiscation-sighash proposed prevouts reserves tier-index)))
              (unless (equalp expected (hex->bytes (w:jget params "sighash")))
                (fail "sighash is not for the confiscation we expect (ours: sats ~a, reserves spk ~a, base seq ~a, outputs ~a)"
                      (car (aref prevouts 0)) (subseq (bytes->hex (cdr (aref prevouts 0))) 0 16)
                      (lg:ledger-sequence (record-ledger (find-record node id)))
                      (mapcar (lambda (o) (cons (btx:txout-value o) (subseq (bytes->hex (btx:txout-script o)) 0 12))) (btx:tx-outputs tx))))
              ;; Its txid does not depend on the witness: keep it, the claim spends it.
              (dolist (fork (forks-of node id)) (setf (record-lottery fork) lottery (record-confiscation fork) proposed))
              (log! node "signed confiscation of ~a proposed by ~a (fee ~a sats)" (subseq id 0 8) (subseq (ev:event-pubkey event) 0 8) fee)
              (respond node event t :result (w:json-object "signer" (node-pubkey-hex node)
                                                           "signature" (bytes->hex (schnorr:schnorr-sign (node-priv node) expected (random-aux))))))))
      (error (e) (log! node "refused confiscation_sign: ~a" e) (respond node event nil :error (princ-to-string e))))))

(defun publish-reveal (node id-hex)
  "Our preimage, both ways it travels: the durable Kind 9106 event, and the
   reference daemon's lottery_reveal request (which it fetches from the relay
   and matches to a participant by commitment hash; no reply expected)."
  (let* ((fork (or (find-fork node id-hex (node-pubkey node)) (fail "no fork")))
         (preimage (or (record-preimage fork) (fail "not armed")))
         (sig (schnorr:schnorr-sign (node-priv node) (w:reveal-message id-hex preimage) (random-aux))))
    (note-reveal node id-hex (node-pubkey node) preimage)
    (bus:bus-publish (node-bus node) (w:request-event (node-keypair node) id-hex "lottery_reveal"
                                                      (w:json-object "ledger_id" id-hex "preimage" (bytes->hex preimage))))
    (bus:bus-publish (node-bus node) (w:reveal-event (node-keypair node) (node-pubkey-hex node) id-hex preimage sig))))

(defun handle-lottery-reveal-request (node event params)
  "The reference's reveal: {ledger_id, preimage}, authored by the node's Nostr
   key (not the participant's key), so the participant is the armer whose
   commitment the preimage opens."
  (let* ((id (or (w:jget params "ledger_id") (w:event-ledger-id event)))
         (preimage (hex->bytes (or (w:jget params "preimage") (return-from handle-lottery-reveal-request nil))))
         (armer (and (find-record node id)
                     (find (lot:commitment-of preimage) (armers-of node id) :key #'second :test #'equalp))))
    (when armer
      (log! node "lottery reveal for ~a from ~a opens ~a's commitment" (subseq id 0 8) (subseq (ev:event-pubkey event) 0 8) (subseq (bytes->hex (first armer)) 0 8))
      (note-reveal node id (first armer) preimage))))

(defun note-reveal (node id-hex member33 preimage)
  (let ((alist (gethash id-hex (node-reveals node))))
    (unless (assoc member33 alist :test #'equalp)
      (setf (gethash id-hex (node-reveals node)) (cons (cons member33 preimage) alist))
      (save-reveals node id-hex))))

(defun reveals-file-name (id-hex) (format nil "reveals_~a.json" (subseq id-hex 0 16)))

(defun save-reveals (node id-hex)
  (when (node-data-dir node)
    (ensure-directories-exist (node-data-dir node))
    (with-open-file (out (merge-pathnames (reveals-file-name id-hex) (node-data-dir node)) :direction :output :if-exists :supersede)
      (format out "[~{~a~^,~%~}]~%"
              (mapcar (lambda (r) (format nil "[~s,~s]" (bytes->hex (car r)) (bytes->hex (cdr r)))) (reverse (gethash id-hex (node-reveals node))))))))

(defun load-reveals (node id-hex path)
  (let* ((text (uiop:read-file-string path))
         (strings (loop with pos = 0
                        for start = (position #\" text :start pos) while start
                        collect (let ((end (position #\" text :start (1+ start)))) (setf pos (1+ end)) (subseq text (1+ start) end)))))
    (loop for (m pre) on strings by #'cddr do (note-reveal node id-hex (hex->bytes m) (hex->bytes pre)))))

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
         (lottery (or (record-lottery fork)
                      ;; After a restart: rebuild from public state (the unsigned tx has the claim's
                      ;; txid).  Its nLockTime is its tier's CLTV, so take the tier whose rebuild is
                      ;; the one on chain; without a chain view, the tier open now.
                      (let ((n (length (rs:reserves-tiers (disputed-reserves node (find-record node id-hex))))))
                        (destructuring-bind (tx l &rest rest)
                            (or (and (node-chain-fn node)
                                     (loop for ti below n
                                           for built = (ignore-errors (multiple-value-list (build-confiscation node id-hex :tier-index ti)))
                                           when (and built (funcall (node-chain-fn node) (btx:tx-txid (first built)) 0))
                                             return built))
                                (multiple-value-list (build-confiscation node id-hex)))
                          (declare (ignore rest))
                          (setf (record-lottery fork) l (record-confiscation fork) tx)
                          l))))
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
               ;; Our declared replacement collateral (a key-path P2TR of our key) comes along as input 1.
               (coll (fourth (find (node-pubkey node) (armers-of node id-hex) :key #'first :test #'equalp)))
               (coll-spk (and coll (lot:key-path-spk (up:x-only (node-pubkey node)))))
               (inputs (append (list (btx:make-txin :prev-hash txid :prev-index 0 :script (octets) :sequence rot:+sequence-rbf+))
                               (and coll (list (btx:make-txin :prev-hash (first coll) :prev-index (second coll) :script (octets) :sequence rot:+sequence-rbf+)))))
               (total (+ amount (if coll (third coll) 0)))
               (tx (btx:parse-tx (bw:make-reader
                                  (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t :inputs inputs
                                                                 :outputs (list (btx:make-txout :value (- total fee) :script spk))
                                                                 :witnesses (make-list (length inputs) :initial-element nil))))))
               (prevouts (coerce (append (list (cons amount (lot:lottery-spk lottery))) (and coll (list (cons (third coll) coll-spk)))) 'vector))
               (sig (schnorr:schnorr-sign (node-priv node) (rot:tier-sighash tx 0 prevouts (first (lot:lottery-leaves lottery))) (random-aux)))
               (witnesses (append (list (lot:claim-witness lottery sig preimages))
                                  (and coll (list (list (key-path-signature node tx 1 prevouts))))))
               (signed (btx:parse-tx (bw:make-reader
                                      (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t :inputs (btx:tx-inputs tx) :outputs (btx:tx-outputs tx)
                                                                     :witnesses witnesses))))))
          (dotimes (i (length inputs))
            (unless (rot:verify-spend signed i prevouts) (fail "claim input ~a does not verify" i)))
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

;;; Respectful disputes: the quorum expired and the operator has not rotated.

(defun expired-quorum-p (node rec h grace)
  "REC is a ledger we cosign whose quorum_expiry is more than GRACE blocks behind H."
  (let ((ledger (record-ledger rec)))
    (and (not (record-owned-p rec)) (not (record-fork-p rec))
         (lg:ledger-quorum-expiry ledger) (> h (+ (lg:ledger-quorum-expiry ledger) grace))
         (member (node-pubkey node) (lg:ledger-quorum-members ledger) :key #'lg:member-pubkey :test #'equalp)
         (not (find-fork node (record-id-hex rec) (node-pubkey node))))))

(defun check-expired-quorums (node &key anchor-block-hash (grace 0) skip)
  "For every ledger we cosign whose quorum_expiry is more than GRACE blocks behind
   the chain tip (and whose id is not in SKIP), publish a QuorumExpired proof and
   open a dispute fork.  Returns the ledger ids disputed."
  (let ((h (height node)) (disputed '()))
    (loop for rec being the hash-values of (node-ledgers node)
          for ledger = (record-ledger rec)
          when (and (expired-quorum-p node rec h grace) (not (member (record-id-hex rec) skip :test #'equal)))
            do (let ((proof (fr:make-quorum-expired-proof (lg:ledger-operator-key ledger) (hex->bytes (record-id-hex rec))
                                                          (or anchor-block-hash (make-array 32 :element-type '(unsigned-byte 8)))
                                                          (lg:ledger-quorum-expiry ledger))))
                 (broadcast-fraud node proof)
                 (unless (find-fork node (record-id-hex rec) (node-pubkey node))
                   (enter-dispute node rec (lg:ledger-sequence ledger) :reason "quorum_expired"
                                  :anchor-block-hash anchor-block-hash :anchor-block-height h))
                 (push (record-id-hex rec) disputed)))
    disputed))

;;; ---------------------------------------------------------------------------
;;; Collateral wallet: the node key's own P2TR (our-target-address) holds the
;;; UTXOs a disputant pledges as replacement collateral (DEP-06 Phase 1).
;;; Discovery goes through UTXOS-FN (bitcoind scantxoutset: no bitcoind wallet);
;;; a pledge is a whole UTXO declared at its full value, because the winner's
;;; claim signs that input for exactly the declared amount; pledges persist in
;;; the data dir so a restart never pledges one UTXO to two disputes.

(defparameter *reference-claim-fee-sats* 5000
  "The reference cosigner's claim_fee_estimate: its floor is the stricter of the two.")

(defun required-replacement-sats (base)
  "What a pledge on BASE must cover to pass every cosigner: our floor and the
   reference's (obligations x collateral/reserves, rounded up, + 5000 sats)."
  (let* ((l (record-ledger base))
         (reserves (lg:ledger-reserves-amount l))
         (theirs (if (plusp reserves)
                     (+ (ceiling (* (lg:total-obligations l) (lg:ledger-collateral-amount l)) (* reserves 1000))
                        *reference-claim-fee-sats*)
                     0)))
    (max theirs (collateral-floor-sats base))))

(defun outpoint-key (txid vout) (format nil "~a:~a" (txid-hex txid) vout))

(defun save-pledges (node)
  (when (node-data-dir node)
    (with-open-file (out (merge-pathnames "pledges.sexp" (node-data-dir node)) :direction :output :if-exists :supersede)
      (with-standard-io-syntax
        (prin1 (loop for k being the hash-keys of (node-pledges node) using (hash-value v) collect (cons k v)) out)))))

(defun load-pledges (node)
  (let ((f (and (node-data-dir node) (probe-file (merge-pathnames "pledges.sexp" (node-data-dir node))))))
    (when f
      (with-open-file (in f)
        (dolist (p (with-standard-io-syntax (let ((*read-eval* nil)) (read in nil '()))))
          (setf (gethash (car p) (node-pledges node)) (cdr p)))))))

(defun release-pledges (node id-hex)
  (loop for k being the hash-keys of (node-pledges node) using (hash-value v)
        when (equal v id-hex) do (remhash k (node-pledges node)))
  (save-pledges node))

(defun our-utxos (node)
  "Our P2TR's UTXOs, each a plist :txid (wire order) :vout :sats :confirmations."
  (and (node-utxos-fn node) (funcall (node-utxos-fn node) (our-target-address node))))

(defun consolidate-utxos (node utxos &key (sat-per-vb 2))
  "Key-path spend of UTXOS into one output back to us.  Returns (values txid vout sats)."
  (let* ((spk (lot:key-path-spk (up:x-only (node-pubkey node))))
         (total (reduce #'+ utxos :key (lambda (u) (getf u :sats))))
         (fee (* sat-per-vb (+ 11 (* 58 (length utxos)) 43)))
         (inputs (loop for u in utxos collect (btx:make-txin :prev-hash (getf u :txid) :prev-index (getf u :vout) :script (octets) :sequence rot:+sequence-rbf+)))
         (unsigned (btx:parse-tx (bw:make-reader
                                  (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t :inputs inputs
                                                                 :outputs (list (btx:make-txout :value (- total fee) :script spk))
                                                                 :witnesses (make-list (length inputs) :initial-element nil))))))
         (prevouts (coerce (loop for u in utxos collect (cons (getf u :sats) spk)) 'vector))
         (signed (btx:parse-tx (bw:make-reader
                                (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t :inputs (btx:tx-inputs unsigned)
                                                               :outputs (btx:tx-outputs unsigned)
                                                               :witnesses (loop for i below (length inputs)
                                                                                collect (list (key-path-signature node unsigned i prevouts)))))))))
    (dotimes (i (length inputs))
      (unless (rot:verify-spend signed i prevouts) (fail "consolidation input ~a does not verify" i)))
    (broadcast node signed)
    (values (btx:tx-txid signed) 0 (- total fee))))

(defun pledge-collateral (node id-hex)
  "A confirmed UTXO of ours, pledged to ID-HEX, covering its required replacement
   collateral: (txid vout sats), or NIL.  When no single UTXO is large enough but
   together they are, consolidate them (the result is pledgeable once confirmed)
   and return NIL for now; a pledge already made for ID-HEX is returned again."
  (let ((mine (loop for k being the hash-keys of (node-pledges node) using (hash-value v) when (equal v id-hex) collect k))
        (utxos (our-utxos node)))
    (when mine
      (let ((u (find (first mine) utxos :key (lambda (u) (outpoint-key (getf u :txid) (getf u :vout))) :test #'equal)))
        (when u (return-from pledge-collateral (list (getf u :txid) (getf u :vout) (getf u :sats))))
        (remhash (first mine) (node-pledges node))))           ; spent or gone: pledge afresh
    (let* ((need (required-replacement-sats (or (find-record node id-hex) (fail "unknown ledger"))))
           ;; Anything we declared in a DisputeArmed is taken, recorded or not (an arm
           ;; made by hand on the control socket, or before pledges were kept).
           (declared (loop for r being the hash-values of (node-ledgers node)
                           when (and (record-fork-p r) (record-owned-p r))
                             append (loop for u in (record-history r)
                                          for o = (op:decode-operation (up:update-message u))
                                          when (and (eq (op:operation-type o) :dispute-armed) (op:field o :replacement-collateral-txid))
                                            collect (outpoint-key (op:field o :replacement-collateral-txid) (op:field o :replacement-collateral-vout)))))
           (free (remove-if (lambda (u) (let ((k (outpoint-key (getf u :txid) (getf u :vout))))
                                          (or (< (getf u :confirmations) (max 1 (node-min-confs node)))
                                              (gethash k (node-pledges node)) (member k declared :test #'equal))))
                            utxos))
           (fits (sort (remove-if (lambda (u) (< (getf u :sats) need)) free) #'< :key (lambda (u) (getf u :sats)))))
      (cond (fits
             (let ((u (first fits)))
               (setf (gethash (outpoint-key (getf u :txid) (getf u :vout)) (node-pledges node)) id-hex)
               (save-pledges node)
               (list (getf u :txid) (getf u :vout) (getf u :sats))))
            ((and (rest free) (>= (reduce #'+ free :key (lambda (u) (getf u :sats))) (+ need 1000)))
             (multiple-value-bind (txid vout sats) (consolidate-utxos node free)
               (log! node "collateral for ~a: consolidated ~a UTXOs into ~a:~a (~a sats), pledgeable once confirmed"
                     (subseq id-hex 0 8) (length free) (txid-hex txid) vout sats))
             nil)
            (t (log! node "collateral for ~a: need ~a sats at ~a, have ~a unpledged"
                     (subseq id-hex 0 8) need (our-target-address node) (reduce #'+ free :key (lambda (u) (getf u :sats))))
               nil)))))

;;; Key-path Taproot spend of our own P2TR (replacement collateral inputs).

(defun key-path-signature (node tx in-index prevouts)
  "BIP-341 key-path signature for input IN-INDEX under our tweaked key."
  (let* ((xonly (up:x-only (node-pubkey node)))
         (tweak (cl-consensus.wallet::taproot-tweak xonly))
         (d (mod (+ (node-priv node) tweak) secp256k1-fast:*secp256k1-n*))
         (sighash (cl-consensus.script:taproot-sighash tx in-index prevouts 0 :ext-flag 0)))
    (multiple-value-bind (spk parity) (lot:p2tr-spk xonly (octets))
      (declare (ignore spk))
      (schnorr:schnorr-sign (if (= parity 1) (- secp256k1-fast:*secp256k1-n* d) d) sighash (random-aux)))))

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
          (fr:verify-proof proof :history (reverse (record-history rec))
                           :height-of-block (or (node-height-of-block node)
                                                ;; no chain view: trust our own tip for the anchor
                                                (lambda (hash) (declare (ignore hash)) (height node))))
        (if ok
            (let ((last-valid (min (lg:ledger-sequence (record-ledger rec))
                                   (case (getf proof :type)
                                     ((:equivocation :non-conforming-update) (1- (getf (getf proof :evidence) (if (eq (getf proof :type) :equivocation) :sequence :fault-sequence))))
                                     (t (lg:ledger-sequence (record-ledger rec)))))))
              (log! node "fraud proof ~a on ~a verified: disputing from seq ~a" (getf proof :type) (subseq id 0 8) last-valid)
              (enter-dispute node rec last-valid
                             ;; snake_case, as the reference writes and matches it
                             ;; ("quorum_expired", dispute.rs); "quorum-expired" made our
                             ;; expiry disputes unrecognisable, to it and to our own driver.
                             :reason (substitute #\_ #\- (string-downcase (symbol-name (getf proof :type))))))
            (log! node "fraud proof rejected: ~a" why))))))

;;; ---------------------------------------------------------------------------
;;; Persistence: the fixture format — a JSON array of base64 updates, oldest first.

(defun record-file-name (rec)
  (if (record-fork-p rec)
      (format nil "ledger_~a_fork_~a.json" (subseq (record-id-hex rec) 0 16) (subseq (bytes->hex (record-fork-operator rec)) 0 16))
      (format nil "ledger_~a.json" (subseq (record-id-hex rec) 0 16))))

(defun save-record (node rec)
  "Persist the history as a JSON array of base64 updates, one per line.  The
   common case — one new update on a file we wrote — APPENDS inside the closing
   bracket; rewriting the whole file per update was O(sequence) and at seq 1800
   (a 5.7 MB file, six updates a second across the ledgers a node replicates)
   it pegged a core in base64 alone."
  (when (and *deferred-saves* (not (member rec (car *deferred-saves*))))
    (push rec (car *deferred-saves*)))
  (when (and (node-data-dir node) (not *deferred-saves*))
    (ensure-directories-exist (node-data-dir node))
    (let* ((path (merge-pathnames (record-file-name rec) (node-data-dir node)))
           (n (length (record-history rec)))
           (appendable (and (plusp (record-persisted rec)) (= n (1+ (record-persisted rec))) (probe-file path)
                            (with-open-file (in path :external-format :latin-1)
                              (and (> (file-length in) 2)
                                   (progn (file-position in (- (file-length in) 2))
                                          (and (char= (read-char in) #\]) (char= (read-char in) #\Newline))))))))
      (if appendable
          (with-open-file (out path :direction :output :if-exists :overwrite :external-format :latin-1)
            (file-position out (- (file-length out) 2))
            (format out ",~%~s]~%" (base64-encode (up:encode-update (first (record-history rec))))))
          ;; Whole file: write beside it and rename.  SBCL DELETES a :supersede
          ;; target when the write is aborted — and a node killed mid-write (or
          ;; an error inside FORMAT) aborts it: that is how replicas vanished.
          (let ((tmp (make-pathname :type "tmp" :defaults path)))
            (with-open-file (out tmp :direction :output :if-exists :supersede :external-format :latin-1)
              (format out "[~{~s~^,~%~}]~%" (mapcar (lambda (u) (base64-encode (up:encode-update u))) (reverse (record-history rec)))))
            (uiop:rename-file-overwriting-target tmp path)))
      (setf (record-persisted rec) n))))

(defun load-record (node path &key owned-p)
  "Rebuild a record from a saved (or fixture) file, validating as we go.  A
   fork file (ledger_<id>_fork_<op>.json) becomes a fork record of its base,
   which must already be loaded."
  (let* (;; One entry per line, streamed: slurping an 84 MB file into a Lisp
         ;; string (4 bytes a character, then a SUBSEQ copy) blew a 1 GB heap
         ;; at startup.  A node killed mid-append leaves a truncated last entry:
         ;; keep what decodes, drop the tail, catch-up refills it from the relay.
         (clean t)   ; NIL if we stopped before the end: the file must be REWRITTEN, never appended to
         (updates (with-open-file (in path :external-format :latin-1)
                    (loop for line = (read-line in nil nil) while line
                          for start = (position #\" line)
                          for end = (and start (position #\" line :start (1+ start)))
                          for u = (and end (handler-case (up:decode-update (base64-decode (subseq line (1+ start) end)))
                                             (error () nil)))
                          for closing = (string= (string-trim '(#\Space #\Return #\Tab) line) "]")
                          while (or u (and closing (not (read-line in nil nil))))   ; a lone "]" as the last line
                          when u collect u
                          finally (unless (or u closing) (setf clean nil)))))
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
    ;; An entry that does not chain (a gap or a bad update mid-file, from a
    ;; rewrite of a history that was itself loaded past damage) ends the load
    ;; there, like a damaged tail: keep the prefix, rewrite, catch up.
    ;;
    ;; Our own data dir holds only what we validated before persisting it, so by
    ;; default a load re-applies without re-verifying signatures (CLD_VERIFY_ON_LOAD
    ;; restores the full check) and never writes: ACCEPT-UPDATE's SAVE-RECORD
    ;; rewrote the file being loaded from its first entry and then appended every
    ;; other one, one open-seek-write each.  With a million updates across the
    ;; soak's replicas and forks, that and ~2M Schnorr verifications made a
    ;; restart take 20 minutes.
    (let ((*deferred-saves* (list nil)))
     (dolist (u updates)
      (when (> (up:update-seq u) (lg:ledger-sequence (record-ledger rec)))   ; a fork file's inherited prefix: skipped
        (handler-case
            (cond ((and (record-owned-p rec) (not fork-p))
                   (lg:apply-update (record-ledger rec) u) (push u (record-history rec)))
                  (*verify-on-load* (accept-update node rec u))
                  (t (when (and fork-p (not (equalp (up:update-operator-id u) (record-fork-operator rec))))
                       (fail "fork update not signed by the fork's operator"))
                     (lg:apply-update (record-ledger rec) u) (push u (record-history rec))))
          (error (e)
            (log! node "~a: entry at seq ~a does not apply (~a); keeping ~a entries"
                  (file-namestring path) (up:update-seq u) e (length (record-history rec)))
            (setf clean nil) (return))))))
    (unless fork-p (setf (gethash (record-id-hex rec) (node-ledgers node)) rec))
    (setf (record-persisted rec) (if clean (length (record-history rec)) 0))   ; a damaged file is rewritten whole on the next save
    (unless clean (log! node "~a: damaged after seq ~a; will rewrite, catch-up refills the rest" (file-namestring path) (lg:ledger-sequence (record-ledger rec))))
    (when (and owned-p (not fork-p) (null (node-member-ledger-hex node)))
      (setf (node-member-ledger-hex node) (record-id-hex rec)))
    ;; Our own fork, armed before the restart: the preimage is re-derivable.
    (when (and fork-p (record-owned-p rec))
      (let ((armed (find :dispute-armed (record-history rec) :key (lambda (u) (op:operation-type (op:decode-operation (up:update-message u)))))))
        (when armed
          (let ((preimage (lot:derive-preimage (lottery-seed node id-hex) (dispute-lottery-n rec))))
            (if (equalp (lot:commitment-of preimage) (op:field (op:decode-operation (up:update-message armed)) :commitment-hash))
                (setf (record-preimage rec) preimage)
                (log! node "fork ~a: armed with a preimage we cannot re-derive" (subseq id-hex 0 8)))))))
    rec))

(defun load-data-dir (node &key (log-fn (lambda (fmt &rest args) (apply #'log! node fmt args))))
  "Reload everything we knew: our ledgers, the ones we cosign, forks, reveals."
  (let* ((dir (node-data-dir node))
         (log-lock (bt:make-lock "load-log"))
         (files (directory (merge-pathnames "ledger_*.json" dir))))
    (flet ((load-one (f)
             (handler-case
                 (let* ((first (with-open-file (in f) (read-line in)))
                        (u (up:decode-update (base64-decode (string-trim '(#\[ #\" #\, #\Space) first))))
                        (owned (equalp (up:update-operator-id u) (node-pubkey node)))
                        (fork-op (let ((i (search "_fork_" (file-namestring f)))) (and i (subseq (file-namestring f) (+ i 6) (+ i 22)))))
                        (rec (load-record node f :owned-p owned)))
                   (bt:with-lock-held (log-lock)
                     (funcall log-fn "loaded ~a (~a)" (file-namestring f)
                              (cond ((and fork-op (record-owned-p rec)) "our fork") (fork-op "their fork") (owned "ours") (t "replica")))))
               (error (e) (bt:with-lock-held (log-lock) (funcall log-fn "could not load ~a: ~a" f e))))))
      ;; Bases, then forks (a fork is built from its base), each set in parallel:
      ;; the files are independent and a restart waited on them one at a time.
      (dolist (set (list (remove-if (lambda (f) (search "_fork_" (file-namestring f))) files)
                         (remove-if-not (lambda (f) (search "_fork_" (file-namestring f))) files)))
        (mapc #'bt:join-thread
              (mapcar (lambda (f) (bt:make-thread (lambda () (load-one f)) :name "cld-load")) set))))
    (dolist (f (directory (merge-pathnames "reveals_*.json" dir)))
      (let* ((prefix (subseq (pathname-name f) 8))
             (id (loop for k being the hash-keys of (node-ledgers node) when (and (>= (length k) 16) (string= prefix (subseq k 0 16))) return k)))
        (if id
            (handler-case (load-reveals node id f) (error (e) (funcall log-fn "could not load ~a: ~a" f e)))
            (funcall log-fn "reveals file ~a for a ledger we do not hold" (file-namestring f)))))
    (handler-case (load-pledges node) (error (e) (funcall log-fn "could not load pledges: ~a" e)))
    node))
