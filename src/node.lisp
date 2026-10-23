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
  (:local-nicknames (#:cf #:cl-deposits.conformance) (#:up #:cl-deposits.update) (#:op #:cl-deposits.operation)
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
           #:node-chain-fn #:node-pledge-fn #:lottery-armers #:split-armers #:eligibility-floor-sats #:node-min-confs #:node-data-dir #:record-pinned #:height #:tip
           #:node-error #:request #:wallet #:make-wallet #:wallet-pubkey #:wallet-request
           #:wallet-open-deposit #:wallet-balance #:wallet-transfer #:wallet-complete-transfer #:wallet-exit #:wallet-exit-cancel #:wallet-migrate #:wallet-make-offer #:wallet-complete-offer #:address->spk
           #:wallet-make-invoice #:wallet-pay-invoice #:credit-paid-invoices #:settle-pending-payments #:start-invoice-poller #:node-ln #:node-invoices
           #:enter-dispute #:arm-dispute #:fork-key #:find-fork #:forks-of #:armers-of #:disputed-reserves
           #:rotate-vault #:pending-rotation #:build-confiscation #:confiscate #:publish-reveal #:reveals-of #:claim-or-yield #:node-broadcast-fn
           #:node-broadcasts #:broadcast-fraud #:record-fork-p #:record-preimage #:record-lottery #:record-confiscation
           #:node-height-of-block #:fork-live-p #:live-fork #:fork-summaries #:equivocate #:node-spender-fn #:drive-vault-watch #:node-reported-vault-spend
           #:check-expired-quorums #:collateral-floor-sats #:follow-ledger #:wallet-escalate #:node-ignore-actions #:wallet-request-hash #:wallet-lock-to
           #:node-hooks #:add-hook #:wallet-pending-lock #:completion-satisfied-p #:node-busy
           #:save-record #:load-record #:load-data-dir #:stop-node #:lottery-seed #:*cosign-timeout* #:*cosign-response-seconds* #:*drive-dispute-async* #:inbox-depths #:catch-up #:catch-up-all #:fail-expired-transfers #:start-transfer-timeout-poller #:node-adversary
           #:dispute-expired-quorums #:start-expiry-watch #:*expiry-grace-blocks*
           #:required-replacement-sats #:pledge-collateral #:release-pledges #:our-utxos #:node-pledges
           #:drive-disputes #:dispute-arm-closes #:outpoint-key #:save-pledges
           #:vault-spend #:build-vault-theft))
(in-package #:cl-deposits.node)

(define-condition node-error (error)
  ((detail :initarg :detail :reader detail))
  (:report (lambda (c s) (format s "node: ~a" (detail c)))))
(defun fail (fmt &rest args) (error 'node-error :detail (apply #'format nil fmt args)))

(defparameter *cosign-timeout* 10 "Seconds to wait for a cosignature quorum.")
(defparameter *cosign-response-seconds* 30
  "DEP-05 cosign_response_seconds (advisory): how long a member has to answer a cosign request,
   and so the least an operator waits before calling a round short.")
(defparameter *cosign-round-keep* (* 30 60)
  "Seconds a round that fell short is kept for late answers and retries (DEP-05 §Cosign Rounds).")

(defstruct record
  id-hex ledger (history '()) owned-p reserves
  pinned                                       ; (reserves . expiry) prepared for the next QuorumBegin
  fork-p fork-of fork-operator                 ; a dispute fork: of which ledger, signed by whom
  last-event-id                                ; Nostr id of the last update we published
  (persisted 0)                                ; how many history entries the file on disk holds (append-only save)
  (append-lock (bt:make-lock "append"))        ; one append at a time per owned ledger, cosign wait included
  preimage lottery confiscation                ; our lottery secret; the built lottery; the confiscation tx
  rotation                                     ; broadcast rotation awaiting its QuorumBegin (plist; persisted)
  (offers (make-hash-table :test #'equalp)))   ; DEP-10 funding offers we made: offer id -> plist

(defstruct (node (:constructor %make-node))
  priv pubkey pubkey-hex keypair bus network
  (ledgers (make-hash-table :test #'equal :synchronized t))    ; ledger id hex -> record (both lanes add records)
  (pending (make-hash-table :test #'equal))    ; request event id -> waiter
  ;; DEP-05 §Cosign Rounds: cosign_data -> cosign-round, kept past the deadline, and the
  ;; request ids whose (late) answers feed each one.
  (cosign-rounds (make-hash-table :test #'equalp :synchronized t))
  (late-cosign-requests (make-hash-table :test #'equal :synchronized t))
  ;; DEP-03 "When the set is final": ledger id -> the block its confiscation confirmed in.
  (confiscation-heights (make-hash-table :test #'equal :synchronized t))
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
  (loading nil)                                ; T until LOAD-DATA-DIR has run: the worker lanes wait
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
  ;; Payment ids a pay_invoice handler is polling right now; SETTLE-PENDING-PAYMENTS
  ;; leaves those to the handler so a lock is never settled twice.
  (ln-polling (make-hash-table :test #'equalp :synchronized t))
  (chain-fn nil)                               ; (lambda (txid vout)) -> plist :value-sats :confirmations, or NIL
  (pledge-fn nil)                              ; (lambda (txid vout scan-from)) -> plist :created :value-sats :spend (DEP-03 cut), or NIL
  (utxos-fn nil)                               ; (lambda (address)) -> list of plists :txid :vout :sats :confirmations
  (pledges (make-hash-table :test #'equal :synchronized t))   ; "txidhex:vout" -> ledger id hex we pledged it to
  (dispute-notes (make-hash-table :test #'equal))   ; ledger id -> the last dispute-driver state we logged
  (refused (make-hash-table :test #'equal :synchronized t))   ; ledger id -> seq whose update the rules rejected
  (spender-fn nil)                             ; (lambda (from to outpoints)) -> spend plists (:txid :vout :tx :prevouts :block-hash :height)
  (feerate-fn nil)                             ; (lambda (height)) -> block feerate (DEP-03 Reference feerate)
  (vault-scanned nil)                          ; the last block height scanned for vault spends
  (reported-vault-spend (make-hash-table :test (quote equal) :synchronized t))
  (migrations-watched (make-hash-table :test (quote equal) :synchronized t)) ; "ledger:seq" -> (:height h :hash b) | :done
  (obligation-proofs (make-hash-table :test (quote equal) :synchronized t))  ; ledger id hex -> verified offer-evidence proof JSON texts
  ;; ledger id hex -> txids of confiscations we saw confirmed.  Kept apart from the forks: a fork
  ;; forgets its confiscation once the lottery output is spent (the winner's claim), and the vault
  ;; watch must still excuse it.  Persisted in confiscations.txt.
  (known-confiscations (make-hash-table :test (quote equal) :synchronized t))
  ;; ledger id hex -> ((tx . lottery) ...): every confiscation proposal we signed.  Two
  ;; proposers can race (cl and reference); whichever lands is one we verified.
  (signed-confiscations (make-hash-table :test (quote equal) :synchronized t))
  (signed-rotations (make-hash-table :test (quote equal) :synchronized t))   ; ledger id hex -> rotation txids we signed
  (inflight-rotations (make-hash-table :test (quote equalp) :synchronized t)) ; rung-0 txid -> (:rungs signed bytes :qb-height h), rebroadcast and bumped until one confirms
  (spend-answers (make-hash-table :test (quote equal) :synchronized t))   ; ledger id hex -> updates answering spend challenges (Kind 9112)
  ;; ledger id hex -> proposed confiscation txs we received, signed or not: a proposal we
  ;; refused (a different view of the cut, a fee we would not pick) may be the one that lands.
  (seen-confiscations (make-hash-table :test (quote equal) :synchronized t))
  ;; (accused spent-ledger spend-tx governing-seq) -> (universal-time ok why): one theft yields a proof
  ;; per signer, key parity and operated ledger, and verifying fetches the spent ledger's history
  (vault-spend-verdicts (make-hash-table :test (quote equal) :synchronized t))
  (derelict-watch (make-hash-table :test (quote equal) :synchronized t))
  (reported-derelict (make-hash-table :test (quote equal) :synchronized t))
  (min-confs 1)
  (member-ledger-hex nil))                     ; our own ledger used for QuorumJoin / member_ledger_hash

(defvar *log-file-lock* (bt:make-lock "node.log"))
(defun log! (node fmt &rest args)
  ;; One line per entry: the control socket is line-oriented.  With a data dir it is also
  ;; appended to node.log there, timestamped, so it outlives a restart.
  (let ((line (substitute #\Space #\Newline (apply #'format nil fmt args))))
    (push line (node-log node))
    (when (node-data-dir node)
      (ignore-errors
       (bt:with-lock-held (*log-file-lock*)
         (with-open-file (s (merge-pathnames "node.log" (node-data-dir node))
                            :direction :output :if-exists :append :if-does-not-exist :create)
           (multiple-value-bind (sec min hr d mo y) (decode-universal-time (get-universal-time) 0)
             (format s "~d-~2,'0d-~2,'0dT~2,'0d:~2,'0d:~2,'0dZ ~a~%" y mo d hr min sec line))))))))

(defun add-hook (node fn) (push fn (node-hooks node)))
(defun extra-actions (node)
  "Actions registered by roles layered on the node (couriers), addressed to us by p tag."
  (or (get (intern (node-pubkey-hex node) :keyword) 'actions)
      (setf (get (intern (node-pubkey-hex node) :keyword) 'actions) (make-hash-table :test #'equal))))
(defun run-hooks (node rec update)
  (let ((o (op:decode-operation (up:update-message update))))
    (dolist (h (node-hooks node)) (handler-case (funcall h rec update o) (error (e) (log! node "hook: ~a" e))))))

(defun make-node (&key priv bus (network "signet") height-fn data-dir chain-fn pledge-fn spender-fn utxos-fn (min-confs 1) ln relays broadcast-fn height-of-block block-hash-fn feerate-fn)
  (let* ((priv (w:even-y-privkey priv))
         (pub (up:compressed-pubkey priv))
         (node (%make-node :priv priv :pubkey pub :pubkey-hex (bytes->hex pub)
                           :keypair (w:nostr-keypair priv) :bus bus :network network
                           :height-fn (or height-fn (lambda () 0)) :data-dir data-dir
                           :chain-fn chain-fn :pledge-fn pledge-fn :spender-fn spender-fn :utxos-fn utxos-fn :min-confs min-confs :ln ln :relays relays
                           :feerate-fn feerate-fn
                           :broadcast-fn broadcast-fn :height-of-block height-of-block :block-hash-fn block-hash-fn
                           ;; We subscribe below, before the caller loads the data dir.  A
                           ;; cosign request handled then found no record, took the ledger
                           ;; for a replica we had lost, and rebuilt it from the relay: 80k
                           ;; updates, racing the load, through every fork's updates too.
                           :loading (and data-dir t))))
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
                                                              w:+kind-fraud-proof+ w:+kind-lottery-reveal+ w:+kind-rotation-tx+
                                                              w:+kind-spend-challenge+ w:+kind-challenge-answer+)
                                                  :since (if (bus:bus-async-p bus) (- (get-universal-time) 2208988800 60) nil))
                             (lambda (event)
                               (cond ((or (null (node-worker node)) (= (ev:event-kind event) w:+kind-response+))
                                      (handle-event node event))
                                     ((replica-lane-event-p event) (enqueue-fast node event))
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
  (loop while (node-loading node) do (sleep 0.1))   ; see make-node
  (loop
    (let ((event (bt:with-lock-held ((node-inbox-lock node))
                   (loop until (node-inbox node) do (bt:condition-wait (node-inbox-cv node) (node-inbox-lock node)))
                   (setf (node-busy node) t)
                   (pop (node-inbox node)))))
      (unwind-protect (handle-event node event) (setf (node-busy node) nil)))))

(defun cosign-request-event-p (event)
  (and (= (ev:event-kind event) w:+kind-request+) (equal (w:event-action event) "cosign_update")))

(defun replica-lane-event-p (event)
  "Events the replica lane (the cosigner thread) handles: updates, which it applies to the
   replicas, and the member requests that read a replica and must see it between updates,
   never during one.  rotation_sign rebuilds the ladder from the replica: on the main worker it
   raced the replica lane applying the QuorumBegin it names, read the new vault as the one being
   spent and refused an honest rotation (signet soak, 2026-10-22)."
  (or (= (ev:event-kind event) w:+kind-update+)
      (and (= (ev:event-kind event) w:+kind-request+)
           (member (w:event-action event) '("cosign_update" "rotation_sign") :test #'equal))))

(defun fast-event-ledger (event)
  "The ledger an event on the replica lane concerns, by its 16-hex prefix: an update's d
   tag, a request's l tag."
  (let ((id (if (= (ev:event-kind event) w:+kind-update+) (w:event-d-tag event) (w:event-ledger-id event))))
    (and id (>= (length id) 16) (subseq id 0 16))))

(defun enqueue-fast (node event)
  ;; DEP-05 §Cosign Rounds: a member SHOULD answer cosign requests ahead of other relay
  ;; traffic.  A cosign request goes ahead of everything queued except earlier cosign
  ;; requests and its own ledger's events (the updates it chains onto, see the lane note
  ;; on NODE).  Behind a burst of other ledgers' updates it missed the operator's window.
  (bt:with-lock-held ((node-fast-lock node))
    (setf (node-fast-inbox node)
          (if (cosign-request-event-p event)
              (let* ((inbox (node-fast-inbox node)) (ledger (fast-event-ledger event))
                     (after (position-if (lambda (e) (or (cosign-request-event-p e) (equal (fast-event-ledger e) ledger)))
                                         inbox :from-end t)))
                (if after
                    (append (subseq inbox 0 (1+ after)) (list event) (nthcdr (1+ after) inbox))
                    (cons event inbox)))
              (append (node-fast-inbox node) (list event))))
    (bt:condition-notify (node-fast-cv node))))

(defun fast-worker-loop (node)
  ;; Replicas are applied and read here only; the main worker mutates owned
  ;; records.  What the two share (the seen table, the ledgers table) is locked.
  (loop while (node-loading node) do (sleep 0.1))   ; see make-node
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

(defstruct waiter (lock (bt:make-lock)) (cv (bt:make-condition-variable)) (responses '()) (done nil) want (successes-only nil) (ids '()) (counts nil)
  (settled nil))                               ; (lambda (responses)): nothing more is coming

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
                      (and (waiter-settled wt) (funcall (waiter-settled wt) (waiter-responses wt)))
                      (> (get-internal-real-time) deadline))
            do (bt:condition-wait (waiter-cv wt) (waiter-lock wt) :timeout 0.2)))
    (remhash request-id (node-pending node))
    (reverse (waiter-responses wt))))

(defun send-request (node ledger-id-hex action params &key (want 1) (timeout *cosign-timeout*) extra-tags successes-only counts
                                                           settled on-publish)
  "Publish a Kind 20101 request and collect WANT Kind 20102 responses (successful
   ones when SUCCESSES-ONLY; those satisfying COUNTS when given), or stop early once
   SETTLED says no more are coming.  ON-PUBLISH gets the request's event id first."
  (let ((event (w:request-event (node-keypair node) ledger-id-hex action params :extra-tags extra-tags)))
    (setf (gethash (ev:event-id event) (node-pending node))
          (make-waiter :want want :successes-only successes-only :counts counts :settled settled))
    (when on-publish (funcall on-publish (ev:event-id event)))
    (bus:bus-publish (node-bus node) event)
    (wait-for node (ev:event-id event) want :timeout timeout)))

(defun respond (node request success &key result error)
  (bus:bus-publish (node-bus node)
                   (w:response-event (node-keypair node) (ev:event-id request) (w:event-ledger-id request) success
                                     :result result :error error)))

;;; ---------------------------------------------------------------------------
;;; Building and publishing our own updates

(defun new-update (node rec op &key (height (height node)))
  "DEP-02 §Block height and hash: dated at our tip but never below the chain's last height (a
   reorganisation that lowered our tip leaves us at that height), and naming a block."
  (let* ((t0 (tip rec))
         (height (max height (if t0 (up:update-block-height t0) 0))))
    (up:make-signed-update :operator-id (node-pubkey node) :ledger-id (hex->bytes (record-id-hex rec))
                           :seq (if t0 (1+ (up:update-seq t0)) 0)
                           :prev-hash (if t0 (up:chain-hash t0) (make-array 32 :element-type '(unsigned-byte 8)))
                           :message (op:encode-operation op) :block-height height
                           :block-hash (block-hash-at node height t0))))

(defun block-hash-at (node height &optional predecessor)
  "The block hash to sign at HEIGHT: PREDECESSOR's when it is at the same height (one block, one
   hash, even after a reorganisation), else our chain's, else (no chain view) a stand-in.  Never
   zero; never judged against anyone's chain (DEP-02)."
  (or (and predecessor (= height (up:update-block-height predecessor))
           (let ((h (up:update-block-hash predecessor))) (and h (not (zero-bytes-p h)) h)))
      (and (node-block-hash-fn node) (ignore-errors (funcall (node-block-hash-fn node) height)))
      (sha256 (ascii->bytes (format nil "deposits: no chain view at height ~a" height)))))

(defun commit-update (node rec update)
  "Operator-sign, apply, record, publish, persist.  The update's cosignatures
   must already be in place."
  (up:sign-operator update (node-priv node))
  (handler-case (lg:apply-update (record-ledger rec) update)       ; signals ledger-error if invalid
    (lg:ledger-error (e)
      ;; ADVERSARY :sign-invalid — an operator that publishes, with its colluders'
      ;; cosignatures, an update its own validator rejects: the chain advances,
      ;; the operation's effect does not (red team #1: what an honest minority
      ;; must catch is exactly this update on the relay).
      (unless (getf (node-adversary node) :sign-invalid) (error e))
      (log! node "ADVERSARY: committing seq ~a on ~a that our validator rejects: ~a"
            (up:update-seq update) (subseq (record-id-hex rec) 0 8) e)
      (setf (lg:ledger-sequence (record-ledger rec)) (up:update-seq update)
            (lg:ledger-chain-tip (record-ledger rec)) (up:chain-hash update))))
  (push update (record-history rec))
  (setf (record-last-event-id rec) (ev:event-id (bus:bus-publish (node-bus node) (w:update-event (node-keypair node) update))))
  (save-record node rec)
  (run-hooks node rec update)
  update)

(defparameter *cosign-tip-wait-seconds* 10
  "How long a cosigner waits for its tip to reach a proposed height above it (within the tolerance).")

(defparameter *cosign-height-tolerance* 6
  "A cosigner refuses an update whose (signed) block_height is further than this
   from its own chain tip: the height decides the lifecycle tier.")

(defvar *extra-cosign-params* nil
  "Extra (key value ...) for the cosign request of the update being appended (DEP-20 §8.3's manifest).")

;;; DEP-05 §Cosign Rounds.  A cosignature binds cosign_data, not the moment it arrived: one that
;;; reaches us after we stopped waiting still counts for that update.  A round is kept per
;;; cosign_data; late answers land in it (HANDLE-RESPONSE) and a retry of the same update
;;; starts from them.

(defstruct cosign-round (started (get-universal-time)) update signers (cosigs '()) (request-ids '()) (lock (bt:make-lock "round")))

(defun response-cosignature (response)
  "The cosignature a successful cosign_update response carries, or NIL."
  (let ((res (w:jget response "result")))
    (when (and (w:jget response "success") (hash-table-p res) (w:jget res "cosigner_pubkey"))
      (ignore-errors
       (up:make-cosignature :pubkey (hex->bytes (w:jget res "cosigner_pubkey"))
                            :signature (hex->bytes (w:jget res "cosign_signature_hex"))
                            :member-ledger-hash (hex->bytes (w:jget res "member_ledger_hash_hex")))))))

(defun round-add (round c)
  "Keep C if it is a signer's valid cosignature over the round's cosign_data, one per signer."
  (when (and c (member (up:cosig-pubkey c) (cosign-round-signers round) :key #'lg:member-pubkey :test #'equalp)
             (ignore-errors (up:verify-cosignature (cosign-round-update round) c)))
    (bt:with-lock-held ((cosign-round-lock round))
      (unless (member (up:cosig-pubkey c) (cosign-round-cosigs round) :key #'up:cosig-pubkey :test #'equalp)
        (push c (cosign-round-cosigs round))
        t))))

(defun keep-late-cosignature (node data response)
  (let ((round (gethash data (node-cosign-rounds node))))
    (when (and round (round-add round (response-cosignature response)))
      (log! node "late cosignature for seq ~a kept (~a held)" (up:update-seq (cosign-round-update round))
            (length (cosign-round-cosigs round))))))

(defun begin-cosign-round (node update signers)
  "The round for UPDATE's cosign_data: the one kept from an earlier attempt, or a fresh one."
  (let ((rounds (node-cosign-rounds node)) (now (get-universal-time)))
    (sb-ext:with-locked-hash-table (rounds)
      (loop for data being the hash-keys of rounds using (hash-value r)
            when (> (- now (cosign-round-started r)) *cosign-round-keep*)
              do (remhash data rounds)
                 (dolist (id (cosign-round-request-ids r)) (remhash id (node-late-cosign-requests node))))
      (let* ((data (up::cosign-data update))
             (round (or (gethash data rounds)
                        (setf (gethash data rounds) (make-cosign-round :update (up::copy-signed-update update) :signers signers)))))
        (setf (cosign-round-signers round) signers)   ; the requirement may have moved (another tier)
        round))))

(defun end-cosign-round (node update)
  (let ((round (gethash (up::cosign-data update) (node-cosign-rounds node))))
    (when round
      (dolist (id (cosign-round-request-ids round)) (remhash id (node-late-cosign-requests node)))
      (remhash (up::cosign-data update) (node-cosign-rounds node)))))

(defun solicit-cosignatures (node rec update signers required)
  "Ask the quorum; return when REQUIRED valid cosignatures are in the update."
  (let* ((data (up::cosign-data update))
         (round (begin-cosign-round node update signers))
         (params (apply #'w:json-object "sequence_number" (up:update-seq update)
                                "cosign_data_hex" (bytes->hex data)
                                "content_hash_hex" (bytes->hex (up:content-hash update))
                                "message_type" 32769
                                "fork_operator" (and (record-fork-p rec) (bytes->hex (record-fork-operator rec)))
                                ;; DEP-03 Rotation ordering: cosigners rebuild every rung, unsigned.
                                "rotation_rungs_tx" (let ((r (record-rotation rec)))
                                                      (and r (getf r :rungs) (not (getf r :qb-seq))
                                                           (eq (op:operation-type (op:decode-operation (up:update-message update))) :quorum-begin)
                                                           (coerce (getf r :rungs) 'vector)))
                                *extra-cosign-params*))
         (signer-xs (mapcar (lambda (m) (x-hex (lg:member-pubkey m))) signers))
         (attempt 0))
    (labels ((take-round ()
               ;; Everything the round holds (earlier attempts, late answers) into the update.
               (dolist (c (bt:with-lock-held ((cosign-round-lock round)) (copy-list (cosign-round-cosigs round))))
                 (unless (member (up:cosig-pubkey c) (up:update-cosignatures update) :key #'up:cosig-pubkey :test #'equalp)
                   (push c (up:update-cosignatures update)))))
             (enough () (>= (length (up:update-cosignatures update)) required))
             (answered (r)
               ;; Who answered, as x-only hex: the cosigner's key on a cosignature, the
               ;; responder's on a refusal.
               (let ((c (response-cosignature r)))
                 (if c (x-hex (up:cosig-pubkey c)) (gethash "responder" r)))))
      (take-round)
      ;; A member may still be applying the update this one chains onto (relays
      ;; reorder); ask again after a pause before giving up.
      (loop until (or (enough) (>= attempt 3))
            do (dolist (r (send-request node (record-id-hex rec) "cosign_update" params
                                        :want (- required (length (up:update-cosignatures update)))
                                        :counts (lambda (r) (let ((c (response-cosignature r)))
                                                              (and c (member (up:cosig-pubkey c) signers :key #'lg:member-pubkey :test #'equalp))))
                                        ;; Every signer has answered (signed or refused): nothing more is coming.
                                        :settled (lambda (rs) (let ((who (mapcar #'answered rs)))
                                                                (every (lambda (x) (member x who :test #'equal)) signer-xs)))
                                        :on-publish (lambda (id)
                                                      (bt:with-lock-held ((cosign-round-lock round))
                                                        (push id (cosign-round-request-ids round)))
                                                      (setf (gethash id (node-late-cosign-requests node)) data))
                                        :timeout (if (zerop attempt) *cosign-response-seconds* 3)))
                 (round-add round (response-cosignature r)))
               (take-round)
               (incf attempt)
               (unless (enough) (sleep 0.3))))
    (when (< (length (up:update-cosignatures update)) required)
      (fail "only ~a of ~a cosignatures for seq ~a" (length (up:update-cosignatures update)) required (up:update-seq update)))
    (end-cosign-round node update)
    update))

(defun append-operation (node rec op &key (height (height node)) op-fn)
  "The operator's one entry point: chain OP onto REC's ledger with whatever
   cosignatures DEP-05 requires at HEIGHT.  With OP-FN, OP is (funcall OP-FN tip-chain-hash),
   built under the append lock on the tip it extends (a rotation's anchor, DEP-03)."
  (unless (record-owned-p rec) (fail "not our ledger"))
  ;; Serialised per ledger, cosign round included: the control socket (a
  ;; rotation's QuorumAddMember) and the worker (a wallet's transfer) both
  ;; append here, and an update built from a tip that moved during its own
  ;; cosign round commits as "SEQUENCE (expected N+1, got N)".  Under steady
  ;; traffic a rotation never won that race and only succeeded post-expiry,
  ;; when value-moving operations were being refused and nothing competed.
  (bt:with-lock-held ((record-append-lock rec))
    (when op-fn (setf op (funcall op-fn (up:chain-hash (tip rec)))))
    ;; Would it apply?  Check on a copy before asking anyone to cosign it.
    ;; ADVERSARY :sign-invalid — an operator that asks its quorum to cosign an
    ;; operation its own validator rejects (red team #1).
    (unless (getf (node-adversary node) :sign-invalid)
      (let ((lg:*block-height* height) (lg:*update-seq* (1+ (lg:ledger-sequence (record-ledger rec)))))
        (lg:apply-operation (lg:copy-ledger (record-ledger rec)) op)))
    (let ((update (new-update node rec op :height height)))
      (multiple-value-bind (required signers tier operator-alone allowed)
          (lg:cosign-requirement (record-ledger rec) op height)
        (declare (ignore operator-alone))
        (unless allowed (fail "~a not cosignable at ~a" (op:operation-type op) tier))
        (when (plusp required)
          ;; Members that forked against this quorum refuse every cosign: once too few
          ;; are left to reach REQUIRED, stand down now instead of timing out each time.
          (let ((disputing (disputing-members node rec)) (custodian (custody-moved-to node rec)))
            (when custodian
              (fail "ledger disputed: custody moved to ~a by DisputeAcquire; this operator stands down"
                    (subseq (bytes->hex custodian) 0 16)))
            (when (> required (count-if-not (lambda (m) (member (lg:member-pubkey m) disputing :test #'equalp)) signers))
              (fail "ledger disputed: ~a of ~a members forked it; ~a cosignatures are out of reach (custody follows the dispute)"
                    (length disputing) (length signers) required)))
          (solicit-cosignatures node rec update signers required)))
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

(defun add-member (node rec member-pubkey &key member-ledger-id (membership-blocks 4320) (ruleset "cltv-offset-v2") (min-fee-bps 0) (min-fee-fixed 0) (max-fee-period 2016) dispute-response-blocks dormancy-blocks dormancy-notice-blocks)
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
                                      :dormancy-blocks dormancy-blocks :dormancy-notice-blocks dormancy-notice-blocks
                                      :quorum-member-signature consent
                                      :member-ledger-id (or (w:jget res "member_ledger_id") member-ledger-id "")
                                      :min-fee-bps min-fee-bps :min-fee-fixed min-fee-fixed :max-fee-period max-fee-period
                                      :membership-until (w:jget res "membership_expires")
                                      :dispute-response-blocks dispute-response-blocks
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
    ;; A member whose commitment has already lapsed would make the quorum born
    ;; expired (every value-moving op refused): say which, rather than pin it.
    (when (<= expiry (height node))
      (fail "quorum would be born expired: a member's commitment ends at ~a, height ~a" expiry (height node)))
    (setf (record-pinned rec) (cons reserves expiry))
    reserves))

(defun rotation-file (node rec)
  (and (node-data-dir node)
       (merge-pathnames (format nil "rotation_~a.sexp" (subseq (record-id-hex rec) 0 16)) (node-data-dir node))))

(defun save-rotation (node rec plist)
  "Persist a broadcast rotation: the old vault is spent, and a restart before its
   QuorumBegin must still know where the reserves went."
  (setf (record-rotation rec) plist)
  (let ((f (rotation-file node rec)))
    (when f
      (ensure-directories-exist f)
      (with-open-file (out f :direction :output :if-exists :supersede)
        (with-standard-io-syntax (prin1 plist out))))))

(defun pending-rotation (node rec)
  (or (record-rotation rec)
      (let ((f (rotation-file node rec)))
        (when (and f (probe-file f))
          (setf (record-rotation rec) (with-open-file (in f) (with-standard-io-syntax (read in))))))))

(defun clear-rotation (node rec)
  (setf (record-rotation rec) nil)
  (let ((f (rotation-file node rec))) (when (and f (probe-file f)) (delete-file f))))

(defun has-quorum-begin-p (rec)
  "REC holds a vault its next QuorumBegin must rotate: a QuorumBegin with no DisputeAcquire
   after it (an acquisition's first QuorumBegin is funded by the lottery claim instead)."
  (loop for u in (record-history rec)                 ; newest first
        for type = (op:operation-type (op:decode-operation (up:update-message u)))
        when (eq type :dispute-acquire) return nil
        when (eq type :quorum-begin) return t))

(defun rotation-tier-index (reserves height)
  "The highest-numbered tier whose CLTV is satisfied at HEIGHT (Tier 0 before expiry)."
  (loop for tier in (rs:reserves-tiers reserves) for i from 0
        when (<= (rs:tier-locktime tier) height) maximize i))

(defun exit-settlement (ledger height cutoff)
  "DEP-20 §3: the due exits at HEIGHT under CUTOFF as (values extras entries exits-cost): EXTRAS the
   rotation's exit outputs ((spk . sats) ...), each less its own cost, ENTRIES the QuorumBegin's
   exit_outputs, EXITS-COST the sum of those costs (the part of the fee the exits pay)."
  (let ((due (lg:due-exits ledger height cutoff)) (f (lg:rotation-feerate ledger)))
    (values (loop for (nil . e) in due
                  collect (cons (getf e :exit-address)
                                (- (floor (getf e :amount) 1000) (lg:exit-cost (getf e :exit-address) f))))
            (loop for (nil . e) in due for i from 1 collect (list (getf e :deposit-id) (getf e :amount) i))
            (loop for (nil . e) in due sum (lg:exit-cost (getf e :exit-address) f)))))

(defun dormancy-settlement (ledger cutoff nexits)
  "DEP-20 §8.2: the spin-outs a rotating QuorumBegin at HEIGHT must pay, as (values extras entries
   cost): EXTRAS ((spk . sats) ...) after NEXITS exit outputs, ENTRIES the dormancy_outputs, COST
   the operator's (collateral's) share of the fee for them."
  (let ((spins (lg:dormancy-spin-outs ledger cutoff)))
    (values (loop for (nil bal spk) in spins collect (cons spk (floor bal 1000)))
            (loop for (id bal) in spins for j from 1 collect (list id bal (+ nexits j)))
            (* (length spins) (lg:dormancy-cost ledger)))))

(defun settlement (ledger height cutoff)
  "Every DEP-20 output a rotation at HEIGHT pays: (values extras exit-entries dormancy-entries
   exits-cost dormancy-cost migration premium), DORMANCY-COST including the migration output's
   own cost (a fee), MIGRATION (:entries :vout) or NIL, PREMIUM the sats the migration output
   carries beyond the deposits (not a fee); collateral pays the dormancy cost and the premium."
  (multiple-value-bind (ex ee ec) (exit-settlement ledger height cutoff)
    (multiple-value-bind (dx de dc) (dormancy-settlement ledger cutoff (length ee))
      (multiple-value-bind (mentries mspk msats) (lg:dormancy-migration ledger cutoff (length de) height)
        (if mentries
            (let ((premium-msat (or (getf (lg:ledger-dormancy-notice ledger) :premium) 0)))
              (values (append ex dx (list (cons mspk msats))) ee de ec
                      (+ dc (* (lg:rotation-feerate ledger) (+ 9 (length mspk))))
                      (list :entries mentries :vout (+ 1 (length ee) (length de)))
                      (floor premium-msat 1000)))
            (values (append ex dx) ee de ec dc nil 0))))))

(defun median-feerate (node height)
  "DEP-03 Reference feerate: m = floor((s3 + s4) / 2) over the block feerates of heights h-6..h-1,
   or NIL without a feerate source."
  (when (node-feerate-fn node)
    (let ((fs (loop for b from (- height 6) below height collect (funcall (node-feerate-fn node) b))))
      (unless (member nil fs)
        (let ((s (sort fs #'<))) (floor (+ (nth 2 s) (nth 3 s)) 2))))))

(defun feerate-bounds (m) (values (max 1 (floor m 2)) (max 2 (* 2 m))))

(defun splice-outpoint-bytes (txid vout) (cat txid (int->be vout 4)))

(defun splice-prevout (node txid vout)
  "DEP-20 §4: a splice-in outpoint, confirmed to the policy depth and unspent: (values sats spk)."
  (let ((info (and (node-chain-fn node) (funcall (node-chain-fn node) txid vout))))
    (unless info (fail "splice-in outpoint ~a:~a is spent or unknown" (bytes->hex txid) vout))
    (unless (>= (or (getf info :confirmations) 0) 1) (fail "splice-in outpoint is unconfirmed"))
    (values (getf info :value-sats)
            (or (getf info :spk) (lot:p2tr-spk (up:x-only (node-pubkey node)) (octets))))))

(defun rotation-collateral (ledger vault-sats fee-sats)
  "DEP-20 §3 Amounts: collateral bears only its share of FEE-SATS, the vault's part of the
   rotation fee (the fee less what the exits paid themselves)."
  (let ((old (+ (lg:ledger-reserves-amount ledger) (lg:ledger-collateral-amount ledger))))
    (if (plusp old) (floor (* (lg:ledger-collateral-amount ledger) (- vault-sats fee-sats) 1000) old) 0)))

(defun rotate-vault (node rec &key (ruleset "cltv-offset-v2") (expiry-blocks 4320) (timeout 90) splice)
  "DEP-03 rotation, first step: plan the spend of the current vault into the reserves of the
   staged quorum with the shared builder (rot:build-ladder).  Nothing is signed yet: BEGIN-QUORUM
   records the QuorumBegin naming every rung, then gathers the members' signatures on the rungs
   (rotation_sign), assembles and broadcasts (DEP-03 Rotation ordering).  Returns (values txid
   new-vault-sats): rung 0 as it would be built on our current tip (BEGIN-QUORUM's answer is the
   one recorded)."
  (declare (ignore timeout))
  (unless (record-owned-p rec) (fail "not our ledger"))
  (unless (has-quorum-begin-p rec) (fail "no vault yet: the first QuorumBegin is funded, not rotated"))
  (let ((pending (pending-rotation node rec)))
    (when (and pending (getf pending :qb-seq)) (fail "a rotation is already recorded and awaits its signatures"))
    ;; Planned but never recorded (its begin-quorum fell short): nothing is signed yet, and its
    ;; exit cutoff ages out of the window a QuorumBegin may name, so plan again on this tip.
    (when pending (clear-rotation node rec)))
  (let* ((staged (mapcar #'lg:member-pubkey (lg:ledger-next-quorum-members (record-ledger rec))))
         (new (if (and (record-pinned rec) (equalp (rs:reserves-members (car (record-pinned rec))) staged))
                  (car (record-pinned rec))       ; prepared already (prepare-quorum)
                  (prepare-quorum node rec :ruleset ruleset :expiry-blocks expiry-blocks)))
         (expiry (cdr (record-pinned rec))))
    (multiple-value-bind (cur txid vout sats) (disputed-reserves node rec)
      (let* ((tier-index (rotation-tier-index cur (height node)))
             (tier (nth tier-index (rs:reserves-tiers cur)))
             (cutoff (height node))
             (exits-cost (nth-value 3 (settlement (record-ledger rec) (height node) cutoff)))
             (dorm-cost (nth-value 4 (settlement (record-ledger rec) (height node) cutoff)))
             (extras (settlement (record-ledger rec) (height node) cutoff))
             ;; DEP-20 §4: SPLICE is (txid vout) of a confirmed UTXO paying our key-path P2TR.
             (splice-in (when splice
                          (multiple-value-bind (ssats sspk) (splice-prevout node (first splice) (second splice))
                            (list (first splice) (second splice) ssats sspk))))
             ;; DEP-20 §8.3: a migration output at our own vault script is spent through the same tier.
             (vault-splice (and splice-in (equalp (fourth splice-in) (rs:reserves-spk cur))))
             (plan (list :vault-txid (bytes->hex txid) :vault-vout vout :vault-sats sats
                         :voters (length (rs:reserves-voters cur)) :feerate (lg:rotation-feerate (record-ledger rec))
                         :locktime (rs:tier-locktime tier) :tier-index tier-index
                         :new-vault-spk (bytes->hex (rs:reserves-spk new))
                         :extras (mapcar (lambda (e) (cons (bytes->hex (car e)) (cdr e))) extras)
                         :splice-in (and splice-in (list (bytes->hex (first splice-in)) (second splice-in) (third splice-in)
                                                         (bytes->hex (fourth splice-in))))
                         :splice-vault-p vault-splice
                         ;; DEP-03 §Fee ladder: a migration output's outpoint is named by txid, so one rung
                         :max-rungs (if (nth-value 5 (settlement (record-ledger rec) (height node) cutoff)) 1 rot:+rungs+)
                         :governing-seq (governing-quorum-begin-seq rec (lg:ledger-sequence (record-ledger rec)))))
             (tx (or (first (plan-ladder plan (up:chain-hash (tip rec)) 0))
                     (fail "the rotation leaves the new vault below dust")))
             (new-sats (btx:txout-value (first (btx:tx-outputs tx)))))
        (save-rotation node rec (list :plan plan :sats new-sats :vault-sats sats :cutoff cutoff
                                      :tx (unsigned-tx-hex tx)    ; rung 0 as planned on this tip (inspection only)
                                      :fee (- (+ sats (if splice-in (third splice-in) 0)) (reduce #'+ extras :key #'cdr) new-sats exits-cost dorm-cost)
                                      :dormancy-cost dorm-cost
                                      :premium (nth-value 6 (settlement (record-ledger rec) (height node) cutoff))
                                      :splice (and splice-in (list (bytes->hex (first splice-in)) (second splice-in) (third splice-in)))
                                      :ledger-hash (bytes->hex (rs:reserves-ledger-hash new)) :expiry expiry
                                      :ruleset (rs:reserves-ruleset new)
                                      :members (mapcar #'bytes->hex (rs:reserves-members new))))
        (log! node "rotation of ~a planned: ~a sats into the next vault, spending ~a:~a at tier ~a; recording its QuorumBegin next"
              (subseq (record-id-hex rec) 0 8) new-sats (subseq (bytes->hex txid) 0 16) vout tier-index)
        (values (btx:tx-txid tx) new-sats)))))

(defun plan-ladder (plan anchor collateral-msats)
  "DEP-03 §Fee ladder: the unsigned rungs ROTATE-VAULT's PLAN gives under ANCHOR (the chain hash
   the QuorumBegin extends) and COLLATERAL-MSATS (its collateral_amount)."
  (rot:build-ladder :vault-txid (hex->bytes (getf plan :vault-txid)) :vault-vout (getf plan :vault-vout)
                    :vault-sats (getf plan :vault-sats) :voters (getf plan :voters) :feerate (getf plan :feerate)
                    :locktime (getf plan :locktime) :new-vault-spk (hex->bytes (getf plan :new-vault-spk))
                    :extras (mapcar (lambda (e) (cons (hex->bytes (car e)) (cdr e))) (getf plan :extras))
                    :splice (let ((sp (getf plan :splice-in))) (and sp (list (hex->bytes (first sp)) (second sp) (third sp))))
                    :splice-vault-p (getf plan :splice-vault-p) :anchor anchor :collateral-msats collateral-msats
                    :max-rungs (or (getf plan :max-rungs) rot:+rungs+)))

(defun plan-prevouts (plan cur)
  (let ((sp (getf plan :splice-in)))
    (if sp
        (vector (cons (getf plan :vault-sats) (rs:reserves-spk cur)) (cons (third sp) (hex->bytes (fourth sp))))
        (vector (cons (getf plan :vault-sats) (rs:reserves-spk cur))))))

(defun sign-rotation-rungs (node rec qb-update &key (timeout 90))
  "DEP-03 Rotation ordering, steps 3-4: QB-UPDATE (final, published) names the rungs of the
   pending rotation.  Gather the spent vault's tier signatures on every rung from its members
   (rotation_sign, carrying QB-UPDATE: a member signs only rungs a final QuorumBegin names),
   assemble, verify, broadcast rung 0, publish every rung (Kind 9107) and keep them to
   rebroadcast and bump.  Returns rung 0's txid; signals when too few members sign (the
   rotation stays pending: DRIVE-ROTATION-REBROADCAST retries)."
  (let* ((r (or (pending-rotation node rec) (fail "no pending rotation")))
         (plan (getf r :plan))
         (rungs (mapcar (lambda (h) (btx:parse-tx (bw:make-reader (hex->bytes h)))) (getf r :rungs)))
         (cur (or (fr:spent-vault (record-history rec) (getf plan :governing-seq)) (fail "the spent vault's QuorumBegin is gone")))
         (tier-index (getf plan :tier-index))
         (tier (nth tier-index (rs:reserves-tiers cur)))
         (leaf (nth tier-index (rs:reserves-leaves cur)))
         (prevouts (plan-prevouts plan cur))
         (vault-splice (getf plan :splice-vault-p))
         (hashes (mapcar (lambda (tx) (rot:tier-sighash tx 0 prevouts leaf)) rungs))
         (hashes1 (and vault-splice (mapcar (lambda (tx) (rot:tier-sighash tx 1 prevouts leaf)) rungs)))
         (keys (if (and (= (rs:tier-threshold tier) 1) (rs:tier-tie-breaker-p tier))
                   (list (up:x-only (node-pubkey node)))
                   (rs:tier-keys tier)))
         (me (up:x-only (node-pubkey node)))
         ;; (xonly sigs-per-rung splice-sigs-per-rung)
         (sigs (list (list me (mapcar (lambda (h) (schnorr:schnorr-sign (node-priv node) h (random-aux))) hashes)
                           (mapcar (lambda (h) (schnorr:schnorr-sign (node-priv node) h (random-aux))) hashes1))))
         (need (rs:tier-threshold tier)))
    (when (< (count-if (lambda (s) (member (first s) keys :test #'equalp)) sigs) need)
      (let ((responses (send-request node (record-id-hex rec) "rotation_sign"
                                     (w:json-object "quorum_begin" (base64-encode (up:encode-update qb-update))
                                                    "unsigned_rungs" (coerce (getf r :rungs) 'vector)
                                                    "tier_index" tier-index
                                                    "splice_in_outpoint" (let ((sp (getf plan :splice-in)))
                                                                           (and sp (format nil "~a:~a" (first sp) (second sp)))))
                                     :want (max 0 (- need (count-if (lambda (s) (member (first s) keys :test #'equalp)) sigs)))
                                     :timeout timeout :successes-only t)))
        (dolist (resp responses)
          (let ((res (w:jget resp "result")))
            (when (and (w:jget resp "success") res)
              (let* ((res (if (stringp res) (w:parse-json res) res))
                     (pk (up:x-only (hex->bytes (w:jget res "signer"))))
                     (ss (mapcar #'hex->bytes (coerce (or (w:jget res "signatures") #()) 'list)))
                     (ss1 (mapcar #'hex->bytes (coerce (or (w:jget res "splice_signatures") #()) 'list))))
                (when (and (member pk keys :test #'equalp) (not (assoc pk sigs :test #'equalp))
                           (= (length ss) (length hashes)) (every (lambda (h sg) (schnorr:schnorr-verify pk h sg)) hashes ss)
                           (or (not vault-splice)
                               (and (= (length ss1) (length hashes1)) (every (lambda (h sg) (schnorr:schnorr-verify pk h sg)) hashes1 ss1))))
                  (push (list pk ss ss1) sigs))))))))
    (let ((have (remove-if-not (lambda (s) (member (first s) keys :test #'equalp)) sigs)))
      (when (< (length have) need)
        (fail "rotation: only ~a of ~a signatures on its rungs" (length have) need))
      (let ((signed
              (loop for tx in rungs for i from 0
                    collect (let* ((ordered (mapcar (lambda (k) (let ((e (assoc k have :test #'equalp))) (and e (nth i (second e))))) keys))
                                   (s (rot:attach-tier-witness tx 0 cur tier-index ordered)))
                              (cond (vault-splice
                                     (rot:attach-tier-witness s 1 cur tier-index
                                                              (mapcar (lambda (k) (let ((e (assoc k have :test #'equalp))) (and e (nth i (third e))))) keys)))
                                    ((getf plan :splice-in) (attach-key-path-witness s 1 (key-path-signature node s 1 prevouts)))
                                    (t s))))))
        (dolist (s signed)
          (dotimes (i (length (btx:tx-inputs s)))
            (unless (rot:verify-spend s i prevouts) (fail "assembled rotation input ~a does not verify" i))))
        (let ((bytes (mapcar #'btx:serialize-tx signed)))
          (note-rotation-rungs node (btx:tx-txid (first signed)) bytes (up:update-block-height qb-update))
          (when (node-broadcast-fn node)
            (handler-case (funcall (node-broadcast-fn node) (first bytes))
              (error (c) (log! node "rotation ~a broadcast failed: ~a" (subseq (bytes->hex (btx:tx-txid (first signed))) 0 16) c))))
          (loop for b in bytes for i from 0
                do (bus:bus-publish (node-bus node) (w:rotation-tx-event (node-keypair node) (record-id-hex rec)
                                                                         (up:update-seq qb-update) (bytes->hex b) i)))
          (log! node "rotation of ~a broadcast after its QuorumBegin (seq ~a): ~a rungs signed by ~a"
                (subseq (record-id-hex rec) 0 8) (up:update-seq qb-update) (length signed) (length have))
          (clear-rotation node rec)
          (btx:tx-txid (first signed)))))))

(defun begin-quorum (node rec &key funding-txid funding-vout amount-msats collateral-msats splice-collateral-msats
                                   (ruleset "cltv-offset-v2") (expiry-blocks 4320) (spending-txid funding-txid))
  "Promote the staged members: chain a QuorumBegin.  The first one points at the
   outpoint funding the reserves output prepared by PREPARE-QUORUM (or built now);
   every later one names the rungs of the rotation ROTATE-VAULT planned (DEP-03): built on
   the tip the QuorumBegin extends (their anchor), recorded, then signed and broadcast.  A
   vault is never replaced by a fresh one while the old lingers.  Returns (values update
   reserves rotation-txid), the last NIL for a first QuorumBegin or while the rungs await
   signatures."
  (let ((rotation (and (has-quorum-begin-p rec)
                       (or (pending-rotation node rec)
                           (fail "a rotation must spend the old vault: rotate-vault first")))))
    (when (and rotation (getf rotation :qb-seq))
      ;; recorded already; only its signatures are missing
      (let ((qu (find (getf rotation :qb-seq) (record-history rec) :key #'up:update-seq)))
        (return-from begin-quorum
          (values qu (record-reserves rec) (ignore-errors (sign-rotation-rungs node rec qu))))))
    (when rotation
      (let* ((new-msats (* 1000 (getf rotation :sats)))
             (ledger (record-ledger rec))
             (coll (+ (rotation-collateral ledger (getf rotation :vault-sats) (getf rotation :fee))
                      (- (* 1000 (+ (or (getf rotation :dormancy-cost) 0) (or (getf rotation :premium) 0))))
                      ;; DEP-20 §4: a splice's value goes to collateral unless told otherwise.
                      (if (getf rotation :splice)
                          (min (* 1000 (third (getf rotation :splice)))
                               (or splice-collateral-msats (* 1000 (third (getf rotation :splice)))))
                          0))))
        (setf funding-vout 0 amount-msats (- new-msats coll) collateral-msats coll)
        (unless (record-pinned rec)
          (setf (record-pinned rec)
                (cons (rs:build-reserves :operator (node-pubkey node) :members (mapcar #'hex->bytes (getf rotation :members))
                                         :ledger-hash (hex->bytes (getf rotation :ledger-hash)) :quorum-expiry (getf rotation :expiry)
                                         :ruleset (getf rotation :ruleset)
                                         :network (intern (string-upcase (node-network node)) :keyword))
                      (getf rotation :expiry)))))))
  (let* ((rotation (and (has-quorum-begin-p rec) (pending-rotation node rec)))
         (ledger (record-ledger rec))
         (staged (lg:ledger-next-quorum-members ledger))
         (members (mapcar #'lg:member-pubkey staged))
         (pinned (or (record-pinned rec) (progn (prepare-quorum node rec :ruleset ruleset :expiry-blocks expiry-blocks)
                                                 (record-pinned rec))))
         (reserves (car pinned)) (expiry (cdr pinned)))
    (unless (equalp (rs:reserves-members reserves) members)
      (fail "staged members changed since the reserves were prepared; prepare again"))
    (flet ((build-op (anchor)
             ;; DEP-03: a rotation's rungs carry the chain hash the QuorumBegin extends, so they are
             ;; built here, on the tip, under the append lock.
             (let* ((rungs (and rotation
                                (or (plan-ladder (getf rotation :plan) anchor collateral-msats)
                                    (fail "the rotation leaves the new vault below dust"))))
                    (txid (if rungs (btx:tx-txid (first rungs)) funding-txid))
                    (op (list :type :quorum-begin :reserves-id (rs:reserves-address reserves)
                              :spending-txid (if rungs txid spending-txid) :new-outpoint-txid txid :new-outpoint-vout funding-vout
                              :amount amount-msats :quorum-expiry expiry :ledger-hash (rs:reserves-ledger-hash reserves)
                              :quorum-members members :collateral-amount collateral-msats
                              :quorum-member-ledger-ids (mapcar #'lg:member-ledger-id staged)
                              :protocol-version (rs:reserves-ruleset reserves))))
               (when rungs
                 (unless (= (btx:txout-value (first (btx:tx-outputs (first rungs)))) (getf rotation :sats))
                   (fail "the rotation's new vault moved since it was planned; rotate-vault again"))
                 (setf (getf (record-rotation rec) :rungs) (mapcar #'unsigned-tx-hex rungs)))
               (if (and rotation (getf rotation :cutoff))
                   (let ((entries (nth-value 1 (settlement ledger (height node) (getf rotation :cutoff))))
                         (dentries (nth-value 2 (settlement ledger (height node) (getf rotation :cutoff))))
                         (mig (nth-value 5 (settlement ledger (height node) (getf rotation :cutoff))))
                         (sp (getf rotation :splice)))
                     (append op (list :exit-cutoff-height (getf rotation :cutoff))
                             (let ((m (median-feerate node (height node)))) (when m (list :reference-feerate (max 2 m))))
                             (when entries (list :exit-outputs entries))
                             (when dentries (list :dormancy-outputs dentries))
                             (let ((cid (lg:consumed-notice-id ledger (getf rotation :cutoff))))
                               (when cid (list :consumed-notice cid)))
                             (when mig (list :migration-manifest (getf mig :entries)
                                             :migration-receiver (getf (lg:ledger-dormancy-notice ledger) :receiver)
                                             :migration-vout (getf mig :vout)))
                             (when sp (list :splice-in-outpoint (splice-outpoint-bytes (hex->bytes (first sp)) (second sp))
                                            :splice-in-amount (* 1000 (third sp))))
                             (when rungs (list :rotation-rungs (apply #'cat (mapcar #'btx:tx-txid rungs))))))
                   op))))
      (let ((update (append-operation node rec nil :op-fn #'build-op)))
        (setf (record-reserves rec) reserves (record-pinned rec) nil)
        (if (null rotation)
            (values update reserves nil)
            (progn
              ;; Persisted before anyone signs: a restart resumes at the signatures.
              (save-rotation node rec (append (list :qb-seq (up:update-seq update)) (record-rotation rec)))
              (values update reserves
                      (handler-case (sign-rotation-rungs node rec update)
                        (error (c) (log! node "rotation of ~a recorded at seq ~a; its rungs await signatures: ~a"
                                         (subseq (record-id-hex rec) 0 8) (up:update-seq update) c)
                          nil)))))))))

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
        (#.w:+kind-lottery-reveal+ (handle-reveal node event))
        (#.w:+kind-rotation-tx+ (handle-rotation-tx node event))
        (#.w:+kind-spend-challenge+ (handle-spend-challenge node event))
        (#.w:+kind-challenge-answer+ (handle-challenge-answer node event)))
    (error (e) (log! node "event ~a (kind ~a from ~a): ~a" (subseq (ev:event-id event) 0 8) (ev:event-kind event) (subseq (ev:event-pubkey event) 0 8) e))))

(defun handle-response (node event)
  (let ((wt (gethash (w:event-request-id event) (node-pending node))))
    (unless wt
      ;; An answer to a cosign request after its round's deadline: kept for the retry.
      (let ((data (gethash (w:event-request-id event) (node-late-cosign-requests node))))
        (when data (keep-late-cosignature node data (w:parse-json (ev:event-content event)))))
      (return-from handle-response nil))
    (progn
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
  ;; ADVERSARY :mute — a member that answers nothing at all (no cosign, no rotation_sign):
  ;; a watcher that only replicates.
  (when (getf (node-adversary node) :mute) (return-from handle-request nil))
  (let ((action (w:event-action event)) (params (w:parse-json (ev:event-content event))))
    (cond ((and (ev:first-tag-value event "p") (string= (ev:first-tag-value event "p") (k:public-hex (node-keypair node)))
                (gethash action (extra-actions node)))
           (funcall (gethash action (extra-actions node)) event params))
          ((string= action "cosign_update") (handle-cosign node event params))
          ((string= action "confiscation_sign") (handle-confiscation-sign node event params))
          ((string= action "theft_sign") (handle-theft-sign node event params))
          ((string= action "rotation_sign") (handle-rotation-sign node event params))
          ((string= action "cosign_offer") (handle-cosign-offer node event params))
          ((string= action "lottery_subset_attest") (handle-lottery-subset-attest node event params))
          ((string= action "lottery_reveal") (handle-lottery-reveal-request node event params))
          ((string= action "consent_request") (handle-consent node event params))
          ((string= action "cosign_invoice") (handle-cosign-invoice node event params))
          (t (let ((rec (find-record node (w:event-ledger-id event))))
               (when (and rec (record-owned-p rec))
                 (handle-wallet-request node rec event action params)))))))

;;; ---------------------------------------------------------------------------
;;; Inbound: another operator's published update (we replicate ledgers we cosign)

(defun lagging-p (node id-hex)
  "Fault switch :lag-replica (a ledger id prefix): our replica of that ledger applies nothing, as a
   replica under backpressure that keeps missing updates (red team: a lagging honest watcher)."
  (let ((p (getf (node-adversary node) :lag-replica)))
    (and (stringp p) (plusp (length p)) (<= (length p) (length id-hex)) (string= p id-hex :end2 (length p)))))

(defun handle-update (node event)
  (let* ((update (w:event->update event))
         (id (bytes->hex (up:update-ledger-id update)))
         (rec (and (not (lagging-p node id)) (find-record node id)))
         (signer (up:update-operator-id update)))
    (when rec
      (cond
        ;; The operator's own chain.
        ((and (not (record-owned-p rec)) (equalp signer (lg:ledger-operator-key (record-ledger rec))))
         (let ((ledger (record-ledger rec)))
           (cond
             ;; DEP-02 §Sequence: chained onto our tip but numbered past tip+1 is a skip, a
             ;; NonConformingUpdate provable on sight, not a gap to backfill.
             ((and (not (record-fork-p rec))
                   (> (up:update-seq update) (1+ (lg:ledger-sequence ledger)))
                   (equalp (up:update-prev-hash update) (lg:ledger-chain-tip ledger))
                   (up:verify-operator-signature update))
              (report-non-conforming node rec update
                                     (format nil "sequence skip: ~a follows ~a" (up:update-seq update) (lg:ledger-sequence ledger))))
             (t
              (when (and (not (record-fork-p rec)) (> (up:update-seq update) (1+ (lg:ledger-sequence ledger))))
                (catch-up node rec))
              (accept-update node rec update)))))
        ;; A quorum member's dispute fork (or its continuation).
        ((not (equalp signer (node-pubkey node)))
         (let* ((o (op:decode-operation (up:update-message update)))
                (fork (let ((f (find-fork node id signer)))
                        (if (and f (eq (op:operation-type o) :dispute-enter) (not (fork-live-p node f))
                                 (not (record-owned-p f)))
                            (progn (retire-fork node f) nil)
                            f))))
           (cond (fork
                  ;; a burst published out of order (the reference appends its QuorumAddMembers
                  ;; and DisputeArmed at once): fill the gap first, or the fork never arms here
                  (when (> (up:update-seq update) (1+ (lg:ledger-sequence (record-ledger fork))))
                    (catch-up-fork node fork (1- (up:update-seq update))))
                  (accept-update node fork update))
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
                   (equalp (up:update-operator-id ours) (up:update-operator-id update))   ; a fork's is not the operator's
                   (not (equalp (up:content-hash ours) (up:content-hash update)))
                   (member (node-pubkey node) (lg:ledger-quorum-members ledger) :key #'lg:member-pubkey :test #'equalp))
          ;; ...and only if it follows this ledger's chain.  ledger_id is unsigned and
          ;; the operator signs its other ledgers with the same key: one of their
          ;; updates, relabelled with this ledger's id, is not an equivocation.
          (if (fr:update-binds-to-ledger-p update (up:update-ledger-id ours) (fr:bound-hashes (record-history rec)))
              (progn (log! node "EQUIVOCATION on ~a at seq ~a" (subseq (record-id-hex rec) 0 8) (up:update-seq update))
                     (broadcast-fraud node (fr:make-equivocation-proof (up:update-operator-id update) (up:update-ledger-id update) ours update)))
              (log! node "ignored an update on ~a at seq ~a that is not on its chain (another ledger's, relabelled?)"
                    (subseq (record-id-hex rec) 0 8) (up:update-seq update)))))
      (return-from accept-update :echo))
    (multiple-value-bind (required signers tier operator-alone allowed)
        (lg:cosign-requirement ledger op (up:update-block-height update))
      (declare (ignore tier operator-alone))
      (unless allowed (fail "uncosignable operation at seq ~a" (up:update-seq update)))
      (when (plusp required)
        (multiple-value-bind (ok why)
            (up:verify-cosignatures update :quorum (mapcar #'lg:member-pubkey signers) :threshold required)
          (unless ok (fail "seq ~a: ~a" (up:update-seq update) why)))))
    (handler-case (let ((v (or (up:header-violation (first (record-history rec)) update)
                               (cf:violation ledger op (up:update-block-height update)))))
                    (when v (lg::fail :non-conforming v))
                    (lg:apply-update ledger update))
      (lg:ledger-error (e)
        ;; Signed by the operator, cosigned by the threshold, the next sequence —
        ;; and the rules reject it.  That is provable fraud, not a glitch to retry.
        (report-non-conforming node rec update e)
        (error e)))
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

(defun chains-on-p (rec u)
  "U continues REC's chain: the LedgerOpen that derives its id, or an update
   whose previous_hash is its tip.  The relays hold whatever anyone tags with
   the ledger's id, and ledger_id is signed by no one: the operator's updates of
   its other ledgers, relabelled, sit beside the real ones at the same sequences."
  (if (zerop (up:update-seq u))
      (fr:update-opens-ledger-p u (hex->bytes (record-id-hex rec)))
      (equalp (up:update-prev-hash u) (lg:ledger-chain-tip (record-ledger rec)))))

(defun catch-up (node rec)
  "A replica that missed an update (a restart, a relay that dropped us) can never
   apply another: every later one fails 'expected seq N'.  Fetch the operator's
   chain past our sequence and apply it in order.  Returns how many applied."
  (let ((ledger (record-ledger rec)) (n 0) (from (lg:ledger-sequence (record-ledger rec))) (window 200))
    ;; The operator's next update was already refused by the rules (reported and
    ;; disputed then): nothing past it can chain onto our tip.  Every later update
    ;; showed a gap and sent us back into the same refusal, logged each time.
    (when (or (eql (gethash (record-id-hex rec) (node-refused node)) (1+ (lg:ledger-sequence ledger)))
              (lagging-p node (record-id-hex rec)))
      (return-from catch-up 0))
    ;; Windows of WINDOW sequences past our tip, until a window adds nothing.
    (loop
      (let* ((lo (1+ (lg:ledger-sequence ledger))) (hi (+ lo window -1)) (applied 0)
             (updates (handler-case (ledger-updates-from-relays node (record-id-hex rec) :from lo :to hi)
                        (error (e) (log! node "catch-up on ~a: fetch failed: ~a" (subseq (record-id-hex rec) 0 8) e) '()))))
        (dolist (u updates)
          (when (and (= (up:update-seq u) (1+ (lg:ledger-sequence ledger)))
                     (equalp (up:update-operator-id u) (lg:ledger-operator-key ledger))
                     ;; Not one that follows something else: a relabelled update here
                     ;; failed the chain check, was taken for a rule the operator broke,
                     ;; and stopped this replica's catch-up for good.
                     (chains-on-p rec u))
            (handler-case (when (eq (accept-update node rec u) :applied) (incf n) (incf applied))
              (lg:ledger-error (e)
                (setf (gethash (record-id-hex rec) (node-refused node)) (up:update-seq u))
                (log! node "catch-up on ~a stopped at seq ~a, which the rules reject: ~a (not retried)"
                      (subseq (record-id-hex rec) 0 8) (up:update-seq u) e)
                (return))
              (error (e) (log! node "catch-up on ~a stopped at seq ~a: ~a" (subseq (record-id-hex rec) 0 8) (up:update-seq u) e)
                (return)))))
        (when (zerop applied) (return))))
    (when (plusp n) (log! node "caught up ~a from seq ~a to ~a" (subseq (record-id-hex rec) 0 8) from (lg:ledger-sequence ledger)))
    n))

(defun catch-up-fork (node fork &optional upto)
  "Another member's dispute fork past whose tip an update arrived (or, at startup, any it
   published while we were down): apply that operator's updates from the relays, in order,
   to UPTO (default 200 past our tip).  Returns how many applied."
  (let* ((ledger (record-ledger fork)) (lo (1+ (lg:ledger-sequence ledger))) (n 0))
    (dolist (u (handler-case (ledger-updates-from-relays node (record-id-hex fork) :from lo :to (or upto (+ lo 199)))
                 (error (e) (log! node "fork catch-up on ~a: fetch failed: ~a" (subseq (record-id-hex fork) 0 8) e) '()))
               n)
      (when (and (= (up:update-seq u) (1+ (lg:ledger-sequence ledger)))
                 (equalp (up:update-operator-id u) (record-fork-operator fork))
                 (chains-on-p fork u))
        (handler-case (when (eq (accept-update node fork u) :applied) (incf n))
          (error (e)
            (log! node "fork catch-up on ~a by ~a stopped at seq ~a: ~a" (subseq (record-id-hex fork) 0 8)
                  (subseq (bytes->hex (record-fork-operator fork)) 0 8) (up:update-seq u) e)
            (return n)))))))

(defun catch-up-all (node)
  "At startup: every replica we cosign, before the first cosign request arrives."
  (loop for id being the hash-keys of (node-ledgers node) using (hash-value rec)
        do (cond ((not (record-p rec)) (log! node "catch-up: ~a holds ~s, not a record; dropped" id rec)
                                       (remhash id (node-ledgers node)))
                 ((record-owned-p rec))
                 ((record-fork-p rec) (ignore-errors (catch-up-fork node rec)))
                 (t (ignore-errors (catch-up node rec))))))

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
        ;; Build the chain, not whatever the relays hold at each sequence: two
        ;; updates at seq 0 (one another ledger's, relabelled) made the first one
        ;; the genesis — the rebuilt replica was the operator's other ledger.
        (dolist (u updates)
          ;; ...and the operator's chain: the relay also holds every dispute
          ;; fork's updates under this id, chaining onto the fork point.  Only the
          ;; next link is taken; whatever else sits at a sequence is not ours to judge.
          (when (and (= (up:update-seq u) (1+ (lg:ledger-sequence (record-ledger rec))))
                     (or (zerop (up:update-seq u))
                         (equalp (up:update-operator-id u) (lg:ledger-operator-key (record-ledger rec))))
                     (chains-on-p rec u)
                     (up:verify-operator-signature u))
            (accept-update node rec u)))
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
      ((not (and (>= (length data) 112) (= (length data) (+ 112 (le->int (subseq data 108 112))))))
       (respond node event nil :error "malformed cosign_data"))
      (t
       ;; DEP-02 v2 cosign_data: seq8 || ledger_id32 || height4 || block_hash32 || prev32 || len4 || message.
       ;; We sign exactly these, so we check what they claim.
       (let* ((ledger (record-ledger rec))
              (ledger-id (subseq data 8 40)) (block-height (le->int (subseq data 40 44)))
              (block-hash (subseq data 44 76)) (prev (subseq data 76 108)) (message (subseq data 112))
              (candidate (up:make-signed-update :operator-id (lg:ledger-operator-key ledger) :ledger-id ledger-id
                                                :seq seq :prev-hash prev :message message
                                                :block-height block-height :block-hash block-hash)))
         (handler-case
             (progn
               (unless (equalp ledger-id (hex->bytes (record-id-hex rec))) (fail "ledger_id mismatch"))
               (unless (record-fork-p rec) (check-not-deposed node rec))
               ;; DEP-02: our tip is only a bound.  A height a little above it we wait for (the
               ;; operator saw a block before we did); the hash is never judged against our chain.
               (let ((ours (loop repeat *cosign-tip-wait-seconds* while (> block-height (height node)) do (sleep 1)
                                 finally (return (height node)))))
                 (when (plusp ours)
                   (when (> (- block-height ours) *cosign-height-tolerance*)
                     (fail "block_height ~a is more than ~a above our tip ~a" block-height *cosign-height-tolerance* ours))
                   (when (> (- ours block-height) *cosign-height-tolerance*)
                     (fail "block_height ~a is more than ~a below our tip ~a" block-height *cosign-height-tolerance* ours))))
               (when (and (> seq (1+ (lg:ledger-sequence ledger))) (not (record-fork-p rec)))
                 (catch-up node rec))
               (unless (= seq (1+ (lg:ledger-sequence ledger)))
                 (fail "expected seq ~a" (1+ (lg:ledger-sequence ledger))))
               (unless (equalp prev (lg:ledger-chain-tip ledger)) (fail "chain mismatch: not our tip"))
               (let ((v (up:header-violation (first (record-history rec)) candidate)))
                 (when v (fail "~a" v)))
               (let ((o (op:decode-operation message)))
                 ;; Speculative apply on a fresh replica: the op must be valid on our state.
                 ;; ADVERSARY :cosign-blind — a member that signs whatever chains (red team #1).
                 (unless (getf (node-adversary node) :cosign-blind)
                   ;; Depositor authorization, nonce window, expiry: at the height we sign.
                   (let ((v (cf:violation (record-ledger rec) o block-height))) (when v (fail "~a" v)))
                   (let ((lg:*block-height* block-height) (lg:*update-seq* seq))
                     (lg:apply-operation (lg:copy-ledger (record-ledger rec)) o)))
                 (multiple-value-bind (required signers tier operator-alone allowed)
                     (lg:cosign-requirement ledger o block-height)
                   (declare (ignore required signers tier operator-alone))
                   (unless allowed (fail "not cosignable at this height")))
                 (when (eq (op:operation-type o) :quorum-begin) (check-quorum-begin-vault node rec o params block-height))
                 (when (eq (op:operation-type o) :dormancy-accept) (check-dormancy-accept node rec o params))
                 (when (and (eq (op:operation-type o) :dormancy-notice) (op:field o :migration-receiver))
                   (check-migration-receiver node o)))
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

(defun address-spk (node address)
  (multiple-value-bind (witver program)
      (cl-consensus.encoding:segwit-decode address (rs:hrp-for (intern (string-upcase (node-network node)) :keyword)))
    (cat (octets (if (zerop witver) 0 (+ #x50 witver)) (length program)) program)))

(defun check-relayable (tx)
  "DEP-20 §3: every output of a rotation must relay — a standard type at or above its dust
   floor — or one bad exit makes the whole rotation unbroadcastable."
  (loop for out in (btx:tx-outputs tx) for i from 0
        unless (or (lg:standard-output-p (btx:txout-script out) (btx:txout-value out))
                   ;; DEP-03: the anchor, a zero-value OP_RETURN, last (standard: one 32-byte push)
                   (and (= i (1- (length (btx:tx-outputs tx)))) (rot:anchor-of tx)))
          do (fail "rotation output ~a (~a sats, ~a) would not relay" i (btx:txout-value out)
                   (or (lg:spk-type (btx:txout-script out)) "non-standard script"))))

(defun rung-tier-index (cur locktime height)
  "The tier of CUR whose CLTV is LOCKTIME (a rung's nLockTime), when it is open at HEIGHT."
  (let ((i (position locktime (rs:reserves-tiers cur) :key #'rs:tier-locktime)))
    (unless (and i (<= locktime (max height 0))) (fail "nLockTime ~a names no tier open at ~a" locktime height))
    i))

(defun expected-ladder (node rec o height anchor tier-index)
  "DEP-03: the rungs of the rotation the QuorumBegin O (signed at HEIGHT, extending the update
   whose chain hash is ANCHOR) records, built from REC as it stood before O at TIER-INDEX.  The
   new vault is the reserves O's own fields give (members, ledger hash, expiry, ruleset), which
   must be O's reserves_id.  (values rungs prevouts reserves splice)."
  (multiple-value-bind (cur txid vout sats operator) (disputed-reserves node rec)
    (let* ((sp (op:field o :splice-in-outpoint))
           (splice (when sp
                     (let ((stxid (subseq sp 0 32)) (svout (be->int sp :start 32)))
                       (multiple-value-bind (ssats sspk) (splice-prevout node stxid svout)
                         (unless (eql (op:field o :splice-in-amount) (* 1000 ssats))
                           (fail "splice_in_amount_msats is not the outpoint's value"))
                         (list stxid svout ssats sspk)))))
           (prevouts (if splice
                         (vector (cons sats (rs:reserves-spk cur)) (cons (third splice) (fourth splice)))
                         (vector (cons sats (rs:reserves-spk cur)))))
           (tier (or (nth tier-index (rs:reserves-tiers cur)) (fail "tier ~a out of range" tier-index)))
           (next (rs:build-reserves :operator operator :members (op:field o :quorum-members)
                                    :ledger-hash (op:field o :ledger-hash) :quorum-expiry (op:field o :quorum-expiry)
                                    :ruleset (or (op:field o :protocol-version) "cltv-offset-v2")
                                    :network (intern (string-upcase (node-network node)) :keyword)))
           (ledger (record-ledger rec))
           (cutoff (or (op:field o :exit-cutoff-height) (- height lg:+exit-cutoff-margin+))))
      (unless (equalp (address-spk node (op:field o :reserves-id)) (rs:reserves-spk next))
        (fail "reserves_id is not the reserves the QuorumBegin's quorum gives"))
      (values (rot:build-ladder :vault-txid txid :vault-vout vout :vault-sats sats
                                :feerate (lg:rotation-feerate ledger)
                                :voters (length (rs:reserves-voters cur)) :locktime (rs:tier-locktime tier)
                                :new-vault-spk (rs:reserves-spk next) :extras (settlement ledger height cutoff)
                                :splice (and splice (subseq splice 0 3))
                                :splice-vault-p (and splice (equalp (fourth splice) (rs:reserves-spk cur)))
                                :anchor anchor :collateral-msats (op:field o :collateral-amount)
                                :max-rungs (if (op:field o :migration-manifest) 1 rot:+rungs+))
              prevouts cur splice))))

(defun check-rotation-rungs (node rec o proposed &optional (height (height node)))
  "DEP-03 Rotation ordering, step 2: PROPOSED (unsigned rungs, rung order) is, byte for byte, the
   ladder we build for the QuorumBegin O extending our tip, their txids are O's rotation_rungs
   (rung 0's its new outpoint), every output relays, and rung 0's amounts are O's.  Signals
   otherwise.  Nothing is signed on chain yet, so there is no witness to check."
  (unless proposed (fail "a rotating QuorumBegin must carry rotation_rungs_tx"))
  (unless (and (equalp (btx:tx-txid (first proposed)) (op:field o :new-outpoint-txid)) (eql (op:field o :new-outpoint-vout) 0)
               (equalp (op:field o :spending-txid) (op:field o :new-outpoint-txid)))
    (fail "rung 0 is not the QuorumBegin's new outpoint"))
  (multiple-value-bind (cur) (disputed-reserves node rec)
    (let ((tier-index (rung-tier-index cur (btx:tx-locktime (first proposed)) height)))
      (multiple-value-bind (ours prevouts cur2 splice)
          (expected-ladder node rec o height (lg:ledger-chain-tip (record-ledger rec)) tier-index)
        (declare (ignore prevouts cur2))
        (unless (and ours (= (length ours) (length proposed))
                     (every (lambda (a b) (equalp (btx:serialize-tx a :witness nil) (btx:serialize-tx b :witness nil))) ours proposed))
          (fail "rotation_rungs_tx differ from the DEP-03 ladder we build"))
        (unless (equal (mapcar #'bytes->hex (mapcar #'btx:tx-txid ours)) (mapcar #'bytes->hex (fr:rotation-rungs o)))
          (fail "rotation_rungs is not the ladder's txids"))
        (dolist (tx proposed) (check-relayable tx))
        (let* ((ledger (record-ledger rec)) (tx (first proposed))
               (vault-sats (nth-value 3 (disputed-reserves node rec)))
               (cutoff (or (op:field o :exit-cutoff-height) (- height lg:+exit-cutoff-margin+)))
               (extras (settlement ledger height cutoff))
               (exits-cost (nth-value 3 (settlement ledger height cutoff)))
               (dorm-cost (nth-value 4 (settlement ledger height cutoff)))
               (new (btx:txout-value (first (btx:tx-outputs tx)))))
          (unless (= new (floor (+ (op:field o :amount) (op:field o :collateral-amount)) 1000))
            (fail "QuorumBegin amounts do not sum to the rotation's new vault"))
          (let* ((added (if splice (third splice) 0))
                 (c0 (- (rotation-collateral ledger vault-sats (- (+ vault-sats added) (reduce #'+ extras :key #'cdr) new exits-cost dorm-cost))
                        (* 1000 (+ dorm-cost (nth-value 6 (settlement ledger height cutoff)))))))
            (unless (<= c0 (op:field o :collateral-amount) (+ c0 (* 1000 added)))
              (fail "QuorumBegin collateral is not the DEP-20 §3-4 share"))))))))

(defun check-reference-feerate (node o height)
  "DEP-03: a recorded reference feerate must lie within the bounds the last 6 blocks give."
  (let ((f (op:field o :reference-feerate)) (m (median-feerate node height)))
    (when (and f m)
      (multiple-value-bind (lo hi) (feerate-bounds m)
        (unless (<= lo f hi) (fail "reference feerate ~a outside [~a, ~a] (median ~a)" f lo hi m))))))

(defun check-quorum-begin-vault (node rec o params &optional (height (height node)))
  "A QuorumBegin that rotates a current vault is checked against the unsigned rungs it carries
   (DEP-03 Rotation ordering); one with no current vault (the first, or the first after a
   DisputeAcquire) against the chain."
  (if (and (has-quorum-begin-p rec) (not (record-fork-p rec)))
      (let ((rungs (mapcar (lambda (h) (btx:parse-tx (bw:make-reader (hex->bytes h))))
                           (coerce (or (w:jget params "rotation_rungs_tx") #()) 'list))))
        (check-rotation-rungs node rec o rungs height)
        (check-reference-feerate node o height))
      (progn (check-reserves-outpoint node o) (check-reference-feerate node o height))))

;;; DEP-03 §Fee ladder: every rung of a recorded rotation we hold, (re)broadcast until one confirms.
;;; Rung i goes out once the QuorumBegin is 6·i blocks old with none confirmed: every holder
;;; computes the same schedule, so all of them push the same rung.

(defparameter *rung-bump-blocks* 6 "DEP-03: blocks a rung may stay unconfirmed before the next replaces it.")

(defun note-rotation-rungs (node rung0-txid rung-bytes qb-height)
  "Keep RUNG-BYTES (signed, rung order; NIL where unknown) of the rotation whose rung 0 is RUNG0-TXID."
  (let* ((e (gethash rung0-txid (node-inflight-rotations node)))
         (have (and e (getf e :rungs)))
         (n (max (length rung-bytes) (length have)))
         (merged (loop for i below n collect (or (nth i rung-bytes) (nth i have)))))
    (setf (gethash rung0-txid (node-inflight-rotations node))
          (list :rungs merged :qb-height (or qb-height (and e (getf e :qb-height)) 0)))))

(defun handle-rotation-tx (node event)
  "Kind 9107: keep a rung of a recorded rotation to (re)broadcast and bump, as any watcher may."
  (ignore-errors
   (let* ((c (w:parse-json (ev:event-content event)))
          (rec (find-record node (w:jget c "ledger_id")))
          (bytes (hex->bytes (w:jget c "tx")))
          (txid (btx:tx-txid (btx:parse-tx (bw:make-reader bytes))))
          (qu (and rec (find (w:jget c "sequence") (record-history rec) :key #'up:update-seq)))
          (o (and qu (op:decode-operation (up:update-message qu))))
          (rungs (and o (eq (op:operation-type o) :quorum-begin) (fr:rotation-rungs o)))
          (i (and rungs (position txid rungs :test #'equalp))))
     (when i
       (note-rotation-rungs node (first rungs) (loop for k from 0 to i collect (and (= k i) bytes)) (up:update-block-height qu))))))

(defun drive-rotation-rebroadcast (node)
  "DEP-03: rebroadcast every recorded rotation we hold until a rung confirms, moving to rung i
   once its QuorumBegin is 6·i blocks old.  Also resumes the signing of a rotation of ours that
   was recorded but not yet signed (a restart, or too few members answered)."
  (loop for rec being the hash-values of (node-ledgers node)
        when (and (record-owned-p rec) (not (record-fork-p rec)))
          do (let ((r (pending-rotation node rec)))
               (when (and r (getf r :qb-seq))
                 (let ((qu (find (getf r :qb-seq) (record-history rec) :key #'up:update-seq)))
                   (if qu
                       (handler-case (sign-rotation-rungs node rec qu :timeout 30)
                         (error (c) (log! node "rotation of ~a still awaits its rung signatures: ~a" (subseq (record-id-hex rec) 0 8) c)))
                       (clear-rotation node rec))))))
  (when (and (node-broadcast-fn node) (node-chain-fn node))
    (loop for rung0 being the hash-keys of (node-inflight-rotations node) using (hash-value e)
          do (let* ((rungs (getf e :rungs))
                    (confirmed (loop for b in rungs
                                     thereis (and b (let ((info (ignore-errors (funcall (node-chain-fn node) (btx:tx-txid (btx:parse-tx (bw:make-reader b))) 0))))
                                                      (and info (>= (or (getf info :confirmations) 0) 1)))))))
               (if confirmed
                   (remhash rung0 (node-inflight-rotations node))
                   (let* ((want (min (1- (length rungs)) (max 0 (floor (- (height node) (getf e :qb-height)) *rung-bump-blocks*))))
                          (b (loop for i from want downto 0 thereis (nth i rungs))))
                     (when b (ignore-errors (funcall (node-broadcast-fn node) b)))))))))

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
                                              lg:+supported-rulesets+)))
                 (let ((v (w:jget params "min_fee_bps"))) (and v (cons 10 (int->be v 2))))
                 (let ((v (w:jget params "min_fee_fixed"))) (and v (cons 11 (int->be v 8))))
                 (let ((v (w:jget params "max_fee_period"))) (and v (cons 12 (int->be v 4))))
                 (and (integerp until) (cons 13 (int->be until 4)))))))

;;; ---------------------------------------------------------------------------
;;; DEP-10 funding offers (we are the operator, or a member cosigning one)

(defun offer-cosign-digest (ledger-id-hex offer-id deposit-id operator33 address deadline member-ledger-hash)
  (lg:offer-cosign-digest ledger-id-hex offer-id deposit-id operator33 address deadline member-ledger-hash))

(defun offer-address (node offer-id)
  "A key-path P2TR of our key committing OFFER-ID (tweaked by it), so each offer's payments are its own."
  (let ((spk (lot:p2tr-spk (up:x-only (node-pubkey node)) (sha256 offer-id))))
    (values (cl-consensus.encoding:segwit-encode (rs:hrp-for (intern (string-upcase (node-network node)) :keyword)) 1
                                                 (subseq spk 2))
            spk)))

(defun make-offer (node rec descriptor max-sats min-sats blocks-valid)
  "DEP-10: a funding offer for DESCRIPTOR's deposit, cosigned by a member once the quorum is
   active.  Returns the response object."
  (unless (< 0 min-sats max-sats) (fail "need 0 < min_sats < max_sats"))
  (let* ((offer-id (random-aux)) (deadline (+ (height node) blocks-valid)))
    (multiple-value-bind (address spk) (offer-address node offer-id)
      (let ((offer (list :offer-id offer-id :descriptor descriptor :deposit-id (op:deposit-id descriptor)
                         :address address :spk spk :deadline deadline :min min-sats :max max-sats :status :pending))
            (cosign nil))
        (when (eq (lg:ledger-quorum-state (record-ledger rec)) :active)
          (let ((r (first (send-request node (record-id-hex rec) "cosign_offer"
                                        (w:json-object "offer_id" (bytes->hex offer-id) "operator_id" (node-pubkey-hex node)
                                                       "deposit_id" (bytes->hex (op:deposit-id descriptor))
                                                       "funding_address" address "deadline_block" deadline)
                                        :want 1 :successes-only t))))
            (let ((res (and r (w:jget r "result"))))
              (when (stringp res) (setf res (w:parse-json res)))
              (unless res (fail "no member cosigned the offer"))
              (let ((pk (hex->bytes (w:jget res "cosigner_pubkey"))) (sig (hex->bytes (w:jget res "signature_hex")))
                    (mlh (hex->bytes (w:jget res "member_ledger_hash_hex"))))
                (unless (schnorr:schnorr-verify (up:x-only pk)
                                                (offer-cosign-digest (record-id-hex rec) offer-id (op:deposit-id descriptor) (node-pubkey node) address deadline mlh) sig)
                  (fail "offer cosignature does not verify"))
                (setf cosign res)))))
        (setf (gethash offer-id (record-offers rec)) offer)
        (apply #'w:json-object "offer_id" (bytes->hex offer-id) "operator_id" (node-pubkey-hex node)
               "deposit_id" (bytes->hex (op:deposit-id descriptor))
               "funding_address" address "deadline_block" deadline "max_sats" max-sats "min_sats" min-sats
               "cosign_required" (and cosign t)
               (when cosign (list "cosigner_pubkey" (w:jget cosign "cosigner_pubkey")
                                  "cosigner_ledger_hash" (w:jget cosign "member_ledger_hash_hex")
                                  "cosign_signature" (w:jget cosign "signature_hex"))))))))

(defun complete-offer (node rec offer-id txid vout)
  "DEP-10 §Completion: credit output VOUT of TXID if it pays the offer's address and confirmed at
   a height <= its deadline; the credit is the output's value (capped at the maximum)."
  (let ((offer (or (gethash offer-id (record-offers rec)) (fail "unknown offer"))))
    (when (eq (getf offer :status) :completed) (return-from complete-offer (getf offer :credited)))
    (let ((info (or (and (node-chain-fn node) (funcall (node-chain-fn node) txid vout)) (fail "no such unspent output"))))
      (unless (equalp (getf info :spk) (getf offer :spk)) (fail "the output does not pay the offer's address"))
      (let ((confs (or (getf info :confirmations) 0)))
        (unless (plusp confs) (fail "the funding output is unconfirmed"))
        (when (> (- (height node) (1- confs)) (getf offer :deadline))
          (fail "funding confirmed after the offer's deadline ~a" (getf offer :deadline))))
      (let ((sats (getf info :value-sats)))
        (when (< sats (getf offer :min)) (fail "funding ~a sats below the minimum ~a" sats (getf offer :min)))
        (let ((msat (* 1000 (min sats (getf offer :max)))) (id (getf offer :deposit-id)))
          (unless (gethash id (lg:ledger-deposits (record-ledger rec)))
            (append-operation node rec (list :type :deposit-open :deposit-id id :descriptor (getf offer :descriptor)
                                             :fees (op:make-fees :frequency-blocks 2016) :receive-requires-sig nil)))
          (credit-onchain node rec id msat :txid txid :vout vout :funding-address (getf offer :address))
          (setf (getf (gethash offer-id (record-offers rec)) :status) :completed
                (getf (gethash offer-id (record-offers rec)) :credited) msat)
          msat)))))

(defun dormancy-offer (node rec)
  "DEP-20 §8.3: what a DormancyOffer (Kind 9110) offers now: (values manifest-entries hash total)."
  (let ((m (lg:dormancy-offer-entries (record-ledger rec) (height node))))
    (values m (sha256 (op:encode-manifest m)) (reduce #'+ m :key (lambda (e) (getf e :amount))))))

(defun accept-address (node rec)
  "DEP-20 §8.3: the address a receiver's accept names — its current vault, so the migration sits
   under the quorum's tiers until spliced.  (values address spk)."
  (let ((reserves (disputed-reserves node rec)))
    (values (rs:reserves-address reserves) (rs:reserves-spk reserves))))

(defun dormancy-accept (node rec manifest offer-event-id total &key (expiry-blocks 288) premium-deposit source-ledger)
  "DEP-20 §8.3 receiver: accept a manifest.  Cosigners check its hash, our capacity and fee floors.
   Returns the signed update (its bytes go into the source's DormancyNotice)."
  (let ((hash (sha256 (op:encode-manifest manifest))))
    (multiple-value-bind (address spk) (accept-address node rec)
      (declare (ignore address))
      (let ((*extra-cosign-params* (list "migration_manifest" (bytes->hex (op:encode-manifest manifest)))))
        (append-operation node rec (%strip-nil-fields
                                    (list :type :dormancy-accept :deposit-id premium-deposit :exit-address spk
                                          :expires-at-height (+ (height node) expiry-blocks) :manifest-hash hash
                                          :offer-event-id offer-event-id :accepted-total total
                                          :source-ledger-id source-ledger)))))))

(defun check-dormancy-accept (node rec o params)
  "A receiver's cosigner: the accept names our current vault script, the manifest the request
   carries hashes to the accept's, and our quorum's fee floors are at or below every deposit's
   schedule (DEP-20 §8.3)."
  (unless (equalp (op:field o :exit-address) (ignore-errors (rs:reserves-spk (disputed-reserves node rec))))
    (fail "the accept does not name our current vault script"))
  (let* ((hex (or (w:jget params "migration_manifest") (fail "a DormancyAccept cosign must carry the manifest")))
         (m (op:decode-manifest (hex->bytes hex))))
    (unless (equalp (sha256 (hex->bytes hex)) (op:field o :manifest-hash)) (fail "manifest does not hash to the accept's"))
    (dolist (mem (lg:ledger-quorum-members (record-ledger rec)))
      (dolist (e m)
        (let ((f (getf e :fees)))
          (when (or (and (lg::member-min-fee-bps mem) (< (op:fees-annualized-bps f) (lg::member-min-fee-bps mem)))
                    (and (lg::member-min-fee-fixed mem) (< (op:fees-annualized-msats f) (lg::member-min-fee-fixed mem))))
            (fail "deposit ~a's fees are below a member's floor" (bytes->hex (getf e :deposit-id)))))))))

(defun receiver-history (node ledger-id-hex)
  "A receiver ledger's history, ascending: our replica if we hold one, else the relays'."
  (let ((r (find-record node ledger-id-hex)))
    (if (and r (not (record-fork-p r))) (reverse (record-history r)) (ledger-updates-from-relays node ledger-id-hex))))

(defun receiver-governing-quorum-begin (node accept-update)
  "DEP-20 §8.3: the receiver's latest QuorumBegin before ACCEPT-UPDATE, from its history."
  (let ((qb nil))
    (dolist (u (receiver-history node (bytes->hex (up:update-ledger-id accept-update))))
      (when (and (< (up:update-seq u) (up:update-seq accept-update))
                 (eq (ignore-errors (op:operation-type (op:decode-operation (up:update-message u)))) :quorum-begin))
        (setf qb u)))
    (or qb (fail "the receiver's ledger has no QuorumBegin before the accept"))))

(defun check-migration-receiver (node o)
  "DEP-20 §8.3 (L4), a source cosigner: the accept is in the receiver's canonical history, the
   carried QuorumBegin is the receiver's latest (its quorum is current), and that vault is funded
   and unspent on chain."
  (let* ((au (up:decode-update (op:field o :dormancy-accept)))
         (qu (up:decode-update (or (op:field o :receiver-quorum-begin) (fail "no receiver_quorum_begin"))))
         (qb (op:decode-operation (up:update-message qu)))
         (hist (receiver-history node (bytes->hex (up:update-ledger-id au))))
         (ours (find (up:update-seq au) hist :key #'up:update-seq))
         (latest-qb (let ((q nil))
                      (dolist (u hist q)
                        (when (eq (ignore-errors (op:operation-type (op:decode-operation (up:update-message u)))) :quorum-begin)
                          (setf q u))))))
    (unless (and ours (equalp (up:chain-hash ours) (up:chain-hash au)))
      (fail "the accept is not in the receiver's history"))
    (unless (and latest-qb (equalp (up:chain-hash latest-qb) (up:chain-hash qu)))
      (fail "the carried QuorumBegin is not the receiver's current one"))
    (when (node-chain-fn node)
      (let ((info (funcall (node-chain-fn node) (op:field qb :new-outpoint-txid) (op:field qb :new-outpoint-vout))))
        (unless (and info (plusp (or (getf info :confirmations) 0))
                     (= (getf info :value-sats) (floor (+ (op:field qb :amount) (op:field qb :collateral-amount)) 1000)))
          (fail "the receiver's vault is not funded and unspent on chain"))))
    t))

(defun migration-source-updates (node accept source-ledger-hex)
  "DEP-20 §8.3 receiver: from SOURCE-LEDGER-HEX's history, the notice carrying ACCEPT (our accept
   record) and the QuorumBegin that consumed it: (values notice-update qb-update) or NIL."
  (let* ((hist (receiver-history node source-ledger-hex))
         (nu (find-if (lambda (u) (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
                                    (and o (eq (op:operation-type o) :dormancy-notice)
                                         (equalp (op:field o :manifest-hash) (getf accept :hash)))))
                      hist :from-end t))
         (id (and nu (sha256 (up:update-message nu))))
         (qu (and id (find-if (lambda (u) (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
                                            (and o (eq (op:operation-type o) :quorum-begin)
                                                 (equalp (op:field o :consumed-notice) id))))
                              hist))))
    (when qu (values nu qu))))

(defun dormancy-credit (node rec source-ledger-hex)
  "DEP-20 §8.3 receiver: resolve our accept with positive evidence — the source's notice and the
   QuorumBegin that consumed it (MigrationCredit); the fold credits exactly what migrated."
  (let ((a (or (lg:ledger-dormancy-accept (record-ledger rec)) (fail "no accept to resolve"))))
    (multiple-value-bind (nu qu) (migration-source-updates node a source-ledger-hex)
      (unless qu (fail "the source has not yet consumed the notice"))
      (append-operation node rec (list :type :migration-credit :source-notice-update (up:encode-update nu)
                                       :source-qb-update (up:encode-update qu))))))

(defun handle-cosign-offer (node event params)
  "A member: cosign an operator's funding offer (DEP-10) unless its operator is deposed."
  (let* ((id (w:event-ledger-id event)) (rec (find-record node id)))
    (unless rec (return-from handle-cosign-offer nil))
    (handler-case
        (progn
          (check-not-deposed node rec)
          (unless (member (node-pubkey node) (mapcar #'lg:member-pubkey (lg:ledger-quorum-members (record-ledger rec))) :test #'equalp)
            (fail "not a quorum member"))
          (let* ((offer-id (hex->bytes (w:jget params "offer_id")))
                 (operator (hex->bytes (w:jget params "operator_id")))
                 (address (w:jget params "funding_address")) (deadline (w:jget params "deadline_block"))
                 (deposit-id (hex->bytes (or (w:jget params "deposit_id") (fail "an offer names its deposit_id (DEP-10)"))))
                 (mlh (member-ledger-hash node)))
            (unless (equalp operator (lg:ledger-operator-key (record-ledger rec))) (fail "not this ledger's operator"))
            (unless (and (= (length offer-id) 32) (stringp address) (integerp deadline)) (fail "malformed offer"))
            (respond node event t
                     :result (w:json-object "signature_hex" (bytes->hex (schnorr:schnorr-sign (node-priv node)
                                                                                            (offer-cosign-digest id offer-id deposit-id operator address deadline mlh)
                                                                                            (random-aux)))
                                            "cosigner_pubkey" (node-pubkey-hex node)
                                            "member_ledger_hash_hex" (bytes->hex mlh)))))
      (error (e) (respond node event nil :error (princ-to-string e))))))

;;; ---------------------------------------------------------------------------
;;; Inbound: wallet requests (we are the operator)

(defun handle-wallet-request (node rec event action params)
  (when (member action (node-ignore-actions node) :test #'string=)
    (log! node "ignoring ~a (test switch)" action)
    (return-from handle-wallet-request nil))
  ;; ADVERSARY :ignore-requests — an operator that answers nothing, with no
  ;; error either: the wallet's request times out and nothing on the ledger
  ;; records why (red team: DEP-12 censorship, the escalation path's start).
  (when (getf (node-adversary node) :ignore-requests)
    (log! node "ADVERSARY: dropping wallet request ~a on ~a" action (subseq (record-id-hex rec) 0 8))
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
           (unless (check-nonce node rec o) (append-operation node rec o))
           (respond node event t :result (w:json-object "transfer_id" (bytes->hex (op:field o :transfer-id))))))
        ((member action '("exit_request" "exit_cancel") :test #'string=)
         ;; DEP-20 §3: a depositor-signed ExitRequest / ExitCancel, appended as signed.
         (let* ((o (op:decode-operation (base64-decode (or (w:jget params "operation") (fail "operation required")))))
                (want (if (string= action "exit_request") :exit-request :exit-cancel))
                (d (lg:find-deposit (record-ledger rec) (op:field o :deposit-id))))
           (unless (eq (op:operation-type o) want) (fail "not an ~a" want))
           (unless (authorized-p node rec o d (op:field o :witness)) (fail "witness does not authorize this operation"))
           (let ((u (or (nth-value 1 (check-nonce node rec o)) (append-operation node rec o))))
             (respond node event t :result (w:json-object "exit_request_id" (bytes->hex (if (eq want :exit-request)
                                                                                          (sha256 (op:encode-operation o))
                                                                                          (op:field o :exit-request-id)))
                                                          "sequence" (up:update-seq u))))))
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
        ((string= action "make_offer")
         (respond node event t :result (make-offer node rec (or (w:jget params "descriptor") (fail "descriptor required"))
                                                   (or (w:jget params "max_sats") (fail "max_sats required"))
                                                   (or (w:jget params "min_sats") 1) (or (w:jget params "blocks_valid") 144))))
        ((string= action "complete_offer")
         (let* ((tx (w:jget params "txid"))
                ;; display or internal hex: try the display order (what wallets print) first
                (raw (hex->bytes tx))
                (oid (hex->bytes (w:jget params "offer_id"))) (vout (or (w:jget params "vout") (fail "vout required")))
                (msat (handler-case (complete-offer node rec oid (reverse raw) vout)
                        (error () (complete-offer node rec oid raw vout)))))
           (respond node event t :result (w:json-object "status" "SUCCESS" "credited_msats" msat))))
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
  "Does deposit D's descriptor authorize operation O with WITNESS (a stack)?
   (The rule itself, with the nonce window and expiry, is CF:VIOLATION: cosigners
   and replicas apply it too.)"
  (declare (ignore rec))
  (let ((o (if (equal witness (op:field o :witness)) o (list* :witness witness (copy-list o)))))
    (cf:authorized-p o d (height node))))

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

(defun settle-invoice-lock (node rec payment-id outcome preimage)
  "Append the InvoiceFulfill or InvoiceFail that OUTCOME calls for, if the lock is
   still open.  Only a definitive outcome settles: :succeeded with a preimage that
   hashes to the payment id, or :failed.  Returns the operation appended, or NIL."
  (let ((lock (gethash payment-id (lg:ledger-open-invoice-locks (record-ledger rec)))))
    (when lock
      (cond
        ((and (eq outcome :succeeded) preimage (equalp (sha256 preimage) payment-id))
         (let ((o (list :type :invoice-fulfill :deposit-id (getf lock :deposit-id) :amount (getf lock :amount)
                        :payment-id payment-id :sequence-number (1+ (lg:ledger-sequence (record-ledger rec)))
                        :witness (getf lock :witness) :preimage preimage)))
           (append-operation node rec o) o))
        ((eq outcome :failed)
         (let ((o (list :type :invoice-fail :deposit-id (getf lock :deposit-id) :payment-id payment-id
                        :sequence-number (1+ (lg:ledger-sequence (record-ledger rec))))))
           (append-operation node rec o) o))))))

(defvar *pay-poll-rounds* 60 "Half-second polls a pay_invoice handler waits before answering pending.")

;;; DEP-17 §duplicate delivery.  A relay can deliver one request twice, and a wallet retries a
;;; request whose answer it missed.  The operation it carries is then already on the ledger:
;;; answer as we answered it, never append it again and never answer with a replay error.

(defun nonce-check (node rec o)
  "Classify depositor-signed operation O against REC's ledger at our height:
   (values verdict original-op original-update), VERDICT one of cf:nonce-verdict's.  The
   ledger's seen nonces say whether a live operation shares O's nonce; only then is the history
   read for those operations' sighashes."
  (let* ((h (height node)) (nonce (op:field o :nonce)) (expiry (op:field o :expiry))
         (d (lg:find-deposit (record-ledger rec) (cf:operation-deposit-id o)))
         (live (count-if (lambda (seen) (and (eql (car seen) nonce) (cdr seen) (>= (cdr seen) h)))
                         (lg:deposit-seen-nonces d)))
         (sighash (cf:signed-sighash o)) (accepted '()) (hit nil))
    (when (plusp live)
      (loop for u in (record-history rec)
            for a = (ignore-errors (op:decode-operation (up:update-message u)))
            when (and a (eql (ignore-errors (op:field a :nonce)) nonce)
                      (equalp (cf:operation-deposit-id a) (cf:operation-deposit-id o))
                      (cf:signed-sighash a))
              do (let ((sh (cf:signed-sighash a)))
                   (push (list nonce (op:field a :expiry) sh) accepted)
                   (when (and (null hit) (equalp sh sighash)) (setf hit (cons a u))))
            until (>= (count-if (lambda (x) (>= (second x) h)) accepted) live)))
    (values (cf:nonce-verdict accepted nonce expiry sighash h) (car hit) (cdr hit))))

(defun check-nonce (node rec o)
  "Fail on an expired or replayed O; return the accepted original when O is its duplicate."
  (multiple-value-bind (verdict original update) (nonce-check node rec o)
    (ecase verdict
      (:expired (fail "operation expired"))
      (:replay (fail "nonce replayed"))
      (:duplicate (values original update))
      (:accept nil))))

(defun invoice-fulfill-preimage (rec payment-id)
  (loop for u in (record-history rec)
        for a = (ignore-errors (op:decode-operation (up:update-message u)))
        when (and a (eq (op:operation-type a) :invoice-fulfill) (equalp (op:field a :payment-id) payment-id))
          return (op:field a :preimage)))

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
         (d (lg:find-deposit (record-ledger rec) (op:field o :deposit-id)))
         (asked (ln:invoice-amount-msat bolt11)))
    (unless (equalp (ln:invoice-payment-hash bolt11) (op:field o :payment-id)) (fail "payment_hash does not match the invoice"))
    ;; The lock is what the depositor authorised.  An invoice for any other
    ;; amount is refused here, before anything is locked or sent.
    (when (and asked (/= asked (op:field o :amount)))
      (fail (format nil "the invoice is for ~d msat but the lock is for ~d" asked (op:field o :amount))))
    (unless (authorized-p node rec o d (op:field o :witness)) (fail "witness does not authorize this lock"))
    (when (check-nonce node rec o)
      ;; Already locked: answer as the original does now, and never pay twice.
      (let* ((pid (op:field o :payment-id)) (preimage (invoice-fulfill-preimage rec pid)))
        (return-from handle-pay-invoice
          (cond (preimage
                 (respond node event t :result (w:json-object "payment_id" (bytes->hex pid)
                                                              "deposit_id" (bytes->hex (op:field o :deposit-id))
                                                              "amount_msat" (op:field o :amount) "preimage" (bytes->hex preimage)
                                                              "status" "succeeded")))
                ((gethash pid (lg:ledger-open-invoice-locks (record-ledger rec)))
                 (respond node event nil :error "payment pending; the lock stays until it settles or fails"))
                (t (respond node event nil :error "payment failed; lock released"))))))
    (append-operation node rec o)
    (let ((pid (op:field o :payment-id)) (outcome :pending) (preimage nil))
      (setf (gethash pid (node-ln-polling node)) t)
      (unwind-protect
           (progn
             (handler-case
                 (progn (ln:ln-pay (node-ln node) bolt11 :amount-msat (op:field o :amount) :height (height node))
                        (loop repeat *pay-poll-rounds*
                              do (multiple-value-bind (st pre) (ln:ln-payment-status (node-ln node) pid)
                                   (case st
                                     (:succeeded (setf outcome :succeeded preimage pre) (return))
                                     (:failed (setf outcome :failed) (return))
                                     (t (sleep 0.5))))))
               ;; Declined before any HTLC went out: nothing was sent, so the lock
               ;; can be released.
               (ln:ln-refused (e) (log! node "pay refused: ~a" e) (setf outcome :failed))
               ;; Anything else (a dropped socket, a status we could not read) says
               ;; nothing about whether the payment is in flight: keep the lock.
               (error (e) (log! node "pay ~a: ~a — the lock stays until it resolves" (subseq (bytes->hex pid) 0 8) e)))
             (let ((settled (settle-invoice-lock node rec pid outcome preimage)))
               (cond
                 ((and settled (eq (op:operation-type settled) :invoice-fulfill))
                  (respond node event t :result (w:json-object "payment_id" (bytes->hex pid)
                                                               "deposit_id" (bytes->hex (op:field o :deposit-id))
                                                               "amount_msat" (op:field o :amount) "preimage" (bytes->hex preimage)
                                                               "status" "succeeded")))
                 (settled (respond node event nil :error "payment failed; lock released"))
                 (t (respond node event nil :error "payment pending; the lock stays until it settles or fails")))))
        (remhash pid (node-ln-polling node))))))

(defun settle-pending-payments (node)
  "Every open InvoiceLock on a ledger we operate whose payment is not being polled
   by its handler: ask the Lightning node, and settle the ones it can vouch for.
   The ledger's open locks are the persisted list, so this resumes after a restart.
   Returns the payment ids settled."
  (let ((settled '()))
    (when (node-ln node)
      (loop for rec being the hash-values of (node-ledgers node)
            when (and (record-owned-p rec) (not (record-fork-p rec)))
              do (loop for pid in (loop for k being the hash-keys of (lg:ledger-open-invoice-locks (record-ledger rec)) collect k)
                       unless (gethash pid (node-ln-polling node))
                         do (handler-case
                                (multiple-value-bind (st pre) (ln:ln-payment-status (node-ln node) pid)
                                  (when (settle-invoice-lock node rec pid st pre) (push pid settled)))
                              (error (e) (log! node "settle ~a: ~a" (subseq (bytes->hex pid) 0 8) e))))))
    settled))

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
            when (multiple-value-bind (st received) (ln:ln-invoice-status (node-ln node) hash)
                   ;; Paid means at least the invoiced amount ARRIVED.  A status
                   ;; without a received amount is not enough to credit on.
                   (and (eq st :paid) received (>= received (getf inv :amount))))
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
  ;; ADVERSARY :ignore-fraud — a derelict member also lets an expired quorum lie.
  (when (getf (node-adversary node) :ignore-fraud) (return-from dispute-expired-quorums nil))
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
  "FORK's most recent update of operation TYPE its own operator signed, and its decoded operation.
   (A dispute of a ledger after a custody change forks the winner's chain, whose DisputeEnter and
   DisputeAcquire are the winner's, not this fork's.)"
  (let ((u (find-if (lambda (u) (and (equalp (up:update-operator-id u) (record-fork-operator fork))
                                     (eq (op:operation-type (op:decode-operation (up:update-message u))) type)))
                    (record-history fork))))
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

(defun rebuild-confiscation-on-chain (node id-hex)
  "Rebuild ID-HEX's confiscation from public state as the one whose lottery
   output is in the UTXO set: (tx lottery prevouts reserves tier), or NIL.  Its
   txid depends on the tier (nLockTime) and on whether it was respectful (the
   operator's change output), so both are tried; a rebuild with the defaults
   (non-respectful) never matched a respectful confiscation after a restart."
  (when (and (node-chain-fn node)
             ;; No confiscation can exist while the vault is unspent: one gettxout instead of
             ;; rebuilding every shape x tier x armer subset, each with its obligations (a
             ;; chain walk apiece), on every drive-disputes pass of a fresh dispute.
             (multiple-value-bind (r txid vout) (disputed-reserves node (find-record node id-hex))
               (declare (ignore r))
               (not (funcall (node-chain-fn node) txid vout))))
    (flet ((try (armers)
             (loop for respectful in '(t nil)
                   thereis (loop for ti below (length (rs:reserves-tiers (disputed-reserves node (find-record node id-hex))))
                                 for built = (ignore-errors (multiple-value-list (build-confiscation node id-hex :tier-index ti :respectful respectful :armers armers)))
                                 when (and built (first built) (funcall (node-chain-fn node) (btx:tx-txid (first built)) 0))
                                   return built))))
      ;; The eligibility cut first; then every other set of two or more armers, so
      ;; a confiscation built on a different view of the cut (or by an older node,
      ;; over every armer) is still recognised.
      (or (try nil)
          (let ((all (sort (copy-list (armers-of node id-hex)) #'bytes< :key #'first)))
            (when (<= (length all) 8)
              (loop for mask from (1- (ash 1 (length all))) downto 3
                    for subset = (loop for a in all for i from 0 when (logbitp i mask) collect a)
                    thereis (and (>= (length subset) 2) (try subset)))))))))

(defun confiscation-on-chain (node id-hex)
  "The confiscation of ID-HEX whose lottery output is in the UTXO set (we
   proposed or signed it, or it rebuilds from public state), or NIL.  Reserves
   that are merely spent prove nothing: a stranded rotation spends them too."
  (when (node-chain-fn node)
    (let ((known (loop for f in (forks-of node id-hex) thereis (record-confiscation f))))
      (or (and known (funcall (node-chain-fn node) (btx:tx-txid known) 0) known)
          (first (rebuild-confiscation-on-chain node id-hex))))))

;;; DEP-06 Phase 4: the full-set leaf when everyone revealed; otherwise, past the
;;; reveal deadline, the leaf of the revealers R, which the recovery voters attest.
;;; Nobody revealing sends the output to a re-arm round (not yet orchestrated), and
;;; no voter signs a recovery spend to the accused operator.

(defconstant +max-arms+ 4 "Arms that count per armer: the first and up to three re-arms (DEP-03).")

(defvar *rebuild-misses* (make-hash-table :test #'equalp))
(defvar *rebuild-misses-lock* (bt:make-lock "rebuild-misses"))

(defun note-confiscation-height (node id-hex info)
  "INFO is the chain-fn's view of a confiscation's lottery output: once confirmed, remember
   the block it confirmed in (DEP-03: arms above it do not count).  Returns INFO."
  (let ((c (getf info :confirmations)))
    (when (and c (plusp c) (not (gethash id-hex (node-confiscation-heights node))))
      (setf (gethash id-hex (node-confiscation-heights node)) (1+ (- (height node) c)))))
  info)

(defun confiscated-lottery (node id-hex)
  "The confiscation of ID-HEX that is on chain: one we signed, or rebuilt from
   public state.  (values tx lottery :pending) while its lottery output is unspent."
  (when (node-chain-fn node)
    (loop for (tx . l) in (gethash id-hex (node-signed-confiscations node))
          when (note-confiscation-height node id-hex (funcall (node-chain-fn node) (btx:tx-txid tx) 0))
            do (return-from confiscated-lottery (values tx l :pending)))
    ;; A proposal we saw but did not sign: its lottery output names its participant set, so
    ;; recover the set from it (DEP-03: final once a confiscation confirms).
    (loop for tx in (gethash id-hex (node-seen-confiscations node))
          when (note-confiscation-height node id-hex (funcall (node-chain-fn node) (btx:tx-txid tx) 0))
            do (let ((l (lottery-paid-by node id-hex (btx:txout-script (first (btx:tx-outputs tx))))))
                 (when l (return-from confiscated-lottery (values tx l :pending)))))
    ;; We hold this ledger's confiscation and its lottery output is gone (claimed): nothing
    ;; pending, and rebuilding every shape x tier x subset would only rediscover that, at a
    ;; chain walk per obligation, on every pass.
    (unless (or (gethash id-hex (node-signed-confiscations node))
                (gethash id-hex (node-seen-confiscations node))
                (let ((until (bt:with-lock-held (*rebuild-misses-lock*) (gethash (cons (node-pubkey node) id-hex) *rebuild-misses*))))
                  (and until (< (height node) until))))
      (let ((built (rebuild-confiscation-on-chain node id-hex)))
        (if built
            (values (first built) (second built) :pending)
            ;; Spent vault, no pending lottery it rebuilds to (claimed, or not a confiscation):
            ;; final, since nothing can spend that vault again, so the shape x tier x subset
            ;; search is not repeated (until a restart).
            (when (multiple-value-bind (r txid vout) (disputed-reserves node (find-record node id-hex))
                    (declare (ignore r))
                    (not (funcall (node-chain-fn node) txid vout)))
              (bt:with-lock-held (*rebuild-misses-lock*)
                (setf (gethash (cons (node-pubkey node) id-hex) *rebuild-misses*) most-positive-fixnum))
              nil))))))

(defun lottery-paid-by (node id-hex spk)
  "The lottery over a subset of ID-HEX's armers whose output script is SPK (our cut
   first, then every subset, largest first), or NIL."
  (let* ((base (find-record node id-hex)) (voters (recovery-voters base (dispute-last-valid-seq node id-hex)))
         (threshold (lg:majority-threshold (length voters)))
         (network (intern (string-upcase (node-network node)) :keyword)))
    (flet ((try (armers)
             (let ((ps (loop for (pk c target) in armers collect (lot:make-participant :pubkey (up:x-only pk) :commitment c :target target))))
               (when ps
                 (let ((l (ignore-errors (lot:build-lottery ps voters threshold :network network))))
                   (and l (equalp (lot:lottery-spk l) spk) l))))))
      (or (try (ignore-errors (lottery-armers node id-hex)))
          (let ((all (sort (copy-list (armers-of node id-hex)) #'bytes< :key #'first)))
            (when (<= (length all) 8)
              (loop for mask from (1- (ash 1 (length all))) downto 1
                    thereis (try (loop for a in all for i from 0 when (logbitp i mask) collect a)))))))))

(defun reveal-deadline-passed-p (node conf)
  (let ((info (and (node-chain-fn node) (funcall (node-chain-fn node) (btx:tx-txid conf) 0))))
    (and info (>= (getf info :confirmations) lot:+reveal-csv+))))

(defun revealed-indices (node id-hex lottery)
  "(values indices preimages): the participants whose valid reveals we hold, in
   canonical order."
  (let ((reveals (reveals-of node id-hex)) (idx '()) (pre '()))
    (loop for p in (lot:lottery-participants lottery) for i from 0
          for r = (cdr (find (lot:participant-pubkey p) reveals :key (lambda (r) (up:x-only (car r))) :test #'equalp))
          when (and r (equalp (lot:commitment-of r) (lot:participant-commitment p)) (<= 17 (length r) lot:+max-preimage-len+))
            do (push i idx) (push r pre))
    (values (nreverse idx) (nreverse pre))))

(defun handle-lottery-subset-attest (node event params)
  "A recovery voter (DEP-06 Phase 4): sign a revealer-subset claim only past the
   reveal deadline, only for exactly the reveals we hold, only for that subset's
   winner, and only a claim paying the winner's declared target."
  (let ((id (w:event-ledger-id event)))
    (unless (find-record node id) (return-from handle-lottery-subset-attest nil))
    (handler-case
        (multiple-value-bind (conf lottery) (fork-lottery node id)
          (unless (and conf lottery) (fail "no pending lottery on chain"))
          (unless (member (up:x-only (node-pubkey node)) (lot:lottery-recovery-voters lottery) :test #'equalp)
            (fail "not a recovery voter"))
          (unless (reveal-deadline-passed-p node conf) (fail "reveal deadline not reached (~a blocks)" lot:+reveal-csv+))
          (multiple-value-bind (idx pre) (revealed-indices node id lottery)
            (let* ((asked (mapcar (lambda (h) (let ((x (let ((k (hex->bytes h))) (if (= (length k) 33) (up:x-only k) k))))
                                                (or (position x (lot:lottery-participants lottery) :key #'lot:participant-pubkey :test #'equalp)
                                                    (fail "~a is not a participant" (subseq h 0 8)))))
                                  (coerce (w:jget params "subset") 'list)))
                   (asked (sort (copy-list asked) #'<)))
              (unless (equal asked idx) (fail "subset ~a is not the reveals we hold ~a" asked idx))
              (when (= (length idx) (length (lot:lottery-participants lottery))) (fail "everyone revealed: the full-set leaf needs no attestation"))
              (let ((winner (nth (lot:subset-winner idx pre) (lot:lottery-participants lottery))))
                (let* ((proposed (btx:parse-tx (bw:make-reader (hex->bytes (w:jget params "unsigned_tx")))))
                       (in0 (first (btx:tx-inputs proposed)))
                       (target (lot:participant-target winner))
                       (spk (multiple-value-bind (witver program)
                                (cl-consensus.encoding:segwit-decode target (rs:hrp-for (intern (string-upcase (node-network node)) :keyword)))
                              (cat (octets (if (zerop witver) 0 (+ #x50 witver)) (length program)) program))))
                  (unless (and (equalp (btx:txin-prev-hash in0) (btx:tx-txid conf)) (= (btx:txin-prev-index in0) 0))
                    (fail "the claim does not spend the lottery output"))
                  (unless (and (= 1 (length (btx:tx-outputs proposed))) (equalp (btx:txout-script (first (btx:tx-outputs proposed))) spk))
                    (fail "the claim does not pay the winner's target"))
                  (let* ((leaf (nth (lot:subset-leaf-index lottery idx) (lot:lottery-leaves lottery)))
                         (amounts (coerce (w:jget params "prevout_amounts") 'list)) (spks (coerce (w:jget params "prevout_spks") 'list))
                         (prevouts (coerce (loop for a in amounts for k in spks collect (cons a (hex->bytes k))) 'vector)))
                    (unless (and prevouts (equalp (cdr (aref prevouts 0)) (lot:lottery-spk lottery)))
                      (fail "prevout 0 is not the lottery output"))
                    (let ((sighash (rot:tier-sighash proposed 0 prevouts leaf)))
                      (unless (equalp sighash (hex->bytes (w:jget params "sighash"))) (fail "sighash mismatch"))
                      (log! node "attested lottery subset ~a of ~a for ~a" idx (subseq id 0 8)
                            (subseq (bytes->hex (lot:participant-pubkey winner)) 0 8))
                      (respond node event t :result (w:json-object "signer" (node-pubkey-hex node)
                                                                   "signature" (bytes->hex (schnorr:schnorr-sign (node-priv node) sighash (random-aux))))))))))))
      (error (e) (log! node "refused lottery_subset_attest: ~a" e) (respond node event nil :error (princ-to-string e))))))

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

(defun fork-lottery (node id-hex)
  "(values confiscation lottery :pending) for ID-HEX while its lottery output is
   unspent, or NIL.  Found once by rebuilding (CONFISCATED-LOTTERY), then kept on
   our forks so a pass costs a UTXO lookup.  A kept transaction that is not on
   chain is not evidence of anything (a signer keeps every proposal it signs, and
   the one that confirmed may be another proposer's), so it is dropped and the
   chain asked again."
  (flet ((forget () (dolist (f (forks-of node id-hex)) (setf (record-confiscation f) nil (record-lottery f) nil))))
    (let ((f (find-if (lambda (f) (and (record-confiscation f) (record-lottery f))) (forks-of node id-hex))))
      (when f
        (let ((tx (record-confiscation f)) (l (record-lottery f)))
          (cond ((not (node-chain-fn node)) (return-from fork-lottery (values tx l :pending)))
                ((funcall (node-chain-fn node) (btx:tx-txid tx) 0)
                 (note-confiscation node id-hex (btx:tx-txid tx))
                 (return-from fork-lottery (values tx l :pending)))
                (t (forget)))))
      (multiple-value-bind (tx l state) (confiscated-lottery node id-hex)
        (when tx
          (when state (note-confiscation node id-hex (btx:tx-txid tx)))
          (dolist (f (forks-of node id-hex)) (setf (record-confiscation f) tx (record-lottery f) l)))
        (values tx l state)))))

(defun drive-dispute (node fork)
  (let* ((id (record-id-hex fork)) (base (find-record node id)) (h (height node)))
    (multiple-value-bind (enter enter-op) (fork-op fork :dispute-enter)
      (unless (and base enter)
        (return-from drive-dispute
          (note-dispute node id "not driven: ~:[no replica of the ledger~;no DisputeEnter of ours on the fork~]" base)))
      (flet ((conclude (fmt &rest args)
               (commit-update node fork (new-update node fork (list :type :dispute-yield)))
               (release-pledges node id)
               (return-from drive-dispute (apply #'note-dispute node id fmt args))))
        (when (or (fork-op fork :dispute-acquire) (fork-op fork :dispute-yield))
          (when (loop for v being the hash-values of (node-pledges node) thereis (equal v id)) (release-pledges node id))
          (return-from drive-dispute (note-dispute node id "concluded")))
        (multiple-value-bind (conf lottery lstate) (fork-lottery node id)
          ;; A quorum_expired dispute whose operator has since re-established the
          ;; quorum (or that we opened on a stale replica): stand down, unless it
          ;; is already confiscated.
          (let ((expiry (lg:ledger-quorum-expiry (record-ledger base))))
            (when (and (expiry-reason-p (op:field enter-op :reason)) expiry (<= h (+ expiry *expiry-grace-blocks*)) (null conf))
              (conclude "quorum re-established (expiry ~a); yielded" expiry)))
          (let ((reserves-spent (multiple-value-bind (r txid vout) (disputed-reserves node base)
                                  (declare (ignore r))
                                  (and (node-chain-fn node) (null (funcall (node-chain-fn node) txid vout))))))
            (cond
              ;; Nothing left to confiscate (a stranded rotation spent it): arming
              ;; would only tie up a pledge.
              ((and reserves-spent (null conf) (assoc (node-pubkey node) (reveals-of node id) :test #'equalp))
               ;; We revealed, so a confiscation was on chain; its lottery output is gone
               ;; and not by our recovery sweep: the winner claimed it.
               (conclude "lottery claimed by its winner; yielded"))
              ((and reserves-spent (null conf))
               (note-dispute node id "reserves spent, but not by a confiscation we can rebuild"))
              ((null (fork-op fork :dispute-armed))
               (let ((p (pledge-collateral node id)))
                 (if p
                     (progn (arm-dispute node fork :replacement p)
                            (note-dispute node id "armed, pledging ~a:~a (~a sats)" (txid-hex (first p)) (second p) (third p)))
                     (note-dispute node id "waiting for collateral (~a sats)" (required-replacement-sats base)))))
              ;; DEP-03: our pledge stopped passing the eligibility cut (spent, or never
              ;; confirmed), so we would be excluded from the lottery.  Re-arm with a
              ;; fresh one; the latest arm counts and moves E, reopening the window, up
              ;; to +max-arms+ arms in all.
              ((and (null conf) (not (eq lstate :pending)) (not (getf (node-adversary node) :spend-pledge))
                    (< (count (node-pubkey node) (%all-arms node id) :key #'first :test #'equalp) +max-arms+)
                    (let ((ours (find (node-pubkey node) (armers-of node id) :key #'first :test #'equalp)))
                      (and ours (fourth ours) (node-pledge-fn node)
                           (pledge-failure (node-pledge-fn node) (fourth ours) (height node) 0 nil))))
               (remhash (outpoint-key (first (fourth (find (node-pubkey node) (armers-of node id) :key #'first :test #'equalp)))
                                      (second (fourth (find (node-pubkey node) (armers-of node id) :key #'first :test #'equalp))))
                        (node-pledges node))
               (let ((p (pledge-collateral node id)))
                 (if p
                     (progn (arm-dispute node fork :replacement p)
                            (note-dispute node id "re-armed: our pledge no longer counted; now pledging ~a:~a" (txid-hex (first p)) (second p)))
                     (note-dispute node id "our pledge no longer counts; waiting for collateral to re-arm"))))
              ((eq lstate :pending)
               (cond ((not (assoc (node-pubkey node) (reveals-of node id) :test #'equalp))
                      ;; ADVERSARY :withhold-reveal — an armer that never publishes its
                      ;; preimage: the lottery cannot be claimed, custody waits (red team:
                      ;; the last revealer holds the funds hostage; DEP-06 §Phase 4).
                      (if (getf (node-adversary node) :withhold-reveal)
                          (note-dispute node id "ADVERSARY: confiscation ~a on chain; withholding our reveal" (txid-hex (btx:tx-txid conf)))
                          (progn (publish-reveal node id)
                                 (note-dispute node id "confiscation ~a on chain; revealed" (txid-hex (btx:tx-txid conf))))))
                     ((and (< (length (revealed-indices node id lottery)) (length (lot:lottery-participants lottery)))
                           (not (reveal-deadline-passed-p node conf)))
                      (note-dispute node id "~a of ~a revealed; the reveal deadline is ~a blocks after the confiscation"
                                    (length (revealed-indices node id lottery)) (length (lot:lottery-participants lottery)) lot:+reveal-csv+))
                     (t (handler-case (let ((outcome (claim-or-yield node id :confiscation-txid (btx:tx-txid conf))))
                                        (release-pledges node id)
                                        (note-dispute node id "lottery: ~(~a~)" outcome))
                          (error (e) (note-dispute node id "waiting to claim: ~a" e))))))
              (t
               (let* ((closes (dispute-arm-closes node base))
                      (armers (sort (mapcar #'first (armers-of node id)) #'bytes<))
                      (q (dispute-lottery-n base (dispute-last-valid-seq node id))) (k (length armers)))
                 (cond ((< k 1) (note-dispute node id "armed; waiting for an armer"))
                       ((< h closes) (note-dispute node id "armed; arm window closes at ~a" closes))
                       ((or (equalp (first armers) (node-pubkey node)) (>= h (+ closes *proposer-grace-blocks*)))
                        (handler-case
                            (let ((tx (confiscate node id :respectful (expiry-reason-p (op:field enter-op :reason)))))
                              (note-dispute node id "proposed confiscation ~a~@[ with ~a of ~a armed~]" (txid-hex (btx:tx-txid tx))
                                            (and (< k q) k) q))
                          (error (e) (note-dispute node id "confiscation not yet: ~a" e))))
                       (t (note-dispute node id "armed; another armer proposes first"))))))))))))

(defvar *drive-locks* (make-hash-table :test #'equalp))
(defvar *drive-locks-lock* (bt:make-lock "drive-locks"))

(defun drive-lock (node fork)
  "One lock per (node, disputed ledger): a fork is never driven twice at once, and a long
   pass over old forks never blocks arming a new one."
  (let ((key (cons (node-pubkey node) (record-id-hex fork))))
    (bt:with-lock-held (*drive-locks-lock*)
      (or (gethash key *drive-locks*) (setf (gethash key *drive-locks*) (bt:make-lock "drive-fork"))))))

(defparameter *max-drive-threads* 3
  "Forks one node drives at once in the watch.  Unbounded, every fork of every node ran
   bitcoin-cli together (load 139, members missing their cosign windows).")
(defvar *drive-threads* (make-hash-table :test #'equalp)
  "node pubkey -> live forks being driven; (:dormant . pubkey) -> dormant ones")
(defvar *drive-threads-lock* (bt:make-lock "drive-threads"))

(defun dormant-dispute-p (node fork)
  "A fork the last pass found finished or stuck on a vault already spent: driven after the
   live ones."
  (let ((note (gethash (record-id-hex fork) (node-dispute-notes node))))
    (and note (or (string= note "concluded")
                  (search "reserves spent, but not by a confiscation" note)
                  (search "yielded" note)))))

(defun drive-disputes (node &key parallel)
  "Drive every dispute fork we own.  PARALLEL (the once-a-minute watch): up to
   *max-drive-threads* forks at once, live disputes first, skipping a fork whose previous
   drive is still running.  Driven in turn, a pass over old forks (a fruitless
   confiscation rebuild took minutes each) held a live dispute back 16 minutes, past the
   time its members had to reveal (check-obligations, regtest 2026-10-14)."
  (let ((forks (stable-sort (loop for r being the hash-values of (node-ledgers node)
                                  when (and (record-fork-p r) (record-owned-p r)) collect r)
                            (lambda (a b) (and (not (dormant-dispute-p node a)) (dormant-dispute-p node b))))))
    (dolist (rec forks)
      (if parallel
          ;; Dormant forks share one slot, so live disputes always have the rest: three slow
          ;; dormant drives once held every slot while a live dispute's members never got to
          ;; reveal (check-obligations, regtest 2026-10-14).
          (let* ((lock (drive-lock node rec)) (rec rec) (dormant (dormant-dispute-p node rec))
                 (key (if dormant (cons :dormant (node-pubkey node)) (node-pubkey node))))
            (when (bt:with-lock-held (*drive-threads-lock*)
                    (when (< (gethash key *drive-threads* 0) (if dormant 1 *max-drive-threads*))
                      (incf (gethash key *drive-threads* 0))))
              ;; The thread takes the fork's lock itself (a mutex is released by its owner).
              (bt:make-thread (lambda ()
                                (unwind-protect
                                     (when (bt:acquire-lock lock nil)
                                       (unwind-protect (handler-case (drive-dispute node rec)
                                                         (error (e) (note-dispute node (record-id-hex rec) "error: ~a" e)))
                                         (bt:release-lock lock)))
                                  (bt:with-lock-held (*drive-threads-lock*) (decf (gethash key *drive-threads*)))))
                              :name "drive-dispute")))
          (bt:with-lock-held ((drive-lock node rec))
            (handler-case (drive-dispute node rec)
              (error (e) (note-dispute node (record-id-hex rec) "error: ~a" e))))))))

(defvar *drive-dispute-async* nil
  "Drive a newly entered dispute on its own thread (the daemon sets it; tests drive inline).")

(defvar *drive-dispute-on-enter* t
  "Drive a dispute the moment we enter it (tests that stage arming by hand bind it to NIL).")

(defun drive-dispute-now (node fork)
  "Arm a dispute as soon as we enter it, as the reference does, rather than at the next
   once-a-minute pass: the arm window can close first, leaving us out of the lottery.  Only
   when no pass is driving this ledger (never two arms at once, never blocking the relay
   handler)."
  (let ((lock (drive-lock node fork)))
    (flet ((drive ()
             (when (bt:acquire-lock lock nil)
               (unwind-protect (handler-case (drive-dispute node fork)
                                 (error (e) (note-dispute node (record-id-hex fork) "error: ~a" e)))
                 (bt:release-lock lock)))))
      (when *drive-dispute-on-enter*
        (if *drive-dispute-async*
            ;; Off the caller's thread: entering is the worker handling a fraud proof, and a
            ;; drive can walk the chain for minutes (a confiscation rebuild).  On the worker it
            ;; held every request behind it: an operator's deposit_open timed out (regtest
            ;; 2026-10-14).  The thread takes the lock itself (a mutex is released by its owner).
            (bt:make-thread #'drive :name "drive-dispute-now")
            (drive))))))

(defun start-expiry-watch (node &key (interval 60))
  (bt:make-thread (lambda () (loop (sleep interval)
                                   (ignore-errors (dispute-expired-quorums node))
                                   (ignore-errors (drive-disputes node :parallel t))
                                   (ignore-errors (drive-dereliction node))
                                   (ignore-errors (drive-vault-watch node))
                                   (ignore-errors (drive-migration-watch node))
                                   (ignore-errors (drive-obligation-watch node))
                                   (ignore-errors (drive-rotation-rebroadcast node))))
                  :name "cld-expiry"))

(defun start-invoice-poller (node &key (interval 3))
  (bt:make-thread (lambda () (loop (sleep interval)
                                   (ignore-errors (credit-paid-invoices node))
                                   (ignore-errors (settle-pending-payments node))))
                 :name "cld-invoices"))

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
    ;; The FIRST response is the answer.  An operator that receives the request twice
    ;; (a relay redelivery) answers twice, and the second answer to a lock is "nonce
    ;; already accepted": the signet soak (2026-10-21) took that one, since responses
    ;; are pushed newest first, and logged a committed lock as a failure.
    (let ((r (car (last (waiter-responses wt)))) (h (sha256 (ascii->bytes (ev:event-content event)))))
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

(defun address->spk (address)
  "The scriptPubKey of a segwit ADDRESS (any network: the hrp is read off the address)."
  (let ((hrp (subseq address 0 (position #\1 address :from-end t))))
    (multiple-value-bind (witver program) (cl-consensus.encoding:segwit-decode address hrp)
      (cat (octets (if (zerop witver) 0 (+ #x50 witver)) (length program)) program))))

(defun wallet-exit (wal ledger-id-hex deposit-id amount-msats address &key expires-at (height 0))
  "DEP-20 §3: request an exit of AMOUNT-MSATS from DEPOSIT-ID to ADDRESS at the next rotation.
   Returns the request id (the ExitRequest update's chain_hash, hex)."
  (let ((o (append (list :type :exit-request :deposit-id deposit-id :amount amount-msats
                         :exit-address (address->spk address))
                   (when expires-at (list :expires-at-height expires-at))
                   (list :nonce (incf (wallet-nonce wal)) :expiry (+ height 144) :witness '()))))
    (setf (getf o :witness) (d17:sign-operation o (wallet-priv wal)))
    (multiple-value-bind (ok res err)
        (wallet-request wal ledger-id-hex "exit_request" (w:json-object "operation" (base64-encode (op:encode-operation o))))
      (unless ok (fail "exit_request: ~a" err))
      (w:jget res "exit_request_id"))))

(defun wallet-make-offer (wal ledger-id-hex max-sats &key (min-sats 1) (blocks-valid 144))
  "DEP-10: ask LEDGER-ID-HEX's operator for a cosigned funding offer crediting our pk() deposit.
   Returns the response object (funding_address, deadline_block, offer_id, cosign...)."
  (multiple-value-bind (ok res err)
      ;; An offer waits on the operator's own cosign round with its quorum (DEP-10): give it
      ;; that round plus slack, not one cosign timeout (a reference operator took 14 s).
      (wallet-request wal ledger-id-hex "make_offer"
                      (w:json-object "descriptor" (wallet-descriptor wal) "max_sats" max-sats
                                     "min_sats" min-sats "blocks_valid" blocks-valid)
                      :timeout (* 4 *cosign-timeout*))
    (unless ok (fail "make_offer: ~a" err))
    (if (stringp res) (w:parse-json res) res)))

(defun wallet-complete-offer (wal ledger-id-hex offer-id-hex txid-hex vout)
  "DEP-10 §Completion: name the payment (TXID-HEX display order, VOUT) of an offer on LEDGER-ID-HEX."
  (multiple-value-bind (ok res err)
      (wallet-request wal ledger-id-hex "complete_offer"
                      (w:json-object "offer_id" offer-id-hex "txid" txid-hex "vout" vout "amount_sats" 0))
    (unless ok (fail "complete_offer: ~a" err))
    res))

(defun wallet-migrate (wal from-ledger-hex deposit-id amount-msats to-ledger-hex &key (height 0) (blocks-valid 288))
  "DEP-20 §10: move AMOUNT-MSATS from DEPOSIT-ID on FROM-LEDGER-HEX to our deposit on
   TO-LEDGER-HEX: a cosigned offer there, then an exit here paying its address that is released
   if not settled 6 blocks before the offer's deadline.  Returns (values request-id offer)."
  (let* ((sats (floor amount-msats 1000))
         (offer (wallet-make-offer wal to-ledger-hex sats :min-sats 1 :blocks-valid blocks-valid))   ; the output is sats less its own cost
         (address (or (w:jget offer "funding_address") (fail "offer without funding_address")))
         (deadline (or (w:jget offer "deadline_block") (fail "offer without deadline_block"))))
    (when (<= (- deadline 6) height) (fail "offer deadline ~a leaves no room to settle" deadline))
    (values (wallet-exit wal from-ledger-hex deposit-id amount-msats address :expires-at (- deadline 6) :height height)
            offer)))

(defun wallet-exit-cancel (wal ledger-id-hex deposit-id request-id &key (height 0))
  (let ((o (list :type :exit-cancel :deposit-id deposit-id :exit-request-id request-id
                 :nonce (incf (wallet-nonce wal)) :expiry (+ height 144) :witness '())))
    (setf (getf o :witness) (d17:sign-operation o (wallet-priv wal)))
    (multiple-value-bind (ok res err)
        (wallet-request wal ledger-id-hex "exit_cancel" (w:json-object "operation" (base64-encode (op:encode-operation o))))
      (declare (ignore res))
      (unless ok (fail "exit_cancel: ~a" err))
      t)))

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

(defun completion-satisfied-p (script witness) (lg:completion-satisfied-p script witness))

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

(defun latest-quorum-begin-seq (rec)
  (or (loop for u in (record-history rec)
            when (eq (op:operation-type (op:decode-operation (up:update-message u))) :quorum-begin)
              return (up:update-seq u))
      0))

(defun fork-live-p (node fork)
  "FORK still speaks for its ledger's current dispute: it has custody (DisputeAcquire: the
   base chain is dead), or it is unconcluded and its DisputeEnter is at or after the base's
   latest QuorumBegin.  A yielded fork, or one from before a later QuorumBegin, is history:
   it must not stop us detecting, disputing or acting on what happens on the ledger now."
  (let ((base (find-record node (record-fork-of fork))))
    (multiple-value-bind (enter eo) (fork-op fork :dispute-enter)
      (cond ((fork-op fork :dispute-acquire) t)
            ((fork-op fork :dispute-yield) nil)
            ((null enter) t)
            ((null base) t)
            (t (>= (or (op:field eo :last-valid-sequence) -1) (latest-quorum-begin-seq base)))))))

(defun live-fork (node id-hex operator33)
  "OPERATOR33's fork of ID-HEX when it is live (fork-live-p), else NIL."
  (let ((f (find-fork node id-hex operator33))) (and f (fork-live-p node f) f)))

(defun retire-fork (node fork)
  "Drop a fork that is no longer live so a new dispute can open in its place; what it knew of
   a confiscation is kept (note-confiscation persists it)."
  (when (record-confiscation fork) (note-confiscation node (record-fork-of fork) (btx:tx-txid (record-confiscation fork))))
  (remhash (fork-key (record-fork-of fork) (record-fork-operator fork)) (node-ledgers node))
  (log! node "fork of ~a by ~a retired (concluded or superseded by a later QuorumBegin)"
        (subseq (record-fork-of fork) 0 8) (subseq (bytes->hex (record-fork-operator fork)) 0 8)))

(defun fork-summaries (node)
  "Every dispute fork we hold: ledger, its operator (the disputant), state, and whether it is
   live (fork-live-p) — a non-live fork no longer suppresses detection on its ledger."
  (loop for f being the hash-values of (node-ledgers node)
        when (record-fork-p f)
          collect (list :ledger (record-fork-of f) :by (bytes->hex (record-fork-operator f))
                        :state (cond ((fork-op f :dispute-acquire) :acquired) ((fork-op f :dispute-yield) :yielded)
                                     ((fork-op f :dispute-armed) :armed) (t :entered))
                        :live (and (fork-live-p node f) t))))

(defun disputing-members (node rec)
  "Pubkeys of REC's current quorum members that have disputed it since the quorum
   began: a fork whose DisputeEnter (other than for a lapsed quorum) is at or after
   the latest QuorumBegin, whether still open, armed, yielded or acquired."
  (let* ((qb-seq (or (loop for u in (record-history rec)
                           when (eq (op:operation-type (op:decode-operation (up:update-message u))) :quorum-begin)
                             return (up:update-seq u))
                     0))
         (members (mapcar #'lg:member-pubkey (lg:ledger-quorum-members (record-ledger rec)))))
    (loop for f in (forks-of node (record-id-hex rec))
          for o = (nth-value 1 (fork-op f :dispute-enter))
          when (and o (member (record-fork-operator f) members :test #'equalp)
                    (>= (or (op:field o :last-valid-sequence) -1) qb-seq)
                    ;; respectful: the operator re-establishes.  Any other dispute counts in
                    ;; every state: a loser yields only once the vault is confiscated.
                    (not (expiry-reason-p (op:field o :reason))))
            collect (record-fork-operator f) into keys
          finally (return (remove-duplicates keys :test #'equalp)))))

(defun acquired-fork (node id-hex)
  "The fork of ID-HEX's ledger whose DisputeAcquire took custody, if any."
  (find-if (lambda (f) (fork-op f :dispute-acquire)) (forks-of node id-hex)))

(defun ledger-chain-record (node id-hex)
  "The record holding ID-HEX's ledger as it now runs: the acquired fork after a custody change
   (cl keeps the winner's chain as its fork), else the replica."
  (or (acquired-fork node id-hex) (find-record node id-hex)))

(defun custody-moved-to (node rec)
  "The key a DisputeAcquire on any fork of REC's ledger gave custody to, when it is
   not ours: the ledger's operator from then on (DEP-06)."
  (loop for f in (forks-of node (record-id-hex rec))
        for o = (nth-value 1 (fork-op f :dispute-acquire))
        when (and o (not (equalp (op:field o :new-custodian) (node-pubkey node))))
          return (op:field o :new-custodian)))

(defun cosign-refusal (own members qb-seq disputes)
  "DEP-05 \"Deposed operator\": a reason string when member OWN of MEMBERS must refuse to
   co-sign the operator's chain, else NIL.  DISPUTES are plists (:by :last-valid :reason
   :acquired), one per fork of the ledger.  Pinned by inspect/vectors/cosign_refusal.json,
   shared with deposits-rust."
  (when (some (lambda (d) (getf d :acquired)) disputes)
    (return-from cosign-refusal "custody moved by DisputeAcquire"))
  (let ((freezing (remove-duplicates
                   (loop for d in disputes
                         when (and (>= (getf d :last-valid) qb-seq)
                                   (not (expiry-reason-p (getf d :reason)))
                                   (member (getf d :by) members :test #'equalp))
                           collect (getf d :by))
                   :test #'equalp)))
    (cond ((member own freezing :test #'equalp) "we disputed it; not extending the operator's chain")
          ((> (* 2 (length freezing)) (length members))
           (format nil "~a of ~a members disputed it" (length freezing) (length members))))))

(defun check-not-deposed (node rec)
  "A member refuses to extend REC's base chain once its operator is deposed (DEP-05):
   custody moved by a DisputeAcquire, or we, or a majority of the quorum, disputed it
   at or after the latest QuorumBegin other than for expiry."
  (let* ((qb-seq (or (loop for u in (record-history rec)
                           when (eq (op:operation-type (op:decode-operation (up:update-message u))) :quorum-begin)
                             return (up:update-seq u))
                     0))
         (disputes (loop for f in (forks-of node (record-id-hex rec))
                         for o = (nth-value 1 (fork-op f :dispute-enter))
                         when o collect (list :by (record-fork-operator f)
                                              :last-valid (or (op:field o :last-valid-sequence) -1)
                                              :reason (op:field o :reason)
                                              :acquired (and (fork-op f :dispute-acquire) t))))
         (why (cosign-refusal (node-pubkey node)
                              (mapcar #'lg:member-pubkey (lg:ledger-quorum-members (record-ledger rec)))
                              qb-seq disputes)))
    (when why (fail "ledger disputed: ~a" why))))

(defun make-fork (node rec last-valid-seq operator33)
  "A fork of REC's ledger from LAST-VALID-SEQ, operated by OPERATOR33: the
   truncated history replayed, quorum cleared (the reference does the same,
   so fork operations need no cosignatures)."
  (let* ((history (remove-if (lambda (u) (> (up:update-seq u) last-valid-seq)) (reverse (record-history rec))))
         (ledger (lg:replay history))
         (fork (make-record :id-hex (record-id-hex rec) :ledger ledger :history (reverse history)
                            :owned-p (equalp operator33 (node-pubkey node))
                            :fork-p t :fork-of (record-id-hex rec) :fork-operator operator33)))
    (setf (lg:ledger-quorum-at-fork ledger) (lg:ledger-quorum-members ledger)
          (lg:ledger-quorum-members ledger) '() (lg:ledger-next-quorum-members ledger) '())
    (setf (gethash (fork-key (record-id-hex rec) operator33) (node-ledgers node)) fork)
    fork))

(defun enter-dispute (node rec last-valid-seq &key (reason "fraud") anchor-block-hash anchor-block-height fraud-proof-hash)
  "We are a quorum member of REC's ledger and have grounds: fork it and publish DisputeEnter."
  (let ((stale (find-fork node (record-id-hex rec) (node-pubkey node))))
    (when (and stale (not (fork-live-p node stale))) (retire-fork node stale)))
  (let ((fork (or (find-fork node (record-id-hex rec) (node-pubkey node))
                  (make-fork node rec last-valid-seq (node-pubkey node)))))
    (commit-update node fork (new-update node fork (%strip-nil-fields
                                                    (list :type :dispute-enter :last-valid-sequence last-valid-seq :reason reason
                                                          :anchor-block-hash anchor-block-hash :anchor-block-height anchor-block-height
                                                          :fraud-proof-hash fraud-proof-hash))))
    (drive-dispute-now node fork)
    fork))

(defun dispute-lottery-n (rec &optional fork-point)
  "N disputants = the DEP-06 recovery voters."
  (length (recovery-voters rec fork-point)))

(defun recovery-voters (rec &optional fork-point)
  "DEP-06 recovery voters: x-only keys, other than the original operator's (the author of
   sequence 0), of the members of the latest QuorumBegin the original operator authored at a
   sequence <= FORK-POINT (the dispute's lowest last_valid_sequence; NIL = every sequence)."
  (let ((operator nil) (members '()))
    (dolist (u (reverse (record-history rec)))
      (when (zerop (up:update-seq u)) (setf operator (up:update-operator-id u)))
      (when (and operator (equalp (up:update-operator-id u) operator)
                 (or (null fork-point) (<= (up:update-seq u) fork-point)))
        (let ((o (op:decode-operation (up:update-message u))))
          (when (eq (op:operation-type o) :quorum-begin)
            (setf members (op:field o :quorum-members))))))
    (remove-duplicates (mapcar #'up:x-only (remove operator members :test #'equalp)) :test #'equalp)))

(defun our-target-address (node)
  (cl-consensus.encoding:segwit-encode (rs:hrp-for (intern (string-upcase (node-network node)) :keyword)) 1
                                       (subseq (lot:key-path-spk (up:x-only (node-pubkey node))) 2)))

(defun lottery-seed (node id-hex)
  "Our lottery seed for a dispute on ID-HEX, derived from the node key so a
   restarted node recovers the preimage it committed to."
  (sha256 (cat (ascii->bytes "deposits/cl/lottery-seed/v1") (int->be (node-priv node) 32) (hex->bytes id-hex))))

(defparameter *pledge-height-wait-seconds* 15)

(defun await-pledge-height (node replacement)
  "An arm commits to (height node) as its armed block, and the DEP-03 cut excludes a
   pledge confirmed after the highest such height.  The node's height is cached, so an
   arm right after its pledge's block could name a height before it and exclude itself
   (with every armer doing so, nobody is a participant).  Wait until our height reaches
   the pledge's confirmation; refuse rather than arm with a pledge the cut would drop."
  (let ((pledge-fn (node-pledge-fn node)))
    (when pledge-fn
      (destructuring-bind (txid vout sats) replacement
        (declare (ignore sats))
        (let ((created (getf (funcall pledge-fn txid vout (1+ (height node))) :created))
              (deadline (+ (get-universal-time) *pledge-height-wait-seconds*)))
          (unless created (fail "pledge ~a:~a is not confirmed" (txid-hex txid) vout))
          (loop until (>= (height node) created)
                do (when (> (get-universal-time) deadline)
                     (fail "pledge confirmed at ~a, our chain height is still ~a" created (height node)))
                   (sleep 0.5)))))))

(defun record-obligations (node fork)
  "DEP-06: if the disputed ledger had an unresolved DormancyAccept at the fork point and its source
   consumed the notice, append an ObligationRecord (the source's notice and QuorumBegin) to FORK."
  (let* ((id (record-id-hex fork)) (base (find-record node id)) (lvs (dispute-last-valid-seq node id))
         (l (and base lvs (lg:replay (remove-if (lambda (u) (> (up:update-seq u) lvs)) (reverse (record-history base))))))
         (a (and l (lg:ledger-dormancy-accept l))))
    (when (and a (not (getf a :resolved)) (getf a :source))
      (multiple-value-bind (nu qu) (migration-source-updates node a (bytes->hex (getf a :source)))
        (when qu
          (commit-update node fork (new-update node fork (list :type :obligation-record
                                                               :source-notice-update (up:encode-update nu)
                                                               :source-qb-update (up:encode-update qu))))
          (log! node "recorded the dangling migration of ~a on our fork" (subseq id 0 8)))))
    ;; DEP-06: every proven-uncredited payment we verified against this ledger, and any the
    ;; relays hold (one broadcast after we entered the dispute, or while we were down)
    (when base
      (dolist (e (ignore-errors (bus:bus-fetch (node-bus node) (flt:make-filter :kinds (list w:+kind-fraud-proof+)
                                                                                :tags (list (cons "d" (list (subseq id 0 16))))))))
        (ignore-errors (note-obligation-proof node base (fr:json->broadcast (w:parse-json (ev:event-content e)))))))
    (dolist (json (gethash id (node-obligation-proofs node)))
      (handler-case
          (progn (commit-update node fork (new-update node fork (list :type :obligation-record :uncredited-proof (ascii->bytes json))))
                 (log! node "recorded an uncredited payment of ~a on our fork" (subseq id 0 8)))
        (error (e) (log! node "uncredited payment not recorded on ~a: ~a" (subseq id 0 8) e))))))

(defun arm-dispute (node fork &key seed replacement)
  "Commit to our lottery preimage on our fork.  REPLACEMENT is (txid vout sats) or NIL."
  (let ((preimage (lot:derive-preimage (or seed (lottery-seed node (record-id-hex fork))))))
    (when replacement (await-pledge-height node replacement))
    ;; DEP-06 §Confiscation obligations: record a dangling migration before arming.
    (handler-case (record-obligations node fork)
      (error (e) (log! node "obligation record on ~a: ~a" (subseq (record-id-hex fork) 0 8) e)))
    (setf (record-preimage fork) preimage)
    (commit-update node fork (new-update node fork (%strip-nil-fields
                                                    (list :type :dispute-armed :armed-block (height node)
                                                          :commitment-hash (lot:commitment-of preimage)
                                                          :target-reserves (our-target-address node)
                                                          :replacement-collateral-txid (first replacement)
                                                          :replacement-collateral-vout (second replacement)
                                                          :replacement-collateral-amount (third replacement)))))
    ;; ADVERSARY :spend-pledge — arm, then spend the pledged coin back to ourselves.
    ;; Under the old rule every cosigner then refused the confiscation: one armer
    ;; vetoed the dispute.  DEP-03 now excludes it instead (redteam/attack-veto-pledge.sh).
    (when (and replacement (getf (node-adversary node) :spend-pledge))
      (handler-case
          (let ((txid (consolidate-utxos node (list (list :txid (first replacement) :vout (second replacement) :sats (third replacement))))))
            (log! node "adversary: spent our pledge ~a:~a in ~a" (txid-hex (first replacement)) (second replacement) (txid-hex txid)))
        (error (e) (log! node "adversary: could not spend our pledge: ~a" e))))
    preimage))

(defun armers-of (node id-hex &key until)
  "Each armer's latest DisputeArmed (highest sequence) on any fork of the ledger:
   (pubkey33 commitment target collateral arm-height seq), ARM-HEIGHT being the
   update's signed-header block height.  A member may re-arm to add the replacement
   collateral its first arm lacked (DEP-03; the reference does after losing a
   scantxoutset race); counting every arm listed it twice.  UNTIL: the block the
   confiscation confirmed in; arms above it do not count (DEP-03)."
  (let ((arms (make-hash-table :test #'equalp)))
    (dolist (a (%all-arms node id-hex))
      (unless (and until (> (fifth a) until)) (push a (gethash (first a) arms))))
    ;; Only the first +max-arms+ arms (by sequence) count, so a griefer cannot keep moving E.
    (loop for list being the hash-values of arms
          collect (let ((counted (subseq (sort (copy-list list) #'< :key #'sixth) 0 (min +max-arms+ (length list)))))
                    (car (last counted))))))

(defun %all-arms (node id-hex)
  "Every DisputeArmed on every fork of the ledger, newest first within each fork."
  (loop for fork in (forks-of node id-hex)
        append (loop for u in (record-history fork)
                     for o = (op:decode-operation (up:update-message u))
                     when (eq (op:operation-type o) :dispute-armed)
                       collect (list (up:update-operator-id u) (op:field o :commitment-hash) (op:field o :target-reserves)
                                     (and (op:field o :replacement-collateral-txid)
                                          (list (op:field o :replacement-collateral-txid) (op:field o :replacement-collateral-vout)
                                                (op:field o :replacement-collateral-amount)))
                                     (up:update-block-height u) (up:update-seq u)))))

;;; DEP-03 §"Replacement collateral declaration": who is in the lottery is a
;;; deterministic function of the ledger and the confirmed chain.  E is the highest
;;; signed-header height among the armers' latest arms; a pledge counts if it is
;;; large enough, confirmed by E, unspent through E and holds what it declares.  A
;;; failing armer is excluded and never stalls the dispute: one armer pledging a
;;; spent coin used to make every cosigner refuse, forever.

(defparameter *claim-fee-floor-sats* 5000
  "DEP-03 claim_fee_floor when the governing QuorumBegin records no reference feerate.")

(defun dispute-last-valid-seq (node id-hex)
  "The dispute's fork point: the lowest last_valid_sequence any fork's DisputeEnter names."
  (loop for f in (forks-of node id-hex)
        for (u o) = (multiple-value-list (fork-op f :dispute-enter))
        when u minimize (op:field o :last-valid-sequence)))

(defun fork-point-anchor (update)
  "DEP-03 §On-Chain State Anchor: a confiscation's anchor from the update at the dispute's fork
   point, tagged_hash(\"deposits/fork-point\", cosign_data): its signatures are left out, so every
   variant of the update (one cosignature set or another) gives the same anchor."
  (tagged-hash "deposits/fork-point" (up::cosign-data update)))

(defun dispute-anchor (node id-hex)
  "A confiscation's anchor (FORK-POINT-ANCHOR) from the update at the dispute's fork point (the
   lowest last_valid_sequence any DisputeEnter names), as any fork or our replica holds it."
  (let ((lvs (dispute-last-valid-seq node id-hex)))
    (unless lvs (fail "no fork point for ~a's confiscation anchor" (subseq id-hex 0 8)))
    (let ((u (or (loop for r in (cons (find-record node id-hex) (forks-of node id-hex))
                       thereis (and r (find lvs (record-history r) :key #'up:update-seq)))
                 (fail "no update at ~a's fork point ~a" (subseq id-hex 0 8) lvs))))
      (fork-point-anchor u))))

(defun eligibility-floor-sats (node id-hex)
  "obligations x collateral/reserves at the fork point, + the claim fee floor, in the
   reference's integer arithmetic (floor the product, then round msat up to sats)."
  (let* ((base (or (find-record node id-hex) (fail "unknown ledger")))
         (lvs (dispute-last-valid-seq node id-hex))
         (l (if lvs
                (lg:replay (remove-if (lambda (u) (> (up:update-seq u) lvs)) (reverse (record-history base))))
                (record-ledger base)))
         (reserves (lg:ledger-reserves-amount l)))
    (unless (plusp reserves) (fail "QuorumBegin reserves were zero"))
    (+ (ceiling (floor (* (lg:total-obligations l) (lg:ledger-collateral-amount l)) reserves) 1000)
       *claim-fee-floor-sats*)))

(defvar *pledge-verdicts* (make-hash-table :test #'equal) "(txid vout amount E) -> NIL or a reason, once E is buried.")
(defvar *pledge-verdicts-lock* (bt:make-lock "pledge-verdicts"))

(defun pledge-failure (pledge-fn coll snapshot floor-sats tip)
  "Why the pledge COLL = (txid vout sats) fails the cut at SNAPSHOT, or NIL.  PLEDGE-FN
   is a node's pledge-fn; without one only the declaration is checked."
  (destructuring-bind (txid vout sats) coll
    (when (< sats floor-sats) (return-from pledge-failure (format nil "declared ~a sats, below the floor ~a" sats floor-sats)))
    (unless pledge-fn (return-from pledge-failure nil))
    (let ((key (list (bytes->hex txid) vout sats snapshot)))
      (multiple-value-bind (hit found) (bt:with-lock-held (*pledge-verdicts-lock*) (gethash key *pledge-verdicts*))
        (when found (return-from pledge-failure hit)))
      (let* ((facts (funcall pledge-fn txid vout (1+ snapshot)))
             (created (getf facts :created)) (value (getf facts :value-sats)) (spend (getf facts :spend))
             (verdict (cond ((null facts) "pledge transaction not found")
                            ((null value) "pledge output does not exist")
                            ((null created) "pledge is unconfirmed")
                            ((> created snapshot) (format nil "pledge confirmed at ~a, after the snapshot ~a" created snapshot))
                            ((< value sats) (format nil "pledge holds ~a sats, less than the ~a declared" value sats))
                            ((eq spend :unspent) nil)
                            ((and (consp spend) (> (second spend) snapshot)) nil)
                            (t (format nil "pledge spent, unconfirmed or unknown at the snapshot ~a" snapshot)))))
        (when (and tip (>= tip (+ snapshot 6)))
          (bt:with-lock-held (*pledge-verdicts-lock*) (setf (gethash key *pledge-verdicts*) verdict)))
        verdict))))

(defun split-armers (armers floor-sats pledge-fn &key tip confiscated-at)
  "The DEP-03 cut over ARMERS (armers-of entries): (values participants excluded snapshot),
   participants sorted by key, EXCLUDED ((entry . reason) ...).  Once the confiscation has
   confirmed in block CONFISCATED-AT, an arm above it does not count (DEP-03 \"When the set
   is final\"): it neither moves E nor joins."
  (let* ((armers (sort (remove-if (lambda (a) (and confiscated-at (> (fifth a) confiscated-at))) armers)
                       #'bytes< :key #'first))
         (snapshot (reduce #'max armers :key #'fifth :initial-value 0))
         (in '()) (out '()))
    (dolist (a armers)
      (let ((why (if (fourth a) (pledge-failure pledge-fn (fourth a) snapshot floor-sats tip) "declared no replacement collateral")))
        (if why (push (cons a why) out) (push a in))))
    (values (nreverse in) (nreverse out) snapshot)))

(defun lottery-armers (node id-hex)
  "The lottery's participants: (values participants excluded snapshot floor).  Once the
   confiscation has confirmed, the arms above its block do not count (DEP-03)."
  (let ((floor-sats (eligibility-floor-sats node id-hex))
        (c (gethash id-hex (node-confiscation-heights node))))
    (multiple-value-bind (in out snapshot)
        (split-armers (armers-of node id-hex :until c) floor-sats (node-pledge-fn node) :tip (height node) :confiscated-at c)
      (dolist (x out)
        (log! node "armer ~a excluded from ~a's lottery: ~a" (subseq (bytes->hex (first (car x))) 0 8) (subseq id-hex 0 8) (cdr x)))
      ;; Comparable with the reference's "lottery participants of" line: the set and E.
      (let ((line (format nil "lottery participants of ~a at snapshot ~a: [~{~a~^ ~}]; excluded: [~{~a~^ ~}]"
                          (subseq id-hex 0 16) snapshot
                          (sort (mapcar (lambda (a) (subseq (bytes->hex (first a)) 0 16)) in) #'string<)
                          (sort (mapcar (lambda (x) (subseq (bytes->hex (first (car x))) 0 16)) out) #'string<))))
        (unless (equal line (gethash (cons :participants id-hex) (node-dispute-notes node)))
          (setf (gethash (cons :participants id-hex) (node-dispute-notes node)) line)
          (log! node "~a" line)))
      (values in out snapshot floor-sats))))

(defun collateral-floor-sats (base &key (claim-fee *claim-fee-floor-sats*))
  "DEP-06: obligations x the ledger's collateral ratio, plus the claim fee."
  (let* ((l (record-ledger base))
         (obligations (floor (lg:total-obligations l) 1000))
         (ratio (if (plusp (lg:ledger-reserves-amount l)) (/ (lg:ledger-collateral-amount l) (lg:ledger-reserves-amount l)) 0)))
    (+ (ceiling (* obligations ratio)) claim-fee)))

(defun disputed-reserves (node rec)
  "From the latest QuorumBegin: (values reserves-struct txid vout sats operator33)."
  (let ((operator nil) (qb nil))
    (dolist (u (reverse (record-history rec)))
      (let ((o (op:decode-operation (up:update-message u))))
        (case (op:operation-type o)
          (:ledger-open (setf operator (op:field o :operator-id)))
          (:quorum-begin (setf qb o)))))
    (unless qb (fail "no QuorumBegin"))
    (multiple-value-bind (txid sats) (vault-rung node qb)
      (values (rs:build-reserves :operator operator :members (op:field qb :quorum-members)
                                 :ledger-hash (op:field qb :ledger-hash) :quorum-expiry (op:field qb :quorum-expiry)
                                 :ruleset (or (op:field qb :protocol-version) "cltv-offset-v2")
                                 :network (intern (string-upcase (node-network node)) :keyword))
              txid (op:field qb :new-outpoint-vout) sats operator))))

(defvar *vault-rungs* (make-hash-table :test #'equalp :synchronized t)
  "rung-0 txid -> (txid sats): which rung of a fee ladder confirmed (DEP-03), once seen confirmed.")

(defun vault-rung (node qb)
  "DEP-03 §Fee ladder: the vault QuorumBegin QB created, (values txid sats): output 0 of the rung
   our chain holds (unspent; once spent, the one we saw confirm), else rung 0 at QB's amounts."
  (let* ((rungs (fr:rotation-rungs qb)) (vout (op:field qb :new-outpoint-vout))
         (recorded (floor (+ (op:field qb :amount) (op:field qb :collateral-amount)) 1000))
         (known (gethash (first rungs) *vault-rungs*)))
    (cond (known (values-list known))
          ((or (null (cdr rungs)) (null (node-chain-fn node))) (values (first rungs) recorded))
          (t (loop for txid in rungs for i from 0
                   for info = (ignore-errors (funcall (node-chain-fn node) txid vout))
                   when info
                     ;; rung 0 holds the recorded amounts; a higher rung, what the chain says
                     do (let ((sats (if (zerop i) recorded (getf info :value-sats))))
                          (when (>= (or (getf info :confirmations) 0) 1)
                            (setf (gethash (first rungs) *vault-rungs*) (list txid sats)))
                          (return (values txid sats)))
                   finally (return (values (first rungs) recorded)))))))

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

(defun outpoint-at-snapshot (node txid vout snapshot)
  "An output confirmed by SNAPSHOT and unspent through it: its sats, else NIL (pledge-fn facts)."
  (let ((facts (and (node-pledge-fn node) (funcall (node-pledge-fn node) txid vout (1+ snapshot)))))
    (and facts (getf facts :value-sats) (getf facts :created) (<= (getf facts :created) snapshot)
         (let ((spend (getf facts :spend))) (or (eq spend :unspent) (and (consp spend) (> (second spend) snapshot))))
         (getf facts :value-sats))))

(defvar *obligations-memo* (make-hash-table :test #'equalp))
(defvar *obligations-memo-lock* (bt:make-lock "obligations-memo"))

(defun confiscation-obligations (node id-hex participants snapshot)
  "Memoized for a minute per (ID-HEX, SNAPSHOT, PARTICIPANTS): a rebuild tries every shape
   and tier over the same set, and each computation can walk the chain."
  (let ((key (list (node-pubkey node) id-hex snapshot (mapcar #'first participants) (height node))))
    (multiple-value-bind (hit found) (bt:with-lock-held (*obligations-memo-lock*) (gethash key *obligations-memo*))
      (if found
          (values-list hit)
          (let ((v (multiple-value-list (%confiscation-obligations node id-hex participants snapshot))))
            (bt:with-lock-held (*obligations-memo-lock*)
              (when (> (hash-table-count *obligations-memo*) 4096) (clrhash *obligations-memo*))
              (setf (gethash key *obligations-memo*) v))
            (values-list v))))))

(defun %confiscation-obligations (node id-hex participants snapshot)
  "DEP-06 §Confiscation obligations: (values swept splice-outs residue-sats) for the confiscation of
   ID-HEX.  SWEPT ((txid vout sats) ...) ascending; SPLICE-OUTS ((spk . sats) ...) ascending by
   deposit id; RESIDUE-SATS the owed entries no splice-out pays.  From the ledger at the fork
   point and the ObligationRecords on PARTICIPANTS' forks below their DisputeArmed."
  (let* ((base (or (find-record node id-hex) (fail "unknown ledger")))
         (lvs (dispute-last-valid-seq node id-hex))
         (l (if lvs (lg:replay (remove-if (lambda (u) (> (up:update-seq u) lvs)) (reverse (record-history base)))) (record-ledger base)))
         (a (lg:ledger-dormancy-accept l))
         (swept '()) (outs '()) (residue 0))
    (when a
      ;; a credited migration output not yet spliced backs the ledger's own deposits
      (when (getf a :outpoint)
        (let ((sats (outpoint-at-snapshot node (car (getf a :outpoint)) (cdr (getf a :outpoint)) snapshot)))
          (when sats (push (list (car (getf a :outpoint)) (cdr (getf a :outpoint)) sats) swept))))
      ;; dangling: recorded on a participant's fork, unresolved at the fork point
      (unless (getf a :resolved)
        (let ((seen '()))
          (dolist (p participants)
            (let ((fork (find-fork node id-hex (first p))))
              (dolist (u (and fork (reverse (record-history fork))))
                (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
                  (when (and o (eq (op:operation-type o) :obligation-record) (< (up:update-seq u) (sixth p)))
                    (multiple-value-bind (notice qb qu to-us)
                        (ignore-errors (lg:migration-evidence l (op:field o :source-notice-update) (op:field o :source-qb-update)))
                      (when (and qb to-us
                                 (equalp (op:field notice :manifest-hash) (getf a :hash))
                                 (< (up:update-block-height qu) (getf a :expires)))
                        (let* ((txid (op:field qb :new-outpoint-txid)) (vout (op:field qb :migration-vout))
                               (sats (and (not (member (cons txid vout) seen :test #'equalp))
                                          (outpoint-at-snapshot node txid vout snapshot))))
                          (when sats
                            (push (cons txid vout) seen)
                            (push (list txid vout sats) swept)
                            (dolist (e (op:field qb :migration-manifest))
                              (multiple-value-bind (spk v) (lg:owed-spk-sats e)
                                (if spk
                                    (push (list* (getf e :deposit-id) spk v) outs)
                                    (incf residue (floor (getf e :amount) 1000)))))))))))))))))
    ;; DEP-06: proven-uncredited offer payments recorded on the participants' forks are owed too
    ;; (paid from the vault: the payment itself sits at the operator's offer address).
    (let ((hist (reverse (record-history base))) (paid '())
          (hob (or (node-height-of-block node) (lambda (b) (declare (ignore b)) nil))))
      (dolist (p participants)
        (let ((fork (find-fork node id-hex (first p))))
          (dolist (u (and fork (reverse (record-history fork))))
            (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
              (when (and o (eq (op:operation-type o) :obligation-record) (op:field o :uncredited-proof)
                         (< (up:update-seq u) (sixth p)))
                (let* ((proof (ignore-errors (fr:json->proof (w:parse-json (bytes->ascii (op:field o :uncredited-proof))))))
                       (txid (and proof (ignore-errors (hex->bytes (fr::e proof :txid)))))
                       (vout (and proof (fr::e proof :vout))))
                  (when (and txid (not (member (cons txid vout) paid :test #'equalp))
                             (string-equal (getf proof :ledger-id) id-hex)
                             (fr:verify-proof proof :history hist :height-of-block hob)
                             (not (fr::onchain-credited-p hist (or lvs most-positive-fixnum) txid vout)))
                    (push (cons txid vout) paid)
                    (let ((e (fr::payment-entry proof)))
                      (multiple-value-bind (spk v) (lg:owed-spk-sats e)
                        (if spk
                            (push (list* (getf e :deposit-id) spk v) outs)
                            (incf residue (floor (getf e :amount) 1000)))))))))))))
    (values (sort swept (lambda (x y) (or (bytes< (first x) (first y))
                                          (and (equalp (first x) (first y)) (< (second x) (second y))))))
            (mapcar #'cdr (sort outs #'bytes< :key #'first))
            residue)))

(defun build-confiscation (node id-hex &key respectful fee tier-index armers snapshot)
  "The confiscation transaction for a disputed ledger, from public state only,
   so every cosigner rebuilds the same one.  It spends the reserves through
   TIER-INDEX (default: the tier open at our height), its nLockTime that tier's
   CLTV.  Its lottery is over ARMERS, by default the DEP-03 eligibility cut
   (lottery-armers).  Returns (values tx lottery prevouts reserves tier-index)."
  (let* ((base (or (find-record node id-hex) (fail "unknown ledger")))
         (armers (sort (copy-list (or armers (lottery-armers node id-hex))) #'bytes< :key #'first))
         (voters (recovery-voters base (dispute-last-valid-seq node id-hex)))
         (threshold (lg:majority-threshold (length voters)))
         (participants (loop for (pk c target) in armers collect (lot:make-participant :pubkey (up:x-only pk) :commitment c :target target)))
         (lottery (progn (when (null participants) (fail "no armer is a lottery participant"))
                         (lot:build-lottery participants voters threshold :network (intern (string-upcase (node-network node)) :keyword)))))
    (multiple-value-bind (reserves txid vout sats operator) (disputed-reserves node base)
      (multiple-value-bind (swept splice-outs residue)
          (confiscation-obligations node id-hex armers (or snapshot (nth-value 2 (lottery-armers node id-hex))))
        (let* ((tier-index (or tier-index (confiscation-tier reserves (height node))))
               (tx (lot:confiscation-tx :vault (list txid vout sats) :swept swept :lottery-spk (lot:lottery-spk lottery)
                                        :anchor (dispute-anchor node id-hex)
                                        :voters (1+ (length voters)) :locktime (rs:tier-locktime (nth tier-index (rs:reserves-tiers reserves)))
                                        :respectful respectful :fee fee
                                        :obligations-sats (floor (lg:total-obligations (record-ledger base)) 1000)
                                        :residue-sats residue :splice-outs splice-outs :operator-pubkey33 operator)))
          (values tx lottery (coerce (cons (cons sats (rs:reserves-spk reserves))
                                           (loop for (nil nil ss) in swept collect (cons ss (rs:reserves-spk reserves))))
                                     'vector)
                  reserves tier-index))))))

(defun unsigned-tx-hex (tx)
  "An unsigned transaction as we send it to other signers: the legacy form.
   BIP-144 serializes a transaction without witness data without the segwit
   marker and flag; rust-bitcoin refuses the marker with empty witnesses, which
   is how we used to send confiscation_sign and lottery_recovery_sign requests.
   Neither the txid nor any sighash depends on the form."
  (bytes->hex (btx:serialize-tx tx :witness nil)))

(defun confiscation-sighash (tx prevouts reserves &optional (tier-index 0))
  (rot:tier-sighash tx 0 prevouts (nth tier-index (rs:reserves-leaves reserves))))

(defun confiscate (node id-hex &key respectful fee)
  "Build the confiscation, gather the recovery quorum's tier-0 signatures over
   the relay (confiscation_sign), assemble, and broadcast.  Returns (values tx lottery)."
  (multiple-value-bind (tx lottery prevouts reserves tier-index) (build-confiscation node id-hex :respectful respectful :fee fee)
    (setf fee (- (reduce #'+ prevouts :key #'car) (reduce #'+ (btx:tx-outputs tx) :key #'btx:txout-value)))
    (let* ((sighash (confiscation-sighash tx prevouts reserves tier-index))
           ;; DEP-06: swept migration outputs are spent through the same tier, one signature each
           (sweep-hashes (loop for i from 1 below (length prevouts)
                               collect (rot:tier-sighash tx i prevouts (nth tier-index (rs:reserves-leaves reserves)))))
           (sweep-sigs (list (cons (up:x-only (node-pubkey node))
                                   (mapcar (lambda (h) (schnorr:schnorr-sign (node-priv node) h (random-aux))) sweep-hashes))))
           (tier (nth tier-index (rs:reserves-tiers reserves)))
           (keys (rs:tier-keys tier))
           (ours (schnorr:schnorr-sign (node-priv node) sighash (random-aux)))
           (sigs (list (cons (up:x-only (node-pubkey node)) ours)))
           (responses (send-request node id-hex "confiscation_sign"
                                    ;; The reference's field names: sighash, unsigned_tx, last_valid_sequence.
                                    (w:json-object "sighash" (bytes->hex sighash) "respectful" (and respectful t) "fee_sats" fee
                                                   "tier_index" tier-index
                                                   "sweep_sighashes" (and sweep-hashes (coerce (mapcar #'bytes->hex sweep-hashes) 'vector))
                                                   "unsigned_tx" (unsigned-tx-hex tx)
                                                   "last_valid_sequence" (lg:ledger-sequence (record-ledger (or (find-fork node id-hex (node-pubkey node)) (find-record node id-hex)))))
                                    :want (1- (rs:tier-threshold tier)) :timeout 20 :successes-only t)))
      (dolist (r responses)
        (let ((res (w:jget r "result")))
          (unless (w:jget r "success") (log! node "confiscation_sign refused: ~a" (w:jget r "error")))
          (when (and (w:jget r "success") res)
            (let* ((pk (up:x-only (hex->bytes (w:jget res "signer")))) (sig (hex->bytes (w:jget res "signature")))
                   (ss (mapcar #'hex->bytes (coerce (or (w:jget res "sweep_signatures") #()) 'list))))
              (when (and (member pk keys :test #'equalp) (schnorr:schnorr-verify pk sighash sig)
                         (not (assoc pk sigs :test #'equalp))
                         (= (length ss) (length sweep-hashes))
                         (every (lambda (h s) (schnorr:schnorr-verify pk h s)) sweep-hashes ss))
                (push (cons pk ss) sweep-sigs)
                (push (cons pk sig) sigs))))))
      (when (< (length sigs) (rs:tier-threshold tier)) (fail "only ~a of ~a confiscation signatures" (length sigs) (rs:tier-threshold tier)))
      (let* ((ordered (mapcar (lambda (k) (cdr (assoc k sigs :test #'equalp))) keys))
             (signed (rot:attach-tier-witness tx 0 reserves tier-index ordered)))
        (loop for i from 1 below (length prevouts)
              do (setf signed (rot:attach-tier-witness signed i reserves tier-index
                                                       (mapcar (lambda (k) (nth (1- i) (cdr (assoc k sweep-sigs :test #'equalp)))) keys))))
        (dotimes (i (length prevouts))
          (unless (rot:verify-spend signed i prevouts) (fail "assembled confiscation input ~a does not verify" i)))
        (broadcast node signed)
        (dolist (fork (forks-of node id-hex)) (setf (record-lottery fork) lottery (record-confiscation fork) signed))
        (values signed lottery)))))

(defun broadcast (node tx)
  (push tx (node-broadcasts node))
  (when (node-broadcast-fn node)
    (handler-case (funcall (node-broadcast-fn node) (btx:serialize-tx tx))
      (error (c) (log! node "broadcast of ~a failed: ~a" (bytes->hex (reverse (btx:tx-txid tx))) c) nil))))

;;; ---------------------------------------------------------------------------
;;; Red team: unauthorised vault spend (DEP-06 type 7, the gap docs/MISSING.md
;;; opens with).  A colluding majority of a ledger's quorum spends the reserves
;;; outpoint at Tier 0 to an address of theirs — no dispute, no rotation, no
;;; confiscation: nothing in either implementation watches for it.  This is the
;;; theft the contagion simulation models, made concrete on the devnet.

(defun build-vault-theft (node id-hex destination-address &key (tier-index 0) anchor)
  "The theft transaction: the reserves outpoint spent through TIER-INDEX (default
   Tier 0, the majority leaf, open at any height) to DESTINATION-ADDRESS.  Built
   from public state only, like build-confiscation, so every colluder rebuilds
   the same one.  Returns (values tx prevouts reserves tier-index)."
  (let* ((base (or (find-record node id-hex) (fail "unknown ledger")))
         (network (intern (string-upcase (node-network node)) :keyword)))
    (multiple-value-bind (reserves txid vout sats) (disputed-reserves node base)
      (let* ((tier (nth tier-index (rs:reserves-tiers reserves)))
             (locktime (rs:tier-locktime tier))
             (spk (multiple-value-bind (witver program)
                      (cl-consensus.encoding:segwit-decode destination-address (rs:hrp-for network))
                    (cat (octets (if (zerop witver) 0 (+ #x50 witver)) (length program)) program)))
             (prevouts (vector (cons sats (rs:reserves-spk reserves))))
             (tx (rot:build-spend :prev-txid txid :prev-vout vout :reserves-amount sats
                                  :destination-spk spk :fee-rate 1 :locktime locktime))
             ;; ANCHOR: a forged anchor (red team: a theft that names a place in the ledger no
             ;; rotation answers for, DEP-06 §Spend challenge), as the last output
             (tx (if anchor
                     (btx:parse-tx (bw:make-reader
                                    (btx:serialize-tx
                                     (btx:make-tx :version 2 :locktime locktime :segwit-p t :inputs (btx:tx-inputs tx)
                                                  :outputs (append (btx:tx-outputs tx)
                                                                   (list (btx:make-txout :value 0 :script (rot:anchor-script anchor))))
                                                  :witnesses (list nil)))))
                     tx)))
        (values tx prevouts reserves tier-index)))))

(defun vault-spend (node id-hex destination-address &key (tier-index 0) (broadcast-p t) anchor)
  "Spend a ledger's vault outside any recorded rotation or dispute: build the
   tier-0 theft, sign with our key, collect the rest of the threshold's
   signatures from our co-conspirators over the relay (theft_sign), assemble,
   and broadcast.  Returns (values tx sig-count)."
  (multiple-value-bind (tx prevouts reserves tier-index) (build-vault-theft node id-hex destination-address :tier-index tier-index :anchor anchor)
    (let* ((sighash (rot:tier-sighash tx 0 prevouts (nth tier-index (rs:reserves-leaves reserves))))
           (tier (nth tier-index (rs:reserves-tiers reserves)))
           (keys (rs:tier-keys tier))
           (ours (schnorr:schnorr-sign (node-priv node) sighash (random-aux)))
           (sigs (list (cons (up:x-only (node-pubkey node)) ours)))
           (responses (send-request node id-hex "theft_sign"
                                    (w:json-object "sighash" (bytes->hex sighash) "tier_index" tier-index
                                                   "anchor" (and anchor (bytes->hex anchor))
                                                   "unsigned_tx" (unsigned-tx-hex tx))
                                    :want (1- (rs:tier-threshold tier)) :timeout 90 :successes-only t)))
      (log! node "vault-spend: ~a of ~a theft_sign responses in time"
            (count-if (lambda (r) (w:jget r "success")) responses) (rs:tier-threshold tier))
      (dolist (r responses)
        (let ((res (w:jget r "result")))
          (when (and (w:jget r "success") res)
            (let ((pk (up:x-only (hex->bytes (w:jget res "signer")))) (sig (hex->bytes (w:jget res "signature"))))
              (when (and (member pk keys :test #'equalp) (schnorr:schnorr-verify pk sighash sig)
                         (not (assoc pk sigs :test #'equalp)))
                (push (cons pk sig) sigs))))))
      (when (< (length sigs) (rs:tier-threshold tier))
        (fail "only ~a of ~a theft signatures" (length sigs) (rs:tier-threshold tier)))
      (let* ((ordered (mapcar (lambda (k) (cdr (assoc k sigs :test #'equalp))) keys))
             (signed (rot:attach-tier-witness tx 0 reserves tier-index ordered)))
        (unless (rot:verify-spend signed 0 prevouts) (fail "assembled theft does not verify"))
        (when broadcast-p (broadcast node signed))
        (values signed (length sigs))))))

(defun handle-theft-sign (node event params)
  "A co-conspirator: rebuild the theft from public state and sign the proposer's
   sighash.  Gated on the ADVERSARY switch :theft-sign — an honest node never
   answers, which is the point: the theft needs colluders, and the switch is
   what makes a node one."
  (unless (getf (node-adversary node) :theft-sign)
    (return-from handle-theft-sign nil))
  (let ((id (w:event-ledger-id event)))
    (handler-case
        (let* ((proposed (btx:parse-tx (bw:make-reader (hex->bytes (or (w:jget params "unsigned_tx") (fail "no unsigned_tx"))))))
               (tier-index (or (w:jget params "tier_index") 0))
               (destination (arg-theft-destination node proposed)))
          (multiple-value-bind (tx prevouts reserves tier-index)
              (build-vault-theft node id destination :tier-index tier-index
                                                     :anchor (let ((a (w:jget params "anchor"))) (and a (hex->bytes a))))
            (declare (ignore tx))
            (let ((expected (rot:tier-sighash proposed 0 prevouts (nth tier-index (rs:reserves-leaves reserves)))))
              (unless (equalp expected (hex->bytes (w:jget params "sighash")))
                (fail "sighash is not for the theft we expect"))
              (log! node "ADVERSARY: signing vault theft of ~a proposed by ~a" (subseq id 0 8) (subseq (ev:event-pubkey event) 0 8))
              (respond node event t :result (w:json-object "signer" (node-pubkey-hex node)
                                                           "signature" (bytes->hex (schnorr:schnorr-sign (node-priv node) expected (random-aux))))))))
      (error (e) (log! node "refused theft_sign: ~a" e) (respond node event nil :error (princ-to-string e))))))

;;; A reference operator rotates its vault itself (deposits-rust auto_rotation): it
;;; spends the current vault at a tier, 1-in/1-out, into the reserves of the next
;;; quorum, and asks the members for the tier's script-path signature with
;;; `rotation_sign` {sighash, unsigned_tx, tier_index, ledger_hash, new_quorum_expiry}.
;;; A member rebuilds both ends from the replica it holds and signs only that.

(defun parse-splice-param (node param)
  "\"txidhex:vout\" (rotation_sign) -> (txid vout sats spk), looked up on our chain (DEP-20 §4)."
  (when param
    (let* ((colon (position #\: param)) (txid (hex->bytes (subseq param 0 colon))) (vout (parse-integer param :start (1+ colon))))
      (multiple-value-bind (sats spk) (splice-prevout node txid vout) (list txid vout sats spk)))))

(defun pre-update-view (rec seq)
  "REC as it stood before sequence SEQ: a scratch record whose history and ledger stop at SEQ - 1."
  (if (< (lg:ledger-sequence (record-ledger rec)) seq)
      rec
      (let ((hist (remove-if (lambda (u) (>= (up:update-seq u) seq)) (record-history rec))))
        (make-record :id-hex (record-id-hex rec) :owned-p (record-owned-p rec) :history hist
                     :ledger (lg:replay (reverse hist))))))

(defun handle-rotation-sign (node event params)
  "DEP-03 Rotation ordering, step 3: sign the rungs a FINAL QuorumBegin names, never a vault
   spend no QuorumBegin names.  The QuorumBegin (carried) must be operator-signed and cosigned to
   its requirement, extend our replica, and its rungs be the ladder we build from the ledger as it
   stood before it.  One signature per rung (and per rung for a vault-script splice-in)."
  (let* ((id (w:event-ledger-id event)) (rec (find-record node id)))
    (unless rec (return-from handle-rotation-sign nil))
    (handler-case
        (let* ((qu (up:decode-update (base64-decode (or (w:jget params "quorum_begin") (fail "no quorum_begin")))))
               (o (op:decode-operation (up:update-message qu)))
               (proposed (mapcar (lambda (h) (btx:parse-tx (bw:make-reader (hex->bytes h))))
                                 (coerce (or (w:jget params "unsigned_rungs") (fail "no unsigned_rungs")) 'list)))
               (tier-index (or (w:jget params "tier_index") 0)))
          (when (record-fork-p rec) (fail "not a base ledger"))
          (unless (eq (op:operation-type o) :quorum-begin) (fail "not a QuorumBegin"))
          (unless (and (equalp (up:update-ledger-id qu) (hex->bytes id)) (equalp (up:update-operator-id qu) (lg:ledger-operator-key (record-ledger rec)))
                       (up:verify-operator-signature qu))
            (fail "the QuorumBegin is not this ledger's operator's"))
          ;; it extends what we hold: our tip, or (applied already) the update before it
          (when (< (lg:ledger-sequence (record-ledger rec)) (1- (up:update-seq qu))) (catch-up node rec))
          (let* ((view (pre-update-view rec (up:update-seq qu)))
                 (vtip (tip view)))
            (unless (and vtip (equalp (up:chain-hash vtip) (up:update-prev-hash qu)) (= (up:update-seq qu) (1+ (up:update-seq vtip))))
              (fail "the QuorumBegin does not extend our replica"))
            (multiple-value-bind (required signers) (lg:cosign-requirement (record-ledger view) o (up:update-block-height qu))
              (multiple-value-bind (ok why) (up:verify-cosignatures qu :quorum (mapcar #'lg:member-pubkey signers) :threshold required)
                (unless ok (fail "the QuorumBegin is not final: ~a" why))))
            (check-not-deposed node view)
            (multiple-value-bind (cur) (disputed-reserves node view)
              (unless (member (node-pubkey node) (rs:reserves-members cur) :test #'equalp) (fail "not a member of the spent vault"))
              (unless (eql tier-index (rung-tier-index cur (btx:tx-locktime (first proposed)) (up:update-block-height qu)))
                (fail "tier_index is not the rungs' tier")))
            (multiple-value-bind (ours prevouts cur splice)
                (expected-ladder node view o (up:update-block-height qu) (up:update-prev-hash qu) tier-index)
              (unless (and ours (= (length ours) (length proposed))
                           (every (lambda (a b) (equalp (btx:serialize-tx a :witness nil) (btx:serialize-tx b :witness nil))) ours proposed)
                           (equal (mapcar #'bytes->hex (mapcar #'btx:tx-txid ours)) (mapcar #'bytes->hex (fr:rotation-rungs o))))
                (fail "the rungs are not the ladder the QuorumBegin names"))
              (when (and (node-chain-fn node) (null (funcall (node-chain-fn node) (btx:txin-prev-hash (first (btx:tx-inputs (first ours))))
                                                             (btx:txin-prev-index (first (btx:tx-inputs (first ours)))))))
                (fail "vault outpoint is spent or unknown"))
              (dolist (tx ours) (check-relayable tx))
              (let ((leaf (nth tier-index (rs:reserves-leaves cur)))
                    (vault-splice (and splice (equalp (fourth splice) (rs:reserves-spk cur)))))
                (log! node "signing the ~a rungs of ~a's rotation (QuorumBegin seq ~a) at tier ~a"
                      (length ours) (subseq id 0 8) (up:update-seq qu) tier-index)
                (respond node event t
                         :result (w:json-object
                                  "signer" (node-pubkey-hex node)
                                  "signatures" (coerce (mapcar (lambda (tx) (bytes->hex (schnorr:schnorr-sign (node-priv node) (rot:tier-sighash tx 0 prevouts leaf) (random-aux)))) ours) 'vector)
                                  ;; DEP-03: a vault-script splice-in is signed through the same tier
                                  "splice_signatures" (and vault-splice
                                                           (coerce (mapcar (lambda (tx) (bytes->hex (schnorr:schnorr-sign (node-priv node) (rot:tier-sighash tx 1 prevouts leaf) (random-aux)))) ours) 'vector))))))))
      (error (e) (log! node "refused rotation_sign for ~a: ~a" (subseq id 0 8) e)
        (respond node event nil :error (princ-to-string e))))))

(defun arg-theft-destination (node tx)
  "The destination address of a theft tx: its single output's spk, re-encoded as
   an address.  The conspirators rebuild the same tx from the same public state,
   so this is only a cross-check that the proposer's tx is the one we would build."
  (let* ((spk (btx:txout-script (first (btx:tx-outputs tx))))
         (witver (aref spk 0)) (program (subseq spk (if (>= witver #x50) 2 1))))
    (cl-consensus.encoding:segwit-encode (rs:hrp-for (intern (string-upcase (node-network node)) :keyword))
                                         (if (>= witver #x50) (- witver #x50) witver) program)))

(defun dispute-respectful-p (node id-hex)
  "Whether our dispute of ID-HEX is for a lapsed quorum (a respectful confiscation, DEP-06),
   from our own fork's DisputeEnter: never from a proposer."
  (let ((fork (find-fork node id-hex (node-pubkey node))))
    (and fork (multiple-value-bind (enter enter-op) (fork-op fork :dispute-enter)
                (and enter (expiry-reason-p (op:field enter-op :reason)))))))

(defun unsigned-bytes (tx) (btx:serialize-tx tx :witness nil))

(defun confiscation-match (node id-hex tx &key (respectful (dispute-respectful-p node id-hex)))
  "TX is a confiscation of ID-HEX as the pinned builder makes it (DEP-03): every byte of our
   own rebuild at TX's tier, the shape our dispute's reason dictates, and the rule's fee.  The
   lottery output may pay a lottery over another subset of the armers (a proposer that saw a
   different set of late arms, DEP-03); nothing else may differ.  Returns :ours (our cut),
   :subset, or NIL; second value the lottery it pays."
  (let* ((reserves (ignore-errors (disputed-reserves node (find-record node id-hex))))
         (ti (and reserves (position (btx:tx-locktime tx) (rs:reserves-tiers reserves) :key #'rs:tier-locktime))))
    (when (and ti (not (rs:tier-tie-breaker-p (nth ti (rs:reserves-tiers reserves)))) (btx:tx-outputs tx))
      (let ((ours (ignore-errors (multiple-value-list
                                  (build-confiscation node id-hex :respectful respectful :tier-index ti)))))
        (when ours
          (destructuring-bind (built lottery &rest _) ours
            (declare (ignore _))
            (cond ((equalp (unsigned-bytes built) (unsigned-bytes tx)) (values :ours lottery))
                  (t (let ((l (ignore-errors (lottery-paid-by node id-hex (btx:txout-script (first (btx:tx-outputs tx)))))))
                       (when l
                         (let ((swapped (btx:make-tx :version (btx:tx-version built) :locktime (btx:tx-locktime built) :segwit-p t
                                                     :inputs (btx:tx-inputs built)
                                                     :outputs (cons (btx:make-txout :value (btx:txout-value (first (btx:tx-outputs built)))
                                                                                    :script (lot:lottery-spk l))
                                                                    (rest (btx:tx-outputs built)))
                                                     :witnesses (list nil))))
                           (when (equalp (unsigned-bytes swapped) (unsigned-bytes tx)) (values :subset l)))))))))))))

;;; DEP-06 "Authorised confiscation": a vault spend is a confiscation iff it is byte-identical to
;;; the one the rules build from public state (the ledger's history, the public DisputeArmed
;;; events, the eligibility cut as of the spend's block, the obligations, the fee rule), its
;;; lottery over a set the cut yields for some subset of the arms.  Never "one we know of": a
;;; member that missed the dispute rebuilds it from the relay like anyone else.

(defun dispute-view (node id-hex updates &key confiscated-at)
  "A scratch node holding ID-HEX's ledger and its dispute forks as UPDATES (the relay's, every
   operator's) give them: the original operator's chain, and for each member that entered a
   dispute, the base to its DisputeEnter's fork point then its own updates.  It shares NODE's
   chain functions, so the eligibility cut and obligations are judged on the same chain."
  (let* ((sorted (sort (copy-list updates) #'< :key #'up:update-seq))
         (open (or (find-if (lambda (u) (and (zerop (up:update-seq u)) (fr:update-opens-ledger-p u (hex->bytes id-hex)))) sorted)
                   (fail "no LedgerOpen for ~a" (subseq id-hex 0 8))))
         (origin (up:update-operator-id open))
         ;; The operator's chain by its hash links, from LedgerOpen until it forks (an
         ;; equivocation): every dispute forks before its fault, so that prefix is the one
         ;; the forks share.
         (base (let* ((mine (remove-if-not (lambda (u) (equalp (up:update-operator-id u) origin)) sorted))
                      (chain (list open)))
                 (loop for next = (let ((tip (first chain)))
                                    (remove-duplicates
                                     (remove-if-not (lambda (u) (and (= (up:update-seq u) (1+ (up:update-seq tip)))
                                                                     (equalp (up:update-prev-hash u) (up:chain-hash tip))))
                                                    mine)
                                     :test #'equalp :key #'up:chain-hash))
                       while (= (length next) 1)
                       do (push (first next) chain))
                 (reverse chain)))
         (s (%make-node :pubkey (let ((k (make-array 33 :element-type '(unsigned-byte 8))))
                                  (setf (aref k 0) 2) (loop for i from 1 below 33 do (setf (aref k i) (random 256))) k)
                        :network (node-network node) :height-fn (node-height-fn node) :chain-fn (node-chain-fn node)
                        :pledge-fn (node-pledge-fn node) :spender-fn (node-spender-fn node) :feerate-fn (node-feerate-fn node)
                        :height-of-block (node-height-of-block node) :block-hash-fn (node-block-hash-fn node))))
    (setf (gethash id-hex (node-ledgers s)) (make-record :id-hex id-hex :ledger (lg:replay base) :history (reverse base)))
    (dolist (op (remove-duplicates (loop for u in sorted unless (equalp (up:update-operator-id u) origin) collect (up:update-operator-id u))
                                   :test #'equalp))
      (let* ((mine (remove-if-not (lambda (u) (equalp (up:update-operator-id u) op)) sorted))
             (enter (find :dispute-enter mine :key (lambda (u) (op:operation-type (op:decode-operation (up:update-message u)))))))
        (when enter
          (let ((lvs (op:field (op:decode-operation (up:update-message enter)) :last-valid-sequence)))
            (setf (gethash (fork-key id-hex op) (node-ledgers s))
                  (make-record :id-hex id-hex :ledger (lg:make-ledger) :fork-p t :fork-of id-hex :fork-operator op
                               :history (reverse (append (remove-if (lambda (u) (> (up:update-seq u) lvs)) base)
                                                         (remove-if (lambda (u) (<= (up:update-seq u) lvs)) mine)))))))))
    (when confiscated-at (setf (gethash id-hex (node-confiscation-heights s)) confiscated-at))
    s))

(defun view-respectful-p (view id-hex)
  "DEP-06: a confiscation is respectful iff every DisputeEnter of the dispute is for a lapsed
   quorum; any punitive ground makes it punitive."
  (let ((reasons (loop for f in (forks-of view id-hex)
                       for (u o) = (multiple-value-list (fork-op f :dispute-enter))
                       when u collect (op:field o :reason))))
    (and reasons (every #'expiry-reason-p reasons))))

(defun rebuild-matches-p (view id-hex tx)
  "TX is byte for byte a confiscation VIEW builds: at TX's tier (a confiscation tier, never the
   tie-breaker), in the dispute's shape, its lottery over the cut of some subset of the arms
   counted as of the confiscation's block, with that subset's snapshot for the obligations (as a
   proposer that saw only those arms builds it).  Mirrors deposits-rust's rebuild_matching."
  (let* ((reserves (disputed-reserves view (find-record view id-hex)))
         (tiers (rs:reserves-tiers reserves))
         (ti (position (btx:tx-locktime tx) tiers :key #'rs:tier-locktime))
         (all (sort (copy-list (armers-of view id-hex :until (gethash id-hex (node-confiscation-heights view)))) #'bytes< :key #'first))
         (floor-sats (eligibility-floor-sats view id-hex))
         (respectful (view-respectful-p view id-hex))
         (want (unsigned-bytes tx))
         (tried '()))
    (when (and ti (not (rs:tier-tie-breaker-p (nth ti tiers))) all (<= (length all) 8))
      (loop for mask from (1- (ash 1 (length all))) downto 1
            for arms = (loop for a in all for i from 0 when (logbitp i mask) collect a)
            thereis (multiple-value-bind (in out snapshot) (split-armers arms floor-sats (node-pledge-fn view) :tip (height view))
                      (declare (ignore out))
                      (let ((key (mapcar #'first in)))
                        (when (and in (not (member key tried :test #'equalp)))
                          (push key tried)
                          (let ((built (ignore-errors (build-confiscation view id-hex :tier-index ti :respectful respectful
                                                                                      :armers in :snapshot snapshot))))
                            (and built (equalp (unsigned-bytes built) want))))))))))

(defvar *rebuilt-confiscations* (make-hash-table :test #'equalp) "spend txid -> verdict, once judged")
(defvar *rebuilt-confiscations-lock* (bt:make-lock "rebuilt-confiscations"))

(defun rebuilt-confiscation-p (node id-hex tx &key spend-height updates)
  "DEP-06: TX (a spend of ID-HEX's vault, confirmed at SPEND-HEIGHT) is the confiscation the
   rules build from public state.  UPDATES default to the relay's.  Cached by txid."
  (let ((txid (btx:tx-txid tx)))
    (multiple-value-bind (hit found) (bt:with-lock-held (*rebuilt-confiscations-lock*) (gethash txid *rebuilt-confiscations*))
      (when found (return-from rebuilt-confiscation-p hit)))
    (let* ((updates (or updates (ledger-updates-from-relays node id-hex)))
           (view (and updates (ignore-errors (dispute-view node id-hex updates :confiscated-at spend-height))))
           (verdict (and view (forks-of view id-hex) (ignore-errors (rebuild-matches-p view id-hex tx)))))
      ;; Only a match is final; a miss may be a relay that has not delivered every arm yet.
      (when verdict (bt:with-lock-held (*rebuilt-confiscations-lock*) (setf (gethash txid *rebuilt-confiscations*) t)))
      verdict)))

(defun handle-confiscation-sign (node event params)
  "A recovery-quorum member: rebuild the confiscation from public state and sign
   only a transaction byte-identical to that rebuild (FINDINGS D2: never a sighash
   the proposer computed over a transaction of its choosing)."
  (let ((id (w:event-ledger-id event)))
    (unless (find-fork node id (node-pubkey node))
      (log! node "confiscation_sign for ~a from ~a: we hold no fork, not answering" (subseq id 0 8) (subseq (ev:event-pubkey event) 0 8))
      (return-from handle-confiscation-sign nil))   ; not a disputant: not ours to answer
    (handler-case
        (let* ((proposed (btx:parse-tx (bw:make-reader (hex->bytes (or (w:jget params "unsigned_tx") (w:jget params "tx_hex") (fail "no unsigned_tx"))))))
               ;; DEP-03: the fee is the rule's and the shape our own dispute's reason, never the proposer's.
               (fee nil)
               (respectful (dispute-respectful-p node id))
               (match (confiscation-match node id proposed)))
          (let ((r (w:jget params "respectful")))
            (when (and r (not (eq r :false)) (not respectful)) (fail "a respectful confiscation of a punitive dispute")))
          ;; A proposal over another subset of the armers is a real confiscation (it may land, and
          ;; we must recognise it), but not ours to sign until our views of late arms converge.
          (when (and match (not (find (btx:tx-txid proposed) (gethash id (node-seen-confiscations node)) :key #'btx:tx-txid :test #'equalp)))
            (push proposed (gethash id (node-seen-confiscations node))))
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
            (unless (and (equalp (btx:tx-txid tx) (btx:tx-txid proposed)) (equalp (unsigned-bytes tx) (unsigned-bytes proposed)))
              (fail "~a confiscation is not the one we rebuild (ours: sats ~a, base seq ~a, outputs ~a)"
                    (if (eq match :subset) "a subset-lottery" "the proposed")
                    (car (aref prevouts 0)) (lg:ledger-sequence (record-ledger (find-record node id)))
                    (mapcar (lambda (o) (cons (btx:txout-value o) (subseq (bytes->hex (btx:txout-script o)) 0 12))) (btx:tx-outputs tx))))
            (let ((expected (confiscation-sighash tx prevouts reserves tier-index)))
              (unless (equalp expected (hex->bytes (w:jget params "sighash")))
                (fail "the proposer's sighash is not our rebuild's"))
              ;; Its txid does not depend on the witness: keep it, the claim spends it.  Keep every
              ;; one we sign, too: a proposal from another proposer may be the one that lands.
              (dolist (fork (forks-of node id)) (setf (record-lottery fork) lottery (record-confiscation fork) proposed))
              (unless (find (btx:tx-txid proposed) (gethash id (node-signed-confiscations node))
                            :key (lambda (e) (btx:tx-txid (car e))) :test #'equalp)
                (push (cons proposed lottery) (gethash id (node-signed-confiscations node))))
              (log! node "signed confiscation of ~a proposed by ~a (fee ~a sats)" (subseq id 0 8) (subseq (ev:event-pubkey event) 0 8)
                    (- (reduce #'+ prevouts :key #'car) (reduce #'+ (btx:tx-outputs tx) :key #'btx:txout-value)))
              (respond node event t :result (w:json-object "signer" (node-pubkey-hex node)
                                                           "signature" (bytes->hex (schnorr:schnorr-sign (node-priv node) expected (random-aux)))
                                                           ;; DEP-06: one signature per swept migration output
                                                           "sweep_signatures"
                                                           (coerce (loop for i from 1 below (length prevouts)
                                                                         collect (bytes->hex (schnorr:schnorr-sign
                                                                                              (node-priv node)
                                                                                              (rot:tier-sighash tx i prevouts (nth tier-index (rs:reserves-leaves reserves)))
                                                                                              (random-aux))))
                                                                   'vector))))))
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
               ;; The preimage must open the SIGNER's commitment.  Any armer's would do
               ;; before: a member waited for the others' reveals and published, as its
               ;; own, whichever copy made it the winner, never opening its own.
               (find-if (lambda (a) (and (equalp (first a) member) (equalp (second a) (lot:commitment-of preimage))))
                        (armers-of node id)))
      (note-reveal node id member preimage))))

(defun reveals-of (node id-hex) (gethash id-hex (node-reveals node)))

(defun claim-or-yield (node id-hex &key confiscation-txid (fee lot:+claim-fee-floor+))
  "The drawn winner claims the lottery output and takes custody (DisputeAcquire);
   everyone else yields.  Every participant revealed: the full-set leaf.  Past the
   reveal deadline with some missing: the leaf of the revealers we hold, with the
   recovery voters' attestation.  Returns (values :won-or-:yielded claim-tx)."
  (let* ((fork (or (find-fork node id-hex (node-pubkey node)) (fail "no fork")))
         (lottery (or (record-lottery fork)
                      ;; After a restart: rebuild from public state (the unsigned tx has the claim's
                      ;; txid).  Its nLockTime is its tier's CLTV, so take the tier whose rebuild is
                      ;; the one on chain; without a chain view, the tier open now.
                      (destructuring-bind (tx l &rest rest)
                          (or (rebuild-confiscation-on-chain node id-hex)
                              (multiple-value-list (build-confiscation node id-hex)))
                        (declare (ignore rest))
                        (setf (record-lottery fork) l (record-confiscation fork) tx)
                        l)))
         (participants (lot:lottery-participants lottery))
         (k (length participants))
         (conf (record-confiscation fork)))
    (multiple-value-bind (idx preimages) (revealed-indices node id-hex lottery)
      (let ((full (= (length idx) k)))
        (cond ((= k 1) (setf idx '(0) preimages (list nil) full t))
              (full)
              ((null idx) (fail "nobody revealed"))
              ((not (and conf (reveal-deadline-passed-p node conf))) (fail "missing a reveal before the deadline")))
        (let* ((winner (if (= k 1) 0 (lot:subset-winner idx preimages)))
               (winner-pk (lot:participant-pubkey (nth winner participants))))
          (unless (equalp winner-pk (up:x-only (node-pubkey node)))
            (commit-update node fork (new-update node fork (list :type :dispute-yield)))
            (return-from claim-or-yield (values :yielded nil)))
          (let* ((txid (or confiscation-txid (and conf (btx:tx-txid conf)) (fail "no confiscation tx")))
                 (amount (btx:txout-value (first (btx:tx-outputs conf))))
                 (target (lot:participant-target (nth winner participants)))
                 (spk (multiple-value-bind (witver program)
                          (cl-consensus.encoding:segwit-decode target (rs:hrp-for (intern (string-upcase (node-network node)) :keyword)))
                        (cat (octets (if (zerop witver) 0 (+ #x50 witver)) (length program)) program)))
                 ;; Our declared replacement collateral (a key-path P2TR of our key) comes along as input 1.
                 (coll (fourth (find (node-pubkey node) (armers-of node id-hex) :key #'first :test #'equalp)))
                 (coll-spk (and coll (lot:key-path-spk (up:x-only (node-pubkey node)))))
                 ;; DEP-03: the shared claim shape (deposits-core build_lottery_claim_tx).
                 (tx (btx:parse-tx (bw:make-reader
                                    (btx:serialize-tx (lot:claim-tx txid 0 amount coll spk :fee fee :subset (not full))))))
                 (prevouts (coerce (append (list (cons amount (lot:lottery-spk lottery))) (and coll (list (cons (third coll) coll-spk)))) 'vector))
                 (leaf (if full (first (lot:lottery-leaves lottery))
                           (nth (lot:subset-leaf-index lottery idx) (lot:lottery-leaves lottery))))
                 (sighash (rot:tier-sighash tx 0 prevouts leaf))
                 (sig (schnorr:schnorr-sign (node-priv node) sighash (random-aux)))
                 (w0 (if full
                         (lot:claim-witness lottery sig preimages)
                         (lot:subset-witness lottery idx sig preimages (subset-attestations node id-hex lottery idx tx prevouts sighash))))
                 (witnesses (append (list w0) (and coll (list (list (key-path-signature node tx 1 prevouts))))))
                 (signed (btx:parse-tx (bw:make-reader
                                        (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t :inputs (btx:tx-inputs tx) :outputs (btx:tx-outputs tx)
                                                                       :witnesses witnesses))))))
            (dotimes (i (length (btx:tx-inputs signed)))
              (unless (rot:verify-spend signed i prevouts) (fail "claim input ~a does not verify" i)))
            (broadcast node signed)
            (commit-update node fork (new-update node fork (list :type :dispute-acquire :new-custodian (node-pubkey node)
                                                                 :claim-txid (btx:tx-txid signed) :new-reserves-address target
                                                                 ;; DEP-06: the confiscation whose residue we now owe
                                                                 :confiscation-txid txid)))
            ;; DEP-06 §Residue: we owe it now, within the ledger's service_response_blocks.
            ;; ADVERSARY :withhold-residue — a winner that never credits it (proof 11's target).
            (unless (getf (node-adversary node) :withhold-residue)
            (let ((ctx (if (and conf (equalp (btx:tx-txid conf) txid))
                           conf
                           (first (ignore-errors (rebuild-confiscation-on-chain node id-hex))))))
              (if (and ctx (equalp (btx:tx-txid ctx) txid))
                  (handler-case (credit-residue node fork ctx)
                    (error (e) (log! node "residue of ~a: ~a" (subseq id-hex 0 8) e)))
                  (log! node "residue of ~a: the confiscation ~a is not one we can rebuild" (subseq id-hex 0 8) (txid-hex txid)))))
            (values :won signed)))))))

(defun credit-residue (node fork conf)
  "DEP-06 §Residue, as the new operator after DisputeAcquire on FORK: credit every owed entry
   the confiscation CONF did not pay.  A migration dangling at the fork point: one MigrationCredit
   carrying CONF (the fold credits only its unpaid entries, and resolves the accept).  A payment
   proven uncredited (recorded on a fork, or verified by us): its deposit opened if need be, then
   an OnchainCredit of its outpoint.  Returns how many credits were appended."
  (let* ((id (record-id-hex fork)) (base (find-record node id)) (lvs (dispute-last-valid-seq node id))
         (l (and base lvs (lg:replay (remove-if (lambda (u) (> (up:update-seq u) lvs)) (reverse (record-history base))))))
         (a (and l (lg:ledger-dormancy-accept l)))
         (n 0))
    (when (and a (not (getf a :resolved)) (getf a :source))
      (multiple-value-bind (nu qu) (migration-source-updates node a (bytes->hex (getf a :source)))
        (when qu
          (commit-update node fork (new-update node fork (list :type :migration-credit
                                                               :source-notice-update (up:encode-update nu)
                                                               :source-qb-update (up:encode-update qu)
                                                               :confiscation-tx (btx:serialize-tx conf :witness nil))))
          (log! node "residue of ~a: credited the migration's unpaid entries" (subseq id 0 8))
          (incf n))))
    (let ((jsons (remove-duplicates
                  (append (gethash id (node-obligation-proofs node))
                          (loop for f in (forks-of node id)
                                append (loop for u in (record-history f)
                                             for o = (ignore-errors (op:decode-operation (up:update-message u)))
                                             when (and o (eq (op:operation-type o) :obligation-record) (op:field o :uncredited-proof))
                                               collect (bytes->ascii (op:field o :uncredited-proof)))))
                  :test #'string=)))
      (dolist (json jsons)
        (handler-case
            (let* ((proof (fr:json->proof (w:parse-json json))) (e (fr::payment-entry proof))
                   (txid (hex->bytes (fr::e proof :txid))) (vout (fr::e proof :vout)))
              (when (and (string-equal (getf proof :ledger-id) id)
                         (fr::unpaid-in-tx (list e) conf)
                         (not (fr::onchain-credited-p (reverse (record-history fork)) most-positive-fixnum txid vout)))
                (unless (gethash (getf e :deposit-id) (lg:ledger-deposits (record-ledger fork)))
                  (commit-update node fork (new-update node fork (list :type :deposit-open :deposit-id (getf e :deposit-id)
                                                                       :descriptor (getf e :descriptor)))))
                (commit-update node fork (new-update node fork (list :type :onchain-credit :txid txid :vout vout
                                                                     :deposit-id (getf e :deposit-id) :amount (getf e :amount)
                                                                     :funding-address (fr::e proof :funding-address))))
                (log! node "residue of ~a: credited an uncredited payment (~a msat)" (subseq id 0 8) (getf e :amount))
                (incf n)))
          (error (err) (log! node "residue of ~a: a payment not credited: ~a" (subseq id 0 8) err)))))
    n))

(defun subset-attestations (node id-hex lottery idx tx prevouts sighash)
  "The recovery voters' signatures on a revealer-subset claim, parallel to the
   sorted voters (NIL where absent): ours if we are a voter, then
   lottery_subset_attest until the threshold is met."
  (let* ((voters (lot::sorted-keys (lot:lottery-recovery-voters lottery)))
         (threshold (lot:lottery-recovery-threshold lottery))
         (me (up:x-only (node-pubkey node)))
         (sigs (and (member me voters :test #'equalp) (list (cons me (schnorr:schnorr-sign (node-priv node) sighash (random-aux)))))))
    (when (< (length sigs) threshold)
      (dolist (r (send-request node id-hex "lottery_subset_attest"
                               (w:json-object "unsigned_tx" (unsigned-tx-hex tx) "sighash" (bytes->hex sighash)
                                              "subset" (mapcar (lambda (i) (bytes->hex (lot:participant-pubkey (nth i (lot:lottery-participants lottery))))) idx)
                                              "prevout_amounts" (map 'list #'car prevouts)
                                              "prevout_spks" (map 'list (lambda (p) (bytes->hex (cdr p))) prevouts))
                               :want (- threshold (length sigs)) :timeout 30 :successes-only t))
        (let ((res (w:jget r "result")))
          (when (and (w:jget r "success") res)
            (let ((pk (up:x-only (hex->bytes (w:jget res "signer")))) (sig (hex->bytes (w:jget res "signature"))))
              (when (and (member pk voters :test #'equalp) (schnorr:schnorr-verify pk sighash sig) (not (assoc pk sigs :test #'equalp)))
                (push (cons pk sig) sigs)))))))
    (when (< (length sigs) threshold) (fail "only ~a of ~a subset attestations" (length sigs) threshold))
    (mapcar (lambda (v) (cdr (assoc v sigs :test #'equalp))) voters)))

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
                                   :block-height (up:update-block-height last) :block-hash (up:update-block-hash last))))
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
         (not (live-fork node (record-id-hex rec) (node-pubkey node))))))

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
                 (unless (live-fork node (record-id-hex rec) (node-pubkey node))
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

(defun attach-key-path-witness (tx in-index sig)
  (let ((witnesses (let ((w (copy-list (btx:tx-witnesses tx)))) (setf (nth in-index w) (list sig)) w)))
    (btx:parse-tx (bw:make-reader
                   (btx:serialize-tx
                    (btx:make-tx :version (btx:tx-version tx) :inputs (btx:tx-inputs tx) :outputs (btx:tx-outputs tx)
                                 :locktime (btx:tx-locktime tx) :witnesses witnesses :segwit-p t))))))

(defun key-path-signature (node tx in-index prevouts &optional (root (octets)))
  "BIP-341 key-path signature for input IN-INDEX under our key tweaked by ROOT (empty: no tree;
   an offer or accept address commits a 32-byte root)."
  (let* ((xonly (up:x-only (node-pubkey node)))
         (n secp256k1-fast:*secp256k1-n*)
         (d0 (if (= (aref (node-pubkey node) 0) 2) (node-priv node) (- n (node-priv node))))
         (tweak (mod (be->int (tagged-hash "TapTweak" (cat xonly root))) n))
         (d (mod (+ d0 tweak) n))
         (sighash (cl-consensus.script:taproot-sighash tx in-index prevouts 0 :ext-flag 0)))
    (multiple-value-bind (spk parity) (lot:p2tr-spk xonly root)
      (declare (ignore spk))
      (schnorr:schnorr-sign (if (= parity 1) (- secp256k1-fast:*secp256k1-n* d) d) sighash (random-aux)))))

;;; Fraud broadcasts (Kind 9101): verify, and if we are a member, dispute.

(defun report-non-conforming (node rec update condition)
  ;; ADVERSARY :ignore-fraud — a passive derelict member: it refuses the bad update
  ;; (never applies it) but takes no dispute action, self-detected or received.
  (when (getf (node-adversary node) :ignore-fraud) (return-from report-non-conforming nil))
  "UPDATE passed every signature check on REC (operator, cosign threshold, chain)
   and the ledger rules reject it: publish a NonConformingUpdate proof and, as a
   quorum member, dispute from the last valid sequence.  A member that could only
   refuse such an update left the ledger's fraud to someone else — on the soak a
   majority-cosigned credit of twice the reserves went unreported by every
   replica that rejected it (docs/REDTEAM.md attack #1)."
  (let ((id (record-id-hex rec)) (ledger (record-ledger rec)))
    (when (and (not (record-owned-p rec)) (not (record-fork-p rec))
               (equalp (up:update-prev-hash update) (lg:ledger-chain-tip ledger))
               (> (up:update-seq update) (lg:ledger-sequence ledger))
               (not (live-fork node id (node-pubkey node))))
      (log! node "NON-CONFORMING cosigned update on ~a at seq ~a: ~a" (subseq id 0 8) (up:update-seq update) condition)
      (let ((proof (fr:make-non-conforming-update-proof (up:update-operator-id update) (up:update-ledger-id update) update)))
        (broadcast-fraud node proof)
        (broadcast-cosigner-contagion node rec update)
        (when (and (member (node-pubkey node) (lg:ledger-quorum-members ledger) :key #'lg:member-pubkey :test #'equalp)
                   (not (live-fork node id (node-pubkey node))))   ; the proof may have looped back and forked us already
          ;; DEP-19 §6: our DisputeEnter cites the proof; watch co-members who ignore it.
          (watch-derelicts node id proof
                           (enter-dispute node rec (lg:ledger-sequence ledger) :reason "non_conforming_update"
                                                                                :fraud-proof-hash (fr:proof-hash proof))))))))

;;; Contagion (DEP-19 §5-6).  A cosigner of a non-conforming update is slashable on
;;; every ledger it operates, by that ledger's own quorum.  Without it, signing a
;;; theft cost a colluder nothing (docs/TRUST-MODEL.md §2a: the difference between
;;; ~5% and ~30% collusion tolerated at Q = 7).

(defun ledgers-operated-by (node pubkey33 &key strict)
  "Ledger ids PUBKEY33 operates: its advertisements (Kind 39100, tag o) and our
   replicas of ledgers it operates.  Second value: NIL if the relay fetch failed (so the
   list may be incomplete); STRICT callers retry later instead of treating it as final."
  (declare (ignore strict))
  (let ((ids '()) (ok t))
    (dolist (e (handler-case (bus:bus-fetch (node-bus node)
                                            (flt:make-filter :kinds (list w:+kind-advertisement+)
                                                             :tags (list (cons "o" (list (bytes->hex pubkey33))))))
                 (error () (setf ok nil) '())))
      (let ((d (ev:first-tag-value e "d"))) (when (and d (= (length d) 64)) (pushnew d ids :test #'string=))))
    (loop for rec being the hash-values of (node-ledgers node)
          when (and (not (record-fork-p rec)) (equalp (lg:ledger-operator-key (record-ledger rec)) pubkey33))
            do (pushnew (record-id-hex rec) ids :test #'string=))
    (values ids ok)))

(defun governing-quorum-begin-seq (rec seq)
  (let ((qb (find-if (lambda (u) (and (<= (up:update-seq u) seq)
                                      (eq (op:operation-type (op:decode-operation (up:update-message u))) :quorum-begin)))
                     (record-history rec))))            ; newest first: the latest at or before SEQ
    (and qb (up:update-seq qb))))

(defun broadcast-cosigner-contagion (node rec update)
  "Everyone who signed the non-conforming UPDATE on REC, against every other ledger
   they operate: each cosigner, and the operator (DEP-19 §5; operator contagion
   puts the operator's whole collateral at stake, not just this ledger's)."
  (let ((qb (governing-quorum-begin-seq rec (up:update-seq update))))
    (when qb
      (dolist (signer (cons (up:update-operator-id update) (mapcar #'up:cosig-pubkey (up:update-cosignatures update))))
        (dolist (target (remove (record-id-hex rec) (ledgers-operated-by node signer) :test #'string=))
          (log! node "contagion: ~a signed the fault on ~a; proof against its ledger ~a"
                (subseq (bytes->hex signer) 0 8) (subseq (record-id-hex rec) 0 8) (subseq target 0 8))
          (broadcast-fraud node (fr:make-non-conforming-cosignature-proof signer (hex->bytes target) update qb)))))))

(defun fault-prefix (node fault-id-hex fault)
  "The fault ledger's updates before FAULT, as FAULT's signed previous_hash pins them:
   walked back link by link from our replica or the relay.  Oldest first."
  (let* ((rec (find-record node fault-id-hex))
         (pool (if (and rec (not (record-fork-p rec))) (record-history rec) (ledger-updates-from-relays node fault-id-hex)))
         (by-chain (make-hash-table :test #'equalp)) (out '()))
    (dolist (u pool) (setf (gethash (up:chain-hash u) by-chain) u))
    (loop for u = (gethash (up:update-prev-hash fault) by-chain) then (gethash (up:update-prev-hash u) by-chain)
          while u do (push u out)
          until (zerop (up:update-seq u)))
    out))

(defun handle-cosigner-fraud (node proof)
  "A NonConformingCosignature: dispute every ledger we cosign whose operator is the
   accused, whichever of its ledgers the proof names."
  (let* ((accused (hex->bytes (getf proof :accused)))
         (targets (loop for rec being the hash-values of (node-ledgers node)
                        when (and (not (record-owned-p rec)) (not (record-fork-p rec))
                                  ;; the fault ledger itself is judged by its own proof, from before the fault
                                  (not (string= (record-id-hex rec) (getf (getf proof :evidence) :fault-ledger-id)))
                                  (equalp (lg:ledger-operator-key (record-ledger rec)) accused)
                                  (member (node-pubkey node) (lg:ledger-quorum-members (record-ledger rec)) :key #'lg:member-pubkey :test #'equalp)
                                  (not (live-fork node (record-id-hex rec) (node-pubkey node))))
                          collect rec)))
    (when targets
      (let* ((fault (up:decode-update (hex->bytes (getf (getf proof :evidence) :fault-update-hex))))
             (prefix (fault-prefix node (getf (getf proof :evidence) :fault-ledger-id) fault)))
        (multiple-value-bind (ok why) (fr:verify-non-conforming-cosignature proof prefix)
          (if (not ok)
              (log! node "contagion proof against ~a rejected: ~a" (subseq (getf proof :accused) 0 8) why)
              (dolist (rec targets)
                (log! node "contagion: ~a cosigned a non-conforming update on ~a; disputing its ledger ~a"
                      (subseq (getf proof :accused) 0 8) (subseq (getf (getf proof :evidence) :fault-ledger-id) 0 8) (subseq (record-id-hex rec) 0 8))
                (enter-dispute node rec (lg:ledger-sequence (record-ledger rec)) :reason "non_conforming_cosignature" :fraud-proof-hash (fr:proof-hash proof)))))))))

(defun updates-of-ledger (node id-hex)
  "Every update we hold of ID-HEX — its own chain and each fork of it — or, holding none,
   what the relays have."
  (let ((rec (find-record node id-hex)))
    (if (and rec (not (record-fork-p rec)))
        (append (record-history rec) (loop for f in (forks-of node id-hex) append (record-history f)))
        (ledger-updates-from-relays node id-hex))))

(defun watch-derelicts (node id-hex proof fork)
  "DEP-19 §6: we disputed ID-HEX on PROOF with FORK's DisputeEnter, which cites the proof and
   anchors it.  Watch the co-members who do not."
  (let ((enter (and fork (find-if (lambda (u) (eq (ignore-errors (op:operation-type (op:decode-operation (up:update-message u)))) :dispute-enter))
                                  (record-history fork)))))
    (when enter
      (setf (gethash id-hex (node-derelict-watch node)) (list :proof proof :disclosure enter)))))

(defun governing-quorum-begin (rec seq)
  "REC's latest QuorumBegin at or before SEQ."
  (find-if (lambda (u) (and (<= (up:update-seq u) seq)
                            (eq (ignore-errors (op:operation-type (op:decode-operation (up:update-message u)))) :quorum-begin)))
           (record-history rec)))

(defun report-derelict-members (node rec watch)
  "DEP-19 §6 / DEP-11.  We disputed REC on (getf WATCH :proof) with the DisputeEnter (getf WATCH
   :disclosure).  A co-member that cosigned REC at or after that disclosure and then kept operating
   a ledger it runs past its own dispute_response_blocks, without disputing REC, is derelict.  It is
   slashed on the ledgers it OPERATES (which have a quorum), found as contagion finds them
   (advertisements + our replicas), not on the quorumless member-ledger it cited when joining."
  (let* ((id (record-id-hex rec)) (proof (getf watch :proof)) (disc (getf watch :disclosure))
         (anchor (up:update-block-height disc))
         (lvs (op:field (op:decode-operation (up:update-message disc)) :last-valid-sequence))
         (qb (governing-quorum-begin rec lvs))
         (all (updates-of-ledger node id)))
    (when qb
      (dolist (mk (op:field (op:decode-operation (up:update-message qb)) :quorum-members))
        (let* ((vis (and (not (equalp mk (node-pubkey node)))
                         (find-if (lambda (u) (and (>= (up:update-block-height u) anchor)
                                                   (find mk (up:update-cosignatures u) :key #'up:cosig-pubkey :test #'equalp)))
                                  (reverse (record-history rec)))))
               (required (and vis (fr::member-response-blocks (reverse (record-history rec)) mk (up:update-seq qb)))))
          (when (and vis (notany (lambda (u) (fr::acted-on-p u mk (hex->bytes id))) all))
            (dolist (target (ledgers-operated-by node mk))
              (let* ((mrec (find-record node target))
                     (key (format nil "~a:~a:~a" target (bytes->hex mk) id))
                     (newest (and mrec (not (record-fork-p mrec))
                                  (find-if (lambda (u) (equalp (up:update-operator-id u) mk)) (record-history mrec)))))
                (when (and newest
                           (not (gethash key (node-reported-derelict node)))
                           (equalp (lg:ledger-operator-key (record-ledger mrec)) mk)   ; it operates target, we hold it
                           (>= (up:update-block-height newest) (+ (up:update-block-height vis) required)))
                  (let ((d (fr:make-dispute-dereliction-proof mk (hex->bytes target) proof disc qb vis newest)))
                    (multiple-value-bind (ok why)
                        (fr:verify-dispute-dereliction d (reverse (record-history mrec))
                                                       (or (node-height-of-block node) (lambda (h) (declare (ignore h)) (height node)))
                                                       :defrauded-updates all)
                      (if (not ok)
                          (log! node "not reporting ~a on ~a: our own dereliction proof does not verify: ~a"
                                (subseq (bytes->hex mk) 0 8) (subseq target 0 8) why)
                          (progn
                            (log! node "DERELICTION: ~a kept operating ~a ~a blocks past seeing ~a's fraud without disputing it"
                                  (subseq (bytes->hex mk) 0 8) (subseq target 0 8)
                                  (- (up:update-block-height newest) (up:update-block-height vis)) (subseq id 0 8))
                            (broadcast-fraud node d)
                            ;; marked only once published: a failed publish is retried on the next pass
                            (setf (gethash key (node-reported-derelict node)) t))))))))))))))

(defun node-derelict-watch-keys (node) (loop for k being the hash-keys of (node-derelict-watch node) collect k))

(defun drive-dereliction (node)
  "DEP-19 §6: for each ledger we disputed on a fraud proof, report co-members that stayed
   active past dispute_response_blocks without disputing it."
  (loop for id being the hash-keys of (node-derelict-watch node) using (hash-value w)
        for rec = (find-record node id)
        when (and rec (listp w) (getf w :disclosure)) do (ignore-errors (report-derelict-members node rec w))))

;;; Unauthorised vault spend (DEP-06).  A reserves outpoint is spent by its
;;; QuorumBegin's rotation, a recorded exit, or a confiscation.  Anything else that
;;; clears a tier's threshold is a theft by exactly the keys that signed it, and
;;; every one of them is slashable on every ledger it operates (contagion).

(defun note-confiscation (node id-hex txid)
  "Remember that TXID, a confiscation of ledger ID-HEX, confirmed (see known-confiscations)."
  (unless (member txid (gethash id-hex (node-known-confiscations node)) :test #'equalp)
    (push txid (gethash id-hex (node-known-confiscations node)))
    (when (node-data-dir node)
      (ignore-errors
       (with-open-file (out (merge-pathnames "confiscations.txt" (node-data-dir node))
                            :direction :output :if-exists :append :if-does-not-exist :create)
         (format out "~a ~a~%" id-hex (txid-hex txid)))))))

(defun load-known-confiscations (node)
  (let ((f (and (node-data-dir node) (probe-file (merge-pathnames "confiscations.txt" (node-data-dir node))))))
    (when f
      (with-open-file (in f)
        (loop for line = (read-line in nil) while line
              do (let ((sp (position #\Space line)))
                   (when sp (pushnew (reverse (hex->bytes (subseq line (1+ sp))))
                                     (gethash (subseq line 0 sp) (node-known-confiscations node)) :test #'equalp))))))))

;;; DEP-06 §Spend challenge.  A vault spend is judged by its anchor H (its last output): none is
;;; theft on its face; with one, H names the one place in the ledger that must answer for it.  A
;;; judge looks for the answer among everything it holds of the spent ledger, the relay's copies,
;;; and the answers others published (Kind 9112).  Finding nothing proves nothing: the judge
;;; challenges (QuorumChallenge on its own ledger, Kind 9111) and proves the spend only when the
;;; challenge lapses unanswered.

(defun relay-updates-past (node id-hex from &key (page 200) (max-pages 1000))
  "Every update the relays hold of ID-HEX at sequence FROM or later, a page of sequences at a
   time until a page comes back empty."
  (loop for lo from from by page repeat max-pages
        for got = (ledger-updates-from-relays node id-hex :from lo :to (+ lo page -1))
        while got append got))

(defun spend-answer-updates (node id-hex gseq)
  "Everything we can find of ID-HEX past its QuorumBegin at GSEQ: our replica, the relay's copies
   past it (signals when the relay holds nothing at all of the ledger, so the caller judges later),
   and the answers published to challenges of it."
  (let* ((rec (find-record node id-hex))
         (history (and rec (not (record-fork-p rec)) (record-history rec)))
         ;; FAULT :blind-relay (a ledger id prefix): we read none of that ledger's updates on the
         ;; relay, only our replica and published answers (redteam/check-rotation-lag.sh)
         (blind (let ((p (getf (node-adversary node) :blind-relay)))
                  (and (stringp p) (>= (length id-hex) (length p)) (string-equal p (subseq id-hex 0 (length p))))))
         (relay (and (not blind) (relay-updates-past node id-hex (1+ gseq)))))
    (unless (or blind relay (ledger-updates-from-relays node id-hex :from gseq :to gseq))
      (error "the relay holds nothing of ~a at ~a" (subseq id-hex 0 8) gseq))
    (append history relay (gethash id-hex (node-spend-answers node)))))

(defun spend-answered-p (node id-hex tx gseq reserves tier-index &key spend-height)
  "DEP-06 §Spend challenge: TX's spend of ID-HEX's vault (under the QuorumBegin at GSEQ, its
   witness at TIER-INDEX of RESERVES) has an answer we can find: the QuorumBegin that is the child
   of its anchor and names it (FR:ROTATION-ANSWER), or the confiscation the rules rebuild from
   public state.  NIL for an unanchored spend.  Signals when we cannot read the relay."
  (let ((anchor (rot:anchor-of tx)))
    (when anchor
      (let ((updates (spend-answer-updates node id-hex gseq)))
        (or (fr:rotation-answer updates anchor (btx:tx-txid tx) reserves tier-index)
            (rebuilt-confiscation-p node id-hex tx :spend-height spend-height
                                                   :updates (append (unless (getf (node-adversary node) :blind-relay)
                                                                      (ledger-updates-from-relays node id-hex))
                                                                    updates)))))))

(defun authorised-spend-p (node rec tx &key spend-height)
  "DEP-06 §Spend challenge: TX's spend of one of REC's vaults is answered (a rotation naming it,
   or the confiscation the rules rebuild from public state).  The tier is read from TX's witness
   leaf (0 when unsigned)."
  (loop for u in (record-history rec)
        for o = (ignore-errors (op:decode-operation (up:update-message u)))
        thereis (and o (eq (op:operation-type o) :quorum-begin)
                     (multiple-value-bind (reserves rungs vout) (fr:spent-vault (record-history rec) (up:update-seq u))
                       (let ((i (and reserves (position-if (lambda (in) (and (member (btx:txin-prev-hash in) rungs :test #'equalp)
                                                                             (= (btx:txin-prev-index in) vout)))
                                                           (btx:tx-inputs tx)))))
                         (when i
                           (let* ((stack (nth i (btx:tx-witnesses tx)))
                                  (tier (or (and (>= (length stack) 3) (position (nth (- (length stack) 2) stack) (rs:reserves-leaves reserves) :test #'equalp)) 0)))
                             (spend-answered-p node (record-id-hex rec) tx (up:update-seq u) reserves tier :spend-height spend-height))))))))

(defun open-spend-challenge (node e)
  "Record the challenge of owed entry E's anchored spend on our own ledger (QuorumChallenge,
   cosigned as any update) and publish it (Kind 9111).  Returns the challenge update, or NIL when
   we hold no ledger of our own to record it on."
  (let ((own (and (node-member-ledger-hex node) (find-record node (node-member-ledger-hex node)))))
    (when (and own (record-owned-p own))
      (let* ((tx (btx:parse-tx (bw:make-reader (hex->bytes (getf e :tx)))))
             (u (append-operation node own (list :type :quorum-challenge
                                                 :challenged-ledger-id (hex->bytes (getf e :id))
                                                 :challenged-txid (btx:tx-txid tx)
                                                 :challenged-anchor (rot:anchor-of tx)))))
        (bus:bus-publish (node-bus node) (w:spend-challenge-event (node-keypair node) (getf e :id) (bytes->hex (btx:tx-txid tx))
                                                                  (bytes->hex (rot:anchor-of tx)) (base64-encode (up:encode-update u))))
        u))))

(defun handle-spend-challenge (node event)
  "Kind 9111: a challenge of a spend of a vault we follow.  If we hold its answer (the rotation's
   QuorumBegin, or the confiscation's dispute on our fork), publish it (Kind 9112): anyone may
   answer, not only the accused."
  (ignore-errors
   (let* ((c (w:parse-json (ev:event-content event)))
          (id (w:jget c "challenged_ledger_id"))
          (txid (hex->bytes (w:jget c "txid"))) (anchor (hex->bytes (w:jget c "anchor")))
          (rec (find-record node id)))
     (when (and rec (not (record-fork-p rec)))
       (let ((answer (find-if (lambda (u) (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
                                            (and o (eq (op:operation-type o) :quorum-begin) (equalp (up:update-prev-hash u) anchor)
                                                 (member txid (fr:rotation-rungs o) :test #'equalp))))
                              (record-history rec)))
             (fork (find-if (lambda (f) (and (record-confiscation f) (equalp (btx:tx-txid (record-confiscation f)) txid)))
                            (forks-of node id))))
         (cond (answer
                (log! node "answering the challenge of ~a's spend ~a: its rotation's QuorumBegin (seq ~a)"
                      (subseq id 0 8) (subseq (bytes->hex txid) 0 16) (up:update-seq answer))
                (bus:bus-publish (node-bus node) (w:challenge-answer-event (node-keypair node) id (bytes->hex txid) (bytes->hex anchor)
                                                                           (list (base64-encode (up:encode-update answer))))))
               (fork
                (log! node "answering the challenge of ~a's spend ~a: our dispute fork" (subseq id 0 8) (subseq (bytes->hex txid) 0 16))
                (bus:bus-publish (node-bus node) (w:challenge-answer-event (node-keypair node) id (bytes->hex txid) (bytes->hex anchor)
                                                                           (mapcar (lambda (u) (base64-encode (up:encode-update u)))
                                                                                   (remove-if (lambda (u) (equalp (up:update-operator-id u)
                                                                                                                  (lg:ledger-operator-key (record-ledger rec))))
                                                                                              (record-history fork))))))))))))

(defun handle-challenge-answer (node event)
  "Kind 9112: keep the updates answering a challenge, for every later judgement of that ledger's spends."
  (ignore-errors
   (let* ((c (w:parse-json (ev:event-content event)))
          (id (w:jget c "challenged_ledger_id"))
          (updates (loop for b in (coerce (or (w:jget c "updates") #()) 'list)
                         for u = (ignore-errors (up:decode-update (base64-decode b)))
                         when (and u (equalp (up:update-ledger-id u) (hex->bytes id))) collect u)))
     (when updates
       (let ((have (gethash id (node-spend-answers node))))
         (dolist (u updates)
           (unless (member (up:chain-hash u) have :key #'up:chain-hash :test #'equalp) (push u have)))
         (setf (gethash id (node-spend-answers node)) (subseq have 0 (min 64 (length have)))))))))

(defparameter *vault-spend-grace-blocks* 3
  "A rotation's QuorumBegin may reach us a block or two after the spend confirms, so a
   spend is judged only once it is this deep.")
(defparameter *vault-scan-depth* 30 "Blocks before our first scan to look back over.")

(defparameter *vault-spend-publish-blocks* 144
  "Blocks after a theft's block during which we keep (re)publishing its proofs: to targets a
   relay error hid, and to ledgers its signers start advertising later.")

(defun vault-watch-file (node) (and (node-data-dir node) (merge-pathnames "vault-watch.sexp" (node-data-dir node))))

(defun save-vault-watch (node)
  "Persist the scan height and every theft we still owe proofs for (write beside, rename)."
  (let ((f (vault-watch-file node)))
    (when f
      (ensure-directories-exist f)
      (let ((tmp (make-pathname :type "tmp" :defaults f))
            (plist (list :scanned (node-vault-scanned node)
                         :spends (loop for k being the hash-keys of (node-reported-vault-spend node) using (hash-value v)
                                       collect (cons k v)))))
        (with-open-file (out tmp :direction :output :if-exists :supersede)
          (with-standard-io-syntax (let ((*print-readably* nil)) (prin1 plist out))))
        (uiop:rename-file-overwriting-target tmp f)))))

(defun load-vault-watch (node)
  (let ((f (vault-watch-file node)))
    (when (and f (probe-file f))
      (let ((plist (ignore-errors (with-open-file (in f) (with-standard-io-syntax (read in))))))
        (when plist
          (setf (node-vault-scanned node) (getf plist :scanned))
          (dolist (e (getf plist :spends)) (setf (gethash (car e) (node-reported-vault-spend node)) (cdr e))))))))

(defun vault-watch-targets (node)
  "((rec qb-seq txid vout) ...): for every base ledger we hold, the vaults of its latest two
   QuorumBegins."
  (let ((out '()))
    (loop for rec being the hash-values of (node-ledgers node)
          unless (record-fork-p rec)
            do (ignore-errors
                (let ((qbs (loop for u in (record-history rec)
                                 when (eq (op:operation-type (op:decode-operation (up:update-message u))) :quorum-begin)
                                   collect (up:update-seq u))))
                  (dolist (seq (subseq qbs 0 (min 2 (length qbs))))
                    ;; DEP-03 §Fee ladder: output 0 of every rung (only one can confirm)
                    (multiple-value-bind (reserves rungs vout) (fr:spent-vault (record-history rec) seq)
                      (when reserves (dolist (txid rungs) (push (list rec seq txid vout) out))))))))
    out))

(defun drive-vault-watch (node)
  "Scan the blocks that are now GRACE deep for spends of any vault outpoint we replicate.
   A spend its ledger's history does not account for becomes an owed theft record (keyed by
   ledger and spending txid, persisted) BEFORE the scan height moves past it; each pass then
   (re)publishes an UnauthorizedVaultSpend against each signer on each ledger that signer
   operates, until every target found has its proof and the publish window has passed.  A spend
   we could not judge holds the scan height below its block, so the next pass retries it."
  (when (node-spender-fn node)
    (let* ((to (- (height node) *vault-spend-grace-blocks*))
           (from (or (and (node-vault-scanned node) (1+ (node-vault-scanned node))) (max 0 (- to *vault-scan-depth*))))
           (watched (make-hash-table :test #'equalp)) (outpoints '()) (hold nil) (dirty nil))
      (when (>= to from)
        ;; The current vault, and the one before it: a QuorumBegin is recorded before its
        ;; rotation confirms (DEP-03), so the old vault stays watched until it is spent by
        ;; that rotation (authorised) or by anything else (theft under the old quorum).
        (loop for (rec seq txid vout) in (vault-watch-targets node)
              do (push (cons rec seq) (gethash (cons txid vout) watched))
                 (pushnew (cons txid vout) outpoints :test #'equalp))
        (dolist (spend (funcall (node-spender-fn node) from to outpoints))
          (dolist (w (gethash (cons (getf spend :txid) (getf spend :vout)) watched))
            (destructuring-bind (rec . qb-seq) w
            (handler-case (when (note-vault-spend node rec spend qb-seq) (setf dirty t))
              (error (e)
                (log! node "vault watch on ~a: ~a (retrying)" (subseq (record-id-hex rec) 0 8) e)
                (let ((h (getf spend :height))) (when h (setf hold (min (or hold h) h)))))))))
        (setf (node-vault-scanned node) (if hold (min to (1- hold)) to))
        (setf dirty t))
      (when (publish-owed-vault-spends node) (setf dirty t))
      (when dirty (ignore-errors (save-vault-watch node))))))

(defun drive-obligation-watch (node)
  "DEP-06 §Confiscation obligations: for each ledger we hold whose custody changed after a
   confiscation, for each obligation it owed — a migration dangling at the acquire, or a payment
   recorded on its history's forks (ObligationRecord) — once the new operator signs an update its
   service_response_blocks past the acquire without crediting the residue, broadcast
   UnhonouredObligation against it (once each)."
  (loop for base being the hash-values of (node-ledgers node)
        ;; the ledger's chain after a custody change: a replica that followed it, or the fork
        ;; that acquired it (we keep the winner's chain as its fork)
        for rec = (and (not (record-fork-p base)) (or (ledger-chain-record node (record-id-hex base)) base))
        for l = (and rec (record-ledger rec))
        when (and l (lg:ledger-confiscation-txid l))
          do (handler-case
                 (let* ((history (reverse (record-history rec)))
                        (au (find :dispute-acquire history :from-end t
                                  :key (lambda (u) (op:operation-type (op:decode-operation (up:update-message u))))))
                        (conf (find (lg:ledger-confiscation-txid l)
                                    (loop for f in (forks-of node (record-id-hex rec)) when (record-confiscation f) collect (record-confiscation f))
                                    :key #'btx:tx-txid :test #'equalp))
                        (a (lg:ledger-dormancy-accept l))
                        (candidates '()))
                   (when (and au conf)
                     (when (and a (not (getf a :resolved)) (getf a :source))
                       (multiple-value-bind (nu qu) (migration-source-updates node a (bytes->hex (getf a :source)))
                         (when qu (push (list (format nil "obligation:~a:migration" (record-id-hex rec)) :notice-update nu :qb-update qu) candidates))))
                     (dolist (u history)
                       (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
                         (when (and o (eq (op:operation-type o) :obligation-record) (op:field o :uncredited-proof)
                                    (< (up:update-seq u) (up:update-seq au)))
                           (push (list (format nil "obligation:~a:~a" (record-id-hex rec) (bytes->hex (sha256 (op:field o :uncredited-proof))))
                                       :uncredited-proof (bytes->ascii (op:field o :uncredited-proof)))
                                 candidates))))
                     (dolist (c candidates)
                       (destructuring-bind (key &rest args) c
                         (unless (gethash key (node-migrations-watched node))
                           (let ((proof (apply #'fr:unhonoured-obligation-proof history au conf args)))
                             (when proof
                               (multiple-value-bind (ok why)
                                   (fr:verify-proof proof :history history
                                                          :height-of-block (or (node-height-of-block node) (lambda (b) (declare (ignore b)) (height node))))
                                 (if ok
                                     (progn (setf (gethash key (node-migrations-watched node)) :done)
                                            (log! node "UNHONOURED OBLIGATION: ~a's new operator left an obligation's residue uncredited; proof broadcast"
                                                  (subseq (record-id-hex rec) 0 8))
                                            (broadcast-fraud node proof)
                                            (ignore-errors (dispute-new-operator node rec proof)))
                                     (log! node "unhonoured-obligation proof on ~a does not verify: ~a" (subseq (record-id-hex rec) 0 8) why))))))))))
               (error (e) (log! node "obligation watch on ~a: ~a" (subseq (record-id-hex rec) 0 8) e)))))

(defun drive-migration-watch (node)
  "DEP-20 §8.3: for each ledger we hold whose latest rotation migrated deposits, note the block
   the migration output confirmed in (while it is still unspent), and once the receiver has signed
   an update its own service_response_blocks later without crediting every migrated entry,
   broadcast the UncreditedOnchainPayment proof against it."
  (loop for rec being the hash-values of (node-ledgers node)
        unless (record-fork-p rec)
          do (let ((source (reverse (record-history rec))))
               (multiple-value-bind (qu nu qb) (fr:latest-migration source)
                 (let* ((key (and qu (format nil "~a:~a" (record-id-hex rec) (up:update-seq qu))))
                        (seen (and key (gethash key (node-migrations-watched node)))))
                   (when (and qu (not (eq seen :done)))
                     (handler-case
                         (let* ((txid (op:field qb :new-outpoint-txid)) (vout (op:field qb :migration-vout))
                                (conf (or seen
                                          (let ((info (and (node-chain-fn node) (funcall (node-chain-fn node) txid vout))))
                                            (when (and info (plusp (or (getf info :confirmations) 0)) (node-block-hash-fn node))
                                              (let* ((h (- (height node) (getf info :confirmations) -1))
                                                     (b (funcall (node-block-hash-fn node) h)))
                                                (when b (setf (gethash key (node-migrations-watched node)) (list :height h :hash b)))))))))
                           (when conf
                             (let* ((au (up:decode-update (op:field (op:decode-operation (up:update-message nu)) :dormancy-accept)))
                                    (rid (bytes->hex (up:update-ledger-id au)))
                                    (rrec (find-record node rid))
                                    (rhist (if (and rrec (not (record-fork-p rrec))) (reverse (record-history rrec)) (ledger-updates-from-relays node rid)))
                                    (proof (fr:uncredited-migration-proof source rhist (getf conf :hash) (getf conf :height))))
                               (cond (proof
                                      (multiple-value-bind (ok why)
                                          (fr:verify-proof proof :history rhist
                                                                 :height-of-block (or (node-height-of-block node) (lambda (b) (declare (ignore b)) (height node))))
                                        (if ok
                                            (progn (log! node "UNCREDITED MIGRATION: ~a has not credited ~a's migration; proof broadcast"
                                                         (subseq rid 0 8) (subseq (record-id-hex rec) 0 8))
                                                   (setf (gethash key (node-migrations-watched node)) :done)
                                                   (broadcast-fraud node proof))
                                            (log! node "uncredited-migration proof against ~a does not verify: ~a" (subseq rid 0 8) why))))
                                     ;; nothing late enough yet, or all credited: done only when all are
                                     ((and rhist (multiple-value-bind (q n qbo) (fr:latest-migration source)
                                                   (declare (ignore q n))
                                                   (fr::migration-credited-p qbo rhist (up:update-seq (car (last rhist)))
                                                                             (op:field qbo :new-outpoint-txid) (op:field qbo :migration-vout))))
                                      (setf (gethash key (node-migrations-watched node)) :done))))))
                       (error (e) (log! node "migration watch on ~a: ~a" (subseq (record-id-hex rec) 0 8) e)))))))))

(defun vault-spend-key (id-hex txid) (format nil "~a:~a" id-hex (txid-hex txid)))

(defun note-vault-spend (node rec spend &optional qb-seq)
  "DEP-06: judge SPEND of REC's vault (under the QuorumBegin at QB-SEQ, default the latest).
   Answered (a rotation or confiscation names it): nothing.  Unanchored: an owed theft, proven at
   once.  Anchored and unanswered: an owed challenge, never a proof until it lapses.  T when newly
   recorded; signals (the scan retries) when we cannot read the relay."
  (let* ((id (record-id-hex rec))
         (tx (btx:parse-tx (bw:make-reader (hex->bytes (getf spend :tx)))))
         (key (vault-spend-key id (btx:tx-txid tx))))
    (unless (gethash key (node-reported-vault-spend node))
      (let* ((qb (or qb-seq (governing-quorum-begin-seq rec (lg:ledger-sequence (record-ledger rec)))))
             (probe (fr:make-unauthorized-vault-spend-proof (node-pubkey node) (hex->bytes id) (hex->bytes id) qb tx
                                                           (getf spend :prevouts) (getf spend :block-hash))))
        (multiple-value-bind (reserves rungs vvout) (fr:spent-vault (record-history rec) qb)
          (multiple-value-bind (signers idx tier-index)
              (fr:vault-spend-signers tx (fr::parse-prevouts (getf (getf probe :evidence) :prevouts)) reserves rungs vvout)
            (declare (ignore idx))
            (when signers
              (let ((anchor (rot:anchor-of tx)))
                (cond ((spend-answered-p node id tx qb reserves tier-index :spend-height (getf spend :height))
                       (log! node "vault watch: ~a's spend ~a is answered by its anchor (~a)" (subseq id 0 8)
                             (subseq (txid-hex (btx:tx-txid tx)) 0 16) (if (rot:anchor-of tx) "a rotation or confiscation" "-"))
                       nil)
                      (t
                       (if anchor
                           (log! node "VAULT SPEND CHALLENGED: ~a's reserves were spent by ~a, anchored at ~a, and nothing we hold answers it; challenging (~a signers)"
                                 (subseq id 0 8) (subseq (txid-hex (btx:tx-txid tx)) 0 16) (subseq (bytes->hex anchor) 0 16) (length signers))
                           (log! node "VAULT SPEND: ~a's reserves were spent by ~a, which carries no anchor: theft on its face; ~a signers"
                                 (subseq id 0 8) (subseq (txid-hex (btx:tx-txid tx)) 0 16) (length signers)))
                       (setf (gethash key (node-reported-vault-spend node))
                             (list :id id :qb qb :tx (getf spend :tx) :height (getf spend :height)
                                   :block-hash (bytes->hex (getf spend :block-hash))
                                   :prevouts (getf (getf probe :evidence) :prevouts)
                                   :form (if anchor :challenge :unanchored) :tier tier-index
                                   :signers (mapcar #'bytes->hex signers) :published '()))
                       t))))))))))

(defun lapsed-challenge (node e)
  "For owed challenge E: (values challenge-update lapse-block-hash new-challenge-hex), the first
   two once its window has passed (the caller then checks for an answer); NIL while open.  Opens
   the challenge first if it is not yet (third value: the update to remember)."
  (let* ((opened (unless (getf e :challenge)
                   (let ((u (ignore-errors (open-spend-challenge node e))))
                     (when u
                       (log! node "challenge of ~a's spend recorded on our ledger at seq ~a" (subseq (getf e :id) 0 8) (up:update-seq u))
                       (bytes->hex (up:encode-update u))))))
         (hex (or (getf e :challenge) opened))
         (cu (and hex (up:decode-update (hex->bytes hex)))))
    (if (null cu)
        (values nil nil opened)
        (let* ((rec (find-record node (getf e :id)))
               (w (fr:spend-window (if rec (record-history rec) (ledger-updates-from-relays node (getf e :id))) (getf e :qb)))
               (end (+ (max (up:update-block-height cu) (or (getf e :height) 0)) w))
               (hash (and (>= (height node) end) (node-block-hash-fn node) (funcall (node-block-hash-fn node) end))))
          (values (and hash cu) hash opened)))))

(defun publish-owed-vault-spends (node)
  "Publish every owed theft proof not yet published; T if anything changed.  An owed challenge
   is re-judged each pass: answered, it is done; lapsed, its proofs go out in the lapsed form."
  (let ((changed nil) (h (height node)))
    (loop for key being the hash-keys of (node-reported-vault-spend node) using (hash-value e)
          when (and (listp e) (not (getf e :done)))
            do (handler-case
                   (if (and (node-height-of-block node) (getf e :block-hash)
                            (null (funcall (node-height-of-block node) (hex->bytes (getf e :block-hash)))))
                       ;; DEP-06: its block was reorganised out.  Not a fault, and not proof: forget
                       ;; it and rescan from below it, so the spend is judged again where it confirms.
                       (progn (remhash key (node-reported-vault-spend node))
                              (when (getf e :height)
                                (setf (node-vault-scanned node) (min (or (node-vault-scanned node) 0) (1- (getf e :height)))))
                              (log! node "vault spend ~a: its block was reorganised out; re-checking" (subseq key 0 8))
                              (setf changed t))
                   (let* ((tx (btx:parse-tx (bw:make-reader (hex->bytes (getf e :tx)))))
                          (prevouts (coerce (fr::parse-prevouts (getf e :prevouts)) 'list))
                          (bh (hex->bytes (getf e :block-hash))) (complete t)
                          (lapse nil) (cu nil))
                     ;; an entry kept before forms existed is judged by its anchor
                     (unless (getf e :form) (setf (getf e :form) (if (rot:anchor-of tx) :challenge :unanchored)))
                     (when (eq (getf e :form) :challenge)
                       (multiple-value-bind (c l opened) (lapsed-challenge node e)
                         (setf cu c lapse l)
                         (when opened (setf (getf e :challenge) opened changed t)))
                       (multiple-value-bind (reserves) (fr:spent-vault (let ((r (find-record node (getf e :id)))) (if r (record-history r) '())) (getf e :qb))
                         (when (and reserves (ignore-errors (spend-answered-p node (getf e :id) tx (getf e :qb) reserves (getf e :tier)
                                                                              :spend-height (getf e :height))))
                           (log! node "the challenge of ~a's spend ~a is answered; nothing to prove" (subseq (getf e :id) 0 8)
                                 (subseq (txid-hex (btx:tx-txid tx)) 0 16))
                           (setf (getf e :done) t (getf e :answered) t lapse nil changed t))))
                     (when (or (eq (getf e :form) :unanchored) lapse)
                       (dolist (xh (getf e :signers))
                         (let ((x (hex->bytes xh)))
                           ;; x-only key; the operated ledgers are advertised under the full key, either parity
                           (dolist (full (list (cat (octets 2) x) (cat (octets 3) x)))
                             (multiple-value-bind (targets ok) (ledgers-operated-by node full :strict t)
                               (unless ok (setf complete nil))
                               (dolist (target targets)
                                 (let ((pk (format nil "~a:~a" (bytes->hex full) target)))
                                   (unless (member pk (getf e :published) :test #'string=)
                                     (log! node "vault spend: ~a signed it; ~a proof against its ledger ~a" (subseq xh 0 8)
                                           (if lapse "lapsed-challenge" "unanchored") (subseq target 0 8))
                                     (broadcast-fraud node (fr:make-unauthorized-vault-spend-proof
                                                            full (hex->bytes target) (hex->bytes (getf e :id)) (getf e :qb) tx prevouts bh
                                                            :challenge-update cu :lapse-block-hash lapse))
                                     (push pk (getf e :published))
                                     (setf changed t)))))))))
                     (when (and complete (or (eq (getf e :form) :unanchored) lapse)
                                (> h (+ (or (getf e :height) 0) *vault-spend-publish-blocks*)))
                       (setf (getf e :done) t changed t))
                     (setf (gethash key (node-reported-vault-spend node)) e)))
                 (error (err) (log! node "vault spend ~a: publishing failed (~a); retrying" (subseq key 0 8) err))))
    changed))

(defparameter *vault-spend-verdict-ttl* 600
  "Seconds a spend's verdict is reused: long enough to absorb one theft's proof storm, short
   enough that a QuorumBegin or confiscation learned later changes the answer.")

(defun handle-vault-spend-fraud (node proof)
  "An UnauthorizedVaultSpend against a ledger the accused operates: if we cosign it, verify
   and dispute (the accused signed a theft of someone's vault)."
  (let* ((ev (getf proof :evidence))
         (accused (hex->bytes (getf proof :accused)))
         (spent-id (getf ev :spent-ledger-id))
         (targets (loop for rec being the hash-values of (node-ledgers node)
                        when (and (not (record-owned-p rec)) (not (record-fork-p rec))
                                  (not (string= (record-id-hex rec) spent-id))
                                  (equalp (lg:ledger-operator-key (record-ledger rec)) accused)
                                  (member (node-pubkey node) (lg:ledger-quorum-members (record-ledger rec)) :key #'lg:member-pubkey :test #'equalp)
                                  (not (live-fork node (record-id-hex rec) (node-pubkey node))))
                          collect rec)))
    (when targets
      (multiple-value-bind (ok why)
          (let* ((key (list (getf proof :accused) spent-id (getf ev :spend-tx-hex) (getf ev :governing-quorumbegin-seq)
                            (getf ev :challenge-update)))
                 (hit (gethash key (node-vault-spend-verdicts node))))
            (if (and hit (< (- (get-universal-time) (first hit)) *vault-spend-verdict-ttl*))
                (values (second hit) (third hit))
                (let* ((srec (find-record node spent-id))
                       (relay (ledger-updates-from-relays node spent-id))
                       (history (if (and srec (not (record-fork-p srec))) (append (record-history srec) relay) relay))
                       (tx (ignore-errors (btx:parse-tx (bw:make-reader (hex->bytes (getf ev :spend-tx-hex))))))
                       (spend-height (ignore-errors (and (node-height-of-block node)
                                                         (funcall (node-height-of-block node) (getf ev :spend-block-hash)))))
                       (gseq (getf ev :governing-quorumbegin-seq)))
                  (multiple-value-bind (ok why)
                      (handler-case
                          (fr:verify-unauthorized-vault-spend
                           proof history (or (node-height-of-block node) (lambda (h) (declare (ignore h)) (height node)))
                           ;; DEP-06: a lapsed challenge is rebutted by any answer we can find
                           :answered-fn (lambda (txid anchor reserves tier-index)
                                          (declare (ignore txid anchor))
                                          (spend-answered-p node spent-id tx gseq reserves tier-index :spend-height spend-height)))
                        (error (e) (return-from handle-vault-spend-fraud
                                     (log! node "vault-spend proof against ~a not judged yet: ~a" (subseq (getf proof :accused) 0 8) e))))
                    (setf (gethash key (node-vault-spend-verdicts node)) (list (get-universal-time) ok why))
                    (values ok why)))))
          (if (not ok)
              (log! node "vault-spend proof against ~a rejected: ~a" (subseq (getf proof :accused) 0 8) why)
              (dolist (rec targets)
                (log! node "contagion: ~a signed an unauthorised spend of ~a's vault; disputing its ledger ~a"
                      (subseq (getf proof :accused) 0 8) (subseq spent-id 0 8) (subseq (record-id-hex rec) 0 8))
                (enter-dispute node rec (lg:ledger-sequence (record-ledger rec)) :reason "unauthorized_vault_spend" :fraud-proof-hash (fr:proof-hash proof))))))))

(defun broadcast-fraud (node proof)
  (bus:bus-publish (node-bus node) (w:fraud-event (node-keypair node) (getf proof :ledger-id) (getf proof :accused) (fr:broadcast->json proof))))

(defun handle-fraud (node event)
  ;; ADVERSARY :ignore-fraud — a member that drops every fraud proof while it keeps
  ;; operating its own ledgers.  DEP-19 §6 makes that provable dereliction; the harness
  ;; redteam/attack-dereliction.sh drives it (docs/REDTEAM.md).
  (when (getf (node-adversary node) :ignore-fraud) (return-from handle-fraud nil))
  (let ((proof (fr:json->broadcast (w:parse-json (ev:event-content event)))))
    (case (getf proof :type)
      (:non-conforming-cosignature (handle-cosigner-fraud node proof))
      (:unauthorized-vault-spend (handle-vault-spend-fraud node proof))
      (t (handle-operator-fraud node proof)))))

(defun offer-proof-p (proof)
  (and (eq (getf proof :type) :uncredited-onchain-payment) (not (fr::e proof :source-qb-update))))

(defun note-obligation-proof (node rec proof)
  "DEP-06: an offer-evidence proof against REC that verifies is owed at confiscation; keep it
   to record on our fork before arming.  True when kept."
  (when (and (offer-proof-p proof) (string-equal (getf proof :ledger-id) (record-id-hex rec))
             (fr:verify-proof proof :history (reverse (record-history rec))
                                    :height-of-block (or (node-height-of-block node) (lambda (h) (declare (ignore h)) (height node)))))
    (pushnew (w:json (fr:proof->json proof)) (gethash (record-id-hex rec) (node-obligation-proofs node)) :test #'string=)
    t))

(defun dispute-new-operator (node chain proof)
  "A verified UnhonouredObligation (DEP-06) against the operator CHAIN's ledger has had since a
   custody change: as a member of that chain's quorum, dispute it from its tip, as the reference
   disputes any proven fraud of a ledger's current operator.  CHAIN is the replica, or (cl keeps
   the winner's chain as its fork) the acquired fork.  Returns our new fork, or NIL."
  (let* ((id (record-id-hex chain)) (l (record-ledger chain))
         (accused (hex->bytes (getf proof :accused))) (us (node-pubkey node))
         ;; DEP-06: judged by the quorum the dispute forked from.  The acquired fork carries
         ;; none (its DisputeEnter cleared it, the DisputeAcquire cleared quorum-at-fork), so
         ;; every member found itself outside it and no one disputed (regtest 2026-10-14);
         ;; the base replica holds the ledger's last QuorumBegin quorum.
         (base (find-record node id))
         (members (or (lg:ledger-quorum-members l) (lg:ledger-quorum-at-fork l)
                      (and base (or (lg:ledger-quorum-members (record-ledger base))
                                    (lg:ledger-quorum-at-fork (record-ledger base)))))))
    (cond ((equalp accused us) nil)
          ((not (equalp accused (lg:ledger-operator-key l)))
           (log! node "unhonoured-obligation proof on ~a names ~a, not its operator" (subseq id 0 8) (subseq (bytes->hex accused) 0 8)) nil)
          ((not (member us members :key #'lg:member-pubkey :test #'equalp))
           (log! node "unhonoured-obligation proof on ~a: not a member of its quorum; not disputing" (subseq id 0 8)) nil)
          ;; already disputing it: our fork holds the custody change
          ((let ((own (find-fork node id us)))
             (and own (not (eq own chain))
                  (some (lambda (u) (eq (op:operation-type (op:decode-operation (up:update-message u))) :dispute-acquire))
                        (record-history own))))
           nil)
          (t
           (log! node "UNHONOURED OBLIGATION on ~a verified: disputing its new operator ~a from seq ~a"
                 (subseq id 0 8) (subseq (bytes->hex accused) 0 8) (lg:ledger-sequence l))
           ;; Our fork from the dispute that moved custody is history now.
           (let ((own (find-fork node id us)))
             (when (and own (not (eq own chain)))
               (release-pledges node id)
               (retire-fork node own)))
           (enter-dispute node chain (lg:ledger-sequence l) :reason "unhonoured_obligation"
                                                            :fraud-proof-hash (fr:proof-hash proof))))))

(defun handle-operator-fraud (node proof)
  (let* ((proof proof)
         (id (getf proof :ledger-id))
         (rec (find-record node id)))
    ;; DEP-06 UnhonouredObligation accuses the new operator: judged on the chain after the
    ;; custody change, never by disputing the old operator's chain.
    (when (and rec (eq (getf proof :type) :unhonoured-obligation))
      (let ((chain (ledger-chain-record node id)))
        (multiple-value-bind (ok why)
            (fr:verify-proof proof :history (reverse (record-history chain))
                                   :height-of-block (or (node-height-of-block node) (lambda (h) (declare (ignore h)) (height node))))
          (if ok
              (dispute-new-operator node chain proof)
              (log! node "unhonoured-obligation proof on ~a rejected: ~a" (subseq id 0 8) why))))
      (return-from handle-operator-fraud nil))
    ;; Already disputing (another proof came first): an offer proof is still owed at confiscation.
    (when (and rec (not (record-owned-p rec)) (offer-proof-p proof) (live-fork node id (node-pubkey node)))
      (ignore-errors (note-obligation-proof node rec proof)))
    (when (and rec (not (record-owned-p rec))
               (member (node-pubkey node) (lg:ledger-quorum-members (record-ledger rec)) :key #'lg:member-pubkey :test #'equalp)
               (not (live-fork node id (node-pubkey node))))
      (multiple-value-bind (ok why)
          (let ((hob (or (node-height-of-block node)
                         ;; no chain view: trust our own tip for the anchor
                         (lambda (hash) (declare (ignore hash)) (height node)))))
            (if (eq (getf proof :type) :dispute-dereliction)
                (let ((original (getf (getf proof :evidence) :original-proof)))
                  (if original
                      (fr:verify-dispute-dereliction proof (reverse (record-history rec)) hob
                                                     :defrauded-updates (updates-of-ledger node (getf original :ledger-id)))
                      (values nil "no original proof")))
                (fr:verify-proof proof :history (reverse (record-history rec)) :height-of-block hob)))
        (when (and ok (eq (getf proof :type) :uncredited-onchain-payment) (not (fr::e proof :source-qb-update)))
          ;; DEP-06: a proven-uncredited payment is owed at confiscation: keep it to record before arming
          (pushnew (w:json (fr:proof->json proof)) (gethash id (node-obligation-proofs node)) :test #'string=))
        (if ok
            (let ((last-valid (min (lg:ledger-sequence (record-ledger rec))
                                   (case (getf proof :type)
                                     ((:equivocation :non-conforming-update) (1- (getf (getf proof :evidence) (if (eq (getf proof :type) :equivocation) :sequence :fault-sequence))))
                                     (t (lg:ledger-sequence (record-ledger rec)))))))
              (log! node "fraud proof ~a on ~a verified: disputing from seq ~a" (getf proof :type) (subseq id 0 8) last-valid)
              (let ((fork (enter-dispute node rec last-valid
                                         ;; snake_case, as the reference writes and matches it
                                         ;; ("quorum_expired", dispute.rs); "quorum-expired" made our
                                         ;; expiry disputes unrecognisable, to it and to our own driver.
                                         :reason (substitute #\_ #\- (string-downcase (symbol-name (getf proof :type))))
                                         :fraud-proof-hash (fr:proof-hash proof))))
                (unless (member (getf proof :type) '(:dispute-dereliction :quorum-expired))
                  (watch-derelicts node id proof fork))))
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
          (let ((preimage (lot:derive-preimage (lottery-seed node id-hex))))
            (if (equalp (lot:commitment-of preimage) (op:field (op:decode-operation (up:update-message armed)) :commitment-hash))
                (setf (record-preimage rec) preimage)
                (log! node "fork ~a: armed with a preimage we cannot re-derive" (subseq id-hex 0 8)))))))
    rec))

(defun load-data-dir (node &rest args)
  "Reload everything we knew: our ledgers, the ones we cosign, forks, reveals.
   Then release the worker lanes (see make-node)."
  (unwind-protect (apply #'%load-data-dir node args)
    (setf (node-loading node) nil)))

(defun %load-data-dir (node &key (log-fn (lambda (fmt &rest args) (apply #'log! node fmt args))))
  (load-known-confiscations node)
  (load-vault-watch node)
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
