;;;; src/daemon.lisp — the control socket: one s-expression per line on localhost.
;;;;
;;;;   (:info)                                   (:log)
;;;;   (:open-ledger :reserves-id "s" :reserves-msat N :collateral-msat M)
;;;;   (:add-member :ledger "hex" :member "pubkey hex" [:membership-blocks N] [:dispute-response-blocks N])
;;;;   (:prepare-quorum :ledger "hex" [:expiry-blocks N] [:ruleset "s"])  -> :address to fund
;;;;   (:begin-quorum :ledger "hex" :txid "hex" :vout N :sats N :collateral-sats M)   ; a rotation's: -> :txid its rung 0
;;;;   (:deposit-open :ledger "hex" :descriptor "pk(...)")
;;;;   (:credit :ledger "hex" :deposit "hex" :msat N :txid "hex" [:vout N])
;;;;   (:balance :ledger "hex" :deposit "hex")
;;;;   (:tip :ledger "hex")
;;;;   (:advertise :ledger "hex")
;;;;   (:address)                                 the node key's address (replacement collateral, lottery target)
;;;;   (:arm :ledger "hex" [:txid "hex" :vout N :sats N])   arm a dispute, optionally pledging replacement collateral

(defpackage #:cl-deposits.daemon
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:nd #:cl-deposits.node) (#:lg #:cl-deposits.ledger) (#:up #:cl-deposits.update)
                    (#:op #:cl-deposits.operation) (#:rs #:cl-deposits.reserves) (#:w #:cl-deposits.wire)
                    (#:bus #:cl-deposits.bus) (#:js #:json-simple) (#:fr #:cl-deposits.fraud))
  (:export #:handle-command #:start-control-server #:bitcoin-cli-height-fn #:bitcoin-cli-chain-fn #:run-cli
           #:bitcoin-cli-broadcast-fn #:bitcoin-cli-height-of-block-fn #:bitcoin-cli-block-hash-fn #:bitcoin-cli-utxos-fn #:bitcoin-cli-spender-fn #:bitcoin-cli-pledge-fn #:bitcoin-cli-feerate-fn))
(in-package #:cl-deposits.daemon)

(defun arg (form key &optional default) (getf (cdr form) key default))
(defun rec! (node form)
  "The ledger :ledger names, as we hold it: the chain we acquired (DisputeAcquire on our fork:
   we operate it now), else the record."
  (let* ((id (arg form :ledger)) (acq (and id (nd::acquired-fork node id))))
    (or (and acq (nd:record-owned-p acq) acq) (nd:find-record node id) (error "no such ledger"))))
(defun ok (&rest plist) (let ((*print-pretty* nil)) (format nil "~s" (list* :status :ok plist))))

(defun ledger-summary (node rec)
  (let ((l (nd:record-ledger rec)))
    (list :id (nd:record-id-hex rec) :owned (nd:record-owned-p rec) :seq (lg:ledger-sequence l)
          :quorum (lg:ledger-quorum-state l) :members (length (lg:ledger-quorum-members l))
          :staged (length (lg:ledger-next-quorum-members l)) :deposits (hash-table-count (lg:ledger-deposits l))
          :obligations (lg:total-obligations l) :reserves (lg:ledger-reserves-amount l)
          :collateral (lg:ledger-collateral-amount l) :reserves-id (lg:ledger-reserves-key l)
          :expiry (lg:ledger-quorum-expiry l)
          :disputed (if (and (nd:record-owned-p rec) (not (nd:record-fork-p rec)))
                        (length (nd::disputing-members node rec)) 0)
          :custody-moved (let ((c (and (nd:record-owned-p rec) (not (nd:record-fork-p rec)) (nd::custody-moved-to node rec))))
                           (and c (subseq (bytes->hex c) 0 16))))))

(defun handle-command (node form)
  (handler-case
      (ecase (car form)
        (:info (ok :pubkey (nd:node-pubkey-hex node) :height (nd:height node)
                   :inbox (getf (nd:inbox-depths node) :inbox) :cosign-inbox (getf (nd:inbox-depths node) :cosign-inbox)
                   :ledgers (loop for rec being the hash-values of (nd:node-ledgers node) collect (ledger-summary node rec))
                   :forks (mapcar (lambda (f) (list :ledger (subseq (getf f :ledger) 0 16) :by (subseq (getf f :by) 0 16)
                                                    :state (getf f :state) :live (getf f :live)))
                                  (nd:fork-summaries node))))
        (:log (let* ((all (nd:node-log node)) (len (length all))
                     ;; (:log [:tail N] [:since K]) — the last N entries, or every entry after the
                     ;; first K (K from an earlier :count), so a flood cannot push a line out of reach
                     (n (or (arg form :tail) (let ((k (arg form :since))) (and k (max 0 (- len k)))) len)))
                (ok :count len :log (reverse (subseq all 0 (min n len))))))
        (:adversary   ; (:adversary :set KEY t|nil ...) / (:adversary) — red team switches, docs/REDTEAM.md
         (loop for (k v) on (cdr (member :set form)) by #'cddr
               do (setf (getf (nd:node-adversary node) k) v))
         (ok :adversary (nd:node-adversary node)))
        (:forge-lock   ; red team: (:forge-lock :ledger L :from DEP :to DEP :msat N) — as operator, lock a
                       ; deposit with NO depositor witness, straight to the cosigners (docs/REDTEAM.md)
         (let* ((rec (rec! node form)) (h (nd:height node))
                (o (list :type :transfer-lock :transfer-nonce (cl-deposits.node::random-aux)
                         :source-deposit-id (hex->bytes (arg form :from)) :destination-deposit-id (hex->bytes (arg form :to))
                         :amount (arg form :msat) :fee 0 :completion-script "sha256(00)" :timeout-height (+ h 100)
                         :transfer-id (cl-deposits.node::random-aux) :nonce (get-universal-time) :expiry (+ h 144) :witness '()))
                (u (nd:append-operation node rec o)))
           (ok :seq (cl-deposits.update:update-seq u))))
        (:profile   ; (:profile :seconds N :top K) — statistical CPU profile of every thread, for finding hot spots
         (let ((secs (arg form :seconds 30)) (top (arg form :top 40)))
           (require :sb-sprof)
           (let ((sprof (find-package :sb-sprof)))
             (funcall (intern "RESET" sprof))
             (funcall (intern "START-PROFILING" sprof) :mode :cpu :sample-interval 0.005 :threads :all)
             (sleep secs)
             (funcall (intern "STOP-PROFILING" sprof))
             (ok :report (with-output-to-string (*standard-output*)
                           (funcall (intern "REPORT" sprof) :type :flat :max top))))))
        (:room   ; heap and GC figures
         (ok :dynamic-usage-mb (round (sb-kernel:dynamic-usage) 1048576)
             :bytes-consed-between-gcs-mb (round (sb-ext:bytes-consed-between-gcs) 1048576)
             :gc-run-time-s (float (/ sb-ext:*gc-run-time* internal-time-units-per-second))
             :total-consed-gb (float (/ (sb-ext:get-bytes-consed) 1073741824))
             :uptime-s (round (get-internal-real-time) internal-time-units-per-second)))
        (:derelict-watch
         (ok :watch (loop for id being the hash-keys of (nd::node-derelict-watch node) collect (subseq id 0 16))
             :reported (loop for k being the hash-keys of (nd::node-reported-derelict node) collect k)))
        (:vault-watch   ; run the unauthorised-vault-spend watch now, errors and all
         (nd:drive-vault-watch node)
         (ok :reported (loop for k being the hash-keys of (nd::node-reported-vault-spend node) collect (subseq k 0 16))
             :scanned-to (nd::node-vault-scanned node)))
        (:threads   ; a backtrace of every thread, for a node that is busy and silent
         (ok :threads (mapcar (lambda (th)
                                (let ((out (make-string-output-stream)) (done (sb-thread:make-semaphore)))
                                  (if (eq th sb-thread:*current-thread*)
                                      (sb-debug:print-backtrace :stream out :count 25)
                                      (progn (sb-thread:interrupt-thread th (lambda () (ignore-errors (sb-debug:print-backtrace :stream out :count 25)) (sb-thread:signal-semaphore done)))
                                             (sb-thread:wait-on-semaphore done :timeout 2)))
                                  (list :name (sb-thread:thread-name th) :backtrace (substitute #\Space #\Newline (get-output-stream-string out)))))
                              (sb-thread:list-all-threads))))
        (:open-ledger
         (let ((rec (nd:open-ledger node :reserves-id (arg form :reserves-id) :reserves (arg form :reserves-msat 0)
                                         :collateral (arg form :collateral-msat 0))))
           (ok :ledger (nd:record-id-hex rec))))
        (:add-member
         (let ((rec (rec! node form)))
           (nd:add-member node rec (hex->bytes (arg form :member)) :member-ledger-id (arg form :member-ledger)
                          :membership-blocks (arg form :membership-blocks 4320)
                          :dispute-response-blocks (arg form :dispute-response-blocks)
                          :dormancy-blocks (arg form :dormancy-blocks) :dormancy-notice-blocks (arg form :dormancy-notice-blocks))
           (ok :staged (length (lg:ledger-next-quorum-members (nd:record-ledger rec))))))
        (:prepare-quorum
         (let* ((rec (rec! node form))
                (r (nd:prepare-quorum node rec :expiry-blocks (arg form :expiry-blocks 4320) :ruleset (arg form :ruleset nil))))
           (ok :address (rs:reserves-address r) :expiry (cdr (nd:record-pinned rec))
               :ledger-hash (bytes->hex (rs:reserves-ledger-hash r)))))
        (:vaults
         ;; Every vault each owned base ledger's QuorumBegins named, oldest first, as
         ;; "txid:vout" (display order): the rotation check proves each but the last spent.
         (ok :ledgers
             (loop for rec being the hash-values of (nd:node-ledgers node)
                   when (and (nd:record-owned-p rec) (not (nd::record-fork-p rec)))
                   collect (list (nd:record-id-hex rec)
                                 (loop for u in (reverse (nd:record-history rec))
                                       for o = (op:decode-operation (up:update-message u))
                                       when (eq (op:operation-type o) :quorum-begin)
                                         collect (format nil "~a:~a" (bytes->hex (reverse (op:field o :new-outpoint-txid)))
                                                         (op:field o :new-outpoint-vout)))))))
        (:dormancy-notice
         ;; DEP-20 §8.1: :rotation-height N (>= height + dormancy_notice_blocks).  §8.3 adds
         ;; :receiver "pubkey hex" :manifest "hex" :accept "signed update hex" [:premium msat].
         (let* ((rec (rec! node form))
                (m (arg form :manifest))
                (u (nd:append-operation node rec
                                        (nd::%strip-nil-fields
                                         (list :type :dormancy-notice :rotation-height (arg form :rotation-height)
                                               :migration-receiver (and (arg form :receiver) (hex->bytes (arg form :receiver)))
                                               :manifest-hash (and m (sha256 (hex->bytes m)))
                                               :migration-manifest (and m (op:decode-manifest (hex->bytes m)))
                                               :dormancy-accept (and (arg form :accept) (hex->bytes (arg form :accept)))
                                               ;; L4: the receiver's governing QuorumBegin (fetched when not given)
                                               :receiver-quorum-begin
                                               (cond ((arg form :receiver-qb) (hex->bytes (arg form :receiver-qb)))
                                                     ((arg form :accept)
                                                      (up:encode-update (nd::receiver-governing-quorum-begin
                                                                         node (up:decode-update (hex->bytes (arg form :accept)))))))
                                               :premium (arg form :premium))))))
           (ok :seq (up:update-seq u))))
        (:uncredited-offer-proof
         ;; DEP-06 (a wallet's evidence, for the red team): :ledger :offer "the operator's offer JSON"
         ;; :descriptor :txid "display" :vout N [:confirmations 6] — proved against the operator's
         ;; latest update in our replica, verified, then broadcast.
         (let* ((rec (rec! node form)) (txid (txid-bytes (arg form :txid))) (vout (arg form :vout))
                (info (or (funcall (nd:node-chain-fn node) txid vout) (error "payment output unknown or spent")))
                (h (- (nd:height node) (getf info :confirmations) -1))
                (history (reverse (nd:record-history rec)))
                (proof (fr:make-uncredited-offer-proof (nd:record-id-hex rec) (w:parse-json (arg form :offer)) (arg form :descriptor)
                                                       txid vout (getf info :value-sats)
                                                       (funcall (nd::node-block-hash-fn node) h) (arg form :confirmations 6)
                                                       (car (last history)))))
           (multiple-value-bind (ok why)
               (fr:verify-proof proof :history history :height-of-block (nd:node-height-of-block node))
             (unless ok (error "the proof does not verify: ~a" why))
             (nd::broadcast-fraud node proof)
             (ok :hash (bytes->hex (fr:proof-hash proof))))))
        (:dormancy-offer
         ;; DEP-20 §8.3: the manifest a notice now would migrate (to hand to a receiver).
         (multiple-value-bind (m hash total) (nd::dormancy-offer node (rec! node form))
           (ok :manifest (bytes->hex (op:encode-manifest m)) :hash (bytes->hex hash) :total total :count (length m))))
        (:dormancy-accept
         ;; DEP-20 §8.3 receiver: :manifest "hex" :total msat [:offer "event id hex"] [:expiry-blocks N] [:premium-deposit "hex"]
         (let* ((rec (rec! node form))
                (u (nd::dormancy-accept node rec (op:decode-manifest (hex->bytes (arg form :manifest)))
                                        (if (arg form :offer) (hex->bytes (arg form :offer)) (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                                        (arg form :total) :expiry-blocks (arg form :expiry-blocks 288)
                                        :premium-deposit (and (arg form :premium-deposit) (hex->bytes (arg form :premium-deposit)))
                                        :source-ledger (and (arg form :source) (hex->bytes (arg form :source))))))
           (ok :seq (up:update-seq u) :accept (bytes->hex (up:encode-update u))
               :address (nd::accept-address node rec))))
        (:dormancy-credit
         ;; DEP-20 §8.3 receiver: :source "source ledger hex" — resolve the accept (MigrationCredit)
         (let ((rec (rec! node form)))
           (nd::dormancy-credit node rec (arg form :source))
           (ok :credited t)))
        (:rotate-vault
         (let ((rec (rec! node form)))
           (multiple-value-bind (txid sats)
               ;; DEP-20 §4 :splice "txid:vout" — a confirmed UTXO paying the node key's P2TR (:address).
               (nd:rotate-vault node rec :expiry-blocks (arg form :expiry-blocks 4320)
                                         :splice (let ((sp (arg form :splice)))
                                                   (when sp (let ((c (position #\: sp)))
                                                              (list (txid-bytes (subseq sp 0 c)) (parse-integer sp :start (1+ c)))))))
             (ok :txid (bytes->hex (reverse txid)) :vout 0 :sats sats))))
        (:begin-quorum
         ;; The first QuorumBegin names its funding outpoint; a later one takes the
         ;; rotation :rotate-vault broadcast (DEP-03) and ignores :txid / :sats.
         (let ((rec (rec! node form)))
           (multiple-value-bind (u r txid)
               (nd:begin-quorum node rec :funding-txid (and (arg form :txid) (txid-bytes (arg form :txid))) :funding-vout (arg form :vout 0)
                                :amount-msats (* 1000 (arg form :sats 0)) :collateral-msats (* 1000 (arg form :collateral-sats 0)))
             ;; :txid the rotation broadcast (rung 0), once its rungs are signed (DEP-03 Rotation ordering)
             (ok :seq (up:update-seq u) :cosigs (length (up:update-cosignatures u)) :address (rs:reserves-address r)
                 :txid (and txid (bytes->hex (reverse txid)))
                 ;; DEP-03 §Fee ladder: every rung the QuorumBegin names (display order), space-separated
                 :rungs (format nil "~{~a~^ ~}" (mapcar (lambda (x) (bytes->hex (reverse x)))
                                                        (cl-deposits.fraud:rotation-rungs (op:decode-operation (up:update-message u)))))))))
        (:deposit-open
         (let* ((rec (rec! node form)) (d (arg form :descriptor)) (id (op:deposit-id d)))
           (nd:append-operation node rec (list :type :deposit-open :deposit-id id :descriptor d :receive-requires-sig nil))
           (ok :deposit (bytes->hex id))))
        (:credit
         (let ((rec (rec! node form)))
           (nd:credit-onchain node rec (hex->bytes (arg form :deposit)) (arg form :msat)
                              :txid (txid-bytes (arg form :txid)) :vout (arg form :vout 0))
           (ok :seq (lg:ledger-sequence (nd:record-ledger rec)))))
        (:balance
         (let ((d (lg:find-deposit (nd:record-ledger (rec! node form)) (hex->bytes (arg form :deposit)))))
           (ok :balance (lg:deposit-balance d) :locked (lg:deposit-locked-balance d))))
        (:tip
         (let ((rec (rec! node form)))
           (ok :seq (lg:ledger-sequence (nd:record-ledger rec)) :tip (bytes->hex (lg:ledger-chain-tip (nd:record-ledger rec)))
               :history (length (nd:record-history rec)))))
        (:equivocate (nd:equivocate node (rec! node form)) (ok :warning "published a conflicting update at the tip sequence"))
        (:vault-spend   ; red team: (:vault-spend :ledger L :address "tb1..." [:tier N]) — spend the
                        ; vault outside any rotation or dispute (docs/MISSING.md, DEP-06 type 7 gap)
         ;; :anchor "tip" (the ledger's tip chain hash) or 64 hex: a forged anchor, DEP-06 §Spend challenge
         (multiple-value-bind (tx n) (nd:vault-spend node (arg form :ledger) (arg form :address)
                                                     :tier-index (arg form :tier 0) :broadcast-p nil
                                                     :anchor (let ((a (arg form :anchor)))
                                                               (cond ((null a) nil)
                                                                     ((string-equal a "tip") (lg:ledger-chain-tip (nd:record-ledger (rec! node form))))
                                                                     (t (hex->bytes a)))))
           ;; Broadcast here, not through the node's fire-and-forget broadcast-fn: a rejected
           ;; theft (non-final, bad witness) must fail the command, not report a txid.
           (multiple-value-bind (out err code)
               (uiop:run-program (append (uiop:split-string (or (uiop:getenv "CLD_BITCOIN_CLI") "bitcoin-cli") :separator " ")
                                         (list "sendrawtransaction" (bytes->hex (cl-consensus.tx:serialize-tx tx))))
                                 :output :string :error-output :string :ignore-error-status t)
             (declare (ignore out))
             (unless (zerop code) (error "sendrawtransaction rejected the theft: ~a" (substitute #\Space #\Newline (string-trim '(#\Newline #\Space) err)))))
           (ok :txid (txid-hex (cl-consensus.tx:tx-txid tx)) :sigs n :warning "unauthorised vault spend broadcast")))
        (:lottery-set   ; (:lottery-set :ledger L) — the eligibility cut over every arm we hold now
         (let ((id (arg form :ledger)))
           (multiple-value-bind (in out snapshot) (nd:lottery-armers node id)
             (ok :snapshot snapshot
                 :participants (sort (mapcar (lambda (a) (subseq (bytes->hex (first a)) 0 16)) in) #'string<)
                 :excluded (sort (mapcar (lambda (x) (subseq (bytes->hex (first (car x))) 0 16)) out) #'string<)
                 ;; the set the confirmed confiscation's lottery commits to (x-only keys), once one has
                 :landed (let ((l (nth-value 1 (ignore-errors (nd::fork-lottery node id)))))
                           (and l (sort (mapcar (lambda (p) (subseq (bytes->hex (cl-deposits.lottery:participant-pubkey p)) 0 14))
                                                (cl-deposits.lottery:lottery-participants l))
                                        #'string<)))))))
        (:forks (ok :forks (mapcar (lambda (f) (list :operator (subseq (bytes->hex (nd::record-fork-operator f)) 0 16) :seq (lg:ledger-sequence (nd:record-ledger f))
                                                     :state (lg:ledger-dispute-state (nd:record-ledger f)) :armed (and (nd:record-preimage f) t)))
                                   (nd:forks-of node (arg form :ledger)))))
        (:dispute-enter (let ((rec (rec! node form)))
                          (nd:enter-dispute node rec (arg form :last-valid-seq (lg:ledger-sequence (nd:record-ledger rec))) :reason (arg form :reason "fraud"))
                          (ok :fork (nd:fork-key (arg form :ledger) (nd:node-pubkey node)))))
        (:arm (let ((fork (or (nd:find-fork node (arg form :ledger) (nd:node-pubkey node)) (error "no fork; :dispute-enter first")))
                    ;; Optional replacement collateral: an outpoint we control (see :address), DEP-06.
                    (replacement (and (arg form :txid) (list (txid-bytes (arg form :txid)) (arg form :vout 0) (arg form :sats)))))
                (when replacement   ; the collateral wallet must not pledge it again
                  (setf (gethash (nd:outpoint-key (first replacement) (second replacement)) (nd:node-pledges node)) (arg form :ledger))
                  (nd:save-pledges node))
                (ok :commitment (bytes->hex (cl-deposits.lottery:commitment-of (nd:arm-dispute node fork :replacement replacement)))
                    :replacement (and replacement t))))
        (:address (ok :address (nd::our-target-address node)))   ; the node key's P2TR key-path address: collateral, lottery target
        (:confiscate (multiple-value-bind (tx lottery) (nd:confiscate node (arg form :ledger) :respectful (arg form :respectful))
                       (ok :txid (txid-hex (cl-consensus.tx:tx-txid tx)) :lottery (cl-deposits.lottery:lottery-address lottery))))
        (:reveal (nd:publish-reveal node (arg form :ledger)) (ok))
        (:check-expired (ok :disputed (nd:check-expired-quorums node :anchor-block-hash (txid-bytes (run-cli (or (uiop:getenv "CLD_BITCOIN_CLI") "bitcoin-cli") "getbestblockhash")))))
        (:reveals (ok :reveals (mapcar (lambda (r) (bytes->hex (car r))) (nd:reveals-of node (arg form :ledger)))))
        (:claim (multiple-value-bind (outcome tx) (nd:claim-or-yield node (arg form :ledger))
                  (ok :outcome outcome :txid (and tx (txid-hex (cl-consensus.tx:tx-txid tx))))))
        (:poll-invoices (ok :credited (mapcar #'bytes->hex (nd:credit-paid-invoices node))))
        (:invoices (ok :pending (loop for h being the hash-keys of (nd:node-invoices node) collect (bytes->hex h))))
        (:advertise
         (let* ((rec (rec! node form)) (l (nd:record-ledger rec)))
           (bus:bus-publish (nd::node-bus node)
                            (w:advertisement-event (nd::node-keypair node)
                                                   ;; Every non-defaulted field of the reference's
                                                   ;; LedgerAdvertisement, or its wallet drops the event.
                                                   (w:json-object "ledger_id" (nd:record-id-hex rec)
                                                                  "operator_pubkey" (nd:node-pubkey-hex node)
                                                                  "delegate_pubkey" ""
                                                                  "reserves_address" (lg:ledger-reserves-key l)
                                                                  "operator_name" "cl-deposits"
                                                                  "annual_fee_bps" 0 "deposit_fee_bps" 0 "withdrawal_fee_bps" 0 "invoice_fee_bps" 0
                                                                  "annualized_fixed_msats" 0 "fee_period_blocks" 2016
                                                                  "transfer_fee_fixed_msats" 0 "transfer_fee_rate_bps" 0
                                                                  "max_deposit_msats" (lg:ledger-reserves-amount l) "min_deposit_msats" 1000
                                                                  "max_deposit_balance_msats" (lg:ledger-reserves-amount l)
                                                                  "reserves_amount_msats" (lg:ledger-reserves-amount l)
                                                                  "collateral_amount_msats" (lg:ledger-collateral-amount l)
                                                                  "relay_url" (first (nd::node-relays node))
                                                                  "network" (nd::node-network node)
                                                                  "current_block" (nd:height node)
                                                                  "quorum_state" (string-downcase (symbol-name (lg:ledger-quorum-state l)))
                                                                  "quorum_members" (coerce (mapcar (lambda (m) (bytes->hex (lg:member-pubkey m))) (lg:ledger-quorum-members l)) 'vector)
                                                                  "version" 1)
                                                   :network (nd::node-network node)))
           (ok))))
    (error (e) (let ((*print-pretty* nil)) (format nil "~s" (list :status :error :message (princ-to-string e)))))))

(defun start-control-server (node port)
  (let ((sock (usocket:socket-listen "127.0.0.1" port :reuse-address t)))
    (bt:make-thread
     (lambda ()
       (loop
         (let ((client (usocket:socket-accept sock)))
           (bt:make-thread
            (lambda ()
              (handler-case
                  (let ((stream (usocket:socket-stream client)))
                    (loop for line = (read-line stream nil nil) while line
                          do (let* ((form (handler-case (let ((*read-eval* nil)) (read-from-string line)) (error () nil)))
                                    (reply (if (consp form) (handle-command node form) "(:status :error :message \"unreadable\")")))
                               (write-line reply stream) (finish-output stream))))
                (error () nil))
              (ignore-errors (usocket:socket-close client)))
            :name "cld-control-client"))))
     :name "cld-control")
    port))

;;; bitcoin-cli as the chain view.

;;; JSON-RPC straight to bitcoind over pooled keep-alive sockets, in place of forking
;;; bitcoin-cli: each fork of a node's multi-gigabyte image cost ~175 ms (below), and with
;;; 25 nodes walking blocks the regtest machine sat at load 60+ on cl alone (2026-10-14).
;;; RUN-CLI keeps bitcoin-cli's contract (stdout text, "" on an error) so every caller is
;;; unchanged; if bitcoind cannot be reached over HTTP it falls back to the process.

(defstruct rpc-endpoint host port cookie user password (pool '()) (lock (bt:make-lock "rpc-pool")))

(defvar *rpc-endpoints* (make-hash-table :test #'equal))
(defvar *rpc-endpoints-lock* (bt:make-lock "rpc-endpoints"))
(defparameter *rpc-idle-seconds* 20 "Drop a pooled connection idle this long (bitcoind's -rpcservertimeout is 30).")

(defun rpc-endpoint-of (cli)
  "The endpoint bitcoin-cli's flags in CLI name, or NIL when they cannot be read."
  (bt:with-lock-held (*rpc-endpoints-lock*)
    (multiple-value-bind (e found) (gethash cli *rpc-endpoints*)
      (when found (return-from rpc-endpoint-of e))
      (setf (gethash cli *rpc-endpoints*)
            (ignore-errors
             (let ((flags (make-hash-table :test #'equal)) (chain "main"))
               (dolist (tok (rest (uiop:split-string cli :separator " ")))
                 (cond ((member tok '("-regtest" "-signet" "-testnet" "-testnet4") :test #'string=)
                        (setf chain (subseq tok 1)))
                       ((and (> (length tok) 1) (char= (char tok 0) #\-) (find #\= tok))
                        (let ((i (position #\= tok))) (setf (gethash (subseq tok 1 i) flags) (subseq tok (1+ i)))))))
               (let* ((datadir (gethash "datadir" flags))
                      (port (or (and (gethash "rpcport" flags) (parse-integer (gethash "rpcport" flags)))
                                (cdr (assoc chain '(("main" . 8332) ("testnet" . 18332) ("testnet4" . 48332)
                                                    ("signet" . 38332) ("regtest" . 18443)) :test #'string=))))
                      (cookie (or (gethash "rpccookiefile" flags)
                                  (and datadir (namestring (merge-pathnames
                                                            (if (string= chain "main") ".cookie"
                                                                (format nil "~a/.cookie" (if (string= chain "testnet") "testnet3" chain)))
                                                            (uiop:ensure-directory-pathname datadir)))))))
                 (make-rpc-endpoint :host (or (gethash "rpcconnect" flags) "127.0.0.1") :port port :cookie cookie
                                    :user (gethash "rpcuser" flags) :password (gethash "rpcpassword" flags)))))))))

(defun rpc-param (arg)
  "ARG as bitcoin-cli would send it: a number, boolean, null, array or object literal as
   JSON, anything else (hashes, addresses, \"start\") as a JSON string."
  (if (or (member arg '("true" "false" "null") :test #'string=)
          (and (plusp (length arg)) (member (char arg 0) '(#\[ #\{)))
          (and (<= 1 (length arg) 15)
               (every #'digit-char-p (string-left-trim "-" arg))
               (string/= arg "-")))
      arg
      (with-output-to-string (o)
        (write-char #\" o)
        (loop for c across arg do (when (member c '(#\" #\\)) (write-char #\\ o)) (write-char c o))
        (write-char #\" o))))

(defun rpc-auth (e)
  (let ((creds (if (rpc-endpoint-user e)
                   (format nil "~a:~a" (rpc-endpoint-user e) (rpc-endpoint-password e))
                   (string-trim '(#\Newline #\Space) (uiop:read-file-string (rpc-endpoint-cookie e))))))
    (base64-encode (sb-ext:string-to-octets creds :external-format :utf-8))))

(defun base64-encode (bytes)
  (let ((abc "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"))
    (with-output-to-string (o)
      (loop for i from 0 below (length bytes) by 3
            do (let* ((n (length bytes))
                      (b (logior (ash (aref bytes i) 16)
                                 (if (< (+ i 1) n) (ash (aref bytes (+ i 1)) 8) 0)
                                 (if (< (+ i 2) n) (aref bytes (+ i 2)) 0))))
                 (write-char (char abc (ldb (byte 6 18) b)) o)
                 (write-char (char abc (ldb (byte 6 12) b)) o)
                 (write-char (if (< (+ i 1) n) (char abc (ldb (byte 6 6) b)) #\=) o)
                 (write-char (if (< (+ i 2) n) (char abc (ldb (byte 6 0) b)) #\=) o))))))

(defun rpc-read-response (stream)
  "Status and body of one HTTP/1.1 response on the byte STREAM."
  (let ((head (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (read-byte stream)
          do (vector-push-extend b head)
          until (and (>= (length head) 4)
                     (= (aref head (- (length head) 4)) 13) (= (aref head (- (length head) 3)) 10)
                     (= (aref head (- (length head) 2)) 13) (= (aref head (- (length head) 1)) 10)))
    (let* ((text (sb-ext:octets-to-string (coerce head '(vector (unsigned-byte 8))) :external-format :latin-1))
           (status (parse-integer text :start 9 :end 12))
           (lines (uiop:split-string text :separator (list #\Newline)))
           (len (loop for l in lines
                      for lc = (string-downcase (string-trim '(#\Return #\Space) l))
                      when (and (> (length lc) 15) (string= "content-length:" lc :end2 15))
                        return (parse-integer lc :start 15)))
           (body (make-array (or len 0) :element-type '(unsigned-byte 8))))
      (unless len (error "no Content-Length"))
      (read-sequence body stream)
      (values status (sb-ext:octets-to-string body :external-format :utf-8)))))

(defun rpc-exchange (e request)
  "One request on a pooled connection (a fresh one if the pooled one has gone away)."
  (let ((now (get-universal-time)))
    (loop for attempt from 0 below 2
          do (let ((conn (bt:with-lock-held ((rpc-endpoint-lock e))
                           (loop for c = (pop (rpc-endpoint-pool e)) while c
                                 if (< (- now (cdr c)) *rpc-idle-seconds*) return (car c)
                                   else do (ignore-errors (usocket:socket-close (car c)))))))
               (when (or (null conn) (plusp attempt))
                 (when conn (ignore-errors (usocket:socket-close conn)))
                 (setf conn (usocket:socket-connect (rpc-endpoint-host e) (rpc-endpoint-port e)
                                                    :element-type '(unsigned-byte 8) :timeout 10)))
               (handler-case
                   (let ((s (usocket:socket-stream conn)))
                     (write-sequence request s) (finish-output s)
                     (multiple-value-bind (status body) (rpc-read-response s)
                       (bt:with-lock-held ((rpc-endpoint-lock e))
                         (push (cons conn (get-universal-time)) (rpc-endpoint-pool e)))
                       (return-from rpc-exchange (values status body))))
                 (error (err)
                   (ignore-errors (usocket:socket-close conn))
                   (when (plusp attempt) (error err))))))))

(defun rpc-call-text (e method args)
  "bitcoin-cli's stdout for METHOD ARGS: a string result bare, null as \"\", anything else
   as bitcoind's own JSON text; \"\" on an RPC error (bitcoin-cli writes those to stderr)."
  (let* ((body (format nil "{\"jsonrpc\":\"1.0\",\"id\":\"cl\",\"method\":\"~a\",\"params\":[~{~a~^,~}]}"
                       method (mapcar #'rpc-param args)))
         (octets (sb-ext:string-to-octets body :external-format :utf-8))
         (request (concatenate '(vector (unsigned-byte 8))
                               (sb-ext:string-to-octets
                                (format nil "POST / HTTP/1.1~c~cHost: ~a~c~cAuthorization: Basic ~a~c~cContent-Type: application/json~c~cContent-Length: ~d~c~c~c~c"
                                        #\Return #\Newline (rpc-endpoint-host e) #\Return #\Newline (rpc-auth e) #\Return #\Newline
                                        #\Return #\Newline (length octets) #\Return #\Newline #\Return #\Newline)
                                :external-format :latin-1)
                               octets)))
    (multiple-value-bind (status text) (rpc-exchange e request)
      (declare (ignore status))   ; bitcoind answers RPC errors with 500 and a JSON body
      (let ((j (js:parse text)))
        (if (and (hash-table-p j) (let ((err (gethash "error" j))) (and err (not (eq err 'null)))))
            ""
            (let ((r (and (hash-table-p j) (gethash "result" j))))
              (cond ((or (null r) (eq r 'null)) "")
                    ((stringp r) r)
                    (t ;; bitcoind's own text for the result: {"result":<raw>,"error":...}
                     (let ((start (+ (search "\"result\":" text) 9)) (end (search ",\"error\":" text :from-end t)))
                       (string-trim '(#\Newline #\Space) (subseq text start end)))))))))))

(defun run-cli (cli &rest args)
  (let ((e (rpc-endpoint-of cli)))
    (or (and e (handler-case (rpc-call-text e (first args) (rest args))
                 (error () nil)))
        (string-trim '(#\Newline #\Space)
                     (uiop:run-program (append (uiop:split-string cli :separator " ") args) :output :string :ignore-error-status t)))))

;;; Every run-cli forks this process, and a node's heap is gigabytes: each call
;;; costs ~175 ms (docs/TRUST-MODEL.md, the Q = 7 soak).  The cosign path asks for
;;; the height twice and, on reference ledgers, a block hash; at seven quorums per
;;; node that capped a cl cosigner at 2-3 cosigns a second against ~6 asked, and
;;; answers queued to 6-20 s.  The height changes once a block, so both are cached.

(defparameter *height-ttl-seconds* 3 "How stale a cached chain height may be.")

(defun bitcoin-cli-height-fn (cli)
  "The lock guards the cached value only, never the call to bitcoind: one caller refreshes a
   stale height while every other gets the cached one at once.  Holding it across the call put
   the worker and the cosigner behind a dispute drive's bitcoind round trips (signet soak,
   2026-10-28)."
  (let ((lock (bt:make-lock "height")) (value 0) (at 0) (refreshing nil))
    (lambda ()
      (let ((mine nil))
        (bt:with-lock-held (lock)
          (when (and (> (- (get-universal-time) at) *height-ttl-seconds*) (not refreshing))
            (setf refreshing t mine t)))
        (when mine
          (unwind-protect
               (let ((h (ignore-errors (parse-integer (run-cli cli "getblockcount")))))
                 (when h (bt:with-lock-held (lock) (setf value h at (get-universal-time)))))
            (bt:with-lock-held (lock) (setf refreshing nil))))
        (bt:with-lock-held (lock) value)))))

(defun bitcoin-cli-chain-fn (cli)
  "gettxout -> (:value-sats n :confirmations n), or NIL when spent/unknown."
  (lambda (txid vout)
    (let ((out (run-cli cli "gettxout" (txid-hex txid) (princ-to-string vout))))   ; wire bytes -> display hex
      (when (and (plusp (length out)) (char= (char out 0) #\{))
        (let ((j (js:parse out)))
          (list :value-sats (round (* (gethash "value" j) 100000000))
                :confirmations (gethash "confirmations" j)
                :spk (let ((spk (gethash "scriptPubKey" j))) (and spk (hex->bytes (gethash "hex" spk))))))))))

(defun bitcoin-cli-broadcast-fn (cli)
  "sendrawtransaction; signals with bitcoind's reason when it refuses (callers log it)."
  (lambda (bytes)
    (multiple-value-bind (out err code)
        (uiop:run-program (append (uiop:split-string cli :separator " ") (list "sendrawtransaction" (bytes->hex bytes)))
                          :output :string :error-output :string :ignore-error-status t)
      (unless (or (zerop code) (search "already" err))   ; known/in the chain: nothing to do
        (error "sendrawtransaction refused: ~a" (string-trim '(#\Newline #\Space) err)))
      (string-trim '(#\Newline #\Space) out))))

(defun bitcoin-cli-block-hash-fn (cli)
  "Height -> block hash (32 bytes, internal byte order), or NIL.  getblockhash prints
   the reversed display order; the hash as DEP-02 signs it and as HEIGHT-OF-BLOCK reads it
   is the internal one.  Decoding the display hex made every stamped or anchored hash
   the reverse of the reference's, and of our own height-of-block's."
  (let ((lock (bt:make-lock "block-hash")) (cache (make-hash-table)))   ; height -> (hash . fetched-at)
    (lambda (height)
      (let ((hit (bt:with-lock-held (lock) (gethash height cache))))
        ;; A cached hash is re-read after a minute, so a reorg of a recent block heals.
        (if (and hit (< (- (get-universal-time) (cdr hit)) 60))
            (car hit)
            ;; bitcoind is asked outside the lock (see BITCOIN-CLI-HEIGHT-FN)
            (let* ((out (string-trim '(#\Newline #\Space) (run-cli cli "getblockhash" (princ-to-string height))))
                   (h (and (= (length out) 64) (txid-bytes out))))
              (when h
                (bt:with-lock-held (lock)
                  (when (> (hash-table-count cache) 4096) (clrhash cache))
                  (setf (gethash height cache) (cons h (get-universal-time)))))
              h))))))

(defun bitcoin-cli-utxos-fn (cli &key (retries 5))
  "Address -> its confirmed UTXOs, via scantxoutset (no bitcoind wallet needed):
   plists :txid (wire order) :vout :sats :confirmations.  bitcoind runs one scan
   at a time (the esplora shim scans too), so a busy scanner is retried."
  (lambda (address)
    (loop repeat retries
          for out = (run-cli cli "scantxoutset" "start" (format nil "[\"addr(~a)\"]" address))
          when (and (plusp (length out)) (char= (char out 0) #\{))
            do (let* ((j (js:parse out)) (tip (gethash "height" j)))
                 (return (map 'list (lambda (u)
                                      (list :txid (txid-bytes (gethash "txid" u)) :vout (gethash "vout" u)
                                            :sats (round (* (gethash "amount" u) 100000000))
                                            :confirmations (1+ (- tip (gethash "height" u)))))
                              (gethash "unspents" j))))
          do (sleep 2))))

(defun bitcoin-cli-spender-fn (cli)
  "(from to outpoints) -> the spends, in blocks FROM..TO, of any of OUTPOINTS (a list of
   (txid . vout), internal byte order).  Each spend is (:txid :vout :tx hex :prevouts
   ((sats . spk)...) :block-hash 32 bytes :height n).  One getblock (verbosity 3: includes prevouts) per block however many
   outpoints are watched."
  (lambda (from to outpoints)
    (let ((want (make-hash-table :test #'equal)) (found '()))
      (dolist (o outpoints) (setf (gethash (format nil "~a:~a" (txid-hex (car o)) (cdr o)) want) o))
      (loop for h from from to to
            for hash = (string-trim '(#\Newline #\Space) (run-cli cli "getblockhash" (princ-to-string h)))
            for blk = (let ((out (run-cli cli "getblock" hash "3"))) (and (plusp (length out)) (char= (char out 0) #\{) (js:parse out)))
            do (when blk
                 (loop for tx across (gethash "tx" blk)
                       do (loop for i across (gethash "vin" tx)
                                for o = (and (gethash "txid" i) (gethash (format nil "~a:~a" (gethash "txid" i) (gethash "vout" i)) want))
                                when o
                                  do (push (list :txid (car o) :vout (cdr o) :tx (gethash "hex" tx) :height h :block-hash (txid-bytes hash)
                                                 :prevouts (map 'list (lambda (vi)
                                                                        (let ((pv (gethash "prevout" vi)))
                                                                          (cons (round (* (gethash "value" pv) 100000000))
                                                                                (hex->bytes (gethash "hex" (gethash "scriptPubKey" pv))))))
                                                                (gethash "vin" tx)))
                                           found)))))
      (nreverse found))))

(defun bitcoin-cli-pledge-fn (cli)
  "(txid vout scan-from) -> (:created h :value-sats n :spend s) for the DEP-03 cut, read from
   the confirmed chain only and without -txindex.  S is :unspent (in the confirmed UTXO set;
   a mempool-only spend is unspent), (:at h) for a spend confirmed in blocks SCAN-FROM..tip
   (getblock verbosity 3 gives the input's prevout height and value), or :before when the
   output is neither: spent earlier, unconfirmed, or unknown.  All three exclude the pledge."
  ;; A confirmed spend never changes, so once found (a walk to the tip, a process pair per
  ;; block) it is remembered.  Without this every dispute pass re-walked the chain for every
  ;; obligation and pledge of every fork, and drive-disputes stopped reaching new disputes.
  ;; Only spends 6+ deep are kept (reorgs); :before only per exact SCAN-FROM once 6 past it
  ;; (an unconfirmed output also reads :before, but cannot become confirmed-at-the-snapshot
  ;; later).  An unspent output is one gettxout.
  (let ((known (make-hash-table :test #'equal)) (lock (bt:make-lock "pledge-fn")))
    (lambda (txid vout scan-from)
      (block pledge
        (let* ((hex (txid-hex txid))
               (hit (bt:with-lock-held (lock) (gethash (cons hex vout) known)))
               (before (bt:with-lock-held (lock) (gethash (list hex vout scan-from) known))))
          (when before (return-from pledge before))
          (when hit
            (return-from pledge
              (if (>= (second (getf hit :spend)) scan-from)
                  hit
                  (list :created 0 :value-sats most-positive-fixnum :spend :before))))
          (let* ((json (lambda (out) (and (plusp (length out)) (char= (char out 0) #\{) (js:parse out))))
                 (tip (parse-integer (string-trim '(#\Newline #\Space) (run-cli cli "getblockcount")) :junk-allowed t))
                 (utxo (funcall json (run-cli cli "gettxout" hex (princ-to-string vout) "false")))
                 (result
                   (cond
                     (utxo (list :created (let ((best (funcall json (run-cli cli "getblockheader" (gethash "bestblock" utxo)))))
                                            ;; heights from gettxout's own bestblock: a block between two calls cannot skew it
                                            (and best (- (gethash "height" best) (1- (gethash "confirmations" utxo)))))
                                 :value-sats (round (* (gethash "value" utxo) 100000000)) :spend :unspent))
                     ((null tip) nil)
                     (t (or (loop for h from scan-from to tip
                                  for bhash = (string-trim '(#\Newline #\Space) (run-cli cli "getblockhash" (princ-to-string h)))
                                  for blk = (funcall json (run-cli cli "getblock" bhash "3"))
                                  thereis (and blk
                                               (loop for tx across (gethash "tx" blk)
                                                     thereis (loop for i across (gethash "vin" tx)
                                                                   for pv = (gethash "prevout" i)
                                                                   thereis (and pv (equal (gethash "txid" i) hex) (eql (gethash "vout" i) vout)
                                                                                (list :created (gethash "height" pv)
                                                                                      :value-sats (round (* (gethash "value" pv) 100000000))
                                                                                      :spend (list :at h)))))))
                            (list :created 0 :value-sats most-positive-fixnum :spend :before))))))
            (let ((spend (getf result :spend)))
              (when (and (consp spend) tip (>= tip (+ (second spend) 6)))
                (bt:with-lock-held (lock) (setf (gethash (cons hex vout) known) result)))
              ;; Not confirmed-and-unspent at snapshot SCAN-FROM - 1, with the tip 6 past it:
              ;; final for that snapshot (an output still unconfirmed now was not confirmed
              ;; then), so kept for exactly that SCAN-FROM.
              (when (and (eq spend :before) tip (>= tip (+ scan-from 5)))
                (bt:with-lock-held (lock) (setf (gethash (list hex vout scan-from) known) result))))
            result))))))

(defun bitcoin-cli-feerate-fn (cli)
  "Height -> the block's feerate, floor(4 x total fee / total weight) over its non-coinbase
   transactions (getblockstats avgfeerate; DEP-03 Reference feerate), or NIL."
  (lambda (height)
    (let ((out (run-cli cli "getblockstats" (princ-to-string height) "[\"avgfeerate\"]")))
      (when (and (plusp (length out)) (char= (char out 0) #\{))
        (gethash "avgfeerate" (js:parse out))))))

(defun bitcoin-cli-height-of-block-fn (cli)
  "Block hash -> confirmed height, or NIL (fraud-proof anchors)."
  (lambda (hash32)
    (let ((out (run-cli cli "getblockheader" (txid-hex hash32))))
      (when (and (plusp (length out)) (char= (char out 0) #\{))
        (let ((j (js:parse out)))
          (and (> (or (gethash "confirmations" j) 0) 0) (gethash "height" j)))))))
