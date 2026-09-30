;;;; src/daemon.lisp — the control socket: one s-expression per line on localhost.
;;;;
;;;;   (:info)                                   (:log)
;;;;   (:open-ledger :reserves-id "s" :reserves-msat N :collateral-msat M)
;;;;   (:add-member :ledger "hex" :member "pubkey hex" [:membership-blocks N])
;;;;   (:prepare-quorum :ledger "hex" [:expiry-blocks N] [:ruleset "s"])  -> :address to fund
;;;;   (:begin-quorum :ledger "hex" :txid "hex" :vout N :sats N :collateral-sats M)
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
                    (#:bus #:cl-deposits.bus) (#:jzon #:com.inuoe.jzon))
  (:export #:handle-command #:start-control-server #:bitcoin-cli-height-fn #:bitcoin-cli-chain-fn #:run-cli
           #:bitcoin-cli-broadcast-fn #:bitcoin-cli-height-of-block-fn #:bitcoin-cli-block-hash-fn #:bitcoin-cli-utxos-fn))
(in-package #:cl-deposits.daemon)

(defun arg (form key &optional default) (getf (cdr form) key default))
(defun rec! (node form) (or (nd:find-record node (arg form :ledger)) (error "no such ledger")))
(defun ok (&rest plist) (let ((*print-pretty* nil)) (format nil "~s" (list* :status :ok plist))))

(defun ledger-summary (rec)
  (let ((l (nd:record-ledger rec)))
    (list :id (nd:record-id-hex rec) :owned (nd:record-owned-p rec) :seq (lg:ledger-sequence l)
          :quorum (lg:ledger-quorum-state l) :members (length (lg:ledger-quorum-members l))
          :staged (length (lg:ledger-next-quorum-members l)) :deposits (hash-table-count (lg:ledger-deposits l))
          :obligations (lg:total-obligations l) :reserves (lg:ledger-reserves-amount l)
          :collateral (lg:ledger-collateral-amount l) :reserves-id (lg:ledger-reserves-key l)
          :expiry (lg:ledger-quorum-expiry l))))

(defun handle-command (node form)
  (handler-case
      (ecase (car form)
        (:info (ok :pubkey (nd:node-pubkey-hex node) :height (nd:height node)
                   :inbox (getf (nd:inbox-depths node) :inbox) :cosign-inbox (getf (nd:inbox-depths node) :cosign-inbox)
                   :ledgers (loop for rec being the hash-values of (nd:node-ledgers node) collect (ledger-summary rec))))
        (:log (ok :log (reverse (nd:node-log node))))
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
                          :membership-blocks (arg form :membership-blocks 4320))
           (ok :staged (length (lg:ledger-next-quorum-members (nd:record-ledger rec))))))
        (:prepare-quorum
         (let* ((rec (rec! node form))
                (r (nd:prepare-quorum node rec :expiry-blocks (arg form :expiry-blocks 4320) :ruleset (arg form :ruleset "cltv-offset-v2"))))
           (ok :address (rs:reserves-address r) :expiry (cdr (nd:record-pinned rec))
               :ledger-hash (bytes->hex (rs:reserves-ledger-hash r)))))
        (:begin-quorum
         (let ((rec (rec! node form)))
           (multiple-value-bind (u r)
               (nd:begin-quorum node rec :funding-txid (txid-bytes (arg form :txid)) :funding-vout (arg form :vout 0)
                                :amount-msats (* 1000 (arg form :sats)) :collateral-msats (* 1000 (arg form :collateral-sats 0)))
             (ok :seq (up:update-seq u) :cosigs (length (up:update-cosignatures u)) :address (rs:reserves-address r)))))
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
        (:confiscate (multiple-value-bind (tx lottery) (nd:confiscate node (arg form :ledger) :respectful (arg form :respectful) :fee (arg form :fee 1000))
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

(defun run-cli (cli &rest args)
  (string-trim '(#\Newline #\Space)
               (uiop:run-program (append (uiop:split-string cli :separator " ") args) :output :string :ignore-error-status t)))

;;; Every run-cli forks this process, and a node's heap is gigabytes: each call
;;; costs ~175 ms (docs/TRUST-MODEL.md, the Q = 7 soak).  The cosign path asks for
;;; the height twice and, on reference ledgers, a block hash; at seven quorums per
;;; node that capped a cl cosigner at 2-3 cosigns a second against ~6 asked, and
;;; answers queued to 6-20 s.  The height changes once a block, so both are cached.

(defparameter *height-ttl-seconds* 3 "How stale a cached chain height may be.")

(defun bitcoin-cli-height-fn (cli)
  (let ((lock (bt:make-lock "height")) (value 0) (at 0))
    (lambda ()
      (bt:with-lock-held (lock)
        (when (> (- (get-universal-time) at) *height-ttl-seconds*)
          (let ((h (ignore-errors (parse-integer (run-cli cli "getblockcount")))))
            (when h (setf value h at (get-universal-time)))))
        value))))

(defun bitcoin-cli-chain-fn (cli)
  "gettxout -> (:value-sats n :confirmations n), or NIL when spent/unknown."
  (lambda (txid vout)
    (let ((out (run-cli cli "gettxout" (txid-hex txid) (princ-to-string vout))))   ; wire bytes -> display hex
      (when (and (plusp (length out)) (char= (char out 0) #\{))
        (let ((j (jzon:parse out)))
          (list :value-sats (round (* (gethash "value" j) 100000000))
                :confirmations (gethash "confirmations" j)))))))

(defun bitcoin-cli-broadcast-fn (cli)
  (lambda (bytes) (run-cli cli "sendrawtransaction" (bytes->hex bytes))))

(defun bitcoin-cli-block-hash-fn (cli)
  "Height -> block hash (32 bytes, internal byte order), or NIL.  getblockhash prints
   the reversed display order; the hash as DEP-02 signs it and as HEIGHT-OF-BLOCK reads it
   is the internal one.  Decoding the display hex made every stamped or anchored hash
   the reverse of the reference's, and of our own height-of-block's."
  (let ((lock (bt:make-lock "block-hash")) (cache (make-hash-table)))   ; height -> (hash . fetched-at)
    (lambda (height)
      (bt:with-lock-held (lock)
        (let ((hit (gethash height cache)))
          ;; A cached hash is re-read after a minute, so a reorg of a recent block heals.
          (if (and hit (< (- (get-universal-time) (cdr hit)) 60))
              (car hit)
              (let* ((out (string-trim '(#\Newline #\Space) (run-cli cli "getblockhash" (princ-to-string height))))
                     (h (and (= (length out) 64) (txid-bytes out))))
                (when h
                  (when (> (hash-table-count cache) 4096) (clrhash cache))
                  (setf (gethash height cache) (cons h (get-universal-time))))
                h)))))))

(defun bitcoin-cli-utxos-fn (cli &key (retries 5))
  "Address -> its confirmed UTXOs, via scantxoutset (no bitcoind wallet needed):
   plists :txid (wire order) :vout :sats :confirmations.  bitcoind runs one scan
   at a time (the esplora shim scans too), so a busy scanner is retried."
  (lambda (address)
    (loop repeat retries
          for out = (run-cli cli "scantxoutset" "start" (format nil "[\"addr(~a)\"]" address))
          when (and (plusp (length out)) (char= (char out 0) #\{))
            do (let* ((j (jzon:parse out)) (tip (gethash "height" j)))
                 (return (map 'list (lambda (u)
                                      (list :txid (txid-bytes (gethash "txid" u)) :vout (gethash "vout" u)
                                            :sats (round (* (gethash "amount" u) 100000000))
                                            :confirmations (1+ (- tip (gethash "height" u)))))
                              (gethash "unspents" j))))
          do (sleep 2))))

(defun bitcoin-cli-height-of-block-fn (cli)
  "Block hash -> confirmed height, or NIL (fraud-proof anchors)."
  (lambda (hash32)
    (let ((out (run-cli cli "getblockheader" (txid-hex hash32))))
      (when (and (plusp (length out)) (char= (char out 0) #\{))
        (let ((j (jzon:parse out)))
          (and (> (or (gethash "confirmations" j) 0) 0) (gethash "height" j)))))))
