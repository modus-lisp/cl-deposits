;;;; src/ledger.lisp — the ledger state machine (DEP-05 accounting).
;;;;
;;;; What a cosigner replicates and what a wallet audits: fold the operations of
;;;; a chain, in order, into balances.  APPLY-OPERATION mirrors the reference
;;;; implementation's apply semantics field for field; APPLY-UPDATE adds the
;;;; chain checks around it (sequence, prev_hash continuity) and advances the tip.
;;;;
;;;; Deliberately NOT here yet: conformance checking (who may sign what, when),
;;;; which is a separate layer over this pure fold.

(defpackage #:cl-deposits.ledger
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:op #:cl-deposits.operation) (#:up #:cl-deposits.update)
                    (#:tr #:cl-consensus.taproot-script))
  (:export #:ledger #:make-ledger #:ledger-error
           #:ledger-id #:ledger-genesis-block #:ledger-operator-key #:ledger-reserves-key
           #:ledger-reserves-amount #:ledger-collateral-amount #:ledger-quorum-state
           #:ledger-quorum-members #:ledger-next-quorum-members #:ledger-quorum-expiry
           #:ledger-deposits #:ledger-pending-transfers #:ledger-open-invoice-locks
           #:ledger-pending-withdrawals #:ledger-credited-payments #:ledger-fees-accumulated
           #:ledger-sequence #:ledger-chain-tip #:ledger-joined-quorums #:ledger-dispute-state
           #:ledger-active-ruleset #:ledger-pending-exits #:ledger-vault-current-p #:due-exits #:+exit-cutoff-margin+
           #:exit-dust-msats #:completion-satisfied-p #:fees-due #:spk-type #:dust-floor-sats #:standard-output-p #:*update-seq* #:ledger-reference-feerate #:rotation-feerate #:exit-cost
           #:ledger-dormancy-notice #:dormancy-spin-outs #:dormancy-amount-msats #:deposit-last-signed-activity
           #:pk-key-path-spk #:dormancy-cost #:dormancy-migration #:ledger-dormancy-accept #:dormancy-offer-entries #:segwit-address-spk
           #:migration-evidence #:ledger-confiscation-txid #:ledger-quorum-at-fork #:offer-cosign-digest #:*uncredited-proof-checker* #:unpaid-entries #:owed-spk-sats
           #:consumed-notice-id #:accept-outstanding-p
           #:deposit #:deposit-id #:deposit-descriptor #:deposit-balance #:deposit-locked-balance
           #:deposit-fees #:deposit-last-fee-assessment #:deposit-transfer-fees #:deposit-available-balance #:deposit-seen-nonces
           #:deposit-opened-at-block #:deposit-last-activity-block #:deposit-last-received-block #:*block-height*
           #:collateral-floor-bps #:collateral-meets-floor-p #:quorum-expiry-ceiling #:planned-quorum-expiry #:quorum-expiry-ok-p #:+min-collateral-bps-floor+ #:quorum-member #:member-pubkey #:member-ledger-id #:member-membership-until #:member-dispute-response-blocks
           #:apply-operation #:apply-update #:total-obligations #:find-deposit
           #:majority-threshold #:+valid-quorum-sizes+ #:+rulesets+ #:+supported-rulesets+ #:+current-ruleset+ #:ruleset-rule-p #:signed-header-applies-p #:born-expired-p #:collateral-below-floor-p #:+ruleset-rules+ #:reserves-family #:newest-shared-ruleset #:cosign-requirement #:lifecycle-tier #:establishment-p #:replay #:copy-ledger))
(in-package #:cl-deposits.ledger)

(define-condition ledger-error (error)
  ((kind :initarg :kind :reader ledger-error-kind)
   (detail :initarg :detail :initform nil :reader detail))
  (:report (lambda (c s) (format s "ledger: ~a~@[ (~a)~]" (ledger-error-kind c) (detail c)))))

(defun fail (kind &optional detail) (error 'ledger-error :kind kind :detail detail))

;; DEP-18 §the registry: append-only, all of the cltv-offset-v2 reserves cascade (tier-1
;; minority ceil(n/2) - 1).  balance-commit-v4 requires balance commitments, which this
;; implementation does not emit, so it advertises the others only; fee-cap-v3's fee cap is
;; intrinsic (DEP-07).  A ruleset's rules are frozen once registered: a change is a new name.
(defparameter +rulesets+ '("cltv-offset-v2" "fee-cap-v3" "balance-commit-v4" "anchor-ladder-v5"))
(defparameter +supported-rulesets+ '("cltv-offset-v2" "anchor-ladder-v5"))
(defparameter +current-ruleset+ "anchor-ladder-v5"
  "What a new ledger's LedgerOpen names, and what a quorum moves to when every member declares it.")

(defparameter +ruleset-rules+
  '(("anchor-ladder-v5" :signed-header :born-expired :collateral-floor :vault-spend-proofs))
  "DEP-18: the gated rules each ruleset adds to the intrinsic ones.")

(defun ruleset-rule-p (ruleset rule)
  "Does RULESET (a name, or NIL for none) enforce the gated RULE?  NIL is dormant: a ledger
   with no active ruleset yet, or a QuorumBegin that names none, is never judged by a gated rule."
  (and ruleset (member rule (cdr (assoc ruleset +ruleset-rules+ :test #'string=))) t))

(defun reserves-family (ruleset)
  (when (member ruleset +rulesets+ :test #'equal) "cltv-offset-v2"))

(defun born-expired-p (ruleset quorum-expiry block-height)
  "DEP-05 born expired, a rule of anchor-ladder-v5: under RULESET (the one the QuorumBegin names),
   is a quorum_expiry at or below the QuorumBegin's block_height?"
  (and (ruleset-rule-p ruleset :born-expired) quorum-expiry (plusp block-height) (<= quorum-expiry block-height)))

(defun collateral-below-floor-p (ruleset reserves collateral floor-bps)
  "DEP-05 collateral floor, a rule of anchor-ladder-v5 (judged under the ruleset the QuorumBegin names)."
  (and (ruleset-rule-p ruleset :collateral-floor) (not (collateral-meets-floor-p reserves collateral floor-bps))))

(defun signed-header-applies-p (ledger update)
  "DEP-18: does the signed-header rule judge UPDATE?  Under LEDGER's active ruleset before it;
   a LedgerOpen (sequence 0) under the ruleset it names itself."
  (ruleset-rule-p (if (zerop (up:update-seq update))
                      (ignore-errors (op:field (op:update-op update) :protocol-version))
                      (ledger-active-ruleset ledger))
                  :signed-header))

(defun member-supported-rulesets (m)
  "The rulesets M declared in its signed QuorumMemberResponse (TLV 7: length-prefixed names);
   NIL without one."
  (let ((blob (member-member-response m)))
    (when blob
      (let ((v (cdr (assoc 7 (ignore-errors (cl-deposits.tlv:decode blob))))) (out '()))
        (when v
          (loop with i = 0 while (< i (length v))
                do (let ((n (aref v i)))
                     (push (map 'string #'code-char (subseq v (1+ i) (min (length v) (+ 1 i n)))) out)
                     (incf i (1+ n)))))
        (nreverse out)))))

(defun newest-shared-ruleset (members)
  "DEP-18 negotiation: the newest ruleset this node supports that every member declared;
   cltv-offset-v2 when none is shared beyond it (or MEMBERS declare nothing)."
  (or (find-if (lambda (r) (every (lambda (m) (member r (member-supported-rulesets m) :test #'string=)) members))
               (reverse +supported-rulesets+))
      "cltv-offset-v2"))

(defparameter +valid-quorum-sizes+ '(3 5 7)
  "DEP-03 §Pre-release policy cap: odd for clean majorities, >= 3 for redundancy, <= 7.")

(defstruct deposit
  id descriptor (balance 0) (locked-balance 0)
  (fees (op:make-fees)) (transfer-fees (op:make-transfer-fees))
  (receive-requires-sig nil) fee-change-after-blocks fee-change-notice-blocks fee-change-limit-bps
  (opened-at-block 0) pending-fee-change (last-fee-assessment 0)
  (last-activity-block 0) (last-received-block 0)
  (last-signed-activity 0)                     ; DEP-20 §8: latest depositor-signed op's height
  (seen-nonces '()))

(defun deposit-available-balance (d) (max 0 (- (deposit-balance d) (deposit-locked-balance d))))

(defstruct (quorum-member (:conc-name member-))
  pubkey (ledger-id "") min-fee-bps min-fee-fixed max-fee-period membership-until min-collateral-bps
  dispute-response-blocks dispute-arm-blocks service-response-blocks max-transfer-timeout-blocks
  max-descriptor-bytes compensation-bps compensation-deposit-id compensation-frequency-blocks
  dormancy-blocks dormancy-notice-blocks
  member-response)

(defstruct (ledger (:constructor %make-ledger) (:copier nil))   ; COPY-LEDGER is the deep copy below
  id (genesis-block 0) operator-key (reserves-key "")
  (reserves-amount 0) (collateral-amount 0)
  (quorum-state :pre-quorum) (quorum-members '()) (next-quorum-members '()) quorum-expiry
  (active-ruleset nil)
  (deposits (make-hash-table :test #'equalp))
  (pending-transfers (make-hash-table :test #'equalp))
  (open-invoice-locks (make-hash-table :test #'equalp))
  (pending-withdrawals (make-hash-table :test #'equalp))
  (credited-payments (make-hash-table :test #'equalp))
  (fees-accumulated 0)
  (sequence -1)                     ; sequence of the last applied update; -1 = empty
  (chain-tip (make-array 32 :element-type '(unsigned-byte 8)))
  (joined-quorums '())
  (dispute-state :normal)
  ;; DEP-20 §3: request id (chain_hash of the ExitRequest update) -> plist
  (pending-exits (make-hash-table :test #'equalp))
  (vault-current-p nil)             ; a QuorumBegin vault the next QuorumBegin rotates
  (reference-feerate nil)           ; the governing QuorumBegin's reference_feerate_sat_vb (DEP-03)
  (dormancy-blocks 26280) (dormancy-notice-blocks 2016)   ; DEP-20 §8, from the promoted members
  (dormancy-notice nil)             ; outstanding DormancyNotice: (:height h :rotation-height r [:manifest :receiver :spk :total :premium])
  (dormancy-accept nil)             ; receiver: our DormancyAccept (:hash :spk :total :expires :premium-deposit :resolved :outpoint)
  (confiscation-txid nil)           ; DEP-06: the confiscation a custody change followed (DisputeAcquire)
  (quorum-at-fork '())              ; the quorum at the fork point (DisputeEnter), which a fork's records are judged by
  (arm-commitment nil))             ; the commitment_hash of this fork's DisputeArmed, which a re-arm must repeat (DEP-03)

(defun make-ledger () (%make-ledger))

(defun find-deposit (ledger id)
  (or (gethash id (ledger-deposits ledger)) (fail :deposit-not-found (bytes->hex id))))

(defun total-obligations (ledger)
  (loop for d being the hash-values of (ledger-deposits ledger) sum (deposit-balance d)))

(defun majority-threshold (n) (1+ (floor n 2)))

(defun %credit (d amount) (incf (deposit-balance d) amount))
(defun %check-obligation-room (ledger amount)
  "DEP-05: refuse a credit that would push total obligations above reserves.
   Pre-quorum ledgers (reserves 0, no QuorumBegin yet) are exempt: nothing is
   bonded and nothing can be cosigned on them anyway."
  (when (and (plusp (ledger-reserves-amount ledger))
             (> (+ (total-obligations ledger) amount) (ledger-reserves-amount ledger)))
    (fail :over-obligation (format nil "credit ~a would take obligations ~a over reserves ~a"
                                   amount (total-obligations ledger) (ledger-reserves-amount ledger)))))
(defun %lock (d amount)
  (when (< (deposit-available-balance d) amount)
    (fail :insufficient-balance (format nil "available ~a, need ~a" (deposit-available-balance d) amount)))
  (incf (deposit-locked-balance d) amount))
(defun %unlock (d amount) (setf (deposit-locked-balance d) (max 0 (- (deposit-locked-balance d) amount))))
(defun %fulfill (d amount)
  (%unlock d amount)
  (setf (deposit-balance d) (max 0 (- (deposit-balance d) amount))))
(defun %charge-fixed (ledger d)
  "On a failed lock the deposit pays its fixed transfer fee, capped at its balance."
  (let ((charged (min (op:transfer-fees-fixed-msats (deposit-transfer-fees d)) (deposit-balance d))))
    (decf (deposit-balance d) charged)
    (incf (ledger-fees-accumulated ledger) charged)))

(defvar *block-height* 0 "The block height of the update being applied (for descriptor snapshots).")
(defvar *update-seq* 0 "The sequence of the update being applied.")

(defparameter +exit-cutoff-margin+ 144 "DEP-20 §3 exit_cutoff_margin_blocks (DEP-11 default).")
(defparameter exit-dust-msats 330000 "DEP-20 §3: requests below 330 sats are carried, not settled.")

(defun rotation-feerate (ledger)
  "DEP-03: the governing QuorumBegin's reference feerate, or 2 sat/vB when none is recorded."
  (or (ledger-reference-feerate ledger) 2))

(defun spk-type (spk)
  "DEP-20 §3 Exit addresses: the standard output types an exit, spin-out or migration may pay —
   :p2pkh :p2sh :p2wpkh :p2wsh :p2tr — or NIL for anything else (bare scripts, other witness
   versions, OP_RETURN, malformed lengths), which would not relay."
  (let ((n (length spk)))
    (cond ((and (= n 25) (= (aref spk 0) #x76) (= (aref spk 1) #xa9) (= (aref spk 2) 20) (= (aref spk 23) #x88) (= (aref spk 24) #xac)) :p2pkh)
          ((and (= n 23) (= (aref spk 0) #xa9) (= (aref spk 1) 20) (= (aref spk 22) #x87)) :p2sh)
          ((and (= n 22) (= (aref spk 0) 0) (= (aref spk 1) 20)) :p2wpkh)
          ((and (= n 34) (= (aref spk 0) 0) (= (aref spk 1) 32)) :p2wsh)
          ((and (= n 34) (= (aref spk 0) #x51) (= (aref spk 1) 32)) :p2tr))))

(defun dust-floor-sats (spk)
  "DEP-20 §3: the smallest output to SPK that relays — Bitcoin Core's dust threshold at the
   3 sat/vB dust relay feerate: P2PKH 546, P2SH 540, P2WPKH 294, P2WSH 330, P2TR 330.  NIL if
   SPK is not a standard exit type."
  (case (spk-type spk) (:p2pkh 546) (:p2sh 540) (:p2wpkh 294) ((:p2wsh :p2tr) 330)))

(defun standard-output-p (spk sats)
  "SPK is a standard exit type and SATS clears its dust floor."
  (let ((f (dust-floor-sats spk))) (and f (>= sats f))))

(defun exit-cost (address feerate)
  "DEP-20 §3: an exit output's own marginal cost, feerate x (9 + len(spk)) sats."
  (* feerate (+ 9 (length address))))

(defun dormancy-amount-msats (ledger)
  "DEP-20 §8: 10 x 34 vB x the governing feerate, in msat."
  (* 10 34 (rotation-feerate ledger) 1000))

(defun pk-key-path-spk (descriptor)
  "DEP-20 §8: a pk(K) deposit's address, the key-path P2TR with K's x-only key internal; else NIL."
  (let ((start (search "pk(" descriptor)))
    (when (and start (= start 0) (= (length descriptor) 70) (char= (char descriptor 69) #\)))
      (let ((k (ignore-errors (hex->bytes (subseq descriptor 3 69)))))
        (and k (= (length k) 33) (member (aref k 0) '(2 3))
             (values (tr::taproot-output-spk-from-root (subseq k 1 33) (make-array 0 :element-type '(unsigned-byte 8)))))))))

(defun quorum-backed-accept-p (accept qb-update receiver)
  "DEP-20 §8.3 (L4): QB-UPDATE is a QuorumBegin signed by RECEIVER on the accept's ledger at a lower
   sequence, cosigned by a strict majority of its quorum_members, and ACCEPT carries valid
   cosignatures from a strict majority of those members.  (values ok reason)."
  (let* ((qb (ignore-errors (op:decode-operation (up:update-message qb-update))))
         (members (and qb (op:field qb :quorum-members))))
    (flet ((majority-of (u)
             (let ((seen '()))
               (dolist (c (up:update-cosignatures u))
                 (when (and (member (up:cosig-pubkey c) members :test #'equalp)
                            (not (member (up:cosig-pubkey c) seen :test #'equalp))
                            (up:verify-cosignature u c))
                   (push (up:cosig-pubkey c) seen)))
               (>= (length seen) (majority-threshold (length members))))))
      (cond ((not (and qb (eq (op:operation-type qb) :quorum-begin) members))
             (values nil "receiver_quorum_begin is not a QuorumBegin"))
            ((not (and (equalp (up:update-operator-id qb-update) receiver) (up:verify-operator-signature qb-update)))
             (values nil "receiver_quorum_begin is not signed by the receiver"))
            ((not (and (equalp (up:update-ledger-id qb-update) (up:update-ledger-id accept))
                       (< (up:update-seq qb-update) (up:update-seq accept))))
             (values nil "receiver_quorum_begin is not an earlier update of the accept's ledger"))
            ((not (majority-of qb-update)) (values nil "receiver_quorum_begin lacks its quorum's majority"))
            ((not (majority-of accept)) (values nil "the accept lacks a majority of the receiver's quorum"))
            (t (values t nil))))))

(defun dormancy-cost (ledger) "An addressable spin-out's output cost, sats." (* (rotation-feerate ledger) (+ 9 34)))

(defun dormancy-spin-outs (ledger cutoff)
  "DEP-20 §8.2: if a rotating QuorumBegin with exit_cutoff_height CUTOFF consumes the outstanding notice, the
   addressable bucket deposits at or above the floor, ascending deposit id, as
   ((deposit-id balance spk) ...); else NIL."
  (let ((n (ledger-dormancy-notice ledger)))
    (when (and n (ledger-vault-current-p ledger) (>= cutoff (getf n :rotation-height)))
      (let ((bound (- (getf n :height) (ledger-dormancy-blocks ledger))) (floor-msat (dormancy-amount-msats ledger))
            (pending (let ((h (make-hash-table :test #'equalp)))
                       (maphash (lambda (k e) (declare (ignore k)) (setf (gethash (getf e :deposit-id) h) t)) (ledger-pending-exits ledger))
                       h))
            (out '()))
        (maphash (lambda (id d)
                   (let ((spk (pk-key-path-spk (deposit-descriptor d))))
                     (when (and spk (plusp (deposit-balance d)) (zerop (deposit-locked-balance d))
                                (not (gethash id pending))
                                (<= (deposit-last-signed-activity d) bound)
                                (>= (deposit-balance d) floor-msat))
                       (push (list id (deposit-balance d) spk) out))))
                 (ledger-deposits ledger))
        (sort out #'bytes< :key #'first)))))

(defun dormancy-offer-entries (ledger height)
  "DEP-20 §8.3: the dormant deposits a spin-out would not pay at HEIGHT (no key-path address, or
   below the floor), ascending deposit id, as manifest entries."
  (let ((bound (- height (ledger-dormancy-blocks ledger))) (floor-msat (dormancy-amount-msats ledger))
        (pending (let ((h (make-hash-table :test #'equalp)))
                   (maphash (lambda (k e) (declare (ignore k)) (setf (gethash (getf e :deposit-id) h) t)) (ledger-pending-exits ledger))
                   h))
        (out '()))
    (maphash (lambda (id d)
               (when (and (plusp (deposit-balance d)) (zerop (deposit-locked-balance d)) (not (gethash id pending))
                          (<= (deposit-last-signed-activity d) bound)
                          (or (null (pk-key-path-spk (deposit-descriptor d))) (< (deposit-balance d) floor-msat)))
                 (push (list :deposit-id id :amount (deposit-balance d) :fees (deposit-fees d) :descriptor (deposit-descriptor d)) out)))
             (ledger-deposits ledger))
    (sort out #'bytes< :key (lambda (e) (getf e :deposit-id)))))

(defvar *uncredited-proof-checker* nil
  "Set by the fraud package: (lambda (ledger proof-json-bytes)) signalling unless the bytes are an
   UncreditedOnchainPayment with offer evidence against LEDGER whose descriptor hashes to its
   deposit_id and whose offer cosignature is by a member of LEDGER's quorum (DEP-06).")

(defun offer-cosign-digest (ledger-id-hex offer-id deposit-id operator33 address deadline member-ledger-hash)
  "DEP-10 offer cosign digest: ledger_id the hex text, the offer's deposit_id (16 bytes),
   len(address) one byte, deadline LE32."
  (let ((tag (sha256 (ascii->bytes "deposits/offer_cosign"))))
    (sha256 (cat tag tag (ascii->bytes ledger-id-hex) offer-id deposit-id (up:x-only operator33)
                 (octets (length address)) (ascii->bytes address) (int->le deadline 4) member-ledger-hash))))

(defun segwit-address-spk (address)
  "The scriptPubKey of a segwit ADDRESS (any network: the hrp is read off the address)."
  (let ((hrp (subseq address 0 (position #\1 address :from-end t))))
    (multiple-value-bind (witver program) (cl-consensus.encoding:segwit-decode address hrp)
      (cat (octets (if (zerop witver) 0 (+ #x50 witver)) (length program)) program))))

(defun consumed-notice-id (ledger cutoff)
  "DEP-20 §8.3: the id (SHA256 of its operation encoding) of the notice a rotating QuorumBegin
   with CUTOFF consumes, or NIL."
  (let ((n (ledger-dormancy-notice ledger)))
    (and n (ledger-vault-current-p ledger) (>= cutoff (getf n :rotation-height)) (getf n :id))))

(defconstant +accept-grace-blocks+ 6 "DEP-20 §8.3: an accept stays outstanding to expires_at_height + 6.")

(defun accept-outstanding-p (ledger height)
  "DEP-20 §8.3 receiver: an accept not yet resolved, below expires_at_height + 6 at HEIGHT."
  (let ((a (ledger-dormancy-accept ledger)))
    (and a (not (getf a :resolved)) (< height (+ (getf a :expires) +accept-grace-blocks+)))))

(defun migration-evidence (ledger notice-bytes qb-bytes)
  "DEP-20 §8.3 / DEP-06: a source's signed DormancyNotice carrying an accept of LEDGER and the
   source QuorumBegin that consumed it (same operator and ledger, later, naming the notice).
   (values notice qb qb-update to-us), TO-US when QB migrates to the accept's signer; or a
   ledger error."
  (multiple-value-bind (nu notice qu qb)
      (handler-case (let* ((nu (up:decode-update notice-bytes)) (qu (up:decode-update qb-bytes)))
                      (values nu (op:decode-operation (up:update-message nu)) qu (op:decode-operation (up:update-message qu))))
        (error () (fail :migration-evidence "the source updates do not decode")))
    (let ((acc (and (eq (op:operation-type notice) :dormancy-notice) (op:field notice :dormancy-accept)
                    (ignore-errors (up:decode-update (op:field notice :dormancy-accept))))))
      (unless (and acc (up:verify-operator-signature nu) (equalp (up:update-ledger-id acc) (ledger-id ledger)))
        (fail :migration-evidence "the notice does not carry this ledger's accept"))
      (unless (and (eq (op:operation-type qb) :quorum-begin) (up:verify-operator-signature qu)
                   (equalp (up:update-operator-id qu) (up:update-operator-id nu))
                   (equalp (up:update-ledger-id qu) (up:update-ledger-id nu))
                   (> (up:update-seq qu) (up:update-seq nu))
                   (equalp (op:field qb :consumed-notice) (sha256 (up:update-message nu))))
        (fail :migration-evidence "the QuorumBegin did not consume that notice"))
      (values notice qb qu (and (op:field qb :migration-manifest)
                                (equalp (op:field qb :migration-receiver) (up:update-operator-id acc)))))))

(defconstant +confiscation-feerate+ 2
  "The confiscation's feerate (both implementations build it at the DEP-03 default).")

(defun owed-spk-sats (e &optional (feerate +confiscation-feerate+))
  "DEP-06: the splice-out a confiscation pays an owed entry E — (values spk sats) when its
   descriptor is pk(K) and floor(amount/1000) - feerate x 43 is at least 330; else NIL (residue)."
  (let ((spk (pk-key-path-spk (getf e :descriptor))) (sats (- (floor (getf e :amount) 1000) (* feerate 43))))
    (when (and spk (>= sats 330)) (values spk sats))))

(defun unpaid-entries (ledger entries tx-bytes)
  "The ENTRIES no output of the confiscation TX-BYTES (whose txid the ledger recorded) paid."
  (let ((tx (handler-case (cl-consensus.tx:parse-tx (cl-consensus.wire:make-reader tx-bytes))
              (error () (fail :migration-credit "confiscation_tx does not decode")))))
    (unless (equalp (cl-consensus.tx:tx-txid tx) (ledger-confiscation-txid ledger))
      (fail :migration-credit "confiscation_tx is not the recorded confiscation"))
    (let ((outs (mapcar (lambda (o) (cons (cl-consensus.tx:txout-script o) (cl-consensus.tx:txout-value o))) (cl-consensus.tx:tx-outputs tx))))
      (remove-if (lambda (e) (multiple-value-bind (spk sats) (owed-spk-sats e)
                               (and spk (find-if (lambda (o) (and (equalp (car o) spk) (= (cdr o) sats))) outs))))
                 entries))))

(defun %open-migrated-deposit (ledger e)
  "DEP-20 §8.3: a migrated deposit opened on the receiver with its descriptor and fee schedule."
  (let ((d (make-deposit :id (getf e :deposit-id) :descriptor (getf e :descriptor) :opened-at-block *block-height*
                         :last-fee-assessment *block-height* :last-activity-block *block-height*
                         :last-signed-activity *block-height*)))
    (when (getf e :fees) (setf (deposit-fees d) (getf e :fees)))
    (setf (gethash (getf e :deposit-id) (ledger-deposits ledger)) d)))

(defun dormancy-migration (ledger cutoff nspins &optional (height *block-height*))
  "DEP-20 §8.3: at a rotating QuorumBegin with exit_cutoff_height CUTOFF that consumes a notice
   naming a receiver, the migrated deposits (manifest-shaped plists, ascending id, capped by the
   accept's total) and the output: (values entries spk sats).  NIL if no migration."
  (let ((n (ledger-dormancy-notice ledger)))
    (when (and n (getf n :receiver) (ledger-vault-current-p ledger) (>= cutoff (getf n :rotation-height))
               ;; nothing migrates at or past the accept's expiry
               (< height (getf n :expires)))
      (let* ((bound (- (getf n :height) (ledger-dormancy-blocks ledger)))
             (spun (mapcar #'first (dormancy-spin-outs ledger cutoff)))
             (offered (mapcar (lambda (e) (getf e :deposit-id)) (getf n :manifest)))
             (pending (let ((h (make-hash-table :test #'equalp)))
                        (maphash (lambda (k e) (declare (ignore k)) (setf (gethash (getf e :deposit-id) h) t)) (ledger-pending-exits ledger))
                        h))
             (cands '()) (total 0) (premium (or (getf n :premium) 0)) (out '()))
        (declare (ignore nspins))
        (maphash (lambda (id d)
                   (when (and (plusp (deposit-balance d)) (zerop (deposit-locked-balance d)) (not (gethash id pending))
                              (<= (deposit-last-signed-activity d) bound)
                              (not (member id spun :test #'equalp)) (member id offered :test #'equalp))
                     (push d cands)))
                 (ledger-deposits ledger))
        (dolist (d (sort cands #'bytes< :key #'deposit-id))
          (when (<= (+ total (deposit-balance d) premium) (getf n :total))
            (incf total (deposit-balance d))
            (push (list :deposit-id (deposit-id d) :amount (deposit-balance d) :fees (deposit-fees d)
                        :descriptor (deposit-descriptor d))
                  out)))
        ;; Below its dust floor the output would not relay: nothing migrates.
        (when (and out (standard-output-p (getf n :spk) (floor (+ total premium) 1000)))
          (values (nreverse out) (getf n :spk) (floor (+ total premium) 1000)))))))

(defun due-exits (ledger height cutoff)
  "DEP-20 §3 due set: pending requests appended at block_height <= CUTOFF whose output clears the
   dust floor of its address type (dust-floor-sats) after its own cost, unexpired, in append
   order, as a list of (id . plist)."
  (let ((due '()) (f (rotation-feerate ledger)))
    (maphash (lambda (id e)
               (when (and (<= (getf e :block-height) cutoff)
                          (standard-output-p (getf e :exit-address)
                                             (- (floor (getf e :amount) 1000) (exit-cost (getf e :exit-address) f)))
                          (or (null (getf e :expires-at)) (> (getf e :expires-at) cutoff)))
                 (push (cons id e) due)))
             (ledger-pending-exits ledger))
    (sort due #'< :key (lambda (c) (getf (cdr c) :seq)))))

(defun %release-expired-exits (ledger height)
  (let ((gone '()))
    (maphash (lambda (id e) (when (and (getf e :expires-at) (<= (getf e :expires-at) height)) (push (cons id e) gone)))
             (ledger-pending-exits ledger))
    (loop for (id . e) in gone
          do (let ((d (gethash (getf e :deposit-id) (ledger-deposits ledger))))
               (when d (%unlock d (getf e :amount))))
             (remhash id (ledger-pending-exits ledger)))))

(defun %settle-exits (ledger o)
  "DEP-20 §3 settlement on a QuorumBegin: EXIT-OUTPUTS must be exactly the due set (rotating
   QuorumBegins only); each entry's deposit is debited and its request removed."
  (let* ((entries (op:field o :exit-outputs))
         (h *block-height*)
         (cutoff (or (op:field o :exit-cutoff-height) (- h +exit-cutoff-margin+))))
    (unless (ledger-vault-current-p ledger)
      (when entries (fail :exit-outputs "a QuorumBegin with no current vault settles no exits"))
      (return-from %settle-exits))
    (unless (<= (- h +exit-cutoff-margin+) cutoff h)
      (fail :exit-cutoff (format nil "cutoff ~a outside [~a, ~a]" cutoff (- h +exit-cutoff-margin+) h)))
    (let ((due (due-exits ledger h cutoff)))
      (unless (= (length due) (length entries))
        (fail :exit-outputs (format nil "~a due exits, ~a settled" (length due) (length entries))))
      (loop for (id . e) in due for (dep amount vout) in entries for i from 1
            do (unless (and (equalp dep (getf e :deposit-id)) (= amount (getf e :amount)) (= vout i))
                 (fail :exit-outputs (format nil "entry ~a does not match due request ~a" i (bytes->hex id))))
               (let ((d (find-deposit ledger dep)))
                 (%unlock d amount)
                 (setf (deposit-balance d) (max 0 (- (deposit-balance d) amount))))
               (remhash id (ledger-pending-exits ledger))))))

(defun %touch (ledger o)
  "Record activity heights on the deposits an operation moves."
  (dolist (name '(:deposit-id :source-deposit-id))
    (let ((d (and (op:field o name) (gethash (op:field o name) (ledger-deposits ledger)))))
      (when d (setf (deposit-last-activity-block d) *block-height*))))
  (when (member (op:operation-type o) '(:invoice-credit :onchain-credit))
    (let ((d (gethash (op:field o :deposit-id) (ledger-deposits ledger))))
      (when d (setf (deposit-last-received-block d) *block-height*))))
  ;; DEP-20 §8 signed activity: depositor-signed operations only.
  (let ((spender (case (op:operation-type o)
                   ((:invoice-lock :onchain-lock :deposit-key-rotate :exit-request :exit-cancel) (op:field o :deposit-id))
                   (:transfer-lock (op:field o :source-deposit-id)))))
    (when spender
      (let ((d (gethash spender (ledger-deposits ledger))))
        (when d (setf (deposit-last-signed-activity d) *block-height*))))))

(defun completion-satisfied-p (script witness)
  "DEP-09: WITNESS (one element) satisfies a transfer's completion SCRIPT: sha256(H) by a
   preimage of H, pointlock(P) by a scalar s with s·G = P."
  (let ((arg (and (position #\( script) (position #\) script) (subseq script (1+ (position #\( script)) (position #\) script)))))
    (and witness (= 1 (length witness)) arg
         (cond ((search "sha256(" script) (equalp (sha256 (first witness)) (hex->bytes arg)))
               ((search "pointlock(" script)
                (let ((s (be->int (first witness))))
                  (and (= 32 (length (first witness))) (< 0 s secp256k1-fast:*secp256k1-n*)
                       (equalp (up:public-scalar-point s) (hex->bytes arg)))))
               (t nil)))))

(defun fees-due (d height)
  "DEP-07: the custody fee deposit D owes at HEIGHT — one frequency_blocks period at most, none
   before the window has elapsed: annualized_msats·b/52560 + balance·annualized_bps·b/525600000,
   each floored, b = min(height − last_fee_assessment, frequency_blocks)."
  (let* ((fees (deposit-fees d)) (freq (op:fees-frequency-blocks fees))
         (elapsed (- height (deposit-last-fee-assessment d))))
    (if (or (<= elapsed 0) (< elapsed freq))
        0
        (let ((b (min elapsed freq)))
          (+ (floor (* (op:fees-annualized-msats fees) b) 52560)
             (floor (* (deposit-balance d) (op:fees-annualized-bps fees) b) (* 52560 10000)))))))

(defun apply-operation (ledger o)
  "Fold one operation into LEDGER, or signal LEDGER-ERROR leaving it untouched
   in the ways that matter (callers replaying a chain treat any error as fatal)."
  (prog1 (%apply-operation ledger o) (%touch ledger o)))

(defun %apply-operation (ledger o)
  (flet ((f (name) (op:field o name)))
    (ecase (op:operation-type o)
      (:ledger-open
       ;; DEP-18: a LedgerOpen may name the ruleset in force before its first QuorumBegin.
       (when (and (f :protocol-version) (not (member (f :protocol-version) +rulesets+ :test #'equal)))
         (fail :unknown-ruleset (format nil "LedgerOpen protocol_version ~s is not a known ruleset" (f :protocol-version))))
       (setf (ledger-active-ruleset ledger) (f :protocol-version))
       (setf (ledger-operator-key ledger) (f :operator-id)
             (ledger-reserves-key ledger) (f :reserves-id)
             (ledger-genesis-block ledger) (f :genesis-block)
             (ledger-id ledger) (op:compute-ledger-id (f :operator-id) (f :reserves-id) (f :genesis-block))
             (ledger-reserves-amount ledger) (f :reserves-amount)
             (ledger-collateral-amount ledger) (f :collateral-amount)))
      (:quorum-begin
       (let* ((declared (f :quorum-members))
              (promoted (remove-if-not (lambda (m) (member (member-pubkey m) declared :test #'equalp))
                                       (ledger-next-quorum-members ledger))))
         ;; DEP-03 pre-release size policy, enforced by every validator.
         (unless (member (length declared) +valid-quorum-sizes+)
           (fail :quorum-size-invalid (format nil "Q=~a not in ~a" (length declared) +valid-quorum-sizes+)))
         (unless (member (f :protocol-version) +rulesets+ :test #'equal)
           (fail :unknown-ruleset (format nil "QuorumBegin protocol_version ~s is not a known ruleset" (f :protocol-version))))
         ;; DEP-05 "Collateral floor": collateral is at least the strictest member's share of
         ;; the vault, never below 20%.  Collateral is a floor, not a cap on credits.
         ;; DEP-05 "Quorum expiry": the operator may shorten a member's commitment, never extend it.
         (let ((ceiling (quorum-expiry-ceiling promoted)))
           (when (and ceiling (f :quorum-expiry) (> (f :quorum-expiry) ceiling))
             (fail :quorum-expiry-exceeds-commitment
                   (format nil "quorum_expiry ~a exceeds the shortest member commitment ~a" (f :quorum-expiry) ceiling))))
         ;; DEP-05 "Born expired": a quorum past expiry from its first update buys nothing.
         ;; Gated (DEP-18): judged under the ruleset this QuorumBegin names.
         (when (born-expired-p (f :protocol-version) (f :quorum-expiry) *block-height*)
           (fail :quorum-expiry-not-after-block
                 (format nil "quorum_expiry ~a is not after the QuorumBegin's block_height ~a" (f :quorum-expiry) *block-height*)))
         (let ((floor (collateral-floor-bps promoted)))
           (when (collateral-below-floor-p (f :protocol-version) (f :amount) (f :collateral-amount) floor)
             (fail :collateral-below-floor
                   (format nil "collateral ~a is below ~a bps of the vault (reserves ~a)" (f :collateral-amount) floor (f :amount)))))
         (let* ((cutoff (or (op:field o :exit-cutoff-height) (- *block-height* +exit-cutoff-margin+)))
                (spins (dormancy-spin-outs ledger cutoff))
                (nexits (length (op:field o :exit-outputs))))
           (%settle-exits ledger o)
           (let ((entries (op:field o :dormancy-outputs)))
             (unless (and (= (length spins) (length entries))
                          (loop for (id bal) in spins for (eid eamt vout) in entries for j from 1
                                always (and (equalp id eid) (= bal eamt) (= vout (+ nexits j)))))
               (fail :dormancy-outputs (format nil "~a spin-outs due, ~a recorded or mismatched" (length spins) (length entries))))
             (loop for (id) in spins do (setf (deposit-balance (find-deposit ledger id)) 0))
             ;; DEP-20 §8.3 source: the migration must be exactly the rule's.
             (multiple-value-bind (mentries) (dormancy-migration ledger cutoff (length spins))
               (let ((rec (op:field o :migration-manifest)))
                 (unless (and (= (length mentries) (length rec))
                              (loop for m in mentries for r in rec
                                    always (and (equalp (getf m :deposit-id) (getf r :deposit-id)) (= (getf m :amount) (getf r :amount))))
                              (or (null mentries)
                                  (and (equalp (op:field o :migration-receiver) (getf (ledger-dormancy-notice ledger) :receiver))
                                       (eql (op:field o :migration-vout) (+ 1 nexits (length spins))))))
                   (fail :migration-manifest (format nil "~a deposits migrate, ~a recorded or mismatched" (length mentries) (length rec))))
                 (dolist (m mentries) (setf (deposit-balance (find-deposit ledger (getf m :deposit-id))) 0))))
             ;; DEP-20 §8.3 source: a QuorumBegin consuming a notice names it.
             (let ((cid (consumed-notice-id ledger cutoff)))
               (unless (equalp cid (op:field o :consumed-notice))
                 (fail :consumed-notice (if cid "a QuorumBegin consuming a notice must record consumed_notice"
                                            "consumed_notice names no notice this QuorumBegin consumes"))))
             ;; DEP-20 §8.3 receiver: no rotation while an accept is outstanding.
             (when (and (ledger-vault-current-p ledger) (accept-outstanding-p ledger *block-height*))
               (fail :migration-freeze "a receiver may not rotate while its DormancyAccept is outstanding"))
             ;; DEP-20 §8.3 receiver: a credited migration must be spliced in at this rotation.
             (let ((a (ledger-dormancy-accept ledger)))
               (when (and a (getf a :outpoint) (ledger-vault-current-p ledger))
                 (let ((sp (op:field o :splice-in-outpoint)))
                   (unless (and sp (equalp (subseq sp 0 32) (car (getf a :outpoint))) (= (be->int sp :start 32) (cdr (getf a :outpoint))))
                     (fail :migration-splice "a credited migration output must be spliced in at this rotation"))
                   (setf (ledger-dormancy-accept ledger) nil))))
             (when (and (ledger-dormancy-notice ledger) (ledger-vault-current-p ledger)
                        (>= cutoff (getf (ledger-dormancy-notice ledger) :rotation-height)))
               (setf (ledger-dormancy-notice ledger) nil))))
         (%release-expired-exits ledger *block-height*)   ; after settlement (DEP-20 §3 Expiry)
         (setf (ledger-reference-feerate ledger) (f :reference-feerate)
               ;; DEP-20 §8: the largest declared value applies; the default only when none is declared.
               (ledger-dormancy-blocks ledger) (let ((v (remove nil (mapcar #'member-dormancy-blocks promoted))))
                                                 (if v (reduce #'max v) 26280))
               (ledger-dormancy-notice-blocks ledger) (let ((v (remove nil (mapcar #'member-dormancy-notice-blocks promoted))))
                                                        (if v (reduce #'max v) 2016)))
         (setf (ledger-next-quorum-members ledger) '()
               (ledger-vault-current-p ledger) t
               (ledger-reserves-key ledger) (f :reserves-id)
               (ledger-reserves-amount ledger) (f :amount)
               (ledger-collateral-amount ledger) (f :collateral-amount)
               (ledger-quorum-expiry ledger) (f :quorum-expiry)
               (ledger-active-ruleset ledger) (f :protocol-version)
               (ledger-quorum-members ledger) promoted
               (ledger-quorum-state ledger) :active)))
      (:deposit-open
       (let ((id (f :deposit-id)))
         (when (gethash id (ledger-deposits ledger)) (fail :deposit-exists))
         (let ((d (make-deposit :id id :descriptor (f :descriptor) :opened-at-block *block-height*
                                :last-fee-assessment (if (zerop *block-height*) (ledger-genesis-block ledger) *block-height*)
                                :last-activity-block *block-height* :last-signed-activity *block-height*)))
           (when (f :fees) (setf (deposit-fees d) (f :fees)))
           (when (f :transfer-fees) (setf (deposit-transfer-fees d) (f :transfer-fees)))
           (setf (deposit-receive-requires-sig d) (f :receive-requires-sig)
                 (deposit-fee-change-after-blocks d) (f :fee-change-after-blocks)
                 (deposit-fee-change-notice-blocks d) (f :fee-change-notice-blocks)
                 (deposit-fee-change-limit-bps d) (f :fee-change-limit-bps))
           (setf (gethash id (ledger-deposits ledger)) d))))
      (:deposit-close
       (let ((d (find-deposit ledger (f :deposit-id))))
         (when (plusp (deposit-balance d)) (fail :non-zero-balance (deposit-balance d)))
         (remhash (f :deposit-id) (ledger-deposits ledger))))
      (:fee-change
       (let ((d (gethash (f :deposit-id) (ledger-deposits ledger))))
         (when d (setf (deposit-pending-fee-change d) (cons (f :new-fees) (f :effective-block))))))
      (:deposit-key-rotate
       (let ((d (gethash (f :deposit-id) (ledger-deposits ledger))))
         (when d
           (setf (deposit-descriptor d) (f :new-descriptor))
           (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d)))))
      (:invoice-credit
       (when (gethash (f :payment-hash) (ledger-credited-payments ledger))
         (fail :duplicate-credit (bytes->hex (f :payment-hash))))
       (let ((d (find-deposit ledger (f :deposit-id))))
         (%credit d (f :amount))
         (setf (gethash (f :payment-hash) (ledger-credited-payments ledger)) t)))
      (:invoice-lock
       (let* ((d (find-deposit ledger (f :deposit-id))) (fee (or (f :fee) 0)))
         (%lock d (+ (f :amount) fee))
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (setf (gethash (f :payment-id) (ledger-open-invoice-locks ledger))
               (list :deposit-id (f :deposit-id) :amount (f :amount) :fee fee
                     :lock-sequence (f :sequence-number) :timeout-height (f :timeout-height)
                     :witness (f :witness)))))
      (:invoice-fail
       (let* ((lock (gethash (f :payment-id) (ledger-open-invoice-locks ledger)))
              (d (find-deposit ledger (f :deposit-id))))
         ;; FINDINGS L6: an operator-only op, so checked here by every member and replica.
         (unless (and lock (equalp (getf lock :deposit-id) (f :deposit-id)))
           (fail :invoice-fail "names no open invoice lock of this deposit"))
         (%unlock d (+ (or (getf lock :amount) 0) (or (getf lock :fee) 0)))
         (%charge-fixed ledger d)
         (remhash (f :payment-id) (ledger-open-invoice-locks ledger))))
      (:invoice-fulfill
       (let* ((lock (gethash (f :payment-id) (ledger-open-invoice-locks ledger)))
              (fee (or (getf lock :fee) 0))
              (d (find-deposit ledger (f :deposit-id))))
         (unless (and lock (equalp (getf lock :deposit-id) (f :deposit-id)))
           (fail :invoice-fulfill "names no open invoice lock of this deposit"))
         (unless (eql (f :amount) (getf lock :amount))
           (fail :invoice-fulfill (format nil "amount ~a is not the lock's ~a" (f :amount) (getf lock :amount))))
         (unless (and (f :preimage) (equalp (sha256 (f :preimage)) (f :payment-id)))
           (fail :invoice-fulfill "preimage does not open the payment hash"))
         (%fulfill d (+ (f :amount) fee))
         (remhash (f :payment-id) (ledger-open-invoice-locks ledger))
         (incf (ledger-fees-accumulated ledger) fee)))
      (:onchain-credit
       ;; DEP-05 §Obligation Limits: total obligations (the sum of balances) must
       ;; not exceed the reserves amount.  Unchecked until the red team read this
       ;; arm (docs/REDTEAM.md #1): a cl cosigner would sign an operator crediting
       ;; itself any amount.  (The reference additionally caps by collateral.)
       ;; An outstanding DormancyAccept reserves its total (DEP-20 §8.3).
       (%check-obligation-room ledger (+ (f :amount) (if (accept-outstanding-p ledger *block-height*)
                                                         (getf (ledger-dormancy-accept ledger) :total) 0)))
       (%credit (find-deposit ledger (f :deposit-id)) (f :amount)))
      (:onchain-lock
       (let ((d (find-deposit ledger (f :deposit-id))))
         (%lock d (+ (f :amount) (f :fee-sats)))
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (setf (gethash (f :withdrawal-id) (ledger-pending-withdrawals ledger))
               (list :deposit-id (f :deposit-id) :amount (f :amount) :fee-sats (f :fee-sats)
                     :destination-address (f :destination-address)))))
      (:onchain-fail
       (find-deposit ledger (f :deposit-id))
       (let ((p (gethash (f :withdrawal-id) (ledger-pending-withdrawals ledger))))
         (remhash (f :withdrawal-id) (ledger-pending-withdrawals ledger))
         (when p
           (let ((d (gethash (getf p :deposit-id) (ledger-deposits ledger))))
             (when d
               (%unlock d (+ (getf p :amount) (getf p :fee-sats)))
               (%charge-fixed ledger d))))))
      (:onchain-fulfill
       (find-deposit ledger (f :deposit-id))
       (let ((p (gethash (f :withdrawal-id) (ledger-pending-withdrawals ledger))))
         (remhash (f :withdrawal-id) (ledger-pending-withdrawals ledger))
         (when p
           (let ((d (gethash (getf p :deposit-id) (ledger-deposits ledger))))
             (when d (%fulfill d (+ (getf p :amount) (getf p :fee-sats))))))))
      (:fee-collect
       (let ((d (gethash (f :deposit-id) (ledger-deposits ledger))))
         (when d
           (let ((pending (deposit-pending-fee-change d)))
             (when (and pending (>= (f :block-height) (cdr pending)))
               (setf (deposit-fees d) (car pending) (deposit-pending-fee-change d) nil)))
           (setf (deposit-balance d) (max 0 (- (deposit-balance d) (f :amount)))
                 (deposit-last-fee-assessment d) (f :block-height))
           (incf (ledger-fees-accumulated ledger) (f :amount)))))
      (:quorum-add-member
       (let ((m (make-quorum-member :pubkey (f :quorum-member) :ledger-id (f :member-ledger-id)
                             :min-fee-bps (f :min-fee-bps) :min-fee-fixed (f :min-fee-fixed)
                             :max-fee-period (f :max-fee-period) :membership-until (f :membership-until)
                             :dispute-response-blocks (f :dispute-response-blocks)
                             :dispute-arm-blocks (f :dispute-arm-blocks)
                             :service-response-blocks (f :service-response-blocks)
                             :max-transfer-timeout-blocks (f :max-transfer-timeout-blocks)
                             :max-descriptor-bytes (f :max-descriptor-bytes)
                             :compensation-bps (f :compensation-bps)
                             :compensation-deposit-id (f :compensation-deposit-id)
                             :compensation-frequency-blocks (f :compensation-frequency-blocks)
                             :min-collateral-bps (f :min-collateral-bps)
                             :dormancy-blocks (f :dormancy-blocks) :dormancy-notice-blocks (f :dormancy-notice-blocks)
                             :member-response (f :member-response))))
         (setf (ledger-next-quorum-members ledger)
               (append (remove (f :quorum-member) (ledger-next-quorum-members ledger)
                               :key #'member-pubkey :test #'equalp)
                       (list m)))))
      (:quorum-remove-member
       (setf (ledger-next-quorum-members ledger)
             (remove (f :quorum-member) (ledger-next-quorum-members ledger) :key #'member-pubkey :test #'equalp)))
      (:quorum-upgrade (setf (ledger-active-ruleset ledger) (f :new-protocol-version)))
      (:quorum-join
       (let ((existing (find-if (lambda (j) (and (equalp (getf j :operator-id) (f :operator-id))
                                                 (string= (getf j :ledger-id) (f :ledger-id))))
                                (ledger-joined-quorums ledger))))
         (if existing
             (setf (getf existing :membership-expires) (f :membership-expires))
             (push (list :operator-id (f :operator-id) :ledger-id (f :ledger-id)
                         :membership-expires (f :membership-expires)
                         :joined-at-sequence (1+ (ledger-sequence ledger)))
                   (ledger-joined-quorums ledger)))))
      (:ledger-close nil)
      (:dispute-enter (setf (ledger-dispute-state ledger) :disputed)
                      ;; a live fork cleared its quorum and set this already (MAKE-FORK); a replay sets it here
                      (when (ledger-quorum-members ledger)
                        (setf (ledger-quorum-at-fork ledger) (ledger-quorum-members ledger))))
      (:dispute-armed
       ;; DEP-03 (vector dispute_rearm.json): a re-arm repeats the commitment and declares
       ;; collateral; a fresh pledge after a failed one is a valid re-arm.
       (when (eq (ledger-dispute-state ledger) :armed)
         (unless (equalp (f :commitment-hash) (ledger-arm-commitment ledger))
           (fail :dispute-armed-commitment-changed "a re-arm must repeat the prior arm's commitment_hash"))
         (unless (f :replacement-collateral-txid)
           (fail :dispute-armed-no-upgrade "a re-arm must declare replacement collateral")))
       (setf (ledger-dispute-state ledger) :armed (ledger-arm-commitment ledger) (f :commitment-hash)))
      (:dispute-acquire (setf (ledger-confiscation-txid ledger) (f :confiscation-txid)
                              (ledger-operator-key ledger) (f :new-custodian)
                              (ledger-vault-current-p ledger) nil (ledger-dormancy-notice ledger) nil
                              (ledger-dispute-state ledger) :normal (ledger-quorum-at-fork ledger) '()))
      (:dormancy-notice
       (when (ledger-dormancy-notice ledger) (fail :dormancy-notice "a notice is already outstanding"))
       (unless (>= (f :rotation-height) (+ *block-height* (ledger-dormancy-notice-blocks ledger)))
         (fail :dormancy-notice (format nil "rotation_height ~a is less than ~a blocks ahead" (f :rotation-height)
                                        (ledger-dormancy-notice-blocks ledger))))
       (setf (ledger-dormancy-notice ledger)
             (append (list :height *block-height* :rotation-height (f :rotation-height))
                     (when (f :migration-receiver)
                       ;; DEP-20 §8.3: the receiver's signed accept, verified without its ledger.
                       (let* ((u (handler-case (up:decode-update (f :dormancy-accept))
                                   (error () (fail :dormancy-notice "dormancy_accept does not decode"))))
                              (a (op:decode-operation (up:update-message u))))
                         (unless (and (eq (op:operation-type a) :dormancy-accept)
                                      (equalp (up:update-operator-id u) (f :migration-receiver))
                                      (up:verify-operator-signature u))
                           (fail :dormancy-notice "dormancy_accept is not the receiver's signed DormancyAccept"))
                         (unless (and (f :migration-manifest)
                                      (equalp (sha256 (op:encode-manifest (f :migration-manifest))) (f :manifest-hash))
                                      (equalp (op:field a :manifest-hash) (f :manifest-hash)))
                           (fail :dormancy-notice "manifest, its hash and the accept disagree"))
                         (unless (> (op:field a :expires-at-height) (f :rotation-height))
                           (fail :dormancy-notice "the accept expires before the rotation"))
                         (unless (zerop (mod (or (f :premium) 0) 1000))
                           (fail :dormancy-notice "premium_msats must be whole satoshis"))
                         ;; L4: an update of an existing, quorum-backed receiver ledger, paying its own key.
                         (multiple-value-bind (ok why)
                             (if (f :receiver-quorum-begin)
                                 (handler-case (quorum-backed-accept-p u (up:decode-update (f :receiver-quorum-begin)) (f :migration-receiver))
                                   (error () (values nil "receiver_quorum_begin does not decode")))
                                 (values nil "the notice carries no receiver_quorum_begin"))
                           (unless ok (fail :dormancy-notice why)))
                         (unless (equalp (op:field a :exit-address)
                                         (ignore-errors
                                          (segwit-address-spk (op:field (op:decode-operation (up:update-message (up:decode-update (f :receiver-quorum-begin))))
                                                                        :reserves-id))))
                           (fail :dormancy-notice "exit_address is not the receiver's current vault script"))
                         (list :receiver (f :migration-receiver) :manifest (f :migration-manifest)
                               :spk (op:field a :exit-address) :total (op:field a :accepted-total)
                               :premium (f :premium) :expires (op:field a :expires-at-height))))
                     ;; DEP-20 §8.3: the id a consuming QuorumBegin records.
                     (list :id (sha256 (op:encode-operation o))))))
      (:dormancy-accept
       (let ((a (ledger-dormancy-accept ledger)))
         (unless (spk-type (f :exit-address)) (fail :dormancy-accept "migration address is not a standard output script"))
         (when (and a (or (getf a :outpoint) (accept-outstanding-p ledger *block-height*)))
           (fail :dormancy-accept "another migration is outstanding"))
         (when (> (+ (total-obligations ledger) (f :accepted-total)) (ledger-reserves-amount ledger))
           (fail :dormancy-accept (format nil "obligations ~a + ~a exceed reserves ~a" (total-obligations ledger)
                                          (f :accepted-total) (ledger-reserves-amount ledger))))
         (setf (ledger-dormancy-accept ledger)
               (list :hash (f :manifest-hash) :spk (f :exit-address) :total (f :accepted-total)
                     :expires (f :expires-at-height) :premium-deposit (f :deposit-id) :resolved nil :outpoint nil
                     :source (f :source-ledger-id)))))
      (:migration-credit
       ;; DEP-20 §8.3: positive evidence — the source's signed notice and the QuorumBegin that consumed it.
       (let ((a (or (ledger-dormancy-accept ledger) (fail :migration-credit "no DormancyAccept to resolve"))))
         (when (getf a :resolved) (fail :migration-credit "the accept is already resolved"))
         (multiple-value-bind (notice qb qu to-us) (migration-evidence ledger (f :source-notice-update) (f :source-qb-update))
           (unless (equalp (op:field notice :manifest-hash) (getf a :hash))
             (fail :migration-credit "the notice does not carry this ledger's accept"))
           (if (and to-us (< (up:update-block-height qu) (getf a :expires)))
               (let* ((sum (reduce #'+ (op:field qb :migration-manifest) :key (lambda (e) (getf e :amount))))
                      (premium (or (op:field notice :premium) 0))
                      ;; DEP-06: after a custody change only what the confiscation did not pay
                      (entries (if (ledger-confiscation-txid ledger)
                                   (let ((tx (or (f :confiscation-tx) (fail :migration-credit "after a custody change a MigrationCredit carries the confiscation"))))
                                     (unpaid-entries ledger (op:field qb :migration-manifest) tx))
                                   (op:field qb :migration-manifest))))
                 (when (> (+ sum premium) (getf a :total)) (fail :migration-credit "the migration exceeds the accepted total"))
                 (dolist (e entries)
                   (unless (gethash (getf e :deposit-id) (ledger-deposits ledger))
                     (%open-migrated-deposit ledger e))
                   (%credit (find-deposit ledger (getf e :deposit-id)) (getf e :amount)))
                 (let ((pd (and (getf a :premium-deposit) (gethash (getf a :premium-deposit) (ledger-deposits ledger)))))
                   (when (and pd (plusp premium) (not (ledger-confiscation-txid ledger))) (%credit pd premium)))
                 (setf (getf (ledger-dormancy-accept ledger) :outpoint)
                       (and (not (ledger-confiscation-txid ledger))   ; a confiscation swept it
                            (cons (op:field qb :new-outpoint-txid) (op:field qb :migration-vout)))
                       (getf (ledger-dormancy-accept ledger) :resolved) t))
               ;; consumed without migrating to us: the accept is resolved, nothing credited
               (setf (ledger-dormancy-accept ledger) nil)))))
      (:obligation-record
       ;; DEP-06 §Confiscation obligations: on a fork, before arming; evidence only, no state.
       (unless (eq (ledger-dispute-state ledger) :disputed)
         (fail :obligation-record "an obligation is recorded on a disputing fork before arming"))
       (cond ((f :uncredited-proof)
              (when (or (f :source-notice-update) (f :source-qb-update))
                (fail :obligation-record "one form: a migration or a payment"))
              (handler-case (funcall *uncredited-proof-checker* ledger (f :uncredited-proof))
                (ledger-error (c) (error c))
                (error (c) (fail :obligation-record (princ-to-string c)))))
             ((and (f :source-notice-update) (f :source-qb-update))
              (migration-evidence ledger (f :source-notice-update) (f :source-qb-update)))
             (t (fail :obligation-record "an ObligationRecord carries a migration or a payment"))))
      (:exit-request
       (unless (spk-type (f :exit-address)) (fail :exit-address "not a standard output script (DEP-20 §3)"))
       (let ((d (find-deposit ledger (f :deposit-id))))
         (unless (plusp (f :amount)) (fail :exit-amount "zero"))
         (%lock d (f :amount))
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (setf (gethash (sha256 (op:encode-operation o)) (ledger-pending-exits ledger))
               (list :deposit-id (f :deposit-id) :amount (f :amount) :exit-address (f :exit-address)
                     :expires-at (f :expires-at-height) :block-height *block-height* :seq *update-seq*))))
      (:exit-cancel
       (let* ((d (find-deposit ledger (f :deposit-id)))
              (e (gethash (f :exit-request-id) (ledger-pending-exits ledger))))
         (unless (and e (equalp (getf e :deposit-id) (f :deposit-id)))
           (fail :exit-cancel "names no pending exit request of this deposit"))
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (%unlock d (getf e :amount))
         (remhash (f :exit-request-id) (ledger-pending-exits ledger))))
      (:dispute-yield (setf (ledger-dispute-state ledger) :tombstoned))
      (:transfer-lock
       (let* ((d (find-deposit ledger (f :source-deposit-id)))
              (total (+ (f :amount) (f :fee))))
         (when (< (deposit-available-balance d) total)
           (fail :insufficient-balance (format nil "available ~a, need ~a" (deposit-available-balance d) total)))
         (incf (deposit-locked-balance d) total)
         (push (cons (f :nonce) (f :expiry)) (deposit-seen-nonces d))
         (setf (gethash (f :transfer-id) (ledger-pending-transfers ledger))
               (list :source (f :source-deposit-id) :destination (f :destination-deposit-id)
                     :amount (f :amount) :fee (f :fee) :completion-script (f :completion-script)
                     :timeout-height (f :timeout-height) :transfer-nonce (f :transfer-nonce)))))
      (:transfer-complete
       (let ((p (gethash (f :transfer-id) (ledger-pending-transfers ledger))))
         (unless p (fail :transfer-complete "no such pending transfer"))
         (unless (completion-satisfied-p (getf p :completion-script) (f :script-witness))
           (fail :transfer-complete "script_witness does not satisfy the lock's completion script"))
         (remhash (f :transfer-id) (ledger-pending-transfers ledger))
         (when p
           (let ((src (gethash (getf p :source) (ledger-deposits ledger)))
                 (dst (gethash (getf p :destination) (ledger-deposits ledger)))
                 (total (+ (getf p :amount) (getf p :fee))))
             (when src
               (%unlock src total)
               (setf (deposit-balance src) (max 0 (- (deposit-balance src) (getf p :amount)))))
             (when dst (%credit dst (getf p :amount)))
             (incf (ledger-fees-accumulated ledger) (getf p :fee))))))
      (:transfer-fail
       (let ((p (gethash (f :transfer-id) (ledger-pending-transfers ledger))))
         (unless p (fail :transfer-fail "no such pending transfer"))
         (when (and (integerp (getf p :timeout-height)) (< *block-height* (getf p :timeout-height)))
           (fail :transfer-fail (format nil "block ~a is before the lock's timeout ~a" *block-height* (getf p :timeout-height))))
         (remhash (f :transfer-id) (ledger-pending-transfers ledger))
         (when p
           (let ((src (gethash (getf p :source) (ledger-deposits ledger))))
             (when src
               (%unlock src (+ (getf p :amount) (getf p :fee)))
               (%charge-fixed ledger src))))))
      (:delivery-embed nil)
      ;; DEP-06 §Spend challenge: a notice on the challenger's own ledger; no state.
      (:quorum-challenge nil)
      (:batch (fail :unsupported "batch")))
    ledger))

(defun apply-update (ledger update &key (check-chain t))
  "Apply a signed update: it must be the next sequence and chain to our tip."
  (when check-chain
    (unless (= (up:update-seq update) (1+ (ledger-sequence ledger)))
      (fail :sequence (format nil "expected ~a, got ~a" (1+ (ledger-sequence ledger)) (up:update-seq update))))
    (unless (equalp (up:update-prev-hash update) (ledger-chain-tip ledger))
      (fail :chain-break (format nil "at sequence ~a" (up:update-seq update)))))
  (let ((*block-height* (up:update-block-height update))
        (*update-seq* (up:update-seq update)))
    (let ((o (op:decode-operation (up:update-message update))))
      (unless (eq (op:operation-type o) :quorum-begin) (%release-expired-exits ledger *block-height*))
      (apply-operation ledger o)))
  (setf (ledger-sequence ledger) (up:update-seq update)
        (ledger-chain-tip ledger) (up:chain-hash update))
  ledger)

;;; ---------------------------------------------------------------------------
;;; DEP-05 §Lifecycle: how many cosignatures an operation needs at a height.

(defparameter +tier-1-offset+ 720)
(defparameter +tier-2-offset+ 4032)
(defparameter +tier-3-offset+ 8064)

(defun establishment-p (op)
  (member (cl-deposits.operation:operation-type op) '(:quorum-add-member :quorum-remove-member :quorum-begin)))

(defconstant +min-collateral-bps-floor+ 2000 "DEP-05: no quorum lets collateral fall below 20% of the vault.")

(defun collateral-floor-bps (members)
  "The strictest member's min_collateral_bps, never below +min-collateral-bps-floor+."
  (reduce #'max (remove nil (mapcar #'member-min-collateral-bps members)) :initial-value +min-collateral-bps-floor+))

(defun collateral-meets-floor-p (reserves collateral floor-bps)
  (>= (* collateral 10000) (* floor-bps (+ reserves collateral))))

(defun quorum-expiry-ceiling (members)
  "DEP-05 \"Quorum expiry\": the latest quorum_expiry a QuorumBegin may carry, the shortest
   membership_until among the members it seats.  Members that declared none impose none;
   NIL when none did."
  (let ((c (remove nil (mapcar #'member-membership-until members))))
    (and c (reduce #'min c))))

(defun planned-quorum-expiry (members current-block window-blocks)
  "The quorum_expiry an operator proposes: its own window, shortened to the members' ceiling."
  (let ((own (+ current-block window-blocks)) (c (quorum-expiry-ceiling members)))
    (if c (min c own) own)))

(defun quorum-expiry-ok-p (members expiry block-height)
  "DEP-05: EXPIRY is a valid quorum_expiry for a QuorumBegin seating MEMBERS at BLOCK-HEIGHT: within
   the shortest commitment, and after the block (a quorum is never born expired)."
  (let ((c (quorum-expiry-ceiling members)))
    (and (or (null c) (<= expiry c)) (> expiry block-height))))

(defun lifecycle-tier (ledger height)
  (let ((expiry (ledger-quorum-expiry ledger)))
    (cond ((null expiry) :tier0)
          ((< height expiry) :tier0)
          ((< height (+ expiry +tier-1-offset+)) :tier0-post-expiry)
          ((< height (+ expiry +tier-2-offset+)) :tier1)
          ((< height (+ expiry +tier-3-offset+)) :tier2)
          (t :tier3))))

(defun cosign-requirement (ledger op height)
  "(values required-sigs signers tier operator-alone-p allowed-p).  SIGNERS is the
   member list the signatures must come from: the active quorum, or for the
   first QuorumBegin the staged set."
  (let* ((active (ledger-quorum-members ledger))
         (staged (ledger-next-quorum-members ledger))
         (signers (cond (active active)
                        ((and staged (eq (cl-deposits.operation:operation-type op) :quorum-begin)) staged)
                        (t nil))))
    (when (null signers)
      (return-from cosign-requirement (values 0 '() :tier0 nil t)))
    (let* ((n (length signers)) (majority (majority-threshold n)) (minority (max 1 (1- (ceiling n 2))))
           (tier (if (member (ledger-active-ruleset ledger) +rulesets+ :test #'string=)
                     (lifecycle-tier ledger height)
                     :tier0)))
      (cond ((eq tier :tier0) (values majority signers tier nil t))
            ((not (establishment-p op)) (values 0 signers tier nil nil))
            ((eq tier :tier0-post-expiry) (values majority signers tier nil t))
            ((eq tier :tier1) (values minority signers tier nil t))
            ((eq tier :tier2) (values 1 signers tier nil t))
            (t (values 0 signers tier t t))))))

(defun replay (updates)
  "A fresh ledger folded from UPDATES in order."
  (let ((l (make-ledger))) (dolist (u updates l) (apply-update l u))))

(defun deep-copy (x)
  "Structures, lists, hash tables and general vectors are copied; strings, byte
   vectors and atoms are shared (nothing mutates them)."
  (typecase x
    (cons (loop for tail = x then (cdr tail)
                collect (deep-copy (car tail)) into acc
                while (consp (cdr tail))
                finally (return (if (null (cdr tail)) acc (nconc acc (deep-copy (cdr tail)))))))
    (hash-table (let ((h (make-hash-table :test (hash-table-test x) :size (hash-table-count x))))
                  (maphash (lambda (k v) (setf (gethash k h) (deep-copy v))) x) h))
    (string x)
    ((array (unsigned-byte 8)) x)
    ((and vector (not simple-array)) (map 'vector #'deep-copy x))
    (simple-vector (map 'simple-vector #'deep-copy x))
    (structure-object (let ((c (copy-structure x)))
                        (dolist (slot (sb-mop:class-slots (class-of c)) c)
                          (let ((n (sb-mop:slot-definition-name slot)))
                            (setf (slot-value c n) (deep-copy (slot-value c n)))))))
    (t x)))

(defun copy-ledger (ledger)
  "A private copy to try an operation on.  Replaying the history from genesis
   was the old way and cost O(sequence) per operation and per cosign: at
   sequence 1400 the operator of a busy ledger spent its whole worker on it."
  (deep-copy ledger))
