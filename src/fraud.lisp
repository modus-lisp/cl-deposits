;;;; src/fraud.lisp — DEP-06 fraud proofs.
;;;;
;;;;   proof_hash = tagged_hash("deposits/fraud_proof",
;;;;                            type_byte || accused_hex || ledger_id_hex || evidence)
;;;;
;;;; A proof is (:type :equivocation :accused "hex33" :ledger-id "hex32"
;;;; :evidence (...)).  Evidence fields follow the reference's names; hashes
;;;; that the reference carries as hex strings are hashed as their ASCII hex.

(defpackage #:cl-deposits.fraud
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:up #:cl-deposits.update) (#:op #:cl-deposits.operation) (#:lg #:cl-deposits.ledger)
                    (#:w #:cl-deposits.wire) (#:cf #:cl-deposits.conformance)
                    (#:rs #:cl-deposits.reserves) (#:rot #:cl-deposits.rotation)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire) (#:schnorr #:secp256k1-fast.schnorr))
  (:export #:proof-hash #:evidence-bytes #:proof-discriminant #:respectful-p
           #:verify-equivocation #:update-binds-to-ledger-p #:update-opens-ledger-p #:bound-hashes #:verify-quorum-expired #:verify-non-conforming-update #:verify-proof
           #:proof->json #:json->proof #:requires-embedding-p #:broadcast->json #:json->broadcast #:make-equivocation-proof
           #:make-quorum-expired-proof #:make-non-conforming-update-proof #:uncredited-migration-proof #:latest-migration #:verify-censorship
           #:make-non-conforming-cosignature-proof #:verify-non-conforming-cosignature
           #:make-dispute-dereliction-proof #:verify-dispute-dereliction
           #:make-unauthorized-vault-spend-proof #:verify-unauthorized-vault-spend #:vault-spend-signers
           #:unhonoured-obligation-proof #:verify-unhonoured-obligation #:make-uncredited-offer-proof))
(in-package #:cl-deposits.fraud)

(defparameter +types+
  '((:uncredited-onchain-payment . 1) (:uncredited-lightning-payment . 2) (:stale-cosignature . 3)
    (:dispute-dereliction . 4) (:non-conforming-update . 5) (:quorum-expired . 6)
    (:winner-collateral-deviation . 7) (:equivocation . 8) (:non-conforming-cosignature . 9)
    (:unauthorized-vault-spend . 10) (:unhonoured-obligation . 11)))

(defparameter +type-names+
  '((:uncredited-onchain-payment . "UncreditedOnchainPayment") (:uncredited-lightning-payment . "UncreditedLightningPayment")
    (:stale-cosignature . "StaleCosignature") (:dispute-dereliction . "DisputeDereliction")
    (:non-conforming-update . "NonConformingUpdate") (:quorum-expired . "QuorumExpired")
    (:winner-collateral-deviation . "WinnerCollateralDeviation") (:equivocation . "Equivocation")
    (:non-conforming-cosignature . "NonConformingCosignature")
    (:unauthorized-vault-spend . "UnauthorizedVaultSpend") (:unhonoured-obligation . "UnhonouredObligation")))

(defun proof-discriminant (type) (or (cdr (assoc type +types+)) (error "unknown proof type ~s" type)))
(defun respectful-p (proof) (eq (getf proof :type) :quorum-expired))
(defun e (proof key) (getf (getf proof :evidence) key))

(defun evidence-bytes (proof)
  (let ((ev (getf proof :evidence)))
    (flet ((s (k) (ascii->bytes (getf ev k))) (b (k) (getf ev k)))
      (ecase (getf proof :type)
        (:equivocation
         (let ((lo (getf ev :update-a-hex)) (hi (getf ev :update-b-hex)))
           (when (string> lo hi) (rotatef lo hi))
           (cat (int->le (getf ev :sequence) 8) (ascii->bytes lo) (ascii->bytes hi))))
        (:quorum-expired (cat (b :anchor-block-hash) (int->le (getf ev :quorum-expiry) 4)))
        (:non-conforming-update (cat (int->le (getf ev :fault-sequence) 8) (s :fault-update-hex)))
        (:non-conforming-cosignature
         (cat (s :fault-ledger-id) (int->le (getf ev :fault-sequence) 8) (int->le (getf ev :governing-quorumbegin-seq) 8) (s :fault-update-hex)))
        (:stale-cosignature (cat (s :stale-update-hash) (s :declared-member-hash) (s :member-later-hash)))
        (:uncredited-lightning-payment (cat (s :payment-hash) (b :deposit-id) (int->le (getf ev :amount-msat) 8) (s :preimage)))
        (:uncredited-onchain-payment
         (if (getf ev :source-qb-update)
             ;; DEP-20 §8.3 migration evidence (the reference's UncreditedMigration).
             (cat (s :source-notice-update) (s :source-qb-update) (s :proof-update) (b :confirmed-at-block-hash))
         (cat (s :offer-id)
              ;; DEP-10: the deposit the offer names, as hex text (JSON may have decoded it to bytes)
              (let ((d (getf ev :deposit-id))) (ascii->bytes (cond ((stringp d) d) (d (bytes->hex d)) (t ""))))
              (int->le (getf ev :deadline-block) 4) (s :txid) (int->le (getf ev :vout) 4)
              (int->le (getf ev :amount-sats) 8) (b :confirmed-at-block-hash))))
        (:dispute-dereliction
         (cat (s :original-fraud-hash) (s :disclosure-update) (s :quorum-begin-update) (s :visibility-update)
              (s :member-ledger-id) (s :member-pubkey) (int->le (getf ev :member-active-sequence) 8)))
        (:unauthorized-vault-spend
         (cat (s :spent-ledger-id) (int->le (getf ev :governing-quorumbegin-seq) 8) (s :spend-tx-hex) (b :spend-block-hash)))
        (:winner-collateral-deviation (cat (s :winner-armed-update-hex) (s :claim-txid) (b :claim-block-hash)))
        (:unhonoured-obligation
         (cat (s :source-notice-update) (s :source-qb-update) (ascii->bytes (or (getf ev :uncredited-proof) ""))
              (s :acquire-update) (s :confiscation-tx) (s :proof-update)))))))

(defun proof-hash (proof)
  (tagged-hash "deposits/fraud_proof" (octets (proof-discriminant (getf proof :type)))
               (ascii->bytes (getf proof :accused)) (ascii->bytes (getf proof :ledger-id)) (evidence-bytes proof)))

;;; ---------------------------------------------------------------------------
;;; Constructing the proofs a node can produce from what it sees

(defun make-equivocation-proof (accused33 ledger-id32 update-a update-b)
  (list :type :equivocation :accused (bytes->hex accused33) :ledger-id (bytes->hex ledger-id32)
        :evidence (list :sequence (up:update-seq update-a)
                        :update-a-hex (bytes->hex (up:encode-update update-a))
                        :update-b-hex (bytes->hex (up:encode-update update-b)))))

(defun make-quorum-expired-proof (accused33 ledger-id32 anchor-block-hash32 quorum-expiry)
  (list :type :quorum-expired :accused (bytes->hex accused33) :ledger-id (bytes->hex ledger-id32)
        :evidence (list :anchor-block-hash anchor-block-hash32 :quorum-expiry quorum-expiry)))

(defun make-dispute-dereliction-proof (member33 member-ledger-id32 original-proof disclosure-update
                                       quorum-begin-update visibility-update member-active-update)
  "DEP-19 §6: MEMBER sat on the defrauded ledger's quorum (QUORUM-BEGIN-UPDATE), the fraud
   ORIGINAL-PROOF was disclosed on that ledger by DISCLOSURE-UPDATE (a co-member's DisputeEnter
   citing its hash, whose signed block is the anchor), MEMBER then cosigned VISIBILITY-UPDATE of
   that ledger at or after the anchor, and kept operating its own ledger (MEMBER-ACTIVE-UPDATE)
   past its own dispute_response_blocks from there without disputing.  Presented on the
   member's own ledger to slash it.  Every element is signed or on chain: no embedding."
  (list :type :dispute-dereliction :accused (bytes->hex member33) :ledger-id (bytes->hex member-ledger-id32)
        :evidence (list :original-proof original-proof
                        :original-fraud-hash (bytes->hex (proof-hash original-proof))
                        :disclosure-update (bytes->hex (up:encode-update disclosure-update))
                        :quorum-begin-update (bytes->hex (up:encode-update quorum-begin-update))
                        :visibility-update (bytes->hex (up:encode-update visibility-update))
                        :member-ledger-id (bytes->hex member-ledger-id32)
                        :member-active-sequence (up:update-seq member-active-update)
                        :member-pubkey (bytes->hex member33))))

(defun make-non-conforming-cosignature-proof (accused33 target-ledger-id32 fault-update governing-quorumbegin-seq)
  "Contagion (DEP-19 §5): ACCUSED cosigned FAULT-UPDATE, a non-conforming update on
   another ledger; presented against TARGET-LEDGER, one ACCUSED operates."
  (list :type :non-conforming-cosignature :accused (bytes->hex accused33) :ledger-id (bytes->hex target-ledger-id32)
        :evidence (list :fault-ledger-id (bytes->hex (up:update-ledger-id fault-update))
                        :fault-sequence (up:update-seq fault-update)
                        :governing-quorumbegin-seq governing-quorumbegin-seq
                        :fault-update-hex (bytes->hex (up:encode-update fault-update)))))

;; DEP-06 "unauthorised vault spend" (the spec's type 7; see the discriminant note in
;; docs/MISSING.md: 7 is WinnerCollateralDeviation in both implementations, so this is 10).
(defun make-unauthorized-vault-spend-proof (signer33 target-ledger-id32 spent-ledger-id32 governing-qb-seq spend-tx prevouts block-hash32)
  "SIGNER33 signed SPEND-TX, which spent SPENT-LEDGER's reserves outpoint (the one its
   QuorumBegin at GOVERNING-QB-SEQ names) to outputs no QuorumBegin or confiscation
   accounts for.  Presented against TARGET-LEDGER, a ledger SIGNER33 operates.  PREVOUTS
   is the spend's (amount . spk) per input, which a script-path sighash commits to."
  (list :type :unauthorized-vault-spend :accused (bytes->hex signer33) :ledger-id (bytes->hex target-ledger-id32)
        :evidence (list :spent-ledger-id (bytes->hex spent-ledger-id32)
                        :governing-quorumbegin-seq governing-qb-seq
                        :spend-tx-hex (bytes->hex (btx:serialize-tx spend-tx))
                        :spend-block-hash block-hash32
                        :prevouts (mapcar (lambda (pv) (format nil "~a:~a" (car pv) (bytes->hex (cdr pv)))) (coerce prevouts 'list)))))

(defun make-non-conforming-update-proof (accused33 ledger-id32 fault-update)
  (list :type :non-conforming-update :accused (bytes->hex accused33) :ledger-id (bytes->hex ledger-id32)
        :evidence (list :fault-sequence (up:update-seq fault-update) :fault-update-hex (bytes->hex (up:encode-update fault-update)))))

;;; ---------------------------------------------------------------------------
;;; Verification.  Each returns (values ok reason).

;;; Binding an update to a ledger.  An update's ledger_id is covered by neither its
;;; content hash nor its operator signature (DEP-02 §Signing: the operator signs
;;; sequence, previous_hash, message and the cosignatures), and one key operates
;;; several ledgers: every cl node signs the ledger it operates and its own
;;; member ledger with its node key.  So an honest update of ledger X, relabelled
;;; Y, carries a valid signature on Y.  What binds it is what was signed: a seq-0
;;; LedgerOpen derives the ledger id, and a later update's previous_hash names
;;; the update it follows.  (The reference's bedabe0 and f581dba, fraud.rs.)

(defun update-opens-ledger-p (u ledger-id)
  "U is a seq-0 LedgerOpen, by its own signer, that derives LEDGER-ID."
  (and (zerop (up:update-seq u))
       (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
         (and o (eq (op:operation-type o) :ledger-open)
              (equalp (op:field o :operator-id) (up:update-operator-id u))
              (equalp (op:compute-ledger-id (op:field o :operator-id) (op:field o :reserves-id) (op:field o :genesis-block))
                      ledger-id)))))

(defun bound-hashes (history)
  "chain hash -> sequence, for every update in HISTORY (a ledger's own chain)."
  (let ((h (make-hash-table :test #'equalp)))
    (dolist (u history h) (setf (gethash (up:chain-hash u) h) (up:update-seq u)))))

(defun update-binds-to-ledger-p (u ledger-id bound)
  "U opens LEDGER-ID, or follows an update in BOUND (see BOUND-HASHES)."
  (if (zerop (up:update-seq u))
      (update-opens-ledger-p u ledger-id)
      (nth-value 1 (gethash (up:update-prev-hash u) bound))))

(defun operator-at (history seq)
  "The key that operates the ledger at sequence SEQ: the fold of HISTORY's
   updates before SEQ (custody can change hands), or NIL when HISTORY does not
   reach SEQ.  For SEQ 0, whoever the genesis LedgerOpen names."
  (let ((prefix (sort (remove-if-not (lambda (u) (< (up:update-seq u) seq)) (copy-list history)) #'< :key #'up:update-seq)))
    (cond ((zerop seq) :genesis)
          ((/= (length prefix) seq) nil)
          (t (ignore-errors (lg:ledger-operator-key (lg:replay prefix)))))))

(defun accused-operates-p (accused-hex history seq)
  "Only the ledger's operator's equivocation or non-conforming update is fraud on
   the ledger.  A quorum member can sign anything under the ledger's id, chained
   onto its tip; accusing itself, it froze an honest operator's ledger."
  (let ((key (operator-at history seq)))
    (or (eq key :genesis) (and key (string= (bytes->hex key) accused-hex)))))

(defun verify-equivocation (proof history)
  "Two updates, same ledger / sequence / operator, both validly signed, different
   content, and both bound to the ledger through HISTORY (its chain): a pair of
   the operator's honest updates from two of its ledgers, one relabelled, is not
   an equivocation."
  (handler-case
      (let* ((a (up:decode-update (hex->bytes (e proof :update-a-hex))))
             (b (up:decode-update (hex->bytes (e proof :update-b-hex))))
             (bound (bound-hashes history)))
        (cond ((not (= (up:update-seq a) (up:update-seq b) (e proof :sequence))) (values nil "sequences differ"))
              ((not (equalp (up:update-ledger-id a) (up:update-ledger-id b))) (values nil "ledgers differ"))
              ((not (equalp (up:update-operator-id a) (up:update-operator-id b))) (values nil "operators differ"))
              ((not (string= (bytes->hex (up:update-operator-id a)) (getf proof :accused))) (values nil "accused is not the signer"))
              ((not (string= (bytes->hex (up:update-ledger-id a)) (getf proof :ledger-id))) (values nil "ledger id mismatch"))
              ((equalp (up:content-hash a) (up:content-hash b)) (values nil "same content: not an equivocation"))
              ((not (and (up:verify-operator-signature a) (up:verify-operator-signature b))) (values nil "a signature does not verify"))
              ((not (accused-operates-p (getf proof :accused) history (up:update-seq a)))
               (values nil "the accused does not operate the ledger at that sequence"))
              ((not (update-binds-to-ledger-p a (up:update-ledger-id a) bound))
               (values nil "update_a follows no update of this ledger: nothing binds it here (ledger_id is unsigned)"))
              ((not (update-binds-to-ledger-p b (up:update-ledger-id a) bound))
               (values nil "update_b follows no update of this ledger: nothing binds it here (ledger_id is unsigned)"))
              (t (values t nil))))
    (error (c) (values nil (princ-to-string c)))))

(defun verify-quorum-expired (proof history height-of-block)
  "HEIGHT-OF-BLOCK maps a block hash to its confirmed height (or NIL)."
  (let* ((anchor (e proof :anchor-block-hash))
         (height (funcall height-of-block anchor))
         (claimed (e proof :quorum-expiry))
         (actual (loop for u in history
                       for o = (op:decode-operation (up:update-message u))
                       when (eq (op:operation-type o) :quorum-begin) collect (op:field o :quorum-expiry) into xs
                       finally (return (car (last xs))))))
    (cond ((null height) (values nil "anchor block not in our chain"))
          ((<= height claimed) (values nil "anchor not past quorum_expiry"))
          ((null actual) (values nil "ledger has no QuorumBegin"))
          ((/= claimed actual) (values nil "claimed expiry does not match the ledger's QuorumBegin"))
          (t (values t nil)))))

(defun verify-non-conforming-update (proof history)
  "HISTORY is the ledger's canonical chain.  The fault update must be signed by
   the accused and bound to this ledger (it opens it, or its previous_hash names
   one of its updates), and then either follow an update other than its
   predecessor (a rewind or a skip) or chain onto the predecessor and fail to
   apply.  A previous_hash that names nothing here is not proof: it may be an
   honest update of another ledger the same key operates, relabelled."
  (handler-case
      (let* ((fault (up:decode-update (hex->bytes (e proof :fault-update-hex))))
             (seq (up:update-seq fault))
             (id (up:update-ledger-id fault))
             (bound (bound-hashes history))
             (prefix (sort (remove-if-not (lambda (u) (< (up:update-seq u) seq)) (copy-list history)) #'< :key #'up:update-seq)))
        (cond ((not (string= (bytes->hex (up:update-operator-id fault)) (getf proof :accused)))
               (values nil "accused is not the signer"))
              ((not (string= (bytes->hex id) (getf proof :ledger-id))) (values nil "ledger id mismatch"))
              ((not (up:verify-operator-signature fault)) (values nil "fault update is not validly signed"))
              ;; Who operates is judged where the fault attaches: after the update it chains onto
              ;; (a skip claims a later sequence than any the verifier holds).
              ((not (accused-operates-p (getf proof :accused) history
                                        (let ((pred (and (plusp seq) (gethash (up:update-prev-hash fault) bound))))
                                          (if pred (1+ pred) seq))))
               (values nil "the accused does not operate the ledger at that sequence"))
              ((/= seq (e proof :fault-sequence)) (values nil "sequence mismatch"))
              ((not (update-binds-to-ledger-p fault id bound))
               (values nil "fault follows no update of this ledger: nothing binds it here (ledger_id is unsigned)"))
              ;; A skip or rewind (DEP-02 §Sequence) is proven by the update it chains onto alone;
              ;; a skip's verifier never holds the sequences it claims to have passed.
              ((and (plusp seq) (/= (gethash (up:update-prev-hash fault) bound) (1- seq)))
               (values t (format nil "fault at seq ~a follows seq ~a" seq (gethash (up:update-prev-hash fault) bound))))
              ((/= (length prefix) seq) (values nil "history does not reach the fault's predecessor"))
              (t
               ;; It chains onto its predecessor, so it must break a rule: the fold's,
               ;; or the depositor's (authorization, nonce window, expiry).
               (let* ((l (lg:replay prefix))
                      (v (cf:violation l (op:decode-operation (up:update-message fault)) (up:update-block-height fault))))
                 (if v
                     (values t v)
                     (handler-case (progn (lg:apply-update l fault) (values nil "fault update applies cleanly: conforming"))
                       (lg:ledger-error (c) (values t (princ-to-string c)))))))))
    (error (c) (values nil (princ-to-string c)))))

(defun verify-non-conforming-cosignature (proof fault-history)
  "FAULT-HISTORY is the fault ledger's chain before the fault.  The accused signed
   the fault update: as its operator (DEP-19 §5: the accused 'MUST appear on the
   update as operator_id or in cosignatures'; operator contagion), or with a valid
   cosignature as a member the governing QuorumBegin names.  And the fault breaks
   the rules, judged as a NonConformingUpdate of the fault ledger's operator
   (binding, operator, conformance and fold)."
  (handler-case
      (let* ((fault (up:decode-update (hex->bytes (e proof :fault-update-hex))))
             (accused (hex->bytes (getf proof :accused)))
             (seq (up:update-seq fault))
             (qb-seq (e proof :governing-quorumbegin-seq))
             (qb (find qb-seq fault-history :key #'up:update-seq))
             (qb-op (and qb (ignore-errors (op:decode-operation (up:update-message qb)))))
             (cosig (find accused (up:update-cosignatures fault) :key #'up:cosig-pubkey :test #'equalp))
             (operator-p (equalp accused (up:update-operator-id fault))))
        (cond ((not (string= (bytes->hex (up:update-ledger-id fault)) (e proof :fault-ledger-id))) (values nil "fault update is not on the named fault ledger"))
              ((/= seq (e proof :fault-sequence)) (values nil "fault sequence mismatch"))
              ;; The operator: its own signature is the evidence (checked by the
              ;; NonConformingUpdate judgement below).
              (operator-p (verify-non-conforming-update
                           (make-non-conforming-update-proof (up:update-operator-id fault) (up:update-ledger-id fault) fault)
                           fault-history))
              ((null cosig) (values nil "the accused did not cosign the fault"))
              ((not (up:verify-cosignature fault cosig)) (values nil "the accused's cosignature does not verify"))
              ((not (and qb-op (eq (op:operation-type qb-op) :quorum-begin) (<= qb-seq seq)))
               (values nil "no governing QuorumBegin at that sequence"))
              ((not (member accused (op:field qb-op :quorum-members) :test #'equalp))
               (values nil "the governing QuorumBegin does not name the accused"))
              (t (verify-non-conforming-update
                  (make-non-conforming-update-proof (up:update-operator-id fault) (up:update-ledger-id fault) fault)
                  fault-history))))
    (error (c) (values nil (princ-to-string c)))))

;;; DEP-19 §6 dereliction.  The proof binds to a real fraud (the original proof is carried and
;;; verified against the defrauded ledger), to a real disclosure (a co-member's signed DisputeEnter
;;; citing that proof's hash: its block is the anchor, not a free choice), to the accused's seat
;;; (the defrauded ledger's QuorumBegin), and to the accused having seen the ledger after the
;;; anchor (its own cosignature there).  The window is the accused's own recorded
;;; dispute_response_blocks; any carried value is ignored.  A DisputeEnter or DisputeArmed the
;;; accused signed on that ledger within the window rebuts it.

(defparameter +default-dispute-response-blocks+ 144 "DEP-11's default when a member declared none.")

(defun derelict-original-verifies-p (original chain height-of-block)
  (if (member (getf original :type) '(:quorum-expired :dispute-dereliction))
      (values nil "the original proof is not a punitive fraud proof")
      (verify-proof original :history chain :height-of-block height-of-block)))

(defun operator-chain (updates operator33)
  "The defrauded ledger's own chain: updates its operator signed, one per sequence, in order."
  (let ((by-seq (make-hash-table)))
    (dolist (u updates) (when (and (equalp (up:update-operator-id u) operator33) (up:verify-operator-signature u))
                          (unless (gethash (up:update-seq u) by-seq) (setf (gethash (up:update-seq u) by-seq) u))))
    (sort (loop for u being the hash-values of by-seq collect u) #'< :key #'up:update-seq)))

(defun member-response-blocks (chain member33 qb-seq)
  "MEMBER's own dispute_response_blocks: from its latest QuorumAddMember at or before QB-SEQ."
  (let ((found nil))
    (dolist (u chain)
      (when (<= (up:update-seq u) qb-seq)
        (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
          (when (and o (eq (op:operation-type o) :quorum-add-member) (equalp (op:field o :quorum-member) member33))
            (setf found (op:field o :dispute-response-blocks))))))
    (or found +default-dispute-response-blocks+)))

(defun acted-on-p (u member33 ledger-id)
  "U is MEMBER's own signed DisputeEnter (not an expiry) or DisputeArmed on LEDGER-ID."
  (and (equalp (up:update-operator-id u) member33) (equalp (up:update-ledger-id u) ledger-id)
       (up:verify-operator-signature u)
       (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
         (and o (or (eq (op:operation-type o) :dispute-armed)
                    (and (eq (op:operation-type o) :dispute-enter)
                         (not (equal (substitute #\_ #\- (or (op:field o :reason) "")) "quorum_expired"))))))))

(defun verify-dispute-dereliction (proof member-history height-of-block &key defrauded-updates)
  "MEMBER-HISTORY is the accused member's own ledger (the one being slashed); DEFRAUDED-UPDATES
   every update the verifier holds of the defrauded ledger (its own chain and any forks).  Fails
   closed without them.  (values ok reason)."
  (handler-case
      (let* ((original (or (e proof :original-proof) (error "no original proof")))
             (h (proof-hash original))
             (mk (hex->bytes (getf proof :accused)))
             (d-id (hex->bytes (getf original :ledger-id)))
             (accused-op (hex->bytes (getf original :accused)))
             (chain (operator-chain (remove-if-not (lambda (u) (equalp (up:update-ledger-id u) d-id)) defrauded-updates) accused-op))
             (disc (up:decode-update (hex->bytes (e proof :disclosure-update))))
             (disc-op (op:decode-operation (up:update-message disc)))
             (qb (up:decode-update (hex->bytes (e proof :quorum-begin-update))))
             (qb-op (op:decode-operation (up:update-message qb)))
             (vis (up:decode-update (hex->bytes (e proof :visibility-update))))
             (active (find (e proof :member-active-sequence) member-history :key #'up:update-seq))
             (anchor (up:update-block-height disc)))
        (flet ((confirmed-at-p (u)
                 ;; A signed header dates the update when it names a block (the reference's do); one
                 ;; with no block hash (cl's, so far) is dated by its signed block_height alone.
                 (let ((bh (up:update-block-hash u)))
                   (or (null bh) (every #'zerop bh)
                       (eql (funcall height-of-block bh) (up:update-block-height u))))))
          (cond
            ((not (string-equal (e proof :original-fraud-hash) (bytes->hex h)))
             (values nil "original_fraud_hash is not the carried proof's hash"))
            ((null chain) (values nil "we hold none of the defrauded ledger's updates"))
            ((multiple-value-bind (ok why) (derelict-original-verifies-p original chain height-of-block)
               (unless ok (return-from verify-dispute-dereliction (values nil (format nil "the original proof does not verify: ~a" why))))
               nil))
            ((not (and (equalp (up:update-ledger-id disc) d-id) (up:verify-operator-signature disc)
                       (eq (op:operation-type disc-op) :dispute-enter) (equalp (op:field disc-op :fraud-proof-hash) h)))
             (values nil "the disclosure is not a signed DisputeEnter on the defrauded ledger citing the proof"))
            ((not (confirmed-at-p disc)) (values nil "the disclosure's block is not on our chain at its height"))
            ((not (and (equalp (up:update-ledger-id qb) d-id) (equalp (up:update-operator-id qb) accused-op)
                       (eq (op:operation-type qb-op) :quorum-begin)
                       (find-if (lambda (u) (equalp (up:encode-update u) (up:encode-update qb))) chain)
                       (<= (up:update-seq qb) (op:field disc-op :last-valid-sequence))
                       (notany (lambda (u) (and (< (up:update-seq qb) (up:update-seq u) (1+ (op:field disc-op :last-valid-sequence)))
                                                (eq (ignore-errors (op:operation-type (op:decode-operation (up:update-message u)))) :quorum-begin)))
                               chain)))
             (values nil "the QuorumBegin is not the one governing the defrauded ledger at the fault"))
            ((not (member mk (op:field qb-op :quorum-members) :test #'equalp))
             (values nil "the accused held no seat on the defrauded ledger's quorum"))
            ((not (member (up:update-operator-id disc) (op:field qb-op :quorum-members) :test #'equalp))
             (values nil "the disclosure is not by a member of that quorum"))
            ((equalp (up:update-operator-id disc) mk) (values nil "the accused disclosed it: it acted"))
            ((not (and (equalp (up:update-ledger-id vis) d-id) (>= (up:update-block-height vis) anchor) (confirmed-at-p vis)
                       (find-if (lambda (c) (and (equalp (up:cosig-pubkey c) mk) (up:verify-cosignature vis c))) (up:update-cosignatures vis))))
             (values nil "no cosignature by the accused on the defrauded ledger at or after the anchor"))
            ((null active) (values nil "member-active update not in the member's history"))
            ((not (and (equalp (up:update-operator-id active) mk) (up:verify-operator-signature active) (confirmed-at-p active)))
             (values nil "member-active update not signed by the accused at a block on our chain"))
            (t (let* ((start (up:update-block-height vis))
                      (required (member-response-blocks chain mk (up:update-seq qb)))
                      (deadline (+ start required)))
                 (cond ((< (up:update-block-height active) deadline)
                        (values nil (format nil "member-active block only ~a past visibility; its window is ~a"
                                            (- (up:update-block-height active) start) required)))
                       ((find-if (lambda (u) (and (acted-on-p u mk d-id) (<= (up:update-block-height u) deadline))) defrauded-updates)
                        (values nil "the accused disputed within its window"))
                       (t (values t nil))))))))
    (error (c) (values nil (princ-to-string c)))))

;;; Unauthorised vault spend.  Everything is checked from chain data and the spent
;;; ledger's own history: the signatures are the evidence, so no embedding.

(defun parse-prevouts (strings)
  (coerce (loop for str in (coerce strings 'list)
                collect (let ((c (position #\: str)))
                          (cons (parse-integer str :end c) (hex->bytes (subseq str (1+ c))))))
          'vector))

(defun spent-vault (history governing-seq)
  "(values reserves txid vout) for the QuorumBegin at GOVERNING-SEQ in HISTORY (the
   spent ledger's chain, any order), or NIL."
  (let ((operator nil) (qb nil))
    (dolist (u (sort (copy-list history) #'< :key #'up:update-seq))
      (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
        (when o
          (case (op:operation-type o)
            (:ledger-open (setf operator (op:field o :operator-id)))
            (:quorum-begin (when (= (up:update-seq u) governing-seq) (setf qb o)))))))
    (when (and qb operator)
      (values (rs:build-reserves :operator operator :members (op:field qb :quorum-members)
                                 :ledger-hash (op:field qb :ledger-hash) :quorum-expiry (op:field qb :quorum-expiry)
                                 :ruleset (or (op:field qb :protocol-version) "cltv-offset-v2"))
              (op:field qb :new-outpoint-txid) (op:field qb :new-outpoint-vout)))))

(defun vault-spend-signers (tx prevouts reserves txid vout)
  "Run the witness of the input of TX spending (TXID, VOUT) against RESERVES's tier
   leaves.  (values signer-xonly-list input-index tier-index): the keys whose Schnorr
   signature verifies over the script-path sighash, provided at least the tier's
   threshold did; else NIL."
  (let* ((idx (position-if (lambda (i) (and (equalp (btx:txin-prev-hash i) txid) (= (btx:txin-prev-index i) vout)))
                           (btx:tx-inputs tx)))
         (stack (and idx (nth idx (btx:tx-witnesses tx))))
         (n (length stack)))
    (when (and idx (>= n 3))
      (let* ((leaf (nth (- n 2) stack))
             (tier-index (position leaf (rs:reserves-leaves reserves) :test #'equalp)))
        (when (and tier-index (< tier-index (length (rs:reserves-tiers reserves)))
                   (equalp (nth (1- n) stack) (rs:control-block-for-tier reserves tier-index)))
          (let* ((tier (nth tier-index (rs:reserves-tiers reserves)))
                 (keys (if (and (= (rs:tier-threshold tier) 1) (rs:tier-tie-breaker-p tier))
                           (list (up:x-only (rs:reserves-operator reserves)))
                           (rs:tier-keys tier)))
                 (sigs (reverse (subseq stack 0 (- n 2))))
                 (msg (rot:tier-sighash tx idx prevouts leaf))
                 (signers (loop for k in keys for sig in sigs
                                when (and (= (length sig) 64) (schnorr:schnorr-verify k msg sig)) collect k)))
            (when (>= (length signers) (rs:tier-threshold tier))
              (values signers idx tier-index))))))))

(defun verify-unauthorized-vault-spend (proof spent-history height-of-block &key authorised-txids)
  "SPENT-HISTORY is the spent ledger's own chain.  Valid when the accused signed (to
   threshold) a spend of the vault outpoint its QuorumBegin names, the spend is in a block
   we confirm, and its txid is none of AUTHORISED-TXIDS (the txids of the ledger's recorded
   rotations, whichever QuorumBegin created them, and any confiscation the verifier knows)."
  (handler-case
      (let* ((ev (getf proof :evidence))
             (tx (btx:parse-tx (bw:make-reader (hex->bytes (getf ev :spend-tx-hex)))))
             (txid (btx:tx-txid tx))
             (prevouts (parse-prevouts (getf ev :prevouts))))
        (multiple-value-bind (reserves vtxid vvout) (spent-vault spent-history (getf ev :governing-quorumbegin-seq))
          (cond ((null reserves) (values nil "no such QuorumBegin on the spent ledger"))
                ((/= (length prevouts) (length (btx:tx-inputs tx))) (values nil "prevouts do not match the inputs"))
                ((null (funcall height-of-block (getf ev :spend-block-hash))) (values nil "spend block not in our chain"))
                ((member txid authorised-txids :test #'equalp) (values nil "the spend is a recorded rotation or confiscation"))
                (t (let ((signers (vault-spend-signers tx prevouts reserves vtxid vvout)))
                     (cond ((null signers) (values nil "no tier witness on the vault input verifies"))
                           ((not (member (up:x-only (hex->bytes (getf proof :accused))) signers :test #'equalp))
                            (values nil "the accused is not among the verified signers"))
                           (t (values t nil))))))))
    (error (c) (values nil (princ-to-string c)))))

(defun latest-migration (source-history)
  "DEP-20 §8.3: the newest QuorumBegin in SOURCE-HISTORY (ascending) that migrated, and the
   DormancyNotice before it carrying the accept: (values qb-update notice-update qb-op), or NIL."
  (let ((qb nil) (notice nil))
    (dolist (u (reverse source-history))
      (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
        (cond ((and (null qb) o (eq (op:operation-type o) :quorum-begin) (op:field o :migration-manifest))
               (setf qb u))
              ((and qb o (eq (op:operation-type o) :dormancy-notice) (op:field o :dormancy-accept))
               (setf notice u) (return)))))
    (when (and qb notice) (values qb notice (op:decode-operation (up:update-message qb))))))

(defparameter +default-service-response-blocks+ 72
  "DEP-05: the service deadline when no member of the governing quorum declared one.")

(defun governing-service-response-blocks (history at-seq)
  "The receiver's own terms at AT-SEQ: the largest service_response_blocks its members declared
   (QuorumAddMember) among the members of the QuorumBegin governing AT-SEQ; the default if none.
   Never a value carried by a proof."
  (let ((declared (make-hash-table :test #'equalp)) (members '()))
    (dolist (u history)
      (when (<= (up:update-seq u) at-seq)
        (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
          (case (and o (op:operation-type o))
            (:quorum-add-member
             (when (op:field o :service-response-blocks)
               (setf (gethash (op:field o :quorum-member) declared) (op:field o :service-response-blocks))))
            (:quorum-begin (setf members (op:field o :quorum-members)))))))
    ;; (LOOP's MAXIMIZE over nothing is 0, not NIL: collect first, so none declared is the default.)
    (let ((vs (loop for m in members for v = (gethash m declared) when v collect v)))
      (if vs (reduce #'max vs) +default-service-response-blocks+))))

(defun uncredited-migration-proof (source-history receiver-history confirmed-block-hash confirmed-height)
  "DEP-20 §8.3 producer: an UncreditedOnchainPayment (migration evidence) against the receiver of
   SOURCE-HISTORY's latest migration, if RECEIVER-HISTORY (ascending) has an update signed its own
   service_response_blocks or more after CONFIRMED-HEIGHT (the rotation's block) while some
   migrated entry is uncredited.  NIL otherwise."
  (multiple-value-bind (qu nu qb) (latest-migration source-history)
    (when qu
      (let* ((notice (op:decode-operation (up:update-message nu)))
             (au (up:decode-update (op:field notice :dormancy-accept)))
             (srb (governing-service-response-blocks receiver-history (up:update-seq au)))
             (txid (op:field qb :new-outpoint-txid)) (vout (op:field qb :migration-vout))
             (pu (car (last (remove-if (lambda (u) (< (up:update-block-height u) (+ confirmed-height srb)))
                                       receiver-history)))))
        (when (and pu (not (migration-credited-p qb receiver-history (up:update-seq pu) txid vout)))
          (list :type :uncredited-onchain-payment
                :accused (bytes->hex (up:update-operator-id au)) :ledger-id (bytes->hex (up:update-ledger-id au))
                :evidence (list :source-notice-update (bytes->hex (up:encode-update nu))
                                :source-qb-update (bytes->hex (up:encode-update qu))
                                :proof-update (bytes->hex (up:encode-update pu))
                                :confirmed-at-block-hash confirmed-block-hash)))))))

(defun migration-credited-p (qb history upto-seq txid vout)
  "HISTORY resolves the migration QB records with a MigrationCredit (DEP-20 §8.3) naming a source
   QuorumBegin of the same rotation (TXID) and migration_vout (VOUT) at or before UPTO-SEQ; the
   fold credits exactly QB's migrated entries."
  (declare (ignore qb))
  (some (lambda (u)
          (and (<= (up:update-seq u) upto-seq)
               (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
                 (and o (eq (op:operation-type o) :migration-credit)
                      (let ((sq (ignore-errors (op:decode-operation (up:update-message (up:decode-update (op:field o :source-qb-update)))))))
                        (and sq (equalp (op:field sq :new-outpoint-txid) txid) (eql (op:field sq :migration-vout) vout)))))))
        history))

(defun verify-uncredited-migration (proof history height-of-block)
  "DEP-20 §8.3: the accused (receiver) signed a DormancyAccept the source's notice carries, over
   the notice's manifest; the source's QuorumBegin migrated entries of it to the accused before
   the accept expired; the rotation confirmed; the accused signed PROOF-UPDATE (carried, in its
   history) at least its own service_response_blocks later (its governing terms at the accept,
   never a carried value) without crediting every migrated entry (deposit, exact amount, rotation
   txid, migration_vout) by then.  HISTORY is the accused's; (values ok reason)."
  (handler-case
      (flet ((dec (hex what)
               (let ((u (up:decode-update (hex->bytes hex))))
                 (unless (up:verify-operator-signature u) (error "~a: bad operator signature" what))
                 (values u (op:decode-operation (up:update-message u))))))
        (multiple-value-bind (nu notice) (dec (e proof :source-notice-update) "source notice")
          (multiple-value-bind (qu qb) (dec (e proof :source-qb-update) "source QuorumBegin")
            (let* ((au (and (eq (op:operation-type notice) :dormancy-notice) (op:field notice :dormancy-accept)
                            (up:decode-update (op:field notice :dormancy-accept))))
                   (accept (and au (op:decode-operation (up:update-message au))))
                   (offered (and au (op:field notice :migration-manifest)))
                   (migrated (and (eq (op:operation-type qb) :quorum-begin) (op:field qb :migration-manifest)))
                   (vout (and migrated (op:field qb :migration-vout)))
                   (txid (and migrated (op:field qb :new-outpoint-txid)))
                   (confirmed (funcall height-of-block (e proof :confirmed-at-block-hash)))
                   (pu (up:decode-update (hex->bytes (e proof :proof-update))))
                   (ours (find (up:update-seq pu) history :key #'up:update-seq))
                   (ph (funcall height-of-block (up:update-block-hash pu)))
                   (srb (and au (governing-service-response-blocks history (up:update-seq au)))))
              (cond
                ((not (and (equalp (up:update-operator-id nu) (up:update-operator-id qu))
                           (equalp (up:update-ledger-id nu) (up:update-ledger-id qu))
                           (< (up:update-seq nu) (up:update-seq qu))))
                 (values nil "the notice and QuorumBegin are not one source ledger's, in order"))
                ((not (and accept (eq (op:operation-type accept) :dormancy-accept) (up:verify-operator-signature au)))
                 (values nil "the notice carries no signed DormancyAccept"))
                ((not (and (equalp (up:update-operator-id au) (op:field notice :migration-receiver))
                           (string-equal (bytes->hex (up:update-operator-id au)) (getf proof :accused))
                           (string-equal (bytes->hex (up:update-ledger-id au)) (getf proof :ledger-id))))
                 (values nil "the accept is not the accused's, on the proof's ledger"))
                ((not (equalp (op:field accept :manifest-hash) (op:field notice :manifest-hash)))
                 (values nil "the accept is for another manifest"))
                ((not (and migrated vout (equalp (op:field qb :migration-receiver) (up:update-operator-id au))))
                 (values nil "the source QuorumBegin migrates nothing to the accused"))
                ((notevery (lambda (m) (find (getf m :deposit-id) offered :key (lambda (o) (getf o :deposit-id)) :test #'equalp)) migrated)
                 (values nil "the QuorumBegin migrates deposits the accepted manifest does not list"))
                ((>= (up:update-block-height qu) (op:field accept :expires-at-height))
                 (values nil "the accept had expired when the source rotated"))
                ((null confirmed) (values nil "confirmed_at_block_hash not in the verifier's chain"))
                ((not (and (up:verify-operator-signature pu) (equalp (up:update-operator-id pu) (up:update-operator-id au))
                           (equalp (up:update-ledger-id pu) (up:update-ledger-id au))))
                 (values nil "the proof update is not the accused's signed update on its ledger"))
                ((not (and ours (equalp (up:chain-hash ours) (up:chain-hash pu))))
                 (values nil "the proof update is not in the accused's history"))
                ((null ph) (values nil "the proof update's block is not in the verifier's chain"))
                ((/= ph (up:update-block-height pu)) (values nil "the proof update's signed height is not its block's"))
                ((< (- ph confirmed) srb)
                 (values nil (format nil "the proof update is fewer than ~a blocks (the accused's terms) after the migration confirmed" srb)))
                ((migration-credited-p qb history (up:update-seq pu) txid vout)
                 (values nil "every migrated deposit was credited: not fraud"))
                (t (values t nil)))))))
    (error (c) (values nil (princ-to-string c)))))

(defun offer-deposit-id (proof)
  "The offer evidence's deposit id as bytes (JSON may give hex text or bytes)."
  (let ((d (e proof :deposit-id))) (if (stringp d) (hex->bytes d) d)))

(defun verify-uncredited-onchain (proof history height-of-block)
  "DEP-06 offer evidence (mirrors the reference's verify_uncredited_onchain): the descriptor hashes
   to the offer's deposit_id; the offer cosignature verifies over the DEP-10 digest (which binds
   that deposit); the payment's block is on our chain; the accused signed PROOF-SEQUENCE at least
   the ledger's governing service_response_blocks later (its own terms; the carried
   required_confirmations is ignored, or a forger lowers it to frame an honest operator); and no
   OnchainCredit of the payment at or before it."
  (handler-case
      (let* ((deposit (offer-deposit-id proof))
             (txid (hex->bytes (e proof :txid))) (vout (e proof :vout))
             (digest (lg:offer-cosign-digest (getf proof :ledger-id) (hex->bytes (e proof :offer-id)) deposit
                                             (hex->bytes (e proof :accused-operator-pubkey)) (e proof :funding-address)
                                             (e proof :deadline-block) (hex->bytes (e proof :cosigner-ledger-hash))))
             (confirmed (funcall height-of-block (let ((b (e proof :confirmed-at-block-hash))) (if (stringp b) (hex->bytes b) b))))
             (pu (find (e proof :proof-sequence) history :key #'up:update-seq))
             (ph (and pu (funcall height-of-block (up:update-block-hash pu)))))
        (cond ((not (and (stringp (e proof :descriptor)) (equalp (op:deposit-id (e proof :descriptor)) deposit)))
               (values nil "descriptor does not hash to the offer's deposit_id"))
              ((not (schnorr:schnorr-verify (up:x-only (hex->bytes (e proof :cosigner-pubkey))) digest (hex->bytes (e proof :cosign-signature))))
               (values nil "offer cosignature does not verify"))
              ((null confirmed) (values nil "confirmed_at_block_hash not in the verifier's chain"))
              ((null pu) (values nil "proof_sequence not in the accused's history"))
              ((null ph) (values nil "the proof_sequence update's block is not on the verifier's chain"))
              ((< (- ph confirmed) (governing-service-response-blocks history (e proof :proof-sequence)))
               (values nil (format nil "the proof update is fewer than ~a blocks (the ledger's terms) after the payment confirmed"
                                   (governing-service-response-blocks history (e proof :proof-sequence)))))
              ((onchain-credited-p history (up:update-seq pu) txid vout) (values nil "the payment was credited: not fraud"))
              (t (values t nil))))
    (error (c) (values nil (princ-to-string c)))))

(defun onchain-credited-p (history upto-seq txid vout &optional (after-seq -1))
  "An OnchainCredit of TXID:VOUT in HISTORY after AFTER-SEQ, at or before UPTO-SEQ."
  (some (lambda (u)
          (and (< after-seq (up:update-seq u) (1+ upto-seq))
               (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
                 (labels ((hit (o) (case (op:operation-type o)
                                     (:onchain-credit (and (equalp (op:field o :txid) txid) (eql (op:field o :vout) vout)))
                                     (:batch (some #'hit (op:field o :operations))))))
                   (and o (hit o))))))
        history))

(defun make-uncredited-offer-proof (ledger-id-hex offer descriptor txid vout amount-sats confirmed-block-hash
                                    required-confirmations proof-update)
  "DEP-06 offer evidence (a wallet's): OFFER is the cosigned offer as the operator returned it
   (JSON object: offer_id, deposit_id, operator_id, funding_address, deadline_block,
   cosigner_pubkey, cosigner_ledger_hash, cosign_signature); PROOF-UPDATE the operator's update
   past the payment's confirmations that does not credit it."
  (list :type :uncredited-onchain-payment :accused (w:jget offer "operator_id") :ledger-id ledger-id-hex
        :evidence (list :offer-id (w:jget offer "offer_id") :deposit-id (w:jget offer "deposit_id") :descriptor descriptor
                        :funding-address (w:jget offer "funding_address") :accused-operator-pubkey (w:jget offer "operator_id")
                        :deadline-block (w:jget offer "deadline_block") :cosigner-pubkey (w:jget offer "cosigner_pubkey")
                        :cosigner-ledger-hash (w:jget offer "cosigner_ledger_hash") :cosign-signature (w:jget offer "cosign_signature")
                        :txid (bytes->hex txid) :vout vout :amount-sats amount-sats
                        :confirmed-at-block-hash confirmed-block-hash :required-confirmations required-confirmations
                        :proof-sequence (up:update-seq proof-update))))

(defun payment-entry (proof)
  "The owed entry of an offer-evidence proof: (:deposit-id :amount msat :descriptor)."
  (list :deposit-id (offer-deposit-id proof) :amount (* 1000 (e proof :amount-sats)) :descriptor (e proof :descriptor)
        :fees (op:make-fees)))

(defun check-uncredited-record (ledger bytes)
  "DEP-06 ObligationRecord (payment form), self-contained: offer evidence against LEDGER, its
   descriptor hashing to its deposit_id, its cosignature by a member of LEDGER's quorum."
  (let ((proof (json->proof (w:parse-json (bytes->ascii bytes)))))
    (unless (and (eq (getf proof :type) :uncredited-onchain-payment) (not (e proof :source-qb-update)) (e proof :offer-id))
      (error "not an UncreditedOnchainPayment with offer evidence"))
    (unless (string-equal (getf proof :ledger-id) (bytes->hex (lg:ledger-id ledger))) (error "the proof is against another ledger"))
    (let ((deposit (offer-deposit-id proof)) (cosigner (hex->bytes (e proof :cosigner-pubkey))))
      (unless (and (stringp (e proof :descriptor)) (equalp (op:deposit-id (e proof :descriptor)) deposit))
        (error "descriptor does not hash to the offer's deposit_id"))
      ;; on a fork (the only place it is recorded) the quorum is the one at the fork point
      (unless (member cosigner (or (lg:ledger-quorum-at-fork ledger) (lg:ledger-quorum-members ledger))
                      :key #'lg:member-pubkey :test #'equalp)
        (error "the offer's cosigner is not a member of the ledger's quorum"))
      (unless (schnorr:schnorr-verify (up:x-only cosigner)
                                      (lg:offer-cosign-digest (getf proof :ledger-id) (hex->bytes (e proof :offer-id)) deposit
                                                              (hex->bytes (e proof :accused-operator-pubkey)) (e proof :funding-address)
                                                              (e proof :deadline-block) (hex->bytes (e proof :cosigner-ledger-hash)))
                                      (hex->bytes (e proof :cosign-signature)))
        (error "offer cosignature does not verify")))
    proof))

(setf lg:*uncredited-proof-checker* #'check-uncredited-record)

(defun unpaid-in-tx (entries tx)
  "DEP-06: the ENTRIES no output of TX pays (the splice-out rule's script and value)."
  (let ((outs (mapcar (lambda (o) (cons (btx:txout-script o) (btx:txout-value o))) (btx:tx-outputs tx))))
    (remove-if (lambda (e) (multiple-value-bind (spk sats) (lg:owed-spk-sats e)
                             (and spk (find-if (lambda (o) (and (equalp (car o) spk) (= (cdr o) sats))) outs))))
               entries)))

(defun residue-credited-p (history after-seq upto-seq txid vout)
  "A MigrationCredit after AFTER-SEQ, at or before UPTO-SEQ, resolving the migration TXID:VOUT."
  (some (lambda (u)
          (and (< after-seq (up:update-seq u) (1+ upto-seq))
               (let ((o (ignore-errors (op:decode-operation (up:update-message u)))))
                 (and o (eq (op:operation-type o) :migration-credit)
                      (let ((sq (ignore-errors (op:decode-operation (up:update-message (up:decode-update (op:field o :source-qb-update)))))))
                        (and sq (equalp (op:field sq :new-outpoint-txid) txid) (eql (op:field sq :migration-vout) vout)))))))
        history))

(defun obligation-context (history acquire-update notice-hex qb-hex)
  "A migration's UnhonouredObligation context: the ledger before the acquire and the source
   evidence checked against it.  (values notice qb qu prefix-ledger prefix) or an error."
  (let* ((prefix (remove-if-not (lambda (u) (< (up:update-seq u) (up:update-seq acquire-update))) history))
         (l (lg:replay prefix))
         (a (or (lg:ledger-dormancy-accept l) (error "no accept before the custody change"))))
    (multiple-value-bind (notice qb qu to-us) (lg:migration-evidence l (hex->bytes notice-hex) (hex->bytes qb-hex))
      (unless (and to-us (equalp (op:field notice :manifest-hash) (getf a :hash)) (not (getf a :resolved))
                   (< (up:update-block-height qu) (getf a :expires)))
        (error "the migration was not dangling at the custody change"))
      (values notice qb qu l prefix))))

(defun obligation-owed (history acquire-update evidence height-of-block)
  "The owed obligation EVIDENCE (a plist: :source-notice-update/:source-qb-update hex, or
   :uncredited-proof JSON text) names: (values entries credited-p prefix), CREDITED-P a function
   (pu-seq) true when the new operator credited it after the acquire, at or before PU-SEQ.  With
   HEIGHT-OF-BLOCK a payment proof is verified against the history before the acquire."
  (let ((prefix (remove-if-not (lambda (u) (< (up:update-seq u) (up:update-seq acquire-update))) history))
        (aseq (up:update-seq acquire-update)))
    (if (getf evidence :uncredited-proof)
        (let* ((proof (json->proof (w:parse-json (getf evidence :uncredited-proof))))
               (txid (hex->bytes (e proof :txid))) (vout (e proof :vout)))
          (unless (and (eq (getf proof :type) :uncredited-onchain-payment) (e proof :offer-id)
                       (string-equal (getf proof :ledger-id) (bytes->hex (up:update-ledger-id acquire-update))))
            (error "not offer evidence against this ledger"))
          (when height-of-block
            (multiple-value-bind (ok why) (verify-uncredited-onchain proof prefix height-of-block)
              (unless ok (error "the payment proof does not verify before the custody change: ~a" why))))
          (values (list (payment-entry proof))
                  (lambda (pu-seq) (onchain-credited-p history pu-seq txid vout aseq))
                  prefix))
        (multiple-value-bind (notice qb) (obligation-context history acquire-update (getf evidence :source-notice-update)
                                                             (getf evidence :source-qb-update))
          (declare (ignore notice))
          (values (op:field qb :migration-manifest)
                  (lambda (pu-seq) (residue-credited-p history aseq pu-seq (op:field qb :new-outpoint-txid) (op:field qb :migration-vout)))
                  prefix)))))

(defun unhonoured-obligation-proof (history acquire-update confiscation-tx &key notice-update qb-update uncredited-proof)
  "DEP-06 producer: an UnhonouredObligation against the new operator (ACQUIRE-UPDATE's custodian)
   whose HISTORY (ascending) has an update its governing service_response_blocks past the acquire
   without crediting the residue — of a dangling migration (NOTICE-UPDATE, QB-UPDATE) or of a
   proven-uncredited payment (UNCREDITED-PROOF, its JSON text) — that CONFISCATION-TX did not pay.
   NIL otherwise."
  (ignore-errors
   (let ((ev (if uncredited-proof
                 (list :uncredited-proof uncredited-proof)
                 (list :source-notice-update (bytes->hex (up:encode-update notice-update))
                       :source-qb-update (bytes->hex (up:encode-update qb-update))))))
     (multiple-value-bind (entries credited-p) (obligation-owed history acquire-update ev nil)
       (when (unpaid-in-tx entries confiscation-tx)
         (let* ((srb (governing-service-response-blocks history (up:update-seq acquire-update)))
                (pu (car (last (remove-if (lambda (u) (< (up:update-block-height u) (+ (up:update-block-height acquire-update) srb))) history)))))
           (when (and pu (not (funcall credited-p (up:update-seq pu))))
             (list :type :unhonoured-obligation
                   :accused (bytes->hex (op:field (op:decode-operation (up:update-message acquire-update)) :new-custodian))
                   :ledger-id (bytes->hex (up:update-ledger-id acquire-update))
                   :evidence (list :source-notice-update (or (getf ev :source-notice-update) "")
                                   :source-qb-update (or (getf ev :source-qb-update) "")
                                   :uncredited-proof (or uncredited-proof "")
                                   :acquire-update (bytes->hex (up:encode-update acquire-update))
                                   :confiscation-tx (bytes->hex (btx:serialize-tx confiscation-tx :witness nil))
                                   :proof-update (bytes->hex (up:encode-update pu)))))))))))

(defun verify-unhonoured-obligation (proof history height-of-block)
  "DEP-06 §Confiscation obligations: the accused took custody (DisputeAcquire naming the
   confiscation), a dangling obligation's residue was not paid by that confiscation, and the
   accused signed PROOF-UPDATE its governing service_response_blocks after the acquire without
   crediting it.  HISTORY is the accused ledger's; (values ok reason)."
  (handler-case
      (let* ((au (up:decode-update (hex->bytes (e proof :acquire-update))))
             (ao (op:decode-operation (up:update-message au)))
             (tx (btx:parse-tx (bw:make-reader (hex->bytes (e proof :confiscation-tx)))))
             (pu (up:decode-update (hex->bytes (e proof :proof-update))))
             (in (lambda (u) (let ((o (find (up:update-seq u) history :key #'up:update-seq)))
                               (and o (equalp (up:chain-hash o) (up:chain-hash u))))))
             (ev (if (plusp (length (or (e proof :uncredited-proof) "")))
                     (list :uncredited-proof (e proof :uncredited-proof))
                     (list :source-notice-update (e proof :source-notice-update) :source-qb-update (e proof :source-qb-update)))))
        (if (not (and (eq (op:operation-type ao) :dispute-acquire) (funcall in au)
                      (string-equal (bytes->hex (op:field ao :new-custodian)) (getf proof :accused))
                      (equalp (op:field ao :confiscation-txid) (btx:tx-txid tx))))
            (values nil "acquire_update is not the accused's custody change naming this confiscation")
            (multiple-value-bind (entries credited-p prefix) (obligation-owed history au ev height-of-block)
              (let* ((vault-qb (find :quorum-begin (reverse prefix) :key (lambda (u) (op:operation-type (op:decode-operation (up:update-message u))))))
                     (vo (and vault-qb (op:decode-operation (up:update-message vault-qb))))
                     (in0 (first (btx:tx-inputs tx)))
                     (ah (funcall height-of-block (up:update-block-hash au)))
                     (ph (funcall height-of-block (up:update-block-hash pu)))
                     (srb (governing-service-response-blocks history (up:update-seq au))))
                (cond
                  ((not (and vo (equalp (btx:txin-prev-hash in0) (op:field vo :new-outpoint-txid))
                             (eql (btx:txin-prev-index in0) (op:field vo :new-outpoint-vout))))
                   (values nil "confiscation_tx does not spend the ledger's vault"))
                  ((null (unpaid-in-tx entries tx)) (values nil "the confiscation paid every entry: no residue"))
                  ((not (and (up:verify-operator-signature pu) (string-equal (bytes->hex (up:update-operator-id pu)) (getf proof :accused))
                             (equalp (up:update-ledger-id pu) (up:update-ledger-id au)) (funcall in pu)))
                   (values nil "proof_update is not the accused's update in its history"))
                  ((not (and ah ph (= ph (up:update-block-height pu)))) (values nil "the updates' blocks are not on the verifier's chain"))
                  ((< (- ph ah) srb) (values nil (format nil "the proof update is fewer than ~a blocks after the custody change" srb)))
                  ((funcall credited-p (up:update-seq pu)) (values nil "the residue was credited: not fraud"))
                  (t (values t nil)))))))
    (error (c) (values nil (princ-to-string c)))))

(defun verify-proof (proof &key history height-of-block)
  (case (getf proof :type)
    (:equivocation (verify-equivocation proof history))
    (:quorum-expired (verify-quorum-expired proof history height-of-block))
    (:non-conforming-update (verify-non-conforming-update proof history))
    (:dispute-dereliction (values nil "dereliction needs the defrauded ledger: verify-dispute-dereliction"))
    (:unhonoured-obligation (verify-unhonoured-obligation proof history height-of-block))
    (:uncredited-onchain-payment
     (if (e proof :source-qb-update)
         (verify-uncredited-migration proof history height-of-block)
         (verify-uncredited-onchain proof history height-of-block)))
    (t (values nil (format nil "cannot verify ~a here" (getf proof :type))))))

;;; ---------------------------------------------------------------------------
;;; JSON (the reference's serde shapes: externally tagged enums, hex for [u8;32])

(defun kebab->snake (k) (substitute #\_ #\- (string-downcase (symbol-name k))))
(defun snake->kebab (s) (intern (string-upcase (substitute #\- #\_ s)) :keyword))

(defun proof->json (proof)
  (let ((ev (w:json-object)))
    (loop for (k v) on (getf proof :evidence) by #'cddr
          do (setf (gethash (kebab->snake k) ev)
                   (cond ((eq k :original-proof) (proof->json v))
                         ((typep v '(vector (unsigned-byte 8))) (bytes->hex v))
                         (t v))))
    (w:json-object "proof_type" (cdr (assoc (getf proof :type) +type-names+))
                   "accused" (getf proof :accused) "ledger_id" (getf proof :ledger-id)
                   "evidence" (w:json-object (if (e proof :source-qb-update) "UncreditedMigration" (evidence-variant (getf proof :type))) ev))))

(defun evidence-variant (type)
  (case type (:uncredited-onchain-payment "UncreditedOnchain") (:uncredited-lightning-payment "UncreditedLightning")
        (:stale-cosignature "StaleCosign") (:non-conforming-update "NonConformingUpdate")
        (t (cdr (assoc type +type-names+)))))

(defparameter +hex-fields+ '(:spend-block-hash :anchor-block-hash :confirmed-at-block-hash :claim-block-hash :deposit-id))

(defun json->proof (j)
  (let* ((type (car (rassoc (w:jget j "proof_type") +type-names+ :test #'string=)))
         (evj (w:jget j "evidence"))
         (variant (and (hash-table-p evj) (car (loop for k being the hash-keys of evj collect k))))
         (fields (and variant (gethash variant evj)))
         (ev '()))
    (when (hash-table-p fields)
      (loop for k being the hash-keys of fields using (hash-value v)
            do (let ((kk (snake->kebab k)))
                 (setf ev (append ev (list kk (cond ((eq kk :original-proof) (json->proof v))
                                                     ((and (member kk +hex-fields+) (stringp v)) (hex->bytes v))
                                                     (t v))))))))
    (list :type type :accused (w:jget j "accused") :ledger-id (w:jget j "ledger_id") :evidence ev)))

(defun requires-embedding-p (type)
  "DEP-06 (Embedding): only a proof whose evidence is off the ledger or depends on
   when something was known needs its hash embedded and causally chained.  A proof
   that is itself cryptographic evidence of non-conformity (a non-conforming update,
   an equivocation, a stale or non-conforming co-signature, a winner collateral
   deviation, an expired quorum) needs neither, and verifiers must not require one.
   The reference classifies the same way (FraudProofType::requires_embedding)."
  (member type '(:uncredited-onchain-payment :uncredited-lightning-payment)))

(defun broadcast->json (proof &key embedding (causal-chain '()))
  "A self-evident proof goes out with no embedding key at all.  It used to carry a
   placeholder (sequence 0, field \"inline\"), which the reference rejected as
   'proof_hash not embedded' (docs/REDTEAM.md 9c)."
  (w:json-object "proof" (proof->json proof)
                 "embedding" (or embedding
                                 (and (requires-embedding-p (getf proof :type))
                                      ;; DEP-20 §8.3 migration evidence is self-evident (DEP-06)
                                      (not (e proof :source-qb-update))
                                      (w:json-object "ledger_id" (getf proof :ledger-id) "sequence" 0 "update_hash" "" "field" "inline")))
                 "causal_chain" (coerce causal-chain 'vector)))

(defun json->broadcast (j) (values (json->proof (w:jget j "proof")) (w:jget j "embedding") (w:jget j "causal_chain")))

;;; ---------------------------------------------------------------------------
;;; DEP-12: provable censorship.  Not a DEP-06 proof type yet in the reference;
;;; this is the verification the spec describes, over public ledger data.  Nothing
;;; acts on it yet (docs/REDTEAM.md, claims #3 and #5).
;;;
;;; The request must still have been servable when the deadline passed: its
;;; operation, replayed onto the operator's chain up to the breach, conforms
;;; (witness, nonce window, expiry at the breach height) and applies (balance).
;;; Otherwise a depositor could escalate a transfer, spend the same funds some
;;; other way before the deadline, and "prove" the first was censored; or a
;;; member could escalate a request no operator could serve.

(defun verify-censorship (request-content embed-update member-history operator-history
                          &key (service-response-blocks 72) processed-p)
  "REQUEST-CONTENT: the signed request's content string.  EMBED-UPDATE: the
   member's DeliveryEmbed update.  PROCESSED-P: (lambda (op)) -> true when an
   operator operation answers the request.  (values ok reason)."
  (let* ((h (sha256 (ascii->bytes request-content)))
         (embed-op (op:decode-operation (up:update-message embed-update)))
         (member-chain (make-hash-table :test #'equalp)))
    (dolist (u member-history) (setf (gethash (up:chain-hash u) member-chain) u))
    (cond
      ((not (eq (op:operation-type embed-op) :delivery-embed)) (values nil "not a DeliveryEmbed"))
      ((not (equalp (op:field embed-op :request-hash) h)) (values nil "embed does not commit to this request"))
      ((not (or (zerop (up:update-seq embed-update)) (gethash (up:update-prev-hash embed-update) member-chain)))
       (values nil "embed is not on the member's chain"))
      (t
       (let* ((member (up:update-operator-id embed-update))
              (embed-height (up:update-block-height embed-update))
              ;; content hashes of the member's ledger at and after the embed
              (later (mapcar #'up:content-hash (remove-if (lambda (u) (< (up:update-seq u) (up:update-seq embed-update))) member-history)))
              (link (find-if (lambda (u) (some (lambda (c) (and (equalp (up:cosig-pubkey c) member)
                                                               (member (up:cosig-member-ledger-hash c) later :test #'equalp)))
                                               (up:update-cosignatures u)))
                             operator-history))
              (deadline (+ embed-height service-response-blocks))
              (breach (find-if (lambda (u) (>= (up:update-block-height u) deadline)) operator-history))
              ;; An answer anywhere in the operator's history counts.  Only answers from
              ;; the causal link on were counted: an operator that served the request
              ;; before the member next cosigned was still "proven" to censor it.
              (answered (and processed-p
                             (some (lambda (u) (funcall processed-p (op:decode-operation (up:update-message u))))
                                   operator-history))))
         (cond ((null link) (values nil "no causal link: the member has not cosigned past the embed"))
               ((null breach) (values nil "deadline not reached"))
               (answered (values nil "the operator processed the request"))
               (t (let ((why (unservable-at request-content operator-history breach)))
                    (if why (values nil why) (values t nil))))))))))

(defun unservable-at (request-content operator-history breach)
  "NIL when the request's operation could have been served just before BREACH (the
   operator update that crosses the deadline), else why not."
  (let ((o (ignore-errors (op:decode-operation (base64-decode (w:jget (w:parse-json request-content) "operation"))))))
    (if (null o)
        "the request carries no operation to judge"
        (let ((state (ignore-errors (lg:replay (sort (remove-if-not (lambda (u) (< (up:update-seq u) (up:update-seq breach)))
                                                                    (copy-list operator-history))
                                                     #'< :key #'up:update-seq))))
              (height (up:update-block-height breach)))
          (cond ((null state) "the operator's chain up to the deadline does not replay")
                ((cf:violation state o height)
                 (format nil "the request was not servable at the deadline: ~a" (cf:violation state o height)))
                ((handler-case (let ((lg:*block-height* height)) (lg:apply-operation (lg:copy-ledger state) o) nil)
                   (lg:ledger-error (e) (format nil "the request was not servable at the deadline: ~a" e)))))))))
