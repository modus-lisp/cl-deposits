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
           #:make-quorum-expired-proof #:make-non-conforming-update-proof #:verify-censorship
           #:make-non-conforming-cosignature-proof #:verify-non-conforming-cosignature
           #:make-dispute-dereliction-proof #:verify-dispute-dereliction
           #:make-unauthorized-vault-spend-proof #:verify-unauthorized-vault-spend #:vault-spend-signers))
(in-package #:cl-deposits.fraud)

(defparameter +types+
  '((:uncredited-onchain-payment . 1) (:uncredited-lightning-payment . 2) (:stale-cosignature . 3)
    (:dispute-dereliction . 4) (:non-conforming-update . 5) (:quorum-expired . 6)
    (:winner-collateral-deviation . 7) (:equivocation . 8) (:non-conforming-cosignature . 9)
    (:unauthorized-vault-spend . 10)))

(defparameter +type-names+
  '((:uncredited-onchain-payment . "UncreditedOnchainPayment") (:uncredited-lightning-payment . "UncreditedLightningPayment")
    (:stale-cosignature . "StaleCosignature") (:dispute-dereliction . "DisputeDereliction")
    (:non-conforming-update . "NonConformingUpdate") (:quorum-expired . "QuorumExpired")
    (:winner-collateral-deviation . "WinnerCollateralDeviation") (:equivocation . "Equivocation")
    (:non-conforming-cosignature . "NonConformingCosignature")
    (:unauthorized-vault-spend . "UnauthorizedVaultSpend")))

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
         (cat (s :offer-id) (int->le (getf ev :deadline-block) 4) (s :txid) (int->le (getf ev :vout) 4)
              (int->le (getf ev :amount-sats) 8) (b :confirmed-at-block-hash)))
        (:dispute-dereliction (cat (s :original-fraud-hash) (b :original-fraud-block-hash) (s :member-ledger-id) (s :member-pubkey)))
        (:unauthorized-vault-spend
         (cat (s :spent-ledger-id) (int->le (getf ev :governing-quorumbegin-seq) 8) (s :spend-tx-hex) (b :spend-block-hash)))
        (:winner-collateral-deviation (cat (s :winner-armed-update-hex) (s :claim-txid) (b :claim-block-hash)))))))

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

(defun make-dispute-dereliction-proof (member33 member-ledger-id32 original-fraud-hash32 original-fraud-block-hash32
                                       required-response-blocks member-active-update)
  "DEP-19 §6: MEMBER kept operating (MEMBER-ACTIVE-UPDATE, past the window) without acting on
   the fraud proof ORIGINAL-FRAUD-HASH, embedded at ORIGINAL-FRAUD-BLOCK-HASH.  Presented on
   the member's own ledger to slash it."
  (list :type :dispute-dereliction :accused (bytes->hex member33) :ledger-id (bytes->hex member-ledger-id32)
        :evidence (list :original-fraud-hash (bytes->hex original-fraud-hash32)
                        :original-fraud-block-hash original-fraud-block-hash32
                        :required-response-blocks required-response-blocks
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
              ((not (accused-operates-p (getf proof :accused) history seq))
               (values nil "the accused does not operate the ledger at that sequence"))
              ((/= seq (e proof :fault-sequence)) (values nil "sequence mismatch"))
              ((not (update-binds-to-ledger-p fault id bound))
               (values nil "fault follows no update of this ledger: nothing binds it here (ledger_id is unsigned)"))
              ((/= (length prefix) seq) (values nil "history does not reach the fault's predecessor"))
              ((and (plusp seq) (/= (gethash (up:update-prev-hash fault) bound) (1- seq)))
               (values t (format nil "fault at seq ~a follows seq ~a" seq (gethash (up:update-prev-hash fault) bound))))
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

(defun verify-dispute-dereliction (proof member-history height-of-block)
  "DEP-19 §6 / DEP-11 §Dispute Participation.  MEMBER-HISTORY is the accused member's own
   ledger (the one being slashed).  The member kept operating past the response window
   without acting on a fraud proof: the original proof was embedded at a block the verifier
   confirms, and the member signed an update of its own whose (v2-signed) block_height is at
   least REQUIRED-RESPONSE-BLOCKS later.  Matches the reference's verify_inactive_quorum_member
   (its fields; the extra two are not in the proof hash, see EVIDENCE-BYTES)."
  (handler-case
      (let* ((orig-h (funcall height-of-block (e proof :original-fraud-block-hash)))
             (seq (e proof :member-active-sequence))
             (member-update (find seq member-history :key #'up:update-seq))
             (required (e proof :required-response-blocks)))
        (cond ((null orig-h) (values nil "original-fraud block not in our chain"))
              ((null member-update) (values nil "member-active update not in the member's history"))
              ((not (string= (bytes->hex (up:update-operator-id member-update)) (e proof :member-pubkey)))
               (values nil "member-active update not signed by the accused member"))
              ((< (- (up:update-block-height member-update) orig-h) required)
               (values nil (format nil "member-active block only ~a past the original fraud; need ~a"
                                   (- (up:update-block-height member-update) orig-h) required)))
              (t (values t nil))))
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

(defun verify-proof (proof &key history height-of-block)
  (case (getf proof :type)
    (:equivocation (verify-equivocation proof history))
    (:quorum-expired (verify-quorum-expired proof history height-of-block))
    (:non-conforming-update (verify-non-conforming-update proof history))
    (:dispute-dereliction (verify-dispute-dereliction proof history height-of-block))
    (t (values nil (format nil "cannot verify ~a here" (getf proof :type))))))

;;; ---------------------------------------------------------------------------
;;; JSON (the reference's serde shapes: externally tagged enums, hex for [u8;32])

(defun kebab->snake (k) (substitute #\_ #\- (string-downcase (symbol-name k))))
(defun snake->kebab (s) (intern (string-upcase (substitute #\- #\_ s)) :keyword))

(defun proof->json (proof)
  (let ((ev (w:json-object)))
    (loop for (k v) on (getf proof :evidence) by #'cddr
          do (setf (gethash (kebab->snake k) ev) (if (typep v '(vector (unsigned-byte 8))) (bytes->hex v) v)))
    (w:json-object "proof_type" (cdr (assoc (getf proof :type) +type-names+))
                   "accused" (getf proof :accused) "ledger_id" (getf proof :ledger-id)
                   "evidence" (w:json-object (evidence-variant (getf proof :type)) ev))))

(defun evidence-variant (type)
  (case type (:uncredited-onchain-payment "UncreditedOnchain") (:uncredited-lightning-payment "UncreditedLightning")
        (:stale-cosignature "StaleCosign") (:non-conforming-update "NonConformingUpdate")
        (t (cdr (assoc type +type-names+)))))

(defparameter +hex-fields+ '(:spend-block-hash :anchor-block-hash :confirmed-at-block-hash :original-fraud-block-hash :claim-block-hash :deposit-id))

(defun json->proof (j)
  (let* ((type (car (rassoc (w:jget j "proof_type") +type-names+ :test #'string=)))
         (evj (w:jget j "evidence"))
         (variant (and (hash-table-p evj) (car (loop for k being the hash-keys of evj collect k))))
         (fields (and variant (gethash variant evj)))
         (ev '()))
    (when (hash-table-p fields)
      (loop for k being the hash-keys of fields using (hash-value v)
            do (let ((kk (snake->kebab k)))
                 (setf ev (append ev (list kk (if (and (member kk +hex-fields+) (stringp v)) (hex->bytes v) v)))))))
    (list :type type :accused (w:jget j "accused") :ledger-id (w:jget j "ledger_id") :evidence ev)))

(defun requires-embedding-p (type)
  "DEP-06 (Embedding): only a proof whose evidence is off the ledger or depends on
   when something was known needs its hash embedded and causally chained.  A proof
   that is itself cryptographic evidence of non-conformity (a non-conforming update,
   an equivocation, a stale or non-conforming co-signature, a winner collateral
   deviation, an expired quorum) needs neither, and verifiers must not require one.
   The reference classifies the same way (FraudProofType::requires_embedding)."
  (member type '(:uncredited-onchain-payment :uncredited-lightning-payment :dispute-dereliction)))

(defun broadcast->json (proof &key embedding (causal-chain '()))
  "A self-evident proof goes out with no embedding key at all.  It used to carry a
   placeholder (sequence 0, field \"inline\"), which the reference rejected as
   'proof_hash not embedded' (docs/REDTEAM.md 9c)."
  (w:json-object "proof" (proof->json proof)
                 "embedding" (or embedding
                                 (and (requires-embedding-p (getf proof :type))
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
