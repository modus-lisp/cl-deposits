;;;; src/rotation.lisp — spending the reserves: rotation and recovery transactions.
;;;;
;;;; A rotation spends the old reserves UTXO through tier 0 into the new reserves
;;;; output, with an OP_RETURN anchor carrying its QuorumBegin's previous_hash
;;;; (DEP-03 §On-Chain State Anchor), at four feerates (§Fee ladder).  Recovery
;;;; spends use the timelocked tiers and set nLockTime accordingly.  Every
;;;; transaction built here is validated by cl-consensus's script interpreter in
;;;; the gate before we trust it.

(defpackage #:cl-deposits.rotation
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:rs #:cl-deposits.reserves) (#:tr #:cl-consensus.taproot-script)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire) (#:bs #:cl-consensus.script)
                    (#:schnorr #:secp256k1-fast.schnorr))
  (:export #:build-spend #:op-return-script #:tier-sighash #:sign-tier #:attach-tier-witness
           #:estimate-fee #:+sequence-rbf+ #:verify-spend
           #:rotation-vsize #:build-rotation #:+default-feerate+
           #:anchor-script #:anchor-of #:+rungs+ #:build-ladder #:ladder-fee-delta))
(in-package #:cl-deposits.rotation)

(defconstant +sequence-rbf+ #xfffffffd "ENABLE_RBF_NO_LOCKTIME: RBF on, CLTV usable.")

(defun op-return-script (data) (cat (octets #x6a (length data)) data))

(defconstant +rungs+ 4 "DEP-03 §Fee ladder: a rotation is signed at m, 2m, 4m and 8m.")

(defun anchor-script (h)
  "DEP-03 §On-Chain State Anchor: OP_RETURN <H>, the last output of every authorised vault spend."
  (unless (= (length h) 32) (error "an anchor is 32 bytes"))
  (cat (octets #x6a #x20) h))

(defun anchor-of (tx)
  "The 32-byte anchor H of TX: its last output, zero-valued, script exactly 6a20 || H.  NIL if none."
  (let ((o (car (last (btx:tx-outputs tx)))))
    (when o
      (let ((spk (btx:txout-script o)))
        (and (zerop (btx:txout-value o)) (= (length spk) 34) (= (aref spk 0) #x6a) (= (aref spk 1) #x20)
             (subseq spk 2))))))

(defun estimate-fee (n-outputs fee-rate-sat-vb)
  "The reference's estimate: 135 vbytes + 43 per output."
  (* (+ 135 (* 43 n-outputs)) fee-rate-sat-vb))

(defun build-spend (&key prev-txid prev-vout reserves-amount destination-spk (splits '())
                         (fee-rate 1) (locktime 0))
  "Unsigned spend of the reserves outpoint.  SPLITS is a list of (spk . sats)
   paid before the change to DESTINATION-SPK, which receives the rest less fee.
   Returns (values tx fee)."
  (let* ((fee (estimate-fee (1+ (length splits)) fee-rate))
         (split-total (reduce #'+ splits :key #'cdr))
         (consumed (+ split-total fee)))
    (when (>= consumed reserves-amount)
      (error "splits (~a) + fee (~a) exceed reserves (~a)" split-total fee reserves-amount))
    (values
     (btx:parse-tx
      (bw:make-reader
       (btx:serialize-tx
        (btx:make-tx :version 2 :locktime locktime :segwit-p t
                     :inputs (list (btx:make-txin :prev-hash prev-txid :prev-index prev-vout
                                                  :script (octets) :sequence +sequence-rbf+))
                     :outputs (append (loop for (spk . sats) in splits collect (btx:make-txout :value sats :script spk))
                                      (list (btx:make-txout :value (- reserves-amount consumed) :script destination-spk)))
                     :witnesses (list nil)))))
     fee)))

(defconstant +default-feerate+ 2 "sat/vB while no reference_feerate_sat_vb is recorded (DEP-03).")

(defun rotation-vsize (voters spk-lengths splice-p &optional splice-vault-p)
  "DEP-03 \"Rotation transaction\": 46 + 30 x VOTERS + sum (9 + len spk) + splice_vsize, the
   splice term 68 for a key-path or P2WPKH splice-in, 41 + 30 x VOTERS for one at the vault's own
   script (spent through the same tier)."
  (+ 46 (* 30 voters) (reduce #'+ spk-lengths :key (lambda (l) (+ 9 l)))
     (cond ((not splice-p) 0) (splice-vault-p (+ 41 (* 30 voters))) (t 68))))

(defun build-rotation (&key vault-txid vault-vout vault-sats voters (feerate +default-feerate+) (locktime 0)
                            new-vault-spk splice extras splice-vault-p anchor (rung 0))
  "DEP-03 \"Rotation transaction\", unsigned: version 2, nLockTime the tier's CLTV;
   input 0 the vault and input 1 SPLICE (txid vout sats), both #xfffffffd; output 0
   the new vault, then EXTRAS ((spk . sats) ...: the exits in recorded order, then the
   migration), last the ANCHOR (OP_RETURN <the QuorumBegin's previous_hash>).  RUNG i
   pays FEERATE x 2^i x rotation-vsize (§Fee ladder).  NIL if the new vault falls below 330."
  (unless anchor (error "a rotation carries an anchor (DEP-03)"))
  (let* ((fee (* feerate (expt 2 rung)
                 (rotation-vsize voters (append (list (length new-vault-spk)) (mapcar (lambda (e) (length (car e))) extras) (list 34))
                                 (and splice t) splice-vault-p)))
         (new (- (+ vault-sats (if splice (third splice) 0)) (reduce #'+ extras :key #'cdr) fee)))
    (when (>= new 330)
      ;; round-tripped, so the struct carries its txid (a rung's txid is recorded before it is signed)
      (btx:parse-tx
       (bw:make-reader
        (btx:serialize-tx
         (btx:make-tx :version 2 :locktime locktime :segwit-p t
                      :inputs (cons (btx:make-txin :prev-hash vault-txid :prev-index vault-vout :script (octets) :sequence +sequence-rbf+)
                                    (when splice
                                      (list (btx:make-txin :prev-hash (first splice) :prev-index (second splice) :script (octets)
                                                           :sequence +sequence-rbf+))))
                      :outputs (append (list (btx:make-txout :value new :script new-vault-spk))
                                       (loop for (spk . sats) in extras collect (btx:make-txout :value sats :script spk))
                                       (list (btx:make-txout :value 0 :script (anchor-script anchor))))
                      :witnesses (make-list (if splice 2 1)))))))))

(defun build-ladder (&rest args &key collateral-msats (max-rungs +rungs+) &allow-other-keys)
  "DEP-03 §Fee ladder: the rungs of a rotation, rung 0 first, each BUILD-ROTATION at 2^i x the
   feerate.  Rung i > 0 exists only while its new vault is at least 330 sats and its extra fee over
   rung 0 is at most COLLATERAL-MSATS / 1000 (the recording QuorumBegin's collateral_amount): the
   ladder stops at the first rung that fails.  MAX-RUNGS 1 for a rotation paying a migration
   output (DEP-03: its outpoint must not depend on which rung confirms).  NIL if rung 0 itself
   is below dust."
  (let* ((args (loop for (k v) on args by #'cddr unless (member k '(:collateral-msats :max-rungs)) append (list k v)))
         (r0 (apply #'build-rotation :rung 0 args)))
    (when r0
      (let ((v0 (btx:txout-value (first (btx:tx-outputs r0)))))
        (cons r0 (loop for i from 1 below (min max-rungs +rungs+)
                       for r = (apply #'build-rotation :rung i args)
                       while (and r (<= (* 1000 (- v0 (btx:txout-value (first (btx:tx-outputs r))))) (or collateral-msats 0)))
                       collect r))))))

(defun ladder-fee-delta (rungs txid)
  "Sats by which the rung with TXID pays more than rung 0 (the collateral it costs), or NIL."
  (let ((r (find txid rungs :key #'btx:tx-txid :test #'equalp)))
    (and r (- (btx:txout-value (first (btx:tx-outputs (first rungs)))) (btx:txout-value (first (btx:tx-outputs r)))))))

(defun tier-sighash (tx in-index prevouts leaf)
  "BIP-341 script-path sighash (SIGHASH_DEFAULT) for LEAF.  PREVOUTS is a vector
   of (amount . spk) for every input."
  (bs:taproot-sighash tx in-index prevouts 0 :ext-flag 1 :tapleaf-hash (tr::tapleaf-hash leaf)))

(defun sign-tier (tx in-index prevouts reserves tier-index privkeys &key (aux (make-array 32 :element-type '(unsigned-byte 8))))
  "Signatures for TIER-INDEX's leaf: a list parallel to the leaf's key order,
   with a 64-byte signature where PRIVKEYS holds the key (alist xonly -> priv)
   and NIL where it does not.  The operator-only leaf has a single slot."
  (let* ((tier (nth tier-index (rs:reserves-tiers reserves)))
         (leaf (nth tier-index (rs:reserves-leaves reserves)))
         (msg (tier-sighash tx in-index prevouts leaf))
         (keys (if (and (= (rs:tier-threshold tier) 1) (rs:tier-tie-breaker-p tier))
                   (list (cl-deposits.update:x-only (rs:reserves-operator reserves)))
                   (rs:tier-keys tier))))
    (loop for k in keys
          collect (let ((priv (cdr (assoc k privkeys :test #'equalp))))
                    (and priv (schnorr:schnorr-sign priv msg aux))))))

(defun attach-tier-witness (tx in-index reserves tier-index signatures)
  "Witness = [sig_{n-1} ... sig_0 (empty where absent), leaf script, control block]."
  (let* ((leaf (nth tier-index (rs:reserves-leaves reserves)))
         (control (rs:control-block-for-tier reserves tier-index))
         (stack (append (mapcar (lambda (s) (or s (octets))) (reverse signatures)) (list leaf control)))
         ;; an unsigned transaction parsed from its legacy form carries no witness list
         (witnesses (let ((w (copy-list (btx:tx-witnesses tx))))
                      (when (< (length w) (length (btx:tx-inputs tx)))
                        (setf w (append w (make-list (- (length (btx:tx-inputs tx)) (length w))))))
                      (setf (nth in-index w) stack) w)))
    (btx:parse-tx (bw:make-reader
                   (btx:serialize-tx
                    (btx:make-tx :version (btx:tx-version tx) :inputs (btx:tx-inputs tx) :outputs (btx:tx-outputs tx)
                                 :locktime (btx:tx-locktime tx) :witnesses witnesses :segwit-p t))))))

(defparameter +consensus-flags+ '(:p2sh :witness :taproot :cltv :csv :nulldummy :minimaldata)
  "What a post-Taproot node enforces.  Without :taproot a v1 output is anyone-can-spend.")

(defun verify-spend (tx in-index prevouts &key (flags +consensus-flags+))
  "Run cl-consensus's interpreter on input IN-INDEX with full enforcement.  T, or NIL."
  (let ((pv (aref prevouts in-index)))
    (handler-case (bs:verify-input tx in-index (cdr pv) (car pv) :prevouts prevouts :flags flags)
      (error () nil))))
