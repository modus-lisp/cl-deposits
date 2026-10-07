;;;; src/rotation.lisp — spending the reserves: rotation and recovery transactions.
;;;;
;;;; A rotation spends the old reserves UTXO through tier 0 into the new reserves
;;;; output, with an OP_RETURN carrying the chain_hash at QuorumBegin (DEP-03
;;;; §On-Chain State Anchor).  Recovery spends use the timelocked tiers and set
;;;; nLockTime accordingly.  Every transaction built here is validated by
;;;; cl-consensus's script interpreter in the gate before we trust it.

(defpackage #:cl-deposits.rotation
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:rs #:cl-deposits.reserves) (#:tr #:cl-consensus.taproot-script)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire) (#:bs #:cl-consensus.script)
                    (#:schnorr #:secp256k1-fast.schnorr))
  (:export #:build-spend #:op-return-script #:tier-sighash #:sign-tier #:attach-tier-witness
           #:estimate-fee #:+sequence-rbf+ #:verify-spend
           #:rotation-vsize #:build-rotation #:+default-feerate+))
(in-package #:cl-deposits.rotation)

(defconstant +sequence-rbf+ #xfffffffd "ENABLE_RBF_NO_LOCKTIME: RBF on, CLTV usable.")

(defun op-return-script (data) (cat (octets #x6a (length data)) data))

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

(defun rotation-vsize (voters spk-lengths splice-p)
  "DEP-03 \"Rotation transaction\": 46 + 30 x VOTERS + sum (9 + len spk) + 68 x [splice-in]."
  (+ 46 (* 30 voters) (reduce #'+ spk-lengths :key (lambda (l) (+ 9 l))) (if splice-p 68 0)))

(defun build-rotation (&key vault-txid vault-vout vault-sats voters (feerate +default-feerate+) (locktime 0)
                            new-vault-spk splice extras)
  "DEP-03 \"Rotation transaction\", unsigned: version 2, nLockTime the tier's CLTV;
   input 0 the vault and input 1 SPLICE (txid vout sats), both #xfffffffd; output 0
   the new vault, then EXTRAS ((spk . sats) ...: the exits in recorded order, then the
   migration).  Fee feerate x rotation-vsize.  NIL if the new vault falls below 330."
  (let* ((fee (* feerate (rotation-vsize voters (cons (length new-vault-spk) (mapcar (lambda (e) (length (car e))) extras))
                                         (and splice t))))
         (new (- (+ vault-sats (if splice (third splice) 0)) (reduce #'+ extras :key #'cdr) fee)))
    (when (>= new 330)
      (btx:make-tx :version 2 :locktime locktime :segwit-p t
                   :inputs (cons (btx:make-txin :prev-hash vault-txid :prev-index vault-vout :script (octets) :sequence +sequence-rbf+)
                                 (when splice
                                   (list (btx:make-txin :prev-hash (first splice) :prev-index (second splice) :script (octets)
                                                        :sequence +sequence-rbf+))))
                   :outputs (cons (btx:make-txout :value new :script new-vault-spk)
                                  (loop for (spk . sats) in extras collect (btx:make-txout :value sats :script spk)))
                   :witnesses (make-list (if splice 2 1))))))

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
         (witnesses (let ((w (copy-list (btx:tx-witnesses tx)))) (setf (nth in-index w) stack) w)))
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
