;;;; src/reserves.lisp — DEP-03 reserves: the Taproot output a ledger's funds live in.
;;;;
;;;; The internal key is a NUMS point (no key path).  The script tree is an
;;;; unbalanced "vine": tier leaves at depths 1, 2, 3, ... and a commitment leaf
;;;; (<ledger_hash> OP_DROP OP_0, unspendable) sharing the deepest level, so the
;;;; output commits to the chain hash at QuorumBegin.  Tier leaves are
;;;; k-of-n CHECKSIGADD scripts over the x-only keys of the VOTERS — the
;;;; operator (tie-breaker) and the quorum members — gated by absolute OP_CLTV
;;;; heights anchored to quorum_expiry, per the ledger's ruleset.
;;;;
;;;; Verified by reproducing a real mainnet reserves address from the fixture
;;;; ledger's QuorumBegin (inspect/reserves-test.lisp).

(defpackage #:cl-deposits.reserves
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:tr #:cl-consensus.taproot-script) (#:enc #:cl-consensus.encoding)
                    (#:up #:cl-deposits.update))
  (:export #:reserves #:make-reserves #:reserves-p #:build-reserves
           #:reserves-leaves #:reserves-tiers #:reserves-root #:reserves-spk #:reserves-address
           #:reserves-internal-key #:reserves-parity #:reserves-voters
           #:tier #:make-tier #:tier-threshold #:tier-tie-breaker-p #:tier-locktime #:tier-keys
           #:tiers-for #:leaf-script #:control-block-for-tier #:+nums-point+
           #:script-num #:push-int #:hrp-for))
(in-package #:cl-deposits.reserves)

(defparameter +nums-point+
  (hex->bytes "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
  "BIP-341's suggested unspendable internal key: H = lift_x(sha256(G))... as used by the reference.")

(defstruct tier threshold tie-breaker-p (locktime 0) description keys)

(defstruct (reserves (:constructor %make-reserves))
  operator members voters ruleset quorum-expiry ledger-hash network
  tiers leaves root internal-key spk parity address)

(defun make-reserves (&rest args) (apply #'build-reserves args))

;;; ---------------------------------------------------------------------------
;;; Rulesets: tier tables.  N is the VOTER count (operator + members).

(defun tiers-for (ruleset n quorum-expiry)
  (flet ((abs-h (offset) (if (zerop offset) 0 (+ quorum-expiry offset)))
         (mk (th tb lock desc) (make-tier :threshold th :tie-breaker-p tb :locktime lock :description desc)))
    (cond
      ((member ruleset '("cltv-offset-v2" "fee-cap-v3" "balance-commit-v4") :test #'string=)
       (if (<= n 2)
           (list (mk 2 nil (abs-h 0) "both") (mk 1 nil (abs-h 720) "single after expiry+5d")
                 (mk 1 t (abs-h 8064) "operator after expiry+8w"))
           (let ((majority (1+ (floor n 2))) (minority (max 1 (floor n 3))))
             (list (mk majority nil (abs-h 0) "majority") (mk minority nil (abs-h 720) "minority after expiry+5d")
                   (mk 1 nil (abs-h 4032) "single after expiry+4w") (mk 1 t (abs-h 8064) "operator after expiry+8w")))))
      ((string= ruleset "cltv-offset-literal")
       (if (<= n 2)
           (list (mk 2 nil 0 "both") (mk 1 nil 720 "single") (mk 1 t 8064 "operator"))
           (let ((majority (1+ (floor n 2))) (minority (max 1 (floor n 3))))
             (list (mk majority nil 0 "majority") (mk minority nil 720 "minority")
                   (mk 1 nil 4032 "single") (mk 1 t 8064 "operator")))))
      ((string= ruleset "legacy")
       (if (<= n 2)
           (list (mk 2 nil 0 "both") (mk 1 t 2016 "operator after 2016") (mk 1 nil 4032 "emergency"))
           (let ((majority (1+ (floor n 2))) (minority (max 1 (floor n 3))))
             (list (mk majority nil 0 "majority") (mk minority nil 1008 "minority after 1008")
                   (mk 1 t 2016 "operator after 2016") (mk 1 nil 4032 "emergency")))))
      (t (error "unknown ruleset ~s" ruleset)))))

;;; ---------------------------------------------------------------------------
;;; Script assembly

(defun script-num (n)
  "CScriptNum: minimal little-endian, sign bit padded.  Positive heights only here."
  (if (zerop n)
      (octets)
      (let ((bytes '()))
        (loop for v = n then (ash v -8) while (plusp v) do (push (logand v #xff) bytes))
        (setf bytes (nreverse bytes))
        (when (logbitp 7 (car (last bytes))) (setf bytes (append bytes (list 0))))
        (apply #'octets bytes))))

(defun push-int (n)
  "rust-bitcoin Builder::push_int: OP_0/OP_1..OP_16 where possible, else a data push."
  (cond ((zerop n) (octets 0))
        ((<= 1 n 16) (octets (+ #x50 n)))
        (t (let ((b (script-num n))) (cat (octets (length b)) b)))))

(defun push-bytes (b) (cat (octets (length b)) b))   ; all pushes here are <= 75 bytes

(defconstant +op-drop+ #x75) (defconstant +op-cltv+ #xb1) (defconstant +op-checksig+ #xac)
(defconstant +op-checksigadd+ #xba) (defconstant +op-greaterthanorequal+ #xa2)

(defun sorted-xonly (keys33) (sort (mapcar #'up:x-only keys33) #'bytes<))

(defun leaf-script (tier operator voters)
  "TIER's leaf over VOTERS (33-byte keys; OPERATOR is the tie-breaker among them)."
  (let ((prefix (if (plusp (tier-locktime tier))
                    (cat (push-int (tier-locktime tier)) (octets +op-cltv+ +op-drop+))
                    (octets))))
    (if (and (= (tier-threshold tier) 1) (tier-tie-breaker-p tier))
        (cat prefix (push-bytes (up:x-only operator)) (octets +op-checksig+))
        (let ((keys (sorted-xonly voters)))
          (setf (tier-keys tier) keys)
          (apply #'cat prefix (push-bytes (first keys)) (octets +op-checksig+)
                 (append (loop for k in (rest keys) collect (cat (push-bytes k) (octets +op-checksigadd+)))
                         (list (push-int (tier-threshold tier)) (octets +op-greaterthanorequal+))))))))

(defun commitment-leaf (ledger-hash) (cat (push-bytes ledger-hash) (octets +op-drop+ 0)))

(defun vine-root (leaf-hashes)
  "Leaves at depths 1, 2, ..., d, d: fold from the deepest pair upward."
  (let ((acc (car (last leaf-hashes))))
    (loop for h in (cdr (reverse leaf-hashes)) do (setf acc (tr::tapbranch-hash h acc)))
    acc))

(defun vine-path (leaf-hashes index)
  "Merkle path (sibling hashes, leaf to root) for the leaf at INDEX in the vine.
   For the two deepest leaves the first sibling is the other one; above that,
   each level's sibling is the shallower leaf."
  (let* ((n (length leaf-hashes)) (path '()))
    (if (>= index (- n 2))
        (progn (push (nth (if (= index (- n 1)) (- n 2) (- n 1)) leaf-hashes) path)
               (loop for i from (- n 3) downto 0 do (push (nth i leaf-hashes) path)))
        (let ((acc (car (last leaf-hashes))))
          ;; subtree hash below INDEX's level
          (loop for i from (- n 2) downto (1+ index) do (setf acc (tr::tapbranch-hash (nth i leaf-hashes) acc)))
          (push acc path)
          (loop for i from (1- index) downto 0 do (push (nth i leaf-hashes) path))))
    (nreverse path)))

(defun hrp-for (network) (ecase network (:mainnet "bc") ((:testnet :signet) "tb") (:regtest "bcrt")))

(defun build-reserves (&key operator members ledger-hash quorum-expiry (ruleset "cltv-offset-v2")
                            (network :mainnet) (internal-key +nums-point+))
  (let* ((voters (cons operator members))
         (tiers (tiers-for ruleset (length voters) quorum-expiry))
         (leaves (append (mapcar (lambda (tier) (leaf-script tier operator voters)) tiers)
                         (list (commitment-leaf ledger-hash))))
         (hashes (mapcar #'tr::tapleaf-hash leaves))
         (root (vine-root hashes)))
    (multiple-value-bind (spk parity) (tr::taproot-output-spk-from-root internal-key root)
      (%make-reserves :operator operator :members members :voters voters :ruleset ruleset
                      :quorum-expiry quorum-expiry :ledger-hash ledger-hash :network network
                      :tiers tiers :leaves leaves :root root :internal-key internal-key
                      :spk spk :parity parity
                      :address (enc:segwit-encode (hrp-for network) 1 (subseq spk 2))))))

(defun control-block-for-tier (r index)
  (let ((hashes (mapcar #'tr::tapleaf-hash (reserves-leaves r))))
    (apply #'cat (octets (logior #xc0 (reserves-parity r))) (reserves-internal-key r)
           (vine-path hashes index))))
