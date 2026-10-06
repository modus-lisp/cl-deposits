;;;; src/lottery.lisp — DEP-03/06 custody lottery: the on-chain selection of a
;;;; disputed ledger's new custodian.
;;;;
;;;; Participants each commit HASH160(preimage); LEN(preimage) - 16 is their
;;;; contribution in 1..60, independent of how many arm.  The lottery output has a
;;;; full-set leaf (every preimage, winner = sum mod k), a CSV-72 leaf per nonempty
;;;; proper subset S of the participants (a threshold of recovery voters attests S,
;;;; then sum over S mod |S|), a recovery cascade (CSV 144/1008/4032, thresholds
;;;; T/T-1/T-2) and an escape hatch (CSV 8064, one voter).  A withholder is simply
;;;; outside S.  Armer shares (punitive confiscations) are reveal-or-sweep outputs.
;;;;
;;;; Scripts are reproduced opcode for opcode from the reference; the gate
;;;; spends every leaf under cl-consensus's interpreter.

(defpackage #:cl-deposits.lottery
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:rs #:cl-deposits.reserves) (#:tr #:cl-consensus.taproot-script)
                    (#:enc #:cl-consensus.encoding) (#:up #:cl-deposits.update))
  (:export #:participant #:make-participant #:participant-pubkey #:participant-commitment #:participant-target
           #:lottery-script #:subset-leaves #:claim-body #:recovery-script #:build-lottery #:lottery-subsets
           #:subset-leaf-index #:subset-witness #:subset-winner #:attest-voters
           #:lottery #:lottery-leaves #:lottery-root #:lottery-spk #:lottery-address #:lottery-participants
           #:lottery-recovery-voters #:lottery-recovery-threshold #:lottery-control-block
           #:calculate-winner #:derive-preimage #:commitment-of #:claim-witness
           #:recovery-witness #:build-armer-share #:armer-share #:armer-share-spk #:armer-share-address
           #:armer-share-leaves #:armer-share-control-block #:forfeit-sweep-outputs
           #:confiscation-outputs #:revealers-from-witness #:tapbuilder-tree #:p2tr-spk #:key-path-spk
           #:+reveal-csv+ #:+armer-sweep-csv+ #:+max-disputants+ #:+timeout-recovery-csv+
           #:+contribution-range+ #:+max-preimage-len+ #:confiscation-fee #:+confiscation-default-feerate+))
(in-package #:cl-deposits.lottery)

(defconstant +max-disputants+ 7 "MAX_LOTTERY_PARTICIPANTS: the subset tree has 2^k - 1 claim leaves.")
(defconstant +reveal-csv+ 72 "The reveal deadline: subset leaves open this many blocks after the confiscation.")
(defconstant +contribution-range+ 60 "Contributions 1..60: uniform mod every m in 1..6 (60 = lcm(1..6)).")
(defconstant +max-preimage-len+ (+ 16 +contribution-range+) "76 bytes, within the 80-byte standard tapscript stack item.")
(defconstant +armer-sweep-csv+ 144)
(defconstant +timeout-recovery-csv+ 8064)
(defconstant +p2wsh-dust+ 330)
(defconstant +p2wpkh-dust+ 294)

(defstruct participant pubkey commitment target)   ; xonly32, hash160 20, target address string

;;; opcodes
(defconstant +op-0+ #x00) (defconstant +op-if+ #x63) (defconstant +op-else+ #x67) (defconstant +op-endif+ #x68)
(defconstant +op-verify+ #x69) (defconstant +op-toalt+ #x6b) (defconstant +op-fromalt+ #x6c)
(defconstant +op-drop+ #x75) (defconstant +op-dup+ #x76) (defconstant +op-swap+ #x7c) (defconstant +op-size+ #x82)
(defconstant +op-equal+ #x87) (defconstant +op-equalverify+ #x88) (defconstant +op-add+ #x93) (defconstant +op-sub+ #x94)
(defconstant +op-lessthanorequal+ #xa1) (defconstant +op-greaterthanorequal+ #xa2) (defconstant +op-hash160+ #xa9)
(defconstant +op-checksig+ #xac) (defconstant +op-csv+ #xb2) (defconstant +op-checksigadd+ #xba)

(defun pushb (b) (cat (octets (length b)) b))
(defun pint (n) (rs:push-int n))

(defun hash160 (bytes) (cl-consensus.wire:hash160 (coerce bytes (quote octets))))
(defun commitment-of (preimage) (hash160 preimage))

;;; ---------------------------------------------------------------------------
;;; Scripts

(defun claim-body (members)
  "Verify each member's preimage (hash, 17..76 bytes), sum the contributions, and
   let only member (sum mod m) spend.  MEMBERS in canonical order."
  (let ((m (length members)) (parts '()))
    (flet ((emit (&rest bs) (dolist (b bs) (push (if (integerp b) (octets b) b) parts))))
      (loop for p in members for i from 0
            do (emit +op-dup+ +op-hash160+ (pushb (participant-commitment p)) +op-equalverify+
                     +op-size+ +op-dup+ (pint 17) +op-greaterthanorequal+ +op-verify+
                     +op-dup+ (pint +max-preimage-len+) +op-lessthanorequal+ +op-verify+
                     +op-swap+ +op-drop+ (pint 16) +op-sub+)
               (when (< i (1- m)) (emit +op-toalt+)))
      (dotimes (i (1- m)) (emit +op-fromalt+ +op-add+))
      (if (= m 1)
          (emit +op-drop+ (pushb (participant-pubkey (first members))) +op-checksig+)
          (progn
            ;; the sum is below 64m: six conditional subtractions of m*2^b reduce it mod m
            (loop for b from 5 downto 0
                  do (let ((x (* m (ash 1 b)))) (emit +op-dup+ (pint x) +op-greaterthanorequal+ +op-if+ (pint x) +op-sub+ +op-endif+)))
            (loop for p in members for i from 0
                  do (emit +op-dup+ (pint i) +op-equal+ +op-if+ +op-drop+ (pushb (participant-pubkey p)) +op-checksig+ +op-else+))
            (emit +op-drop+ +op-0+)
            (dotimes (i m) (emit +op-endif+)))))
    (apply #'cat (nreverse parts))))

(defun lottery-script (participants)
  "The full-set claim leaf.  DEP-03: a sole eligible armer takes custody without a
   draw; its leaf is a plain signature check and no preimage is revealed."
  (let ((k (length participants)))
    (cond ((= k 1) (cat (pushb (participant-pubkey (first participants))) (octets +op-checksig+)))
          ((<= 2 k +max-disputants+) (claim-body participants))
          (t (error "lottery needs 1..~a participants" +max-disputants+)))))

(defun csv-prefix (blocks) (cat (pint blocks) (octets +op-csv+ +op-drop+)))

(defun attest-voters (voters threshold)
  "Recovery voters attesting a revealer subset: all of them, sorted, CHECKSIGADD, >= T."
  (let ((keys (sorted-keys voters)))
    (when (< (length keys) threshold) (error "not enough recovery voters"))
    (apply #'cat (pushb (first keys)) (octets +op-checksig+)
           (append (loop for k in (rest keys) collect (cat (pushb k) (octets +op-checksigadd+)))
                   (list (pint threshold) (octets +op-greaterthanorequal+ +op-verify+))))))

(defun subset-indices (k)
  "Nonempty proper subsets of 0..k-1: by decreasing size, then lexicographically."
  (labels ((combos (start m) (if (zerop m) (list '())
                                  (loop for i from start to (- k m) append (mapcar (lambda (c) (cons i c)) (combos (1+ i) (1- m)))))))
    (loop for m from (1- k) downto 1 append (combos 0 m))))

(defun subset-leaves (participants voters threshold)
  "(indices . leaf) for every nonempty proper subset; none for k < 2."
  (let ((k (length participants)))
    (when (>= k 2)
      (loop for idx in (subset-indices k)
            collect (cons idx (cat (csv-prefix +reveal-csv+) (attest-voters voters threshold)
                                   (claim-body (mapcar (lambda (i) (nth i participants)) idx))))))))

(defun sorted-keys (xonlys) (sort (copy-list xonlys) #'bytes<))

(defun recovery-script (voters threshold csv-blocks)
  (let ((keys (sorted-keys voters)))
    (when (< (length keys) threshold) (error "not enough recovery voters"))
    (if (= threshold 1)
        (cat (csv-prefix csv-blocks) (pushb (first keys)) (octets +op-checksig+))
        (apply #'cat (csv-prefix csv-blocks) (pushb (first keys)) (octets +op-checksig+)
               (append (loop for k in (rest keys) collect (cat (pushb k) (octets +op-checksigadd+)))
                       (list (pint threshold) (octets +op-greaterthanorequal+)))))))

(defun recovery-specs (threshold)
  (list (cons 144 threshold) (cons 1008 (max 1 (1- threshold))) (cons 4032 (max 1 (- threshold 2)))
        (cons +timeout-recovery-csv+ 1)))

;;; ---------------------------------------------------------------------------
;;; The tree, as rust-bitcoin's TaprootBuilder builds it from (depth, leaf) in
;;; order: a stack of nodes; whenever the two on top share a depth they merge
;;; into one a level up.  Returns (values root paths) with paths parallel to
;;; the leaves (sibling hashes, leaf to root).

(defun tapbuilder-tree (leaf-hashes depths)
  (let ((stack '()) (paths (make-array (length leaf-hashes) :initial-element nil)))
    (loop for h in leaf-hashes for d in depths for i from 0
          do (push (list h d (list i)) stack)
             (loop while (and (cdr stack) (= (second (first stack)) (second (second stack))))
                   do (let ((b (pop stack)) (a (pop stack)))
                        (dolist (li (third a)) (push (first b) (aref paths li)))
                        (dolist (li (third b)) (push (first a) (aref paths li)))
                        (push (list (tr::tapbranch-hash (first a) (first b)) (1- (second a)) (append (third a) (third b))) stack))))
    (unless (and stack (null (cdr stack)) (zerop (second (first stack)))) (error "leaf depths do not form a tree"))
    (values (first (first stack)) (loop for i below (length leaf-hashes) collect (reverse (aref paths i))))))

(defun leaf-depths (m)
  "The reference's shape for M leaves: the first 2(m - 2^(dmax-1)) at depth
   dmax, the rest at dmax-1 (all at dmax when m is a power of two)."
  (if (= m 1) (list 0)
      (let* ((dmax (integer-length (1- m)))
             (deep (if (= m (ash 1 dmax)) m (* 2 (- m (ash 1 (1- dmax)))))))
        (append (make-list deep :initial-element dmax) (make-list (- m deep) :initial-element (1- dmax))))))

(defun p2tr-spk (xonly-internal root)
  (multiple-value-bind (spk parity) (tr::taproot-output-spk-from-root xonly-internal root) (values spk parity)))

(defstruct (lottery (:constructor %make-lottery))
  participants recovery-voters recovery-threshold network leaves paths root spk parity address subsets)

(defun build-lottery (participants recovery-voters recovery-threshold &key (network :signet))
  "PARTICIPANTS are sorted by pubkey here (the canonical disputant order)."
  (let* ((ps (sort (copy-list participants) #'bytes< :key #'participant-pubkey))
         (subsets (subset-leaves ps recovery-voters recovery-threshold))
         (leaves (append (list (lottery-script ps)) (mapcar #'cdr subsets)
                         (loop for (csv . th) in (recovery-specs recovery-threshold)
                               collect (recovery-script recovery-voters th csv))))
         (hashes (mapcar #'tr::tapleaf-hash leaves)))
    (multiple-value-bind (root paths) (tapbuilder-tree hashes (leaf-depths (length leaves)))
      (multiple-value-bind (spk parity) (p2tr-spk rs:+nums-point+ root)
        (%make-lottery :participants ps :recovery-voters recovery-voters :recovery-threshold recovery-threshold
                       :network network :leaves leaves :paths paths :root root :spk spk :parity parity
                       :subsets (mapcar #'car subsets)
                       :address (enc:segwit-encode (rs:hrp-for network) 1 (subseq spk 2)))))))

(defun lottery-control-block (l leaf-index)
  (apply #'cat (octets (logior #xc0 (lottery-parity l))) rs:+nums-point+ (nth leaf-index (lottery-paths l))))

;;; ---------------------------------------------------------------------------
;;; Winner, preimages, witnesses

(defun calculate-winner (preimages)
  "Index of the winner among PREIMAGES (in canonical member order): sum of
   (LEN - 16) mod their count.  Every preimage must be 17..76 bytes."
  (let ((n (length preimages)))
    (when (< n 1) (error "need at least 1 preimage"))
    (mod (loop for p in preimages
               do (unless (<= 17 (length p) +max-preimage-len+) (error "preimage length ~a out of 17..~a" (length p) +max-preimage-len+))
               sum (- (length p) 16))
         n)))

(defun subset-winner (indices preimages)
  "The participant index (into the full canonical order) that wins the draw over
   INDICES, given PREIMAGES parallel to INDICES."
  (nth (calculate-winner preimages) indices))

(defun derive-preimage (seed32)
  "Length 17 + (seed mod 60); bytes from SHA256(\"deposits/lottery/preimage/v2\" ||
   seed || counter_le32), expanded by counter."
  (let* ((length (+ 17 (mod (be->int seed32) +contribution-range+)))
         (out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for counter from 0 while (< (length out) length)
          do (let ((block (sha256 (cat (ascii->bytes "deposits/lottery/preimage/v2") seed32 (int->le counter 4)))))
               (loop for b across block while (< (length out) length) do (vector-push-extend b out))))
    (coerce out 'octets)))

(defun claim-witness (l winner-sig preimages)
  "[sig, preimage_{n-1} ... preimage_0, leaf, control]."
  (unless (= (length preimages) (length (lottery-participants l))) (error "need every preimage"))
  (append (list winner-sig)
          (and (> (length preimages) 1) (reverse preimages))   ; a sole participant's leaf checks only the signature
          (list (first (lottery-leaves l)) (lottery-control-block l 0))))

(defun subset-leaf-index (l indices)
  (let ((pos (position indices (lottery-subsets l) :test #'equal)))
    (unless pos (error "no claim leaf for subset ~a" indices))
    (1+ pos)))

(defun subset-witness (l indices winner-sig preimages voter-sigs)
  "PREIMAGES parallel to INDICES; VOTER-SIGS parallel to the sorted voters, NIL
   where absent.  [sig, pre_{m-1}..pre_0, vsig_{r-1}..vsig_0, leaf, control]."
  (let ((i (subset-leaf-index l indices)))
    (append (list winner-sig) (reverse preimages)
            (reverse (mapcar (lambda (s) (or s (octets))) voter-sigs))
            (list (nth i (lottery-leaves l)) (lottery-control-block l i)))))

(defun recovery-leaf-index (l tier) (+ 1 (length (lottery-subsets l)) tier))

(defun recovery-witness (l tier signatures)
  "TIER 0..3 = CSV 144/1008/4032/8064.  SIGNATURES parallel the sorted voter
   order, NIL where absent (empty push).  A threshold-1 leaf names only the
   lowest sorted voter key, so only that voter can use it."
  (let* ((idx (recovery-leaf-index l tier)) (th (cdr (nth tier (recovery-specs (lottery-recovery-threshold l))))))
    (append (if (= th 1)
                (list (or (find-if #'identity signatures) (error "need one signature")))
                (mapcar (lambda (s) (or s (octets))) (reverse signatures)))
            (list (nth idx (lottery-leaves l)) (lottery-control-block l idx)))))

;;; ---------------------------------------------------------------------------
;;; Armer shares (punitive confiscations): reveal-or-sweep

(defstruct (armer-share (:constructor %make-armer-share)) leaves paths root spk parity address)

(defun build-armer-share (armer-xonly commitment recovery-voters recovery-threshold &key (network :signet))
  (let* ((reveal (cat (octets +op-hash160+) (pushb commitment) (octets +op-equalverify+) (pushb armer-xonly) (octets +op-checksig+)))
         (sweep (recovery-script recovery-voters recovery-threshold +armer-sweep-csv+))
         (leaves (list reveal sweep)))
    (multiple-value-bind (root paths) (tapbuilder-tree (mapcar #'tr::tapleaf-hash leaves) '(1 1))
      (multiple-value-bind (spk parity) (p2tr-spk rs:+nums-point+ root)
        (%make-armer-share :leaves leaves :paths paths :root root :spk spk :parity parity
                           :address (enc:segwit-encode (rs:hrp-for network) 1 (subseq spk 2)))))))

(defun armer-share-control-block (a leaf-index)
  (apply #'cat (octets (logior #xc0 (armer-share-parity a))) rs:+nums-point+ (nth leaf-index (armer-share-paths a))))

(defun revealers-from-witness (witness armers)
  "ARMERS: alist (xonly . commitment).  Which of them revealed in this witness?"
  (sorted-keys (loop for item in witness
                     when (<= 17 (length item) +max-preimage-len+)
                       append (loop for (pk . c) in armers when (equalp c (hash160 item)) collect pk))))

(defun forfeit-sweep-outputs (slice-sats revealers fee-sats)
  "DEP-06: pro-rata to revealers (sorted), one P2TR per revealer; dust to fee.
   With no revealers the slice waits for the re-arm round: never the operator."
  (when (>= fee-sats slice-sats) (error "sweep uneconomical"))
  (when (null revealers) (error "no revealers: the slice goes to the re-arm round"))
  (let ((each (floor (- slice-sats fee-sats) (length revealers))))
    (loop for r in (sorted-keys revealers) collect (cons (key-path-spk r) each))))

(defun key-path-spk (xonly)
  "P2TR with no script tree: tweak by tagged_hash(TapTweak, key)."
  (values (tr::taproot-output-spk-from-root xonly (octets))))

;;; ---------------------------------------------------------------------------
;;; Confiscation outputs (DEP-06 §Respectful vs Punitive)

(defconstant +confiscation-default-feerate+ 2 "sat/vB while no reference_feerate_sat_vb is recorded.")

(defun confiscation-fee (voters &optional (feerate +confiscation-default-feerate+))
  "DEP-03 \"Confiscation fee\": feerate x (120 + 30 x VOTERS) sats, VOTERS counting the
   vault's members and operator.  Deterministic, so every cosigner builds the same tx."
  (* feerate (+ 120 (* 30 voters))))

(defun confiscation-outputs (lottery-spk reserves-sats fee-sats &key respectful obligations-sats operator-pubkey33)
  "A list of (spk . sats).  Punitive: everything to the lottery output.
   Respectful: obligations to the lottery, the rest back to the operator's
   P2WPKH — unless that change would be dust, in which case punitive shape."
  (let ((punitive (list (cons lottery-spk (- reserves-sats fee-sats)))))
    (if (not respectful)
        punitive
        (let* ((lottery-value (max (or obligations-sats 0) +p2wsh-dust+))
               (change (- reserves-sats lottery-value fee-sats)))
          (if (< change +p2wpkh-dust+)
              punitive
              (list (cons lottery-spk lottery-value)
                    (cons (cat (octets 0 20) (hash160 operator-pubkey33)) change)))))))
