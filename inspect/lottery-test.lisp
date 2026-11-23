;;;; inspect/lottery-test.lisp — the custody lottery, spent under cl-consensus.

(in-package #:cl-deposits.test)

(defun lot-keys (n) (loop for i from 1 to n collect (tk (+ 424242424242 (* i 1000000007)))))
(defun xonly-of (priv) (up:x-only (up:compressed-pubkey (tk priv))))

(defun random-preimage (&optional (range lot:+contribution-range+))
  (let ((len (+ 17 (random range))))
    (let ((p (make-array len :element-type '(unsigned-byte 8)))) (dotimes (i len p) (setf (aref p i) (random 256))))))

(with-gate ("lottery: winner rule and preimage derivation")
  (check-equal "sum of contributions mod n" (lot:calculate-winner (list (make-array 18) (make-array 19) (make-array 17))) (mod (+ 2 3 1) 3))
  (check-signals "short preimage rejected" error (lot:calculate-winner (list (make-array 16) (make-array 17))))
  (check-signals "a 77-byte preimage is rejected" error (lot:calculate-winner (list (make-array 77) (make-array 17))))
  (check-equal "a 76-byte preimage contributes 60" (lot:calculate-winner (list (make-array 76) (make-array 17))) (mod 61 2))
  (check-equal "subset winner indexes the full order" (lot:subset-winner '(1 3 4) (list (make-array 17) (make-array 17) (make-array 17))) 1)
  (let ((p (lot:derive-preimage (u:sha256 (hx "01")))))
    (check "derived preimage length in 17..76" (<= 17 (length p) 76))
    (check-bytes "derivation is deterministic" (lot:derive-preimage (u:sha256 (hx "01"))) p))
  (check-equal "lengths spread over all 60"
               (length (remove-duplicates (loop for i below 2000 collect (length (lot:derive-preimage (u:sha256 (u:int->be i 4)))))))
               60)
  (check-equal "subsets of 3: by size, then lexicographic" (lot::subset-indices 3) '((0 1) (0 2) (1 2) (0) (1) (2)))
  (check-equal "126 proper subsets of 7" (length (lot::subset-indices 7)) 126)
  (check-equal "tree shape: 6 leaves -> depths 3 3 3 3 2 2" (lot::leaf-depths 6) '(3 3 3 3 2 2))
  (check-equal "tree shape: 8 leaves all depth 3" (lot::leaf-depths 8) '(3 3 3 3 3 3 3 3))
  (check-equal "tree shape: 5 leaves -> 3 3 2 2 2" (lot::leaf-depths 5) '(3 3 2 2 2)))

(defun spend-lottery (l amount witness-fn &key (sequence #xfffffffd) (dest-xonly (xonly-of 7)))
  "Build a claim of the lottery output paying DEST, attach WITNESS-FN's stack, verify."
  (let* ((prevouts (vector (cons amount (lot:lottery-spk l))))
         (tx (rot:build-spend :prev-txid (u:sha256 (hx "1077")) :prev-vout 0 :reserves-amount amount
                              :destination-spk (lot:key-path-spk dest-xonly) :fee-rate 1))
         (tx (btx:parse-tx (cl-consensus.wire:make-reader
                            (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t
                                                           :inputs (list (btx:make-txin :prev-hash (u:sha256 (hx "1077")) :prev-index 0 :script (u:octets) :sequence sequence))
                                                           :outputs (btx:tx-outputs tx) :witnesses (list nil))))))
         (stack (funcall witness-fn tx prevouts))
         (signed (btx:parse-tx (cl-consensus.wire:make-reader
                                (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t :inputs (btx:tx-inputs tx)
                                                               :outputs (btx:tx-outputs tx) :witnesses (list stack)))))))
    (rot:verify-spend signed 0 prevouts)))

(defun sig-for (l tx prevouts leaf priv)
  (declare (ignore l))
  (secp256k1-fast.schnorr:schnorr-sign (tk priv) (rot:tier-sighash tx 0 prevouts leaf)))

(dolist (n '(2 3 5 7))
  (with-gate ((format nil "lottery: k=~a, every revealer subset, spent under consensus" n))
    (let* ((privs (lot-keys n))
           (preimages (loop repeat n collect (random-preimage)))
           (participants (loop for priv in privs for p in preimages
                               collect (lot:make-participant :pubkey (xonly-of priv) :commitment (lot:commitment-of p) :target "tb1p")))
           (vprivs (lot-keys 3))
           (voters (mapcar #'xonly-of vprivs))
           (l (lot:build-lottery participants voters 2))
           ;; canonical order is by pubkey: realign preimages/privs to it
           (order (mapcar (lambda (p) (position (lot:participant-pubkey p) participants :key #'lot:participant-pubkey :test #'equalp)) (lot:lottery-participants l)))
           (ordered-pre (mapcar (lambda (i) (nth i preimages)) order))
           (ordered-priv (mapcar (lambda (i) (nth i privs)) order))
           (winner (lot:calculate-winner ordered-pre))
           (amount 1000000))
      (labels ((voter-sigs (tx pv leaf signers)
                 (mapcar (lambda (k) (let ((p (find k vprivs :key #'xonly-of :test #'equalp)))
                                       (and (member p signers) (sig-for l tx pv leaf p))))
                         (lot::sorted-keys voters)))
               (subset-claim (idx claimant-pos &key (signers (list (first vprivs) (third vprivs))) (sequence 72) (pre ordered-pre))
                 (let ((leaf (nth (lot:subset-leaf-index l idx) (lot:lottery-leaves l))))
                   (spend-lottery l amount (lambda (tx pv) (lot:subset-witness l idx (sig-for l tx pv leaf (nth claimant-pos ordered-priv))
                                                                               (mapcar (lambda (i) (nth i pre)) idx)
                                                                               (voter-sigs tx pv leaf signers)))
                                  :sequence sequence))))
        (check "address is p2tr" (string= "tb1p" (subseq (lot:lottery-address l) 0 4)))
        (check-equal "leaf count = full set + 2^k-2 subsets + 4 recovery" (length (lot:lottery-leaves l)) (+ 1 (- (expt 2 n) 2) 4))
        (check (format nil "full set: winner ~a's claim verifies" winner)
               (spend-lottery l amount (lambda (tx pv) (lot:claim-witness l (sig-for l tx pv (first (lot:lottery-leaves l)) (nth winner ordered-priv)) ordered-pre))))
        (check "full set: every loser's claim fails"
               (loop for i below n
                     always (or (= i winner)
                                (not (spend-lottery l amount (lambda (tx pv) (lot:claim-witness l (sig-for l tx pv (first (lot:lottery-leaves l)) (nth i ordered-priv)) ordered-pre)))))))
        (check "full set: a wrong preimage fails"
               (not (spend-lottery l amount (lambda (tx pv) (let ((bad (copy-list ordered-pre))) (setf (first bad) (random-preimage))
                                                               (lot:claim-witness l (sig-for l tx pv (first (lot:lottery-leaves l)) (nth winner ordered-priv)) bad))))))
        ;; Each single withholder: the other k-1 draw among themselves after CSV 72, attested 2 of 3.
        (dotimes (missing n)
          (let* ((idx (loop for i below n unless (= i missing) collect i))
                 (w (lot:subset-winner idx (mapcar (lambda (i) (nth i ordered-pre)) idx))))
            (check (format nil "withholder ~a: R's winner ~a claims after CSV 72 with 2 attestations" missing w) (subset-claim idx w))
            (when (= missing 0)
              (check "the subset claim before CSV 72 fails" (not (subset-claim idx w :sequence 71)))
              (check "one attestation is not enough" (not (subset-claim idx w :signers (list (first vprivs)))))
              (check "the withholder cannot claim R's leaf" (not (subset-claim idx missing)))
              (when (> (length idx) 1)
                (check "another revealer cannot claim R's leaf" (not (subset-claim idx (find-if (lambda (i) (/= i w)) idx)))))
              (check "the withheld preimage cannot be swapped in"
                     (not (subset-claim idx w :pre (let ((b (copy-list ordered-pre))) (setf (nth (first idx) b) (random-preimage)) b)))))))
        (when (>= n 3)
          (let* ((idx (loop for i from 2 below n collect i))
                 (w (lot:subset-winner idx (mapcar (lambda (i) (nth i ordered-pre)) idx))))
            (check (format nil "two withholders: the remaining ~a draw, winner ~a" (length idx) w) (subset-claim idx w))))
        (check "a sole revealer takes it after CSV 72 with attestation" (subset-claim (list (1- n)) (1- n)))
        ;; Nobody revealed: recovery cascade (2-of-3 after 144; T-1=1 after 1008; escape hatch after 8064).
        (let* ((lowest (find (first (lot::sorted-keys voters)) vprivs :key #'xonly-of :test #'equalp))
               (other (find-if (lambda (p) (not (eql p lowest))) vprivs)))
          (flet ((rec (tier csv signers)
                   (spend-lottery l amount
                                  (lambda (tx pv)
                                    (let* ((idx (lot::recovery-leaf-index l tier)) (leaf (nth idx (lot:lottery-leaves l))))
                                      (lot:recovery-witness l tier (voter-sigs tx pv leaf signers))))
                                  :sequence csv)))
            (check "recovery tier 0: 2 of 3 voters after 144 blocks" (rec 0 144 (list (first vprivs) (third vprivs))))
            (check "recovery tier 0: 1 voter is not enough" (not (rec 0 144 (list (first vprivs)))))
            (check "recovery tier 0: too early fails" (not (rec 0 100 (list (first vprivs) (third vprivs)))))
            (check "recovery tier 1 (T-1=1): the lowest sorted voter after 1008" (rec 1 1008 (list lowest)))
            (check "recovery tier 1: another voter cannot use the single-key leaf" (not (rec 1 1008 (list other))))
            (check "escape hatch: the lowest sorted voter after 8064" (rec 3 8064 (list lowest)))
            (check "escape hatch: too early fails" (not (rec 3 8000 (list lowest))))))))))

(with-gate ("lottery: maximum contributions reduce correctly (k=7, all 76 bytes)")
  (let* ((n 7) (privs (lot-keys n))
         (pre (loop for i below n collect (let ((p (make-array 76 :element-type '(unsigned-byte 8)))) (dotimes (j 76 p) (setf (aref p j) (random 256))))))
         (parts (loop for priv in privs for p in pre collect (lot:make-participant :pubkey (xonly-of priv) :commitment (lot:commitment-of p) :target "tb1p")))
         (l (lot:build-lottery parts (mapcar #'xonly-of (lot-keys 3)) 2))
         (order (mapcar (lambda (p) (position (lot:participant-pubkey p) parts :key #'lot:participant-pubkey :test #'equalp)) (lot:lottery-participants l)))
         (opre (mapcar (lambda (i) (nth i pre)) order)) (opriv (mapcar (lambda (i) (nth i privs)) order))
         (w (lot:calculate-winner opre)))
    (check-equal "sum 420 mod 7 = 0" w 0)
    (check "the winner of an all-maximum draw claims" (spend-lottery l 500000 (lambda (tx pv) (lot:claim-witness l (sig-for l tx pv (first (lot:lottery-leaves l)) (nth w opriv)) opre))))))

(with-gate ("lottery: armer shares and forfeit sweep")
  (let* ((armer 55555) (pre (random-preimage)) (voters (mapcar #'xonly-of (lot-keys 3))) (vprivs (lot-keys 3))
         (a (lot:build-armer-share (xonly-of armer) (lot:commitment-of pre) voters 2))
         (amount 50000)
         (prevouts (vector (cons amount (lot:armer-share-spk a)))))
    (flet ((spend (witness-fn sequence)
             (let* ((tx (btx:parse-tx (cl-consensus.wire:make-reader
                                       (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t
                                                                      :inputs (list (btx:make-txin :prev-hash (u:sha256 (hx "a5")) :prev-index 0 :script (u:octets) :sequence sequence))
                                                                      :outputs (list (btx:make-txout :value (- amount 500) :script (lot:key-path-spk (xonly-of armer)))) :witnesses (list nil))))))
                    (stack (funcall witness-fn tx))
                    (signed (btx:parse-tx (cl-consensus.wire:make-reader (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p t :inputs (btx:tx-inputs tx) :outputs (btx:tx-outputs tx) :witnesses (list stack)))))))
               (rot:verify-spend signed 0 prevouts))))
      (check "armer reveals and claims their share"
             (spend (lambda (tx) (list (sig-for nil tx prevouts (first (lot:armer-share-leaves a)) armer) pre (first (lot:armer-share-leaves a)) (lot:armer-share-control-block a 0))) #xfffffffd))
      (check "wrong preimage fails"
             (not (spend (lambda (tx) (list (sig-for nil tx prevouts (first (lot:armer-share-leaves a)) armer) (random-preimage) (first (lot:armer-share-leaves a)) (lot:armer-share-control-block a 0))) #xfffffffd)))
      (check "recovery voters sweep after 144"
             (spend (lambda (tx) (let* ((leaf (second (lot:armer-share-leaves a))) (sorted (lot::sorted-keys voters))
                                        (sigs (mapcar (lambda (k) (let ((p (find k vprivs :key #'xonly-of :test #'equalp))) (and (member p (list (first vprivs) (second vprivs))) (sig-for nil tx prevouts leaf p)))) sorted)))
                                   (append (mapcar (lambda (s) (or s (u:octets))) (reverse sigs)) (list leaf (lot:armer-share-control-block a 1)))))
                    144))
      (check "sweep before 144 fails"
             (not (spend (lambda (tx) (let* ((leaf (second (lot:armer-share-leaves a))) (sorted (lot::sorted-keys voters))
                                             (sigs (mapcar (lambda (k) (let ((p (find k vprivs :key #'xonly-of :test #'equalp))) (and (member p (list (first vprivs) (second vprivs))) (sig-for nil tx prevouts leaf p)))) sorted)))
                                        (append (mapcar (lambda (s) (or s (u:octets))) (reverse sigs)) (list leaf (lot:armer-share-control-block a 1)))))
                         10))))
    (let ((outs (lot:forfeit-sweep-outputs 10000 (list (xonly-of 1) (xonly-of 2) (xonly-of 3)) 400)))
      (check-equal "sweep pays revealers pro rata (dust to fee)" (mapcar #'cdr outs) '(3200 3200 3200)))
    (check-signals "no revealers: no sweep (the slice waits for the re-arm round)" error (lot:forfeit-sweep-outputs 10000 nil 400))
    (check-equal "revealers are read back from a claim witness"
                 (lot:revealers-from-witness (list (u:octets 1 2) pre (make-array 40)) (list (cons (xonly-of armer) (lot:commitment-of pre))))
                 (list (xonly-of armer)))
    (check-equal "confiscation: punitive = everything to the lottery"
                 (lot:confiscation-outputs (hx "5120aa") 100000 500) (list (cons (hx "5120aa") 99500)))
    (check-equal "confiscation: respectful = obligations to lottery, change to operator p2wpkh"
                 (mapcar #'cdr (lot:confiscation-outputs (hx "5120aa") 100000 500 :respectful t :obligations-sats 40000 :operator-pubkey33 (up:compressed-pubkey (tk 9))))
                 '(40000 59500))
    (check-equal "confiscation: respectful with dust change collapses to punitive"
                 (length (lot:confiscation-outputs (hx "5120aa") 40700 500 :respectful t :obligations-sats 40000 :operator-pubkey33 (up:compressed-pubkey (tk 9))))
                 1)))

(with-gate ("reserves: the reference's pinned cltv-offset-v2 seven-voter script")
  ;; deposits-core CLTV_OFFSET_V2_SEVEN_VOTERS_HEX: operator key [1;32], members [2..7;32],
  ;; quorum_expiry 800000, ledger hash [0x5a;32], signet.  Tier 1 is ceil(7/2) - 1 = 3 of 7.
  (let* ((key (lambda (i) (up:compressed-pubkey (tk (u:be->int (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))))))
         (r (rs:build-reserves :operator (funcall key 1) :members (loop for i from 2 to 7 collect (funcall key i))
                               :ledger-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x5a)
                               :quorum-expiry 800000 :ruleset "cltv-offset-v2" :network :signet)))
    (format t "~&  CL_SEVEN_VOTERS_HEX=~a~%" (u:bytes->hex (rs:reserves-spk r)))
    (check-equal "tier 1 is 3 of 7" (rs:tier-threshold (second (rs:reserves-tiers r))) 3)
    (check-bytes "scriptPubKey matches CLTV_OFFSET_V2_SEVEN_VOTERS_HEX" (rs:reserves-spk r)
                 (hx "51206e92587c6bcdf7bd653c242c1937224eac71bc486fe7c3b9fc6edb70b129dbeb"))))



(with-gate ("lottery: byte-for-byte against the reference builder")
  ;; inspect/vectors/lottery_subsets.txt: deposits-core's tests/lottery_subset_vector.rs
  ;; for keys from secrets [i;32], commitments [i;20], voters 21..23 (2-of-3), signet.
  (let* ((lines (with-open-file (in (vector-path "lottery_subsets.txt"))
                  (loop for l = (read-line in nil) while l collect l)))
         (vec (lambda (key) (let ((pfx (format nil "VEC ~a=" key)))
                              (let ((l (find pfx lines :test (lambda (p l) (and (>= (length l) (length p)) (string= p (subseq l 0 (length p))))))))
                                (and l (subseq l (length pfx)))))))
         (seed-priv (lambda (i) (gossamer:pooled-copy (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))))
         (voters (mapcar (lambda (i) (xonly-of (funcall seed-priv i))) '(21 22 23)))
         (name (lambda (idx) (format nil "~{~a~^,~}" idx))))
    (dolist (k '(1 2 3 7))
      (let* ((parts (loop for i from 1 to k collect (lot:make-participant :pubkey (xonly-of (funcall seed-priv i))
                                                                            :commitment (make-array 20 :element-type '(unsigned-byte 8) :initial-element i)
                                                                            :target (format nil "tb1p~a" i))))
             (l (lot:build-lottery parts voters 2 :network :signet))
             (subsets (lot:lottery-subsets l)) (n (length subsets)))
        (check-equal (format nil "k=~a full-set leaf" k) (u:bytes->hex (first (lot:lottery-leaves l))) (funcall vec (format nil "k=~a full" k)))
        (check-equal (format nil "k=~a lottery address" k) (lot:lottery-address l) (funcall vec (format nil "k=~a address" k)))
        (check-equal (format nil "k=~a control block of the full-set leaf" k) (u:bytes->hex (lot:lottery-control-block l 0)) (funcall vec (format nil "k=~a control_full" k)))
        (check-equal (format nil "k=~a recovery leaf (CSV 144)" k) (u:bytes->hex (nth (lot::recovery-leaf-index l 0) (lot:lottery-leaves l))) (funcall vec (format nil "k=~a recovery144" k)))
        (check-equal (format nil "k=~a subset count" k) (princ-to-string n) (funcall vec (format nil "k=~a subsets" k)))
        (dolist (pos (remove-duplicates (list 0 (floor n 2) (max 0 (1- n)))))
          (when (< pos n)
            (let* ((idx (nth pos subsets)) (i (lot:subset-leaf-index l idx)))
              (check-equal (format nil "k=~a subset [~a] leaf" k (funcall name idx)) (u:bytes->hex (nth i (lot:lottery-leaves l)))
                           (funcall vec (format nil "k=~a subset[~a]" k (funcall name idx))))
              (check-equal (format nil "k=~a subset [~a] control block" k (funcall name idx)) (u:bytes->hex (lot:lottery-control-block l i))
                           (funcall vec (format nil "k=~a control[~a]" k (funcall name idx)))))))))
    (dolist (c '(((0 1 2 3 4 5 6) (17 76 40 23 61 18 50)) ((0 2 5) (20 76 33)) ((1 3 4 6) (76 76 76 76)) ((4) (29)) ((0 1 2 3 5 6) (17 18 19 20 21 22))))
      (destructuring-bind (idx lens) c
        (check-equal (format nil "winner over [~a]" (funcall name idx))
                     (princ-to-string (lot:subset-winner idx (mapcar (lambda (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0)) lens)))
                     (funcall vec (format nil "winner[~a](~a)" (funcall name idx) (funcall name lens))))))
    (dotimes (i 4)
      (check-equal (format nil "derived preimage ~a" i) (u:bytes->hex (lot:derive-preimage (u:sha256 (u:int->be i 4)))) (funcall vec (format nil "preimage[~a]" i))))
    (check-equal "armer share address"
                 (lot:armer-share-address (lot:build-armer-share (xonly-of (funcall seed-priv 1)) (make-array 20 :element-type '(unsigned-byte 8) :initial-element 1) voters 2 :network :signet))
                 (funcall vec "armer_share"))
    ;; The unsigned claim (DEP-03), legacy serialization as the reference pins it.
    (let ((fill (lambda (b) (make-array 32 :element-type '(unsigned-byte 8) :initial-element b)))
          (dest (u:cat (u:octets #x51 #x20) (xonly-of (funcall seed-priv 1)))))
      (loop for (name subset coll) in (list (list "claim_full" nil (list (funcall fill #x33) 1 600000))
                                            (list "claim_subset" t (list (funcall fill #x33) 1 600000))
                                            (list "claim_sole_no_collateral" nil nil))
            do (let ((tx (lot:claim-tx (funcall fill #x22) 0 1000000 coll dest :subset subset)))
                 (check-equal (format nil "~a tx" name)
                              (u:bytes->hex (btx:serialize-tx (btx:make-tx :version 2 :locktime 0 :segwit-p nil :inputs (btx:tx-inputs tx)
                                                                           :outputs (btx:tx-outputs tx) :witnesses nil)))
                              (funcall vec name)))))))

(with-gate ("lottery: the unsigned confiscation, byte for byte against the reference")
  ;; inspect/vectors/confiscation_tx.txt: deposits-node's confiscation_tx_vector_is_pinned.
  (let* ((lines (with-open-file (in (vector-path "confiscation_tx.txt")) (loop for l = (read-line in nil) while l collect l)))
         (vec (lambda (key) (let ((pfx (format nil "VEC ~a=" key)))
                              (let ((l (find-if (lambda (l) (and (>= (length l) (length pfx)) (string= pfx (subseq l 0 (length pfx))))) lines)))
                                (and l (subseq l (length pfx)))))))
         (seed-priv (lambda (i) (gossamer:pooled-copy (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))))
         (voters (mapcar (lambda (i) (xonly-of (funcall seed-priv i))) '(21 22 23)))
         (parts (loop for i from 1 to 3 collect (lot:make-participant :pubkey (xonly-of (funcall seed-priv i))
                                                                       :commitment (make-array 20 :element-type '(unsigned-byte 8) :initial-element i)
                                                                       :target (format nil "tb1p~a" i))))
         (l (lot:build-lottery parts voters 2 :network :signet))
         (fee (lot:confiscation-fee 8))
         (anchor (u:hex->bytes (funcall vec "anchor")))
         (operator (up:compressed-pubkey (tk (funcall seed-priv 9)))))
    (check-equal "DEP-03 fee for 8 voters (the anchor's 43 vB included)" (princ-to-string fee) (funcall vec "fee"))
    (loop for (name respectful locktime) in '(("punitive" nil 0) ("respectful" t 1234))
          do (let* ((outs (lot:confiscation-outputs (lot:lottery-spk l) 50000000 fee :respectful respectful
                                                    :obligations-sats 10000000 :operator-pubkey33 operator))
                    (tx (btx:make-tx :version 2 :locktime locktime :segwit-p nil
                                     :inputs (list (btx:make-txin :prev-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)
                                                                  :prev-index 1 :script (u:octets) :sequence #xfffffffd))
                                     :outputs (append (loop for (spk . v) in outs collect (btx:make-txout :value v :script spk))
                                                      (list (btx:make-txout :value 0 :script (cl-deposits.rotation:anchor-script anchor))))
                                     :witnesses nil)))
               (check-equal (format nil "~a confiscation tx" name) (u:bytes->hex (btx:serialize-tx tx)) (funcall vec name))))))

(with-gate ("lottery: the DEP-03 confiscation ladder against the shared vector")
  ;; inspect/vectors/confiscation_ladder.json, written by inspect/gen-confiscation-ladder.lisp and
  ;; shared with deposits-rust (deposits-core/tests/vectors/confiscation_ladder.json).
  (let* ((v (json-simple:parse (uiop:read-file-string (vector-path "confiscation_ladder.json"))))
         (ladders (make-hash-table :test #'equal)))
    (flet ((g (h k) (gethash k h))
           (outpoint (h) (list (u:hex->bytes (gethash "txid" h)) (gethash "vout" h) (gethash "sats" h))))
      (loop for c across (gethash "cases" v)
            for name = (g c "name") for p = (g c "params")
            for rungs = (lot:confiscation-ladder
                         :vault (outpoint (g p "vault")) :swept (map 'list #'outpoint (g p "swept"))
                         :lottery-spk (u:hex->bytes (g p "lottery_spk")) :voters (g p "voters") :locktime (g p "lock_time")
                         :respectful (g p "respectful") :obligations-sats (g p "obligations_sats") :residue-sats (g p "residue_sats")
                         :splice-outs (map 'list (lambda (o) (cons (u:hex->bytes (g o "spk")) (g o "sats"))) (g p "splice_outs"))
                         :operator-pubkey33 (u:hex->bytes (g p "operator")) :anchor (u:hex->bytes (g p "anchor"))
                         :feerate (g p "feerate") :collateral-msats (g p "collateral_msats"))
            for inputs = (+ (g (g p "vault") "sats") (reduce #'+ (g p "swept") :key (lambda (o) (g o "sats"))))
            do (setf (gethash name ladders) rungs)
               (check-equal (format nil "~a: rung count" name) (length rungs) (length (g c "rungs")))
               (loop for r in rungs for want across (g c "rungs") for fee across (g c "fees") for i from 0
                     do (check-equal (format nil "~a: rung ~a" name i) (u:bytes->hex (btx:serialize-tx r :witness nil)) want)
                        (check-equal (format nil "~a: rung ~a fee" name i)
                                     (- inputs (reduce #'+ (btx:tx-outputs r) :key #'btx:txout-value)) fee)))
      (loop for d across (gethash "decoys" v)
            do (check (format nil "decoy (~a): ~a" (g d "case") (g d "why"))
                      (notany (lambda (r) (string= (u:bytes->hex (btx:serialize-tx r :witness nil)) (g d "tx")))
                              (gethash (g d "case") ladders))))
      (let* ((cl (gethash "claim" v))
             (r (nth (g cl "rung") (gethash (g cl "case") ladders)))
             (tx (lot:claim-tx (btx:tx-txid r) 0 (btx:txout-value (first (btx:tx-outputs r)))
                               (outpoint (g cl "collateral")) (u:hex->bytes (g cl "destination_spk"))
                               :fee (g cl "fee") :subset (g cl "subset"))))
        (check-equal "the claim of a higher rung spends its output 0 at its value"
                     (u:bytes->hex (btx:serialize-tx tx :witness nil)) (g cl "tx"))))))

(with-gate ("ledger: the DEP-05 collateral floor against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "collateral_floor.json")))))
    (loop for case across (gethash "cases" v)
          do (let* ((members (map 'list (lambda (b) (lg::make-quorum-member :min-collateral-bps (and (integerp b) b)))
                                  (gethash "member_bps" case)))
                    (floor (lg:collateral-floor-bps members)))
               (check-equal (format nil "~a: floor" (gethash "name" case)) floor (gethash "floor_bps" case))
               (check-equal (format nil "~a: verdict" (gethash "name" case))
                            (lg:collateral-meets-floor-p (gethash "reserves" case) (gethash "collateral" case) floor)
                            (gethash "ok" case))))))

(with-gate ("ledger: the DEP-05 quorum expiry ceiling against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "quorum_expiry.json")))))
    (loop for case across (gethash "cases" v)
          for name = (gethash "name" case)
          do (let* ((members (map 'list (lambda (c) (lg::make-quorum-member :membership-until (and (integerp c) c)))
                                  (gethash "commitments" case)))
                    (ceiling (lg:quorum-expiry-ceiling members))
                    (want (gethash "ceiling" case)))
               (check-equal (format nil "~a: ceiling" name) ceiling (and (integerp want) want))
               (check-equal (format nil "~a: planned" name)
                            (lg:planned-quorum-expiry members (gethash "current_block" case) (gethash "window_blocks" case))
                            (gethash "planned" case))
               ;; DEP-05 "Born expired": the operator rotates only to an expiry after the block.
               (check-equal (format nil "~a: rotatable" name)
                            (> (lg:planned-quorum-expiry members (gethash "current_block" case) (gethash "window_blocks" case))
                               (gethash "current_block" case))
                            (gethash "rotatable" case))
               (loop for chk across (gethash "checks" case)
                     for e = (gethash "expiry" chk)
                     do (check-equal (format nil "~a: expiry ~a" name e)
                                     (lg:quorum-expiry-ok-p members e (gethash "current_block" case)) (gethash "ok" chk)))))))

;;; inspect/vectors/expiry_dispute_ends.json, shared with deposits-rust
;;; (deposits-protocol/tests/vectors/expiry_dispute_ends.json).
(with-gate ("dispute: when a quorum_expired dispute ends, against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "expiry_dispute_ends.json")))))
    ;; strict-lottery-v8 (:expiry-ends-on-spend): the case's ruleset, at the fork point; a case
    ;; with none is read under a ruleset before v8, where a recorded QuorumBegin ends it.
    (flet ((on-spend (c) (lg:ruleset-rule-p (let ((r (gethash "ruleset" c))) (and (stringp r) r)) :expiry-ends-on-spend))
           (spent (c) (multiple-value-bind (x found) (gethash "rotation_spend_confirmed" c) (if found (eq x t) t))))
      (loop for c across (gethash "ended" v)
            do (check-equal (gethash "name" c)
                            (and (cl-deposits.node::expiry-dispute-ended-p
                                  (gethash "last_valid_sequence" c) (gethash "latest_quorum_begin_sequence" c)
                                  (eq (gethash "confiscation_confirmed" c) t)
                                  :on-spend (on-spend c) :rotation-confirmed (spent c))
                                 t)
                            (eq (gethash "ended" c) t)))
      (loop for c across (gethash "arm" v)
            do (check-equal (gethash "name" c)
                            (and (cl-deposits.node::arm-on-expiry-dispute-p
                                  (gethash "anchor_block_height" c) (gethash "governing_quorum_expiry" c)
                                  (gethash "last_valid_sequence" c) (gethash "latest_quorum_begin_sequence" c)
                                  :on-spend (on-spend c) :rotation-confirmed (spent c))
                                 t)
                            (eq (gethash "arm" c) t))))))

;;; The same vector's fork_reuse cases: whether a new dispute is carried by our existing
;;; quorum_expired fork (FORK-LIVE-P's expiry arm, then BLOCKING-FORK's rule), and its ended cases
;;; that name a history_window_from: the ledger's latest QuorumBegin lies below a window an
;;; implementation might hold in memory (deposits-rust ref4 on 0aeebcc5, signet 2026-11-22).  This
;;; node indexes the whole history, so the window is only checked to be below that QuorumBegin.
(with-gate ("dispute: an answered expiry fork stands in for no later dispute, against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "expiry_dispute_ends.json")))))
    (check "the vector has its fork_reuse cases" (>= (length (gethash "fork_reuse" v)) 8))
    (check "and an ended case below a window"
           (some (lambda (c) (integerp (gethash "history_window_from" c))) (coerce (gethash "ended" v) 'list)))
    (loop for c across (gethash "ended" v)
          for w = (gethash "history_window_from" c)
          when (integerp w)
            do (check (format nil "~a: the QuorumBegin is below the window" (gethash "name" c))
                      (< (gethash "latest_quorum_begin_sequence" c) w)))
    (loop for c across (gethash "fork_reuse" v)
          for on-spend = (lg:ruleset-rule-p (gethash "ruleset" c) :expiry-ends-on-spend)
          for armed = (eq (gethash "fork_armed" c) t)
          for live = (cl-deposits.node::expiry-fork-live-p
                      (gethash "fork_last_valid_sequence" c) (gethash "latest_quorum_begin_sequence" c)
                      on-spend (eq (gethash "rotation_spend_confirmed" c) t))
          do (check-equal (gethash "name" c)
                          (and (cl-deposits.node::fork-reuse-p live (not armed) (eq (gethash "new_punitive" c) t)) t)
                          (eq (gethash "reuse" c) t)))))

;;; inspect/vectors/dispute_ground.json, shared with deposits-rust
;;; (deposits-protocol/tests/vectors/dispute_ground.json).
(with-gate ("dispute: the ground of a DisputeEnter against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "dispute_ground.json")))))
    (loop for c across (gethash "cases" v)
          for e = (gethash "governing_quorum_expiry" c)
          do (check-equal (gethash "name" c)
                          (cl-deposits.node::dispute-ground-expiry-p
                           (gethash "reason" c) (eq (gethash "has_anchor" c) t) (eq (gethash "cites_proof" c) t)
                           (gethash "enter_block_height" c) (and (integerp e) e))
                          (eq (gethash "expiry" c) t)))))

;;; inspect/vectors/armer_eligibility.json: the DEP-03 replacement-collateral cut,
;;; shared with deposits-rust (deposits-node/tests/vectors/armer_eligibility.json).
(with-gate ("lottery: armer eligibility cut against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "armer_eligibility.json")))))
    (loop for case across (gethash "cases" v)
          do (let ((facts (make-hash-table :test #'equalp)) (names (make-hash-table :test #'equalp)) (armers '()))
               (loop for a across (gethash "armers" case) for i from 1
                     for pk = (let ((b (make-array 33 :element-type '(unsigned-byte 8) :initial-element i))) (setf (aref b 0) 2) b)
                     for p = (gethash "pledge" a)
                     for txid = (make-array 32 :element-type '(unsigned-byte 8) :initial-element i)
                     for num = (lambda (k h) (let ((x (gethash k h))) (and (integerp x) x)))
                     do (setf (gethash pk names) (gethash "id" a))
                        (when (hash-table-p p)
                          (setf (gethash txid facts) (list (funcall num "created" p) (funcall num "value" p) (funcall num "spent_at" p))))
                        (push (list pk (make-array 20 :element-type '(unsigned-byte 8) :initial-element i) "t"
                                    (and (hash-table-p p) (list txid 0 (gethash "declared" a)))
                                    (gethash "arm_height" a) 1)
                              armers))
               (let ((pledge-fn (lambda (txid vout scan-from)
                                  (declare (ignore vout))
                                  (destructuring-bind (&optional created value spent) (gethash txid facts)
                                    (list :created created :value-sats value
                                          :spend (cond ((null spent) :unspent) ((>= spent scan-from) (list :at spent)) (t :before)))))))
                 (multiple-value-bind (in out snapshot)
                     (nd:split-armers armers (gethash "required_sats" case) pledge-fn
                                      :confiscated-at (let ((c (gethash "confiscation_height" case))) (and (integerp c) c)))
                   (declare (ignore out))
                   (check-equal (format nil "~a: participants" (gethash "name" case))
                                (sort (mapcar (lambda (a) (gethash (first a) names)) in) #'string<)
                                (coerce (gethash "participants" (gethash "expect" case)) 'list))
                   (check-equal (format nil "~a: snapshot" (gethash "name" case)) snapshot (gethash "snapshot" (gethash "expect" case)))))))))

;;; inspect/vectors/authorised_confiscation.txt: DEP-06 "Authorised confiscation", shared with
;;; deposits-rust (deposits-node/tests/vectors): a vault spend is excused iff it is the rebuild from
;;; public state.  A node that never saw the dispute judges from the relay's updates alone.
(defun authorised-confiscation-vector (file)
  (let ((kv (make-hash-table :test #'equal)) (updates '()) (pledges (make-hash-table :test #'equalp)) (cases '()))
    (with-open-file (in (vector-path file))
      (loop for line = (read-line in nil) while line
            unless (or (zerop (length line)) (char= (char line 0) #\#))
              do (let ((w (uiop:split-string line :separator " ")))
                   (cond ((string= (first w) "update") (push (up:decode-update (u:hex->bytes (second w))) updates))
                         ((string= (first w) "pledge")
                          (setf (gethash (u:hex->bytes (second w)) pledges) (list (parse-integer (fifth w)) (parse-integer (fourth w)))))
                         ((string= (first w) "case") (push (rest w) cases))
                         (t (setf (gethash (first w) kv) (second w)))))))
    (let* ((proto (nd:make-node :priv (tk 424242) :bus (bus:make-mock-bus) :network (gethash "network" kv)
                                :height-fn (let ((h (parse-integer (gethash "spend_height" kv)))) (lambda () h))
                                :pledge-fn (lambda (txid vout scan-from)
                                             (declare (ignore vout scan-from))
                                             (let ((f (gethash txid pledges)))
                                               (and f (list :created (first f) :value-sats (second f) :spend :unspent))))))
           (id (gethash "ledger" kv))
           (view (nd::dispute-view proto id (reverse updates) :confiscated-at (parse-integer (gethash "spend_height" kv)))))
      (dolist (c (reverse cases))
        (destructuring-bind (name verdict hex) c
          (let* ((tx (btx:parse-tx (cl-consensus.wire:make-reader (u:hex->bytes hex))))
                 ;; DEP-03 §Fee ladder: the judge reads the vault rung from the spend's input and its
                 ;; value from that output, as its chain reports it (a pledge line in the vector)
                 (in0 (first (btx:tx-inputs tx)))
                 (known (gethash (btx:txin-prev-hash in0) pledges))
                 (nd::*judged-spend* (and known (list tx (cons (second known) nil)))))
            (check-equal (format nil "~a: ~:[not excused~;excused~]" name (string= verdict "1"))
                         (and (nd::rebuild-matches-p view id tx) t)
                         (string= verdict "1"))))))))

(with-gate ("DEP-06 authorised confiscation: the rebuild from public state, against the shared vector")
  (authorised-confiscation-vector "authorised_confiscation.txt"))

;;; inspect/vectors/confiscation_past_fault.txt: the base ends at the dispute's last fork point
;;; (DEP-06), from the signet soak's ledger 6056fb38: the operator's chain carries on past it with
;;; the fault, and a rebuild that replayed the fault never recognised the honest rung 1.
(with-gate ("DEP-06 authorised confiscation: the base ends at the fork point (soak 6056fb38)")
  (authorised-confiscation-vector "confiscation_past_fault.txt"))

;;; inspect/vectors/confiscation_vault_rung.txt: the vault is a bumped rotation rung, judged after
;;; it was spent (signet soak 2026-11-08, ledger G: rung 0's amounts rebuilt it 6076 sats off).
(with-gate ("DEP-03 fee ladder: a confiscation of a bumped vault, judged from the spend's input")
  (authorised-confiscation-vector "confiscation_vault_rung.txt"))

;;; inspect/vectors/dispute_rearm.json: DEP-03's re-arm shape, shared with deposits-rust
;;; (deposits-core/tests/vectors/dispute_rearm.json).
(with-gate ("DEP-03 re-arm: the fold against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "dispute_rearm.json")))))
    (flet ((arm (c) (append (list :type :dispute-armed :armed-block 100 :commitment-hash (u:hex->bytes (gethash "commitment" c))
                                  :target-reserves "t")
                            (when (eq (gethash "collateral" c) t)
                              (list :replacement-collateral-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                                    :replacement-collateral-vout 0 :replacement-collateral-amount 50000))
                            (when (gethash "round" c) (list :rearm-round (gethash "round" c))))))
      (loop for case across (gethash "cases" v)
            do (let ((l (lg:make-ledger)))
                 (setf (lg::ledger-dispute-state l) :disputed)
                 (when (stringp (gethash "ruleset" case)) (setf (lg::ledger-active-ruleset l) (gethash "ruleset" case)))
                 (lg:apply-operation l (arm (gethash "prior" case)))
                 (when (eq (gethash "yield_between" case) t) (lg:apply-operation l (list :type :dispute-yield)))
                 (when (eq (gethash "acquire_between" case) t)
                   (lg:apply-operation l (list :type :dispute-acquire :new-custodian (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2)
                                               :claim-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4)
                                               :new-reserves-address "")))
                 (check-equal (format nil "re-arm: ~a" (gethash "name" case))
                              (handler-case (progn (lg:apply-operation l (arm (gethash "next" case))) t)
                                (lg:ledger-error () nil))
                              (eq (gethash "ok" case) t)))))))

;;; inspect/vectors/dispute_yield_states.json: where a DisputeYield is valid, shared with
;;; deposits-rust (deposits-core/tests/vectors/dispute_yield_states.json).
(with-gate ("DEP-05/06 DisputeYield: the dispute states against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "dispute_yield_states.json")))))
    (check "the vector has every state, armed and un-armed" (>= (length (gethash "cases" v)) 10))
    (flet ((arm (commit collateral round)
             (append (list :type :dispute-armed :armed-block 100
                           :commitment-hash (make-array 20 :element-type '(unsigned-byte 8) :initial-element commit)
                           :target-reserves "t")
                     (when collateral
                       (list :replacement-collateral-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                             :replacement-collateral-vout 0 :replacement-collateral-amount 50000))
                     (when round (list :rearm-round round)))))
      (loop for c across (gethash "cases" v)
            for name = (gethash "name" c)
            do (let ((l (lg:make-ledger)))
                 (loop for o across (gethash "ops" c)
                       do (lg:apply-operation
                           l (let ((k (gethash "op" o)))
                               (cond ((string= k "enter") (list :type :dispute-enter :last-valid-sequence 0 :reason (gethash "reason" o)))
                                     ((string= k "arm") (arm #x11 t nil))
                                     ((string= k "arm_bare") (arm #x11 nil nil))
                                     ((string= k "arm_round_2") (arm #x22 t 2))
                                     ((string= k "yield") (list :type :dispute-yield))
                                     ((string= k "acquire")
                                      (list :type :dispute-acquire :new-custodian (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2)
                                            :claim-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4)
                                            :new-reserves-address ""))
                                     (t (error "unknown op ~a" k))))))
                 (check-equal (format nil "yield: ~a: state before" name)
                              (string-downcase (symbol-name (lg:ledger-dispute-state l))) (gethash "state_before" c))
                 (check-equal (format nil "yield: ~a" name)
                              (handler-case (progn (lg:apply-operation l (list :type :dispute-yield)) "accept")
                                (lg:ledger-error () "reject"))
                              (gethash "yield" c))
                 (when (stringp (gethash "state_after" c))
                   (check-equal (format nil "yield: ~a: state after" name)
                                (string-downcase (symbol-name (lg:ledger-dispute-state l))) (gethash "state_after" c))))))))

;;; inspect/vectors/dispute_armed_round.json: DisputeArmed's rearm_round (TLV 366) on the wire,
;;; shared with deposits-rust (deposits-protocol/tests/vectors/dispute_armed_round.json).
(with-gate ("DEP-06 re-arm rounds: DisputeArmed's TLV 366 against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "dispute_armed_round.json")))))
    (loop for c across (gethash "cases" v)
          for round = (let ((r (gethash "rearm_round" c))) (and (integerp r) r))
          for op = (append (list :type :dispute-armed :armed-block 100
                                 :commitment-hash (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x11)
                                 :target-reserves "bcrt1qtarget"
                                 :replacement-collateral-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                                 :replacement-collateral-vout 1 :replacement-collateral-amount 50000)
                           (and round (list :rearm-round round)))
          for want = (gethash "hex" c)
          do (check-equal (format nil "~a: encoding" (gethash "name" c)) (u:bytes->hex (op:encode-operation op)) want)
             (check-equal (format nil "~a: decoded round" (gethash "name" c))
                          (op:field (op:decode-operation (u:hex->bytes want)) :rearm-round) round))))

;;; inspect/vectors/cosign_refusal.json: DEP-05 "Deposed operator", shared with deposits-rust
;;; (deposits-node/tests/vectors/cosign_refusal.json).
(with-gate ("DEP-05 deposed operator: cosign refusal against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "cosign_refusal.json")))))
    (check "the vector has cases" (>= (length (gethash "cases" v)) 10))
    (loop for c across (gethash "cases" v)
          for members = (loop for i below (gethash "members" c) collect (format nil "m~a" i))
          for disputes = (loop for d across (gethash "disputes" c)
                               collect (list :by (gethash "by" d) :last-valid (gethash "last_valid_sequence" d)
                                             :reason (gethash "reason" d) :acquired (gethash "acquired" d)
                                             :acquire-confirmed (gethash "acquire_confirmed" d)))
          do (check-equal (gethash "name" c)
                          (and (cl-deposits.node::cosign-refusal "m0" members (gethash "latest_quorum_begin_seq" c) disputes
                                                                 :ruleset (gethash "ruleset" c))
                               t)
                          (gethash "refuse" c)))))

;;; inspect/vectors/rotation_seat.json: DEP-11 "Rotating without a silent member", shared with
;;; deposits-rust (deposits-core/tests/vectors/rotation_seat.json).
(with-gate ("DEP-11 rotating without a silent member: the seated set against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "rotation_seat.json")))))
    (check "the vector has cases" (>= (length (gethash "cases" v)) 6))
    (loop for c across (gethash "cases" v)
          for seat = (gethash "seat" c)
          do (check-equal (gethash "name" c)
                          (lg:seat-consenting (coerce (gethash "current" c) 'list) (coerce (gethash "staged" c) 'list) :test #'string=)
                          (and seat (not (eq seat :null)) (not (eq seat 'null)) (coerce seat 'list))))))

;;; inspect/vectors/rotation_tx.txt: DEP-03 "Rotation transaction" and §Fee ladder, shared with
;;; deposits-rust (deposits-core/tests/vectors/rotation_tx.txt).  Txids there are display (reversed)
;;; hex.  Each case gives the inputs (vault, voters, feerate, locktime, new vault, extras, splice, the
;;; anchor, the collateral bounding the ladder, at most how many rungs) and every rung's unsigned
;;; bytes.  With CL_DEPOSITS_WRITE_VECTORS the rung lines are rewritten from our builder.
(with-gate ("DEP-03 rotation transaction and fee ladder: byte for byte against the shared vector")
  (let ((cases '()) (header '()))
    (with-open-file (in (vector-path "rotation_tx.txt"))
      (loop for line = (read-line in nil) while line
            for words = (uiop:split-string line :separator " ")
            for key = (first words)
            do (cond ((or (zerop (length line)) (char= (char line 0) #\#)) (unless cases (push line header)))
                     ((string= key "case") (push (list :name (second words) :extras '() :rungs '() :lines (list line)) cases))
                     (t (let ((outpoint (lambda (s) (let ((c (position #\: s)))
                                                      (list (reverse (u:hex->bytes (subseq s 0 c))) (parse-integer s :start (1+ c)))))))
                          (unless (string= key "rung") (setf (getf (car cases) :lines) (append (getf (car cases) :lines) (list line))))
                          (cond ((string= key "vault") (setf (getf (car cases) :vault) (append (funcall outpoint (second words)) (list (parse-integer (third words))))))
                                ((string= key "splice") (setf (getf (car cases) :splice) (append (funcall outpoint (second words)) (list (parse-integer (third words))))))
                                ((string= key "out") (setf (getf (car cases) :extras) (append (getf (car cases) :extras) (list (cons (u:hex->bytes (second words)) (parse-integer (third words)))))))
                                ((string= key "new_vault_spk") (setf (getf (car cases) :spk) (u:hex->bytes (second words))))
                                ((string= key "anchor") (setf (getf (car cases) :anchor) (u:hex->bytes (second words))))
                                ((string= key "rung") (setf (getf (car cases) :rungs) (append (getf (car cases) :rungs) (list (third words)))))
                                (t (setf (getf (car cases) (intern (string-upcase key) :keyword)) (parse-integer (second words))))))))))
    (setf cases (reverse cases))
    (check-equal "five shapes" (length cases) 5)
    (flet ((ladder (c)
             (destructuring-bind (txid vout sats) (getf c :vault)
               (cl-deposits.rotation:build-ladder :vault-txid txid :vault-vout vout :vault-sats sats
                                                  :voters (getf c :voters) :feerate (getf c :feerate) :locktime (getf c :locktime)
                                                  :new-vault-spk (getf c :spk) :splice (getf c :splice) :extras (getf c :extras)
                                                  :splice-vault-p (eql (getf c :splice_vault) 1) :anchor (getf c :anchor)
                                                  :collateral-msats (getf c :collateral) :max-rungs (or (getf c :max_rungs) 4)))))
      (when (uiop:getenv "CL_DEPOSITS_WRITE_VECTORS")
        (with-open-file (o (vector-path "rotation_tx.txt") :direction :output :if-exists :supersede)
          (dolist (h (reverse header)) (format o "~a~%" h))
          (dolist (c cases)
            (dolist (l (getf c :lines)) (format o "~a~%" l))
            (loop for tx in (ladder c) for i from 0
                  do (format o "rung ~a ~a~%" i (u:bytes->hex (btx:serialize-tx tx :witness nil)))))))
      (dolist (c cases)
        (let ((ours (mapcar (lambda (tx) (u:bytes->hex (btx:serialize-tx tx :witness nil))) (ladder c))))
          (unless (uiop:getenv "CL_DEPOSITS_WRITE_VECTORS")
            (check-equal (format nil "~a: ~a rungs" (getf c :name) (length (getf c :rungs))) (length ours) (length (getf c :rungs)))
            (loop for a in ours for b in (getf c :rungs) for i from 0
                  do (check-equal (format nil "~a rung ~a" (getf c :name) i) a b)))))
      ;; the ladder's own rules, on the first case
      (let* ((c (first cases)) (rungs (ladder c))
             (fee (lambda (tx) (- (third (getf c :vault)) (reduce #'+ (btx:tx-outputs tx) :key #'btx:txout-value)))))
        (check "every rung's last output is the anchor" (every (lambda (tx) (equalp (cl-deposits.rotation:anchor-of tx) (getf c :anchor))) rungs))
        (check "each rung pays twice its predecessor's fee (BIP-125: more fee, higher feerate, same inputs)"
               (loop for (a b) on rungs while b always (= (funcall fee b) (* 2 (funcall fee a)))))
        (check "rungs differ only in the new vault"
               (loop for r in (rest rungs) always (equalp (mapcar #'btx:txout-script (btx:tx-outputs r)) (mapcar #'btx:txout-script (btx:tx-outputs (first rungs))))))))
    (check "a rotation leaving the vault below dust is refused"
           (null (cl-deposits.rotation:build-rotation :vault-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                                                      :vault-vout 0 :vault-sats 900 :voters 8 :anchor (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)
                                                      :new-vault-spk (make-array 34 :element-type '(unsigned-byte 8) :initial-element 0))))
    (check "the anchor is 43 vB in the fee rule (9 + 34)"
           (= (- (cl-deposits.rotation:rotation-vsize 8 '(34 34) nil) (cl-deposits.rotation:rotation-vsize 8 '(34) nil)) 43))))

(with-gate ("DEP-06 recovery voters: the shared vector (deposits-rust generated, cl reproduces)")
  (let ((cases '()) (cur nil))
    (with-open-file (in (vector-path "lottery_recovery_voters.txt"))
      (loop for line = (read-line in nil) while line
            unless (or (zerop (length line)) (char= (char line 0) #\#))
              do (if (and (> (length line) 5) (string= (subseq line 0 5) "case "))
                     (push (setf cur (list (subseq line 5))) cases)
                     (setf (cdr (last cur)) (list line)))))
    (dolist (c (reverse cases))
      (let ((history '()) (voters nil) (threshold nil))
        (dolist (line (cdr c))
          (let ((f (uiop:split-string line :separator " ")))
            (cond ((string= (first f) "upd")
                   (destructuring-bind (seq author kind &rest args) (rest f)
                     (let ((o (cond ((string= kind "open")
                                     (list :type :ledger-open :operator-id (u:hex->bytes author) :reserves-id "x"
                                           :genesis-block 0 :reserves-amount 0 :collateral-amount 0))
                                    ((string= kind "qb")
                                     (list :type :quorum-begin :reserves-id "x" :spending-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                           :new-outpoint-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                           :new-outpoint-vout 0 :amount 0 :quorum-expiry 1000
                                           :ledger-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                           :quorum-members (mapcar #'u:hex->bytes args) :collateral-amount 0
                                           :protocol-version "cltv-offset-v2"))
                                    ((string= kind "yield") (list :type :dispute-yield))
                                    (t (list :type :dispute-enter :last-valid-sequence (parse-integer (first args)) :reason "test")))))
                       (push (up:make-signed-update :operator-id (u:hex->bytes author) :seq (parse-integer seq)
                                                    :message (op:encode-operation o))
                             history))))
                  ((string= (first f) "voters") (setf voters (rest f)))
                  ((string= (first f) "threshold") (setf threshold (parse-integer (second f)))))))
        ;; history is newest first, as a record keeps it
        (let* ((rec (nd::make-record :id-hex "00" :ledger (lg:make-ledger) :history history))
               ;; The fork point of the CURRENT dispute (DEP-03 §"The dispute"), as the node's
               ;; LOTTERY-VOTERS takes it through DISPUTE-LAST-VALID-SEQ: a stale DisputeEnter below
               ;; Q names none (case stale_enter_below_q_takes_no_part; regtest 8082521c).
               (enters (loop for u in (nd::dispute-scope history)
                             for o = (op:decode-operation (up:update-message u))
                             when (eq (op:operation-type o) :dispute-enter) collect (op:field o :last-valid-sequence)))
               (ours (sort (mapcar #'u:bytes->hex (nd::recovery-voters rec (and enters (reduce #'min enters)))) #'string<)))
          (check-equal (format nil "~a: voters" (car c)) ours voters)
          (check-equal (format nil "~a: threshold" (car c)) (lg:majority-threshold (length ours)) threshold))))))


;;; inspect/vectors/dispute_scope.txt: DEP-03 §"The dispute", shared with deposits-rust
;;; (deposits-core/tests/dispute_scope_vector.rs).
(with-gate ("dispute scope: only the current dispute's DisputeEnters count (shared vector)")
  (let ((ups '()) (name nil) (cases 0) (keys (make-hash-table)))
    (flet ((key (c) (or (gethash c keys)
                        (setf (gethash c keys) (let ((k (make-array 33 :element-type '(unsigned-byte 8) :initial-element (char-code c))))
                                                 (setf (aref k 0) 2) k))))
           (msg (kind arg)
             (op:encode-operation
              (cond ((string= kind "open") (list :type :ledger-open :operator-id (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2)
                                                 :reserves-id "r" :genesis-block 0 :reserves-amount 1 :collateral-amount 1))
                    ((string= kind "qb") (list :type :quorum-begin :reserves-id "r" :spending-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                               :new-outpoint-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                                               :new-outpoint-vout 0 :amount 1 :quorum-expiry 1000000
                                               :ledger-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                               :quorum-members '() :collateral-amount 1))
                    ((string= kind "enter") (list :type :dispute-enter :last-valid-sequence arg :reason "quorum_expired"))
                    (t (list :type :dispute-yield))))))
      (with-open-file (in (vector-path "dispute_scope.txt"))
        (loop for line = (read-line in nil) while line
              for w = (let ((out '()) (cur '()))
                        (loop for c across line
                              do (if (member c '(#\Space #\Tab))
                                     (when cur (push (coerce (nreverse cur) 'string) out) (setf cur '()))
                                     (push c cur)))
                        (when cur (push (coerce (nreverse cur) 'string) out))
                        (nreverse out))
              do (cond ((or (null w) (char= (char (first w) 0) #\#)))
                       ((string= (first w) "case") (setf name (second w) ups '()))
                       ((string= (first w) "u")
                        (let* ((who (char (second w) 0)) (seq (parse-integer (third w)))
                               (u (up:make-signed-update :operator-id (key who) :ledger-id (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)
                                                         :seq seq :prev-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                                         :message (msg (fourth w) (and (fifth w) (parse-integer (fifth w)))))))
                          (setf ups (append ups (list (cons (format nil "~a:~a" who seq) u))))))
                       ((string= (first w) "expect")
                        (let* ((kept (nd::dispute-scope (mapcar #'cdr ups)))
                               (got (mapcar (lambda (k) (car (find k ups :key #'cdr))) kept)))
                          (incf cases)
                          (check-equal (format nil "dispute_scope ~a" name) got (rest w))))))))
    (check-equal "every dispute_scope case ran" cases 5)))

(defun split-sequence-simple (s)
  (let ((out '()) (cur '()))
    (loop for c across s do (if (char= c #\Space) (when cur (push (coerce (nreverse cur) 'string) out) (setf cur '())) (push c cur)))
    (when cur (push (coerce (nreverse cur) 'string) out))
    (nreverse out)))

;;; inspect/vectors/grounded_arms.txt: DEP-03 §Grounded arms (grounded-arms-v7), shared with
;;; deposits-rust (deposits-node/tests/grounded_arms_vector.rs).
(with-gate ("grounded arms: classes, the cut and the shape (shared vector)")
  (let ((kind nil) (name nil) (fields (make-hash-table :test #'equal)) (items '()) (cases 0))
    (flet ((v (k) (let ((x (gethash k fields))) (if (equal x "-") nil x)))
           (verdict (s) (intern (string-upcase s) :keyword))
           (key (s) s))
      (with-open-file (in (vector-path "grounded_arms.txt"))
        (loop for line = (read-line in nil) while line
              for sp = (position #\Space line)
              for head = (if sp (subseq line 0 sp) line)
              for rest = (if sp (subseq line (1+ sp)) "")
              do (cond ((or (zerop (length line)) (char= (char line 0) #\#)))
                       ((member head '("class" "cut" "shape") :test #'string=)
                        (setf kind head name rest items '()) (clrhash fields))
                       ((and (string= head "enter") (string= kind "class"))
                        (let ((w (split-sequence-simple rest)))
                          (setf (gethash "enter" fields) (first w) (gethash "expiry" fields) (third w))))
                       ((string= head "armer") (let ((w (split-sequence-simple rest))) (push (list (key (first w)) (verdict (second w)) "vector") items)))
                       ((and (string= head "enter") (string= kind "shape"))
                        (let ((w (split-sequence-simple rest))) (push (list (first w) (verdict (second w))) items)))
                       ((string= head "expect") (setf (gethash "expect" fields) rest))
                       ((string= head "end")
                        (incf cases)
                        (let ((expect (gethash "expect" fields)))
                          (cond
                            ((string= kind "class")
                             (let* ((o (list :type :dispute-enter :last-valid-sequence 1 :reason (v "reason")
                                             :anchor-block-height (and (v "anchor") (parse-integer (v "anchor")))
                                             :fraud-proof-hash (and (v "hash") (u:hex->bytes (v "hash")))
                                             :fraud-proof (v "proof")))
                                    (got (nd::grounds-class o (parse-integer (v "enter")) (and (v "expiry") (parse-integer (v "expiry")))
                                                            (and (v "operator") (u:hex->bytes (v "operator"))))))
                               (check-equal (format nil "grounded_arms class ~a" name)
                                            (cond ((eq got :expiry) "expiry") ((eq got :ungrounded) "ungrounded") ((consp got) "verify") (t got))
                                            expect)))
                            ((string= kind "cut")
                             (let ((got (handler-case (let ((kept (nd::cut-by-grounds (gethash "ruleset" fields) (reverse items))))
                                                        (if kept (format nil "~{~a~^ ~}" kept) "none"))
                                          (error () "error"))))
                               (check-equal (format nil "grounded_arms cut ~a" name) got expect)))
                            ((string= kind "shape")
                             (let ((got (handler-case (string-downcase (symbol-name (nd::shape-by-grounds (gethash "ruleset" fields) (reverse items))))
                                          (error () "error"))))
                               (check-equal (format nil "grounded_arms shape ~a" name) got expect))))))
                       (t (setf (gethash head fields) rest))))))
    (check-equal "every grounded_arms case ran" cases 24)))

;;; inspect/vectors/lottery_accused.txt: DEP-03 §Lottery, a key the dispute's own grounds convict
;;; never wins; shared with deposits-rust (deposits-protocol/tests/lottery_accused_vector.rs).
(with-gate ("lottery: accused keys never win (shared vector)")
  (let ((kind nil) (name nil) (fields (make-hash-table :test #'equal)) (cases 0))
    (flet ((keys (s) (if (or (null s) (string= s "none")) '() (split-sequence-simple s))))
      (with-open-file (in (vector-path "lottery_accused.txt"))
        (loop for line = (read-line in nil) while line
              for sp = (position #\Space line)
              for head = (if sp (subseq line 0 sp) line)
              for rest = (if sp (subseq line (1+ sp)) "")
              do (cond ((or (zerop (length line)) (char= (char line 0) #\#)))
                       ((member head '("accused" "cut" "judge") :test #'string=)
                        (if (and kind (member kind '("cut" "judge") :test #'string=) (string= head "accused"))
                            (setf (gethash "accused" fields) rest)
                            (progn (setf kind head name rest) (clrhash fields))))
                       ((string= head "end")
                        (incf cases)
                        (let ((expect (gethash "expect" fields)))
                          (cond
                            ((string= kind "judge")
                             ;; DEP-06 §Authorised confiscation under strict-lottery-v8
                             (let ((rs (gethash "ruleset" fields)))
                               (check-equal (format nil "lottery_accused judge ~a" name)
                                            (if (lg:lottery-admissible-p (if (string= rs "-") nil rs)
                                                                         (mapcar #'u:hex->bytes (keys (gethash "participants" fields)))
                                                                         (mapcar #'u:hex->bytes (keys (gethash "accused" fields))))
                                                "admissible" "inadmissible")
                                            expect)))
                            ((string= kind "accused")
                              (let ((got (sort (mapcar #'u:bytes->hex
                                                       (fr:proof-accused-keys (fr:json->broadcast (w:parse-json (gethash "proof" fields)))))
                                               #'string<)))
                                (check-equal (format nil "lottery_accused ~a" name)
                                             (if got (format nil "~{~a~^ ~}" got) "none") expect)))
                            (t
                              (let* ((armers (mapcar (lambda (k) (list (u:cat (u:octets 2) (u:hex->bytes k)))) (keys (gethash "armers" fields))))
                                     (accused (mapcar #'u:hex->bytes (keys (gethash "accused" fields))))
                                     (kept (mapcar (lambda (a) (u:bytes->hex (up:x-only (first a)))) (nd::accused-cut armers accused))))
                                (check-equal (format nil "lottery_accused cut ~a" name)
                                             (if kept (format nil "~{~a~^ ~}" kept) "none") expect))))
                          (setf kind nil)))
                       (t (setf (gethash head fields) rest))))))
    (check-equal "every lottery_accused case ran" cases 22)))

;;; inspect/vectors/rearm_spend.txt: DEP-06 Phase 4 (draft), the re-arm round's recovery spend;
;;; shared with deposits-rust (deposits-core/tests/rearm_spend_vector.rs).  Generated by
;;; inspect/gen-rearm-spend.lisp.  Also checks the claimed vsize against a fully witnessed spend.
(with-gate ("DEP-06 re-arm: the recovery spend, its fee and vsize (shared vector)")
  (let ((seed (lambda (i) (gossamer:pooled-copy (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11))
        (next (u:cat (u:octets #x51 #x20) (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22)))
        (cases 0))
    (with-open-file (in (vector-path "rearm_spend.txt"))
      (loop for line = (read-line in nil) while line
            when (and (> (length line) 4) (string= "VEC " (subseq line 0 4)))
              do (let ((f (make-hash-table :test #'equal)))
                   (dolist (kv (rest (uiop:split-string line :separator " ")))
                     (let ((p (position #\= kv))) (setf (gethash (subseq kv 0 p) f) (subseq kv (1+ p)))))
                   (let* ((k (parse-integer (gethash "k" f))) (r (parse-integer (gethash "r" f)))
                          (tier (parse-integer (gethash "tier" f))) (feerate (parse-integer (gethash "feerate" f)))
                          (l (lot:build-lottery (loop for i from 1 to k
                                                      collect (lot:make-participant :pubkey (xonly-of (funcall seed i))
                                                                                    :commitment (make-array 20 :element-type '(unsigned-byte 8) :initial-element i)
                                                                                    :target (format nil "tb1p~a" i)))
                                                (loop for j from 1 to r collect (xonly-of (funcall seed (+ 20 j))))
                                                (1+ (floor r 2)) :network :signet))
                          (name (format nil "k=~a r=~a tier=~a" k r tier)))
                     (incf cases)
                     (multiple-value-bind (tx fee vsize) (lot:rearm-spend l txid 0 50000000 tier next :feerate feerate)
                       (check-equal (format nil "rearm ~a tx" name) (u:bytes->hex (btx:serialize-tx tx :witness nil)) (gethash "tx" f))
                       (check-equal (format nil "rearm ~a fee" name) (princ-to-string fee) (gethash "fee" f))
                       (check-equal (format nil "rearm ~a vsize" name) (princ-to-string vsize) (gethash "vsize" f))
                       ;; The claimed vsize is the real one: witness the spend as the tier's threshold signs it.
                       (let* ((th (cdr (nth tier (lot::recovery-specs (lot:lottery-recovery-threshold l)))))
                              (sigs (loop for j below r collect (and (< j th) (make-array 64 :element-type '(unsigned-byte 8) :initial-element 9)))))
                         (setf (btx:tx-witnesses tx) (list (lot:recovery-witness l tier sigs)))
                         (check-equal (format nil "rearm ~a vsize is the witnessed spend's" name)
                                      (ceiling (+ (* 3 (length (btx:serialize-tx tx :witness nil))) (length (btx:serialize-tx tx))) 4) vsize)))))))
    (check-equal "every rearm_spend case ran" cases 9)))

;;; inspect/vectors/rearm_windows.json: DEP-06 Phase 4 step 3 (strict-lottery-v8, ruled
;;; 2026-11-07), a re-arm round's recurring arm windows; shared with deposits-rust
;;; (deposits-core/tests/rearm_windows_vector.rs).  Generated by inspect/gen-rearm-windows.lisp.
(with-gate ("DEP-06 re-arm: recurring arm windows (shared vector)")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "rearm_windows.json")))) (cases 0))
    (flet ((g (o k) (gethash k o))
           (win (&optional j o c) (if j (list j o c) :null))
           (jl (x) (if (symbolp x) :null (coerce x 'list))))   ; JSON null parses to a symbol
      (loop for c across (coerce (gethash "cases" v) 'vector)
            do (let* ((name (g c "name")) (h-l (g c "h_l")) (w (g c "w")) (tip (g c "tip"))
                      (arms (coerce (g c "arms") 'list))
                      (revealed (eq (g c "revealed") t))
                      (o (+ h-l (if revealed 144 lot:+reveal-csv+)))
                      (nonempty (lambda (op cl) (some (lambda (a) (< op a (1+ cl))) arms))))
                 (incf cases)
                 (check-equal (format nil "~a: opens" name) o (g c "opens"))
                 (check-equal (format nil "~a: period" name) (lot:rearm-period w) (g c "period"))
                 (check-equal (format nil "~a: windows" name)
                              (loop for j below 6 collect (multiple-value-list (lot:rearm-window-nth o w j)))
                              (mapcar (lambda (x) (coerce x 'list)) (coerce (g c "windows") 'list)))
                 (check-equal (format nil "~a: round window" name)
                              (multiple-value-call #'win (lot:rearm-round-window o w tip nonempty)) (jl (g c "round_window")))
                 (check-equal (format nil "~a: open window" name)
                              (multiple-value-call #'win (lot:rearm-open-window o w tip)) (jl (g c "open")))
                 (check-equal (format nil "~a: next window" name) (lot:rearm-next-window o w tip) (g c "next_opens")))))
    (check-equal "every rearm_windows case ran" cases 11)))

;;; inspect/vectors/lottery_voters_accused.txt: strict-lottery-v8 (provisional), the recovery
;;; voters without the accused and every threshold over what remains; shared with deposits-rust
;;; (deposits-core/tests/lottery_voters_accused_vector.rs).  Generated by inspect/gen-lottery-voters.lisp.
;;; Also spends each lottery under consensus: a subset claim attested by the remaining voters
;;; verifies, one attested only by accused keys fails, and with every voter accused only the
;;; full-set claim exists.
(with-gate ("strict-lottery-v8: recovery voters without the accused (shared vector, spent under consensus)")
  (let* ((seed (lambda (i) (gossamer:pooled-copy (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))))
         (quorum (loop for j from 21 to 25 collect (xonly-of (funcall seed j))))
         (cases 0))
    (with-open-file (in (vector-path "lottery_voters_accused.txt"))
      (loop for line = (read-line in nil) while line
            when (and (> (length line) 4) (string= "VEC " (subseq line 0 4)))
              do (let ((f (make-hash-table :test #'equal)))
                   (dolist (kv (rest (uiop:split-string line :separator " ")))
                     (let ((p (position #\= kv))) (setf (gethash (subseq kv 0 p) f) (subseq kv (1+ p)))))
                   (let* ((name (gethash "case" f))
                          (accused-seeds (if (string= (gethash "accused" f) "-") '()
                                             (mapcar #'parse-integer (uiop:split-string (gethash "accused" f) :separator ","))))
                          (accused (mapcar (lambda (j) (xonly-of (funcall seed j))) accused-seeds)))
                     (incf cases)
                     (multiple-value-bind (voters threshold) (lot:strict-voters quorum accused)
                       (check-equal (format nil "~a voters" name)
                                    (if voters (format nil "~{~a~^,~}" (mapcar #'u:bytes->hex (lot::sorted-keys voters))) "-") (gethash "voters" f))
                       (check-equal (format nil "~a threshold" name) (princ-to-string threshold) (gethash "threshold" f))
                       (let ((l (lot:build-lottery (loop for i from 1 to 3
                                                         collect (lot:make-participant :pubkey (xonly-of (funcall seed i))
                                                                                       :commitment (make-array 20 :element-type '(unsigned-byte 8) :initial-element i)
                                                                                       :target (format nil "tb1p~a" i)))
                                                   voters threshold :network :signet)))
                         (check-equal (format nil "~a address" name) (lot:lottery-address l) (gethash "address" f))
                         (check-equal (format nil "~a leaf count" name) (princ-to-string (length (lot:lottery-leaves l))) (gethash "leaves" f)))
                       ;; Spend it: real preimages, voters from secrets 21..25.
                       (let* ((privs (lot-keys 3)) (pre (loop repeat 3 collect (random-preimage)))
                              (l (lot:build-lottery (loop for k in privs for p in pre
                                                          collect (lot:make-participant :pubkey (xonly-of k) :commitment (lot:commitment-of p) :target "tb1p"))
                                                    voters threshold))
                              (order (mapcar (lambda (p) (position (lot:participant-pubkey p) (mapcar #'xonly-of privs) :test #'equalp)) (lot:lottery-participants l)))
                              (opre (mapcar (lambda (i) (nth i pre)) order)) (opriv (mapcar (lambda (i) (nth i privs)) order))
                              (amount 1000000))
                         (if (null voters)
                             (progn
                               (check-equal (format nil "~a: only the full-set leaf" name) (length (lot:lottery-leaves l)) 1)
                               (check (format nil "~a: the full-set winner's claim verifies" name)
                                      (spend-lottery l amount (lambda (tx pv) (lot:claim-witness l (sig-for l tx pv (first (lot:lottery-leaves l)) (nth (lot:calculate-winner opre) opriv)) opre)))))
                             (let* ((idx '(0 1)) (w (lot:subset-winner idx (list (first opre) (second opre))))
                                    (leaf (nth (lot:subset-leaf-index l idx) (lot:lottery-leaves l)))
                                    (attest (lambda (signer-seeds)
                                              (spend-lottery l amount
                                                             (lambda (tx pv)
                                                               (lot:subset-witness l idx (sig-for l tx pv leaf (nth w opriv)) (list (first opre) (second opre))
                                                                                   (mapcar (lambda (k) (let ((sd (find k signer-seeds :key (lambda (j) (xonly-of (funcall seed j))) :test #'equalp)))
                                                                                                         (and sd (sig-for l tx pv leaf (funcall seed sd)))))
                                                                                           (lot::sorted-keys voters))))
                                                             :sequence 72)))
                                    (honest (remove-if (lambda (j) (member j accused-seeds)) '(21 22 23 24 25))))
                               (check (format nil "~a: a subset claim attested by ~a remaining voters verifies" name threshold)
                                      (funcall attest (subseq honest 0 threshold)))
                               (when accused-seeds
                                 (check (format nil "~a: attestations by accused keys do not count" name)
                                        (not (funcall attest (append accused-seeds (subseq honest 0 (1- threshold)))))))))))))))
    (check-equal "every lottery_voters_accused case ran" cases 4)))

;;; inspect/vectors/rearm_window_arms.json: DEP-06 Phase 4 step 2, each armer's arm in a re-arm
;;; window (the latest in-window arm of its first four), shared with deposits-rust (armers.rs).
(with-gate ("DEP-06 re-arm windows: each armer's in-window arm against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "rearm_window_arms.json")))))
    (loop for c across (gethash "cases" v)
          for arms = (loop for a across (gethash "arms" c)
                           collect (list (gethash "armer" a) nil nil nil (gethash "height" a) (gethash "seq" a) (gethash "round" a)))
          for got = (sort (mapcar (lambda (a) (list (first a) (sixth a)))
                                  (nd::pick-round-arms arms (gethash "round" c) (gethash "opens" c) (gethash "closes" c)))
                          #'string< :key #'first)
          for want = (loop for e across (gethash "expect" c) collect (list (gethash "armer" e) (gethash "seq" e)))
          do (check-equal (format nil "window arms: ~a" (gethash "name" c)) got want))))

;;; inspect/vectors/arm_manifest.json: DEP-06 §Arm manifests, whether a published arm set is valid for a
;;; round's window, shared with deposits-rust (armers.rs, manifest_arms).
(with-gate ("DEP-06 arm manifests: a published arm set against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "arm_manifest.json")))))
    (loop for c across (gethash "cases" v)
          for arms = (loop for a across (gethash "arms" c)
                           collect (list (gethash "armer" a) nil nil nil (gethash "height" a) (gethash "seq" a) (gethash "round" a)))
          for manifest = (loop for e across (gethash "manifest" c) collect (list (gethash "armer" e) (gethash "seq" e)))
          for (got reason) = (multiple-value-list (nd::manifest-arms arms manifest (gethash "round" c) (gethash "opens" c) (gethash "closes" c)))
          do (check-equal (format nil "manifest: ~a~@[ (~a)~]" (gethash "name" c) reason) (and got t) (gethash "valid" c))
             (when got
               (check-equal (format nil "manifest: ~a names exactly its arms" (gethash "name" c))
                            (mapcar (lambda (a) (list (first a) (sixth a))) got)
                            (sort (copy-list manifest) #'string< :key #'first))))))

;;; inspect/vectors/pledge_pick.json: DEP-03, the coin a member pledges in a DisputeArmed, shared with
;;; deposits-rust (dispute.rs, pick_pledge).
(with-gate ("DEP-03 pledge pick: the coin pledged against the shared vector")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "pledge_pick.json")))) (n 0))
    (loop for c across (gethash "cases" v)
          for utxos = (loop for u across (gethash "utxos" c)
                            collect (list :key (gethash "outpoint" u) :sats (gethash "sats" u)
                                          :confirmations (gethash "confirmations" u)))
          for own = (let ((o (gethash "own" c))) (and (stringp o) o))
          for want = (let ((e (gethash "expect" c))) (and (stringp e) e))
          for held = (loop for f across (or (gethash "forks" c) #())
                           append (multiple-value-bind (pledges custody)
                                      (nd::fork-pledges-held
                                       (loop for o across (gethash "ops" f)
                                             for k = (gethash "op" o)
                                             collect (cond ((string= k "enter") (list :enter))
                                                           ((string= k "arm") (let ((p (gethash "pledge" o)))
                                                                                (list :arm (and (stringp p) p) (or (gethash "round" o) 1))))
                                                           ((string= k "yield") (list :yield))
                                                           ((string= k "acquire")
                                                            (list :acquire (format nil "~a:0" (gethash "claim" o)) (eq (gethash "binds" o) t)))
                                                           (t (error "unknown fork op ~a" k))))
                                       :retired (eq (gethash "retired" f) t)
                                       :others (loop for a across (or (gethash "others" f) #())
                                                     when (eq (gethash "binds" a) t) collect (gethash "round" a)))
                                    (append pledges (and custody (list custody)))))
          for got = (nd::pick-pledge utxos (gethash "need" c) (gethash "min_confs" c) own
                                     (append (coerce (gethash "taken" c) 'list) held))
          do (incf n)
             (check-equal (format nil "pledge: ~a" (gethash "name" c)) (getf got :key) want))
    (check-equal "every pledge_pick case ran" n 21)))

;;; inspect/vectors/custody_coin.json: real deposits-rust ref6 transactions (regtest 1121-next4c).  A
;;; lottery claim's output 0 is a ledger's custody and is never pledged, whatever our records say.
(with-gate ("custody coins: a claim's output 0 is never pledged (shared vector, real ref6 transactions)")
  (let* ((v (json-simple:parse (uiop:read-file-string (vector-path "custody_coin.json"))))
         (txs (loop for c across (gethash "cases" v)
                    collect (btx:parse-tx (cl-consensus.wire:make-reader (u:hex->bytes (gethash "hex" c))))))
         (n 0))
    (loop for c across (gethash "cases" v)
          for tx in txs
          do (incf n)
             (check-equal (format nil "txid: ~a" (gethash "name" c)) (u:txid-hex (btx:tx-txid tx)) (gethash "txid" c))
             (check-equal (gethash "name" c) (and (nd::claim-output-p tx (gethash "vout" c)) t) (eq (gethash "custody" c) t))
             (check (format nil "not output 0: ~a" (gethash "name" c)) (not (nd::claim-output-p tx 1))))
    (check-equal "every custody_coin case ran" n 5)
    ;; The incident as a pledge saw it: the 4.99M-sat subset claim is the smallest coin covering a
    ;; 5000-sat need, so without the filter it is the pick; with it, the faucet coin is.
    (let* ((by-name (lambda (k) (nth (position-if (lambda (c) (search k (gethash "name" c))) (coerce (gethash "cases" v) 'list)) txs)))
           (subset (funcall by-name "subset")) (claim (funcall by-name "ad87b48b")) (faucet (funcall by-name "(output 0)"))
           (coin (lambda (tx) (list :txid (btx:tx-txid tx) :vout 0 :sats (btx:txout-value (elt (btx:tx-outputs tx) 0)) :confirmations 6)))
           (utxos (mapcar coin (list subset claim faucet)))
           (keyed (lambda (us) (loop for u in us collect (list* :key (nd::outpoint-key (getf u :txid) (getf u :vout)) u))))
           (node (nd::make-node :priv (tk 424243) :bus (bus:make-mock-bus) :tx-fn (lambda (txid) (let ((tx (find txid txs :key #'btx:tx-txid :test #'equalp))) (and tx (values tx 6)))))))
      (check-equal "unfiltered, the custody coin is the pick (what ref6 pledged)"
                   (getf (nd::pick-pledge (funcall keyed utxos) 5000 1 nil nil) :key)
                   (nd::outpoint-key (btx:tx-txid subset) 0))
      (let ((free (nd::without-custody-coins node utxos)))
        (check-equal "both claim outputs are left out" (length free) 1)
        (check-equal "the faucet coin is the pick"
                     (getf (nd::pick-pledge (funcall keyed free) 5000 1 nil nil) :key)
                     (nd::outpoint-key (btx:tx-txid faucet) 0)))
      ;; ref6's 9e23c858 arm declares fdff3a5f:0 (ad87b48b's custody): a claim with it is refused,
      ;; never rebuilt with another coin (DEP-03 §Claim transaction: input 1 is the declared pledge).
      (let ((fdff (list (btx:tx-txid claim) 0 (btx:txout-value (elt (btx:tx-outputs claim) 0))))
            (plain (list (btx:tx-txid faucet) 0 (btx:txout-value (elt (btx:tx-outputs faucet) 0))))
            (blind (nd::make-node :priv (tk 424244) :bus (bus:make-mock-bus) :tx-fn (lambda (txid) (declare (ignore txid)) nil))))
        (check-equal "fdff3a5f is the custody claim" (u:txid-hex (first fdff))
                     "fdff3a5f90d57a71e0cf73b6c9565ad2f417708dbe96a26ef24d8b2eba4b5307")
        (check "a claim with the custody pledge is refused" (search "custody" (or (nd::claim-collateral-refusal node fdff) "")))
        (check-equal "a claim with a faucet pledge is built" (nd::claim-collateral-refusal node plain) nil)
        (check "an unreadable pledge is refused for the pass" (search "unreadable" (or (nd::claim-collateral-refusal blind plain) "")))
        (check "a custody pledge re-arms while the vault is unspent" (nd::pledge-custody-rearm-p node fdff t))
        (check "no same-round re-arm once the vault is spent" (not (nd::pledge-custody-rearm-p node fdff nil)))
        (check "a faucet pledge never re-arms for custody" (not (nd::pledge-custody-rearm-p node plain t)))))))

;;; Local policy, not the shared vector: a re-arm leaves *REARM-PLEDGE-RESERVE* coins free; a round-1
;;; arm (reserve 0) may take the last; its own pledge is kept whatever the reserve.
(with-gate ("re-arm reserve: a re-arm leaves the last coins for new disputes")
  (let ((utxos (list (list :key "aa:0" :sats 50000 :confirmations 6)
                     (list :key "bb:1" :sats 30000 :confirmations 6)
                     (list :key "cc:0" :sats 10000 :confirmations 6))))
    (check-equal "two cover the need: a re-arm takes neither" (nd::pick-pledge utxos 20000 1 nil nil :reserve 2) nil)
    (check-equal "a round-1 arm takes one" (getf (nd::pick-pledge utxos 20000 1 nil nil) :key) "bb:1")
    (check-equal "three cover it: the re-arm takes the smallest" (getf (nd::pick-pledge utxos 5000 1 nil nil :reserve 2) :key) "cc:0")
    (check-equal "a taken coin is not free" (nd::pick-pledge utxos 5000 1 nil '("aa:0") :reserve 2) nil)
    (check-equal "its own pledge is kept" (getf (nd::pick-pledge utxos 20000 1 "bb:1" '("bb:1") :reserve 2) :key) "bb:1")))

;;; inspect/vectors/acquire_binding.json: DEP-06 "An acquire binds once its claim confirms", shared
;;; with deposits-rust (deposits-node/tests/vectors/acquire_binding.json): a DisputeAcquire binds iff
;;; its claim is confirmed AND spends the dispute's lottery outpoint.  Txids are display hex.
(defun ab-view (c)
  "The vector case C's transactions as a judge's TX-FN: wire txid -> (values tx confirmed-p)."
  (let ((txs (make-hash-table :test #'equalp)))
    (loop for x across (gethash "txs" c)
          do (setf (gethash (u:txid-bytes (gethash "txid" x)) txs)
                   (list (btx:make-tx :version 2 :locktime 0
                                      :inputs (loop for i across (gethash "inputs" x)
                                                    collect (btx:make-txin :prev-hash (u:txid-bytes (gethash "txid" i))
                                                                           :prev-index (gethash "vout" i)
                                                                           :script (make-array 0 :element-type '(unsigned-byte 8))
                                                                           :sequence (gethash "sequence" i)))
                                      :outputs (loop repeat (gethash "outputs" x)
                                                     collect (btx:make-txout :value 1000 :script (make-array 0 :element-type '(unsigned-byte 8)))))
                         (eq (gethash "confirmed" x) t))))
    (lambda (txid) (let ((e (gethash txid txs))) (and e (values (first e) (second e)))))))

(defun ab-judge (c)
  (cl-deposits.node::judge-acquire (ab-view c)
                                   (loop for v across (gethash "vaults" c)
                                         collect (list (u:txid-bytes (gethash "txid" v)) (gethash "vout" v)))
                                   (u:txid-bytes (gethash "claim_txid" c))))

(with-gate ("DEP-06 acquire binding: a claim binds only at its dispute's lottery outpoint (shared vector)")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "acquire_binding.json")))) (n 0))
    (check-equal "tier CSVs agree" (coerce (gethash "tier_csvs" v) 'list) cl-deposits.node::+rearm-tier-csvs+)
    (check-equal "max rounds agree" (gethash "max_rounds" v) cl-deposits.node::+acquire-max-rounds+)
    (loop for c across (gethash "cases" v)
          for got = (ab-judge c)
          for round = (nth-value 1 (ab-judge c))
          do (incf n)
             (check-equal (format nil "round: ~a" (gethash "name" c)) (or round 0) (gethash "round" c))
             (check-equal (gethash "name" c) (string-downcase (symbol-name got)) (gethash "reason" c))
             (check-equal (format nil "binds: ~a" (gethash "name" c)) (eq got :binds) (eq (gethash "binds" c) t)))
    (check "every acquire_binding case ran" (>= n 13))))

;;; The incident itself: a606a4ca's acquire named 21910507, confirmed, which spent 70b0abb3's round-2
;;; output 46a66b12:0.  Confirmation alone (the old rule) bound it.
(with-gate ("DEP-06 acquire binding: a606a4ca's acquire naming 21910507 does not bind")
  (let* ((v (json-simple:parse (uiop:read-file-string (vector-path "acquire_binding.json"))))
         (c (find-if (lambda (c) (search "1120-090836" (gethash "name" c))) (gethash "cases" v)))
         (claim "21910507ef3364bc74d898f339b19c293d49abcd478b99168c907d02de3b3711"))
    (check "the incident case is in the vector" c)
    (check-equal "it names 21910507" (gethash "claim_txid" c) claim)
    (multiple-value-bind (tx confirmed) (funcall (ab-view c) (u:txid-bytes claim))
      (check "the claim is confirmed: the old rule bound it" confirmed)
      (check-equal "it spent 46a66b12:0"
                   (list (u:txid-hex (btx:txin-prev-hash (first (btx:tx-inputs tx)))) (btx:txin-prev-index (first (btx:tx-inputs tx))))
                   (list "46a66b127e0e3afd04f2e4399681128399caab6d6133320c7d02d3569f5c3c79" 0)))
    (check-equal "judged for a606a4ca's vault: not its lottery" (ab-judge c) :not-this-lottery)))

;;; inspect/vectors/claim_after_yield.json: DEP-06 "A claim after the claimant's own yield" (ruled
;;; 2026-11-23, the advantage rule), shared with deposits-rust and the spec.  The fork is SELF's (its
;;; DisputeEnter applied with *UPDATE-OPERATOR* bound to SELF); the acquire after its own yield is taken
;;; structurally, and moves custody only if its claim binds the yielded arm's round or a later one.
(defun cay-ops (c self)
  (flet ((arm (commit round)
           (append (list :type :dispute-armed :armed-block 100
                         :commitment-hash (make-array 20 :element-type '(unsigned-byte 8) :initial-element commit)
                         :target-reserves "t"
                         :replacement-collateral-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                         :replacement-collateral-vout 0 :replacement-collateral-amount 50000)
                   (when round (list :rearm-round round)))))
    (loop for o across (gethash "ops" c)
          for k = (gethash "op" o)
          collect (cond ((string= k "enter") (list :type :dispute-enter :last-valid-sequence 0 :reason (gethash "reason" o)))
                        ((string= k "arm") (arm #x11 nil))
                        ((string= k "arm_round_2") (arm #x22 2))
                        ((string= k "yield") (list :type :dispute-yield))
                        (t (error "unknown op ~a" k))))
    ))

(with-gate ("DEP-06 the advantage rule: a claim after the claimant's own yield (shared vector)")
  (let* ((v (json-simple:parse (uiop:read-file-string (vector-path "claim_after_yield.json"))))
         (self (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2))
         (other (make-array 33 :element-type '(unsigned-byte 8) :initial-element 3))
         (n 0))
    (setf (aref self 1) 1 (aref other 1) 1)
    (loop for c across (gethash "cases" v)
          for name = (gethash "name" c)
          for ops = (cay-ops c self)
          do (incf n)
             (let ((l (lg:make-ledger)))
               (setf (lg:ledger-active-ruleset l) (gethash "ruleset" c))
               (let ((lg::*update-operator* self))
                 (dolist (o ops) (lg:apply-operation l o)))
               (let ((acq (list :type :dispute-acquire
                                :new-custodian (if (string= (gethash "acquire_by" c) "self") self other)
                                :claim-txid (u:txid-bytes (or (and (stringp (gethash "claim_txid" c)) (gethash "claim_txid" c)) (make-string 64 :initial-element #\4)))
                                :new-reserves-address "")))
                 (check-equal (format nil "fold: ~a" name)
                              (handler-case (let ((lg::*update-operator* self)) (lg:apply-operation l acq) "accept")
                                (lg:ledger-error () "reject"))
                              (gethash "fold" c))
                 (when (string= (gethash "fold" c) "accept")
                   (check-equal (format nil "custody to the claimant on the fold: ~a" name)
                                (lg:ledger-operator-key l) (getf acq :new-custodian))
                   ;; the round bound, from the acquirer's own arms and yields before the acquire
                   (let ((min (nd::acquire-min-round
                               (loop for o in ops
                                     collect (case (getf o :type)
                                               (:dispute-armed (list :arm (or (getf o :rearm-round) 1)))
                                               (:dispute-yield (list :yield))
                                               (t (list :other)))))))
                     (check-equal (format nil "min_round: ~a" name) min (gethash "min_round" c))
                     (multiple-value-bind (verdict round) (ab-judge c)
                       (check-equal (format nil "binding: ~a" name) (string-downcase (symbol-name verdict)) (gethash "binding" c))
                       (check-equal (format nil "round: ~a" name) (or round 0) (gethash "round" c))
                       (let ((custodian (and (eq verdict :binds) (>= round min))))
                         (check-equal (format nil "custodian: ~a" name) (if custodian "self" "none") (gethash "custodian" c))
                         ;; what the claimant's fork still holds (the pledge_pick fork fold)
                         (let ((held (gethash "held" c))
                               (claim-key (format nil "~a:0" (gethash "claim_txid" c))))
                           (multiple-value-bind (pledges custody)
                               (nd::fork-pledges-held
                                (append (loop for o in ops
                                              collect (case (getf o :type)
                                                        (:dispute-enter (list :enter))
                                                        (:dispute-armed (let ((r (or (getf o :rearm-round) 1)))
                                                                          (list :arm (format nil "~{~a~}:0" (make-list 32 :initial-element (if (= r 1) "d4" "d5"))) r)))
                                                        (:dispute-yield (list :yield))))
                                        (list (list :acquire claim-key custodian))))
                             (check-equal (format nil "held pledges: ~a" name) pledges (coerce (gethash "pledges" held) 'list))
                             (check-equal (format nil "held custody: ~a" name) custody
                                          (let ((k (gethash "custody" held))) (and (stringp k) k))))))))))))
    (check "every claim_after_yield case ran" (>= n 8))))

;;; The same case on a NODE: the fork's own acquire after its own yield is judged by
;;; ACQUIRE-CONFIRMED-P with the round bound (FORK-ACQUIRE-MIN-ROUND), from the fork's updates.
(with-gate ("DEP-06 the advantage rule: the round bound read off a fork's own updates")
  (check-equal "an acquire after a yield of a round-2 arm: bound 2"
               (nd::acquire-min-round '((:arm 2) (:yield))) 2)
  (check-equal "a later arm after the yield lifts nothing: bound 0 until it yields again"
               (nd::acquire-min-round '((:arm 1) (:yield) (:arm 2))) 0)
  (check-equal "no yield: no bound" (nd::acquire-min-round '((:arm 2))) 0)
  (check-equal "yield, re-arm, yield: the latest arm's round" (nd::acquire-min-round '((:arm 1) (:yield) (:arm 2) (:yield))) 2))

;;; DEP-06 "An invalid yield is void": a yield naming a transaction that is not confirmed frees no
;;; pledge (FORK-PLEDGE-EVENTS reads it as (:void-yield)); once it confirms, it does.  Mirrors
;;; deposits-rust's a_yield_whose_named_transaction_is_unconfirmed_frees_no_pledge.
(with-gate ("DEP-06 a yield whose evidence is not seen frees no pledge")
  (let* ((named (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab))
         (held (lambda (yield-op confs)
                 (let* ((n (nd:make-node :priv (tk 31337) :bus (bus:make-mock-bus) :tx-fn (lambda (txid) (if (equalp txid named) (values :tx confs) nil))))
                        (ev (list (list :enter) (list :arm "d7:1" 1)
                                  (if (nd::yield-evidence-seen-p n yield-op) (list :yield) (list :void-yield)))))
                   (length (nd::fork-pledges-held ev))))))
    (check-equal "lost_to unconfirmed: the pledge is held" (funcall held (list :type :dispute-yield :lost-to named) 0) 1)
    (check-equal "lost_to confirmed: freed" (funcall held (list :type :dispute-yield :lost-to named) 3) 0)
    (check-equal "excluded_by unconfirmed: held" (funcall held (list :type :dispute-yield :excluded-by named) 0) 1)
    (check-equal "excluded_by confirmed: freed" (funcall held (list :type :dispute-yield :excluded-by named) 3) 0)
    (check-equal "a reasonless yield: freed" (funcall held (list :type :dispute-yield) 0) 0)))

;;; inspect/vectors/yield_evidence.json: DEP-06 "What a yield must say" (yield-evidence-v9, ruled
;;; 2026-11-23), shared with deposits-rust and the spec: the reason TLVs on the wire, the fold's
;;; structural check, and the judge.
(defun ye-tx-fn (c)
  (let ((txs (make-hash-table :test #'equalp)))
    (loop for x across (gethash "txs" c)
          do (setf (gethash (u:txid-bytes (gethash "txid" x)) txs)
                   (list (btx:make-tx :version 2 :locktime 0
                                      :inputs (loop for i across (gethash "inputs" x)
                                                    collect (btx:make-txin :prev-hash (u:txid-bytes (gethash "txid" i))
                                                                           :prev-index (gethash "vout" i)
                                                                           :script (make-array 0 :element-type '(unsigned-byte 8))
                                                                           :sequence (gethash "sequence" i)))
                                      :outputs (loop for o across (gethash "outputs" x)
                                                     collect (btx:make-txout :value 1000 :script (u:hex->bytes o))))
                         (let ((hh (gethash "height" x))) (and (integerp hh) hh)))))
    (lambda (txid) (let ((e (gethash txid txs))) (and e (values (first e) (second e)))))))

(defun ye-reasons (r)
  "A vector `reasons` object as YIELD-ONCE's plist: txids as wire bytes, the reestablished hash as written."
  (loop for (json key txid) in '(("lost_to" :lost-to t) ("reestablished" :reestablished nil) ("excluded_by" :excluded-by t))
        for x = (gethash json r)
        when (stringp x) append (list key (if txid (u:txid-bytes x) (u:hex->bytes x)))))

(with-gate ("DEP-06 yield evidence: reasons on the wire, the fold, the judge (shared vector)")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "yield_evidence.json")))) (n 0))
    (loop for w across (gethash "wire" v)
          for op = (append (list :type :dispute-yield) (ye-reasons (gethash "reasons" w)))
          do (check-equal (format nil "wire: ~a" (gethash "name" w)) (u:bytes->hex (op:encode-operation op)) (gethash "hex" w))
             (check-equal (format nil "wire round trip: ~a" (gethash "name" w))
                          (op:decode-operation (u:hex->bytes (gethash "hex" w))) op))
    (loop for c across (gethash "cases" v)
          for name = (gethash "name" c)
          for reasons = (ye-reasons (gethash "reasons" c))
          for y = (gethash "yielder" c)
          do (incf n)
             ;; the fold: a fork under the case's ruleset, entered and armed, takes the yield or not
             (let ((l (lg:make-ledger)))
               (setf (lg:ledger-active-ruleset l) (gethash "ruleset" c))
               (lg:apply-operation l (list :type :dispute-enter :last-valid-sequence 0 :reason "equivocation"))
               (lg:apply-operation l (list :type :dispute-armed :armed-block 100
                                           :commitment-hash (make-array 20 :element-type '(unsigned-byte 8) :initial-element 1)
                                           :target-reserves "t"))
               (check-equal (format nil "fold: ~a" name)
                            (handler-case (progn (lg:apply-operation l (append (list :type :dispute-yield) reasons)) "accept")
                              (lg:ledger-error () "reject"))
                            (gethash "fold" c)))
             (multiple-value-bind (verdict why)
                 (nd::judge-yield :ruleset (gethash "ruleset" c) :reasons reasons
                                  :yield-height (gethash "yield_height" c) :arm-round (gethash "arm_round" c)
                                  :yielder (u:hex->bytes (gethash "xonly" y))
                                  :targets (map 'list #'u:hex->bytes (gethash "targets" y))
                                  :pledges (map 'list (lambda (p) (list (u:txid-bytes (gethash "txid" p)) (gethash "vout" p))) (gethash "pledges" y))
                                  :vaults (map 'list (lambda (p) (list (u:txid-bytes (gethash "txid" p)) (gethash "vout" p))) (gethash "vaults" c))
                                  :tx-fn (ye-tx-fn c)
                                  :dispute-reason (gethash "reason" (gethash "dispute" c))
                                  :last-valid-sequence (gethash "last_valid_sequence" (gethash "dispute" c))
                                  :quorum-begins (map 'list (lambda (q) (list (u:hex->bytes (gethash "hash" q)) (gethash "seq" q) (eq (gethash "spend_confirmed" q) t)))
                                                      (gethash "quorum_begins" c))
                                  :participants (map 'list #'u:hex->bytes (gethash "participants" c)))
               (check-equal (format nil "verdict: ~a" name) (string-downcase (symbol-name verdict)) (gethash "verdict" c))
               (check-equal (format nil "why: ~a" name) (string-downcase (symbol-name why)) (gethash "why" c))))
    (check "every yield_evidence case ran" (>= n 24))))

;;; inspect/vectors/rearm_round_agree.json: DEP-03 §"The dispute" and DEP-06 Phase 4 step 2 over
;;; real regtest ledgers (2026-11-19/21), shared with deposits-rust (armers.rs) and the spec.  A
;;; stale DisputeEnter (below Q, yielded) took the Rust voters to the old QuorumBegin, so ref6 never
;;; found four lotteries and refused 12bc96d2's attestations; and cld364 re-armed round 2 on that
;;; stale fork every pass of every window, since its own arms, rightly no arms, never showed in the
;;; checks meant to stop it.  The updates are loaded as a node loads its replica files.
(with-gate ("DEP-06 re-arm rounds: the current dispute's voters, arms and manifests on real ledgers (shared vector)")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "rearm_round_agree.json"))))
        (n 0))
    (loop for c across (gethash "cases" v)
          for name = (subseq (gethash "name" c) 0 8)
          for e = (gethash "expect" c)
          for dir = (uiop:ensure-directory-pathname (format nil "/tmp/cl-deposits-rra-~a-~a/" (random 1000000000) name))
          for node = (nd:make-node :priv (tk 4242424242424242424242) :bus (bus:make-mock-bus) :network "regtest")
          for ups = (loop for h across (gethash "updates" c) collect (u:hex->bytes h))
          for id = (gethash "ledger_id" c)
          do (incf n)
             (ensure-directories-exist dir)
             ;; the base chain (the original operator's), then one file per fork, as on disk
             (let* ((dec (mapcar (lambda (b) (cons b (up:decode-update b))) ups))
                    (origin (up:update-operator-id (cdr (find 0 dec :key (lambda (x) (up:update-seq (cdr x)))))))
                    (by (make-hash-table :test #'equalp)))
               (dolist (x dec) (push x (gethash (up:update-operator-id (cdr x)) by)))
               (flet ((write-file (path xs)
                        (with-open-file (o path :direction :output :if-exists :supersede)
                          (format o "[~{\"~a\"~^,~%~}]~%" (mapcar (lambda (x) (u:base64-encode (car x))) (sort (copy-list xs) #'< :key (lambda (x) (up:update-seq (cdr x)))))))
                        path))
                 (nd:load-record node (write-file (merge-pathnames (format nil "ledger_~a.json" (subseq id 0 16)) dir) (gethash origin by)))
                 (maphash (lambda (op xs)
                            (unless (equalp op origin)
                              (nd:load-record node (write-file (merge-pathnames (format nil "ledger_~a_fork_~a.json" (subseq id 0 16) (subseq (u:bytes->hex op) 0 16)) dir) xs))))
                          by)))
             (let* ((forks (nd::forks-of node id))
                    (in (sort (mapcar (lambda (f) (u:bytes->hex (nd::record-fork-operator f))) (nd::dispute-forks node id)) #'string<))
                    (fork-of (lambda (k) (find k forks :key (lambda (f) (u:bytes->hex (nd::record-fork-operator f))) :test #'string=)))
                    (base (nd::find-record node id))
                    (fp (nd::dispute-last-valid-seq node id))
                    (voters (sort (mapcar #'u:bytes->hex (nd::recovery-voters base fp)) #'string<))
                    (arms (nd::%all-arms node id))
                    (pair (lambda (a) (list (u:bytes->hex (first a)) (sixth a))))
                    (want-pairs (lambda (xs) (loop for a across xs collect (list (gethash "armer" a) (gethash "seq" a)))))
                    (sorted (lambda (l) (sort (copy-list l) #'string< :key #'first))))
               (check-equal (format nil "~a: the disputants in the current dispute" name) in (coerce (gethash "in_dispute" e) 'list))
               (check-equal (format nil "~a: the fork point" name) fp (gethash "fork_point" e))
               (check-equal (format nil "~a: Q" name) (nd::dispute-scope-q base fp) (gethash "quorum_begin_seq" e))
               (check-equal (format nil "~a: the recovery voters are Q's members less the operator" name) voters (coerce (gethash "recovery_voters" e) 'list))
               (check-equal (format nil "~a: the recovery threshold" name) (lg:majority-threshold (length voters)) (gethash "recovery_threshold" e))
               (check-equal (format nil "~a: round 1's arms at the confiscation" name)
                            (funcall sorted (mapcar pair (nd::pick-round-arms arms 1 -1 (gethash "confiscation_height" (gethash "chain" c)))))
                            (funcall want-pairs (gethash "round1_arms" e)))
               (loop for k across (gethash "in_dispute" e)
                     do (check (format nil "~a: ~a's fork may arm a later round" name (subseq k 0 8))
                               (null (nd::rearm-fork-out-of-dispute node id (funcall fork-of k)))))
               (loop for k across (gethash "out_of_dispute" e)
                     do (check (format nil "~a: ~a's stale fork may not arm a later round" name (subseq k 0 8))
                               (nd::rearm-fork-out-of-dispute node id (funcall fork-of k)))
                        (check (format nil "~a: ~a's stale fork's arms are no arms" name (subseq k 0 8))
                               (notany (lambda (a) (string= (u:bytes->hex (first a)) k)) arms)))
               (loop for w across (gethash "windows" e)
                     do (check-equal (format nil "~a: round ~a's arms in (~a, ~a]" name (gethash "round" w) (gethash "opens" w) (gethash "closes" w))
                                     (funcall sorted (mapcar pair (nd::pick-round-arms arms (gethash "round" w) (gethash "opens" w) (gethash "closes" w))))
                                     (funcall want-pairs (gethash "arms" w))))
               (loop for m across (gethash "manifests" e)
                     for named = (loop for a across (gethash "arms" m) collect (list (u:hex->bytes (aref a 0)) (aref a 1)))
                     do (check-equal (format nil "~a: manifest of round ~a in (~a, ~a] valid" name (gethash "round" m) (gethash "opens" m) (gethash "closes" m))
                                     (and (nd::manifest-arms arms named (gethash "round" m) (gethash "opens" m) (gethash "closes" m)) t)
                                     (gethash "valid" m)))
               ;; the landed lottery: manifest 0's arms, Q's voters less the accused; the chain's spk
               (let* ((l (gethash "lottery" e))
                      (m (aref (gethash "manifests" e) (gethash "manifest" l)))
                      (named (nd::manifest-arms arms (loop for a across (gethash "arms" m) collect (list (u:hex->bytes (aref a 0)) (aref a 1)))
                                                (gethash "round" m) (gethash "opens" m) (gethash "closes" m)))
                      (accused (coerce (gethash "accused" e) 'list))
                      (kept (remove-if (lambda (x) (member x accused :test #'string=)) voters))
                      (lot (lot:build-lottery (loop for (pk commitment target) in named
                                                    collect (lot:make-participant :pubkey (up:x-only pk) :commitment commitment :target target))
                                              (mapcar #'u:hex->bytes kept) (lg:majority-threshold (length kept)) :network :regtest)))
                 (check-equal (format nil "~a: the voters less the accused" name) kept (coerce (gethash "voters" l) 'list))
                 (check-equal (format nil "~a: the lottery is the confirmed output's" name) (u:bytes->hex (lot:lottery-spk lot)) (gethash "lottery_spk" (gethash "chain" c)))))
             (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))
    (check-equal "every rearm_round_agree case ran" n 4)))

(defun rra-load-node (c dir)
  "A node holding case C's updates as replica files in DIR (the base chain, then a file per
   fork), as the gate above loads them.  (values node ledger-id)."
  (let* ((node (nd:make-node :priv (tk 4242424242424242424242) :bus (bus:make-mock-bus) :network "regtest"))
         (id (gethash "ledger_id" c))
         (dec (loop for h across (gethash "updates" c) for b = (u:hex->bytes h) collect (cons b (up:decode-update b))))
         (origin (up:update-operator-id (cdr (find 0 dec :key (lambda (x) (up:update-seq (cdr x)))))))
         (by (make-hash-table :test #'equalp)))
    (ensure-directories-exist dir)
    (dolist (x dec) (push x (gethash (up:update-operator-id (cdr x)) by)))
    (flet ((write-file (path xs)
             (with-open-file (o path :direction :output :if-exists :supersede)
               (format o "[~{\"~a\"~^,~%~}]~%" (mapcar (lambda (x) (u:base64-encode (car x))) (sort (copy-list xs) #'< :key (lambda (x) (up:update-seq (cdr x)))))))
             path))
      (nd:load-record node (write-file (merge-pathnames (format nil "ledger_~a.json" (subseq id 0 16)) dir) (gethash origin by)))
      (maphash (lambda (op xs)
                 (unless (equalp op origin)
                   (nd:load-record node (write-file (merge-pathnames (format nil "ledger_~a_fork_~a.json" (subseq id 0 16) (subseq (u:bytes->hex op) 0 16)) dir) xs))))
               by))
    (values node id)))

;;; DEP-03 §When the set is final, for DisputeEnters (vector rearm_round_agree.json, late_enter):
;;; 12bc96d2's DisputeEnter signed at 34763, after the confiscation at 23996, on a re-sent
;;; contagion proof convicting c30c1b29.  Under the rule (`final`) it takes no part: c30c1b29's
;;; round-2 arm is the cut of (24140, 24146] and the voters are the lottery's on chain.  Without it
;;; (`control`: no confiscation height known) the arm is cut and the voters lose c30c1b29, which is
;;; what cld364 did from 01:06Z on 2026-11-21.  Every carried proof is taken as grounded (each
;;; verifies on regtest), seeded into the grounds cache.  Two repeat-entry cases follow it: c30c1b29
;;; entering again above C, below Q (fork point 4) and past its own arm (fork point 10).
(with-gate ("DEP-03 when the set is final: a DisputeEnter above the confiscation takes no part (shared vector, 12bc96d2)")
  (let ((v (json-simple:parse (uiop:read-file-string (vector-path "rearm_round_agree.json"))))
        (n 0))
    (loop for c across (gethash "late_enter" v)
          for name = (subseq (gethash "name" c) 0 (position #\: (gethash "name" c)))
          for dir = (uiop:ensure-directory-pathname (format nil "/tmp/cl-deposits-rra-late-~a/" (random 1000000000)))
          do (incf n)
             (multiple-value-bind (node id) (rra-load-node c dir)
               (dolist (f (nd::forks-of node id))
                 (dolist (u (nd::fork-own-updates f :dispute-enter))
                   (when (op:field (op:update-op u) :fraud-proof)
                     (setf (gethash (up:chain-hash u) (nd::node-grounds-verdicts node)) (cons :grounded "taken as grounded")))))
               (let ((chash (gethash "confiscation_height" (gethash "chain" c))))
                 (dolist (arm '("final" "control"))
                   (let ((e (gethash arm c)))
                     (if (string= arm "final")
                         (setf (gethash id (nd::node-confiscation-heights node)) chash)
                         (remhash id (nd::node-confiscation-heights node)))
                     (let* ((in (sort (mapcar (lambda (f) (u:bytes->hex (nd::record-fork-operator f))) (nd::dispute-forks node id)) #'string<))
                            (accused (nd::dispute-accused-keys node id))
                            (convicted (sort (mapcar #'u:bytes->hex accused) #'string<))
                            (arms (nd::%all-arms node id))
                            (voters (sort (mapcar #'u:bytes->hex (nd::lottery-voters node id)) #'string<)))
                       (check-equal (format nil "~a ~a: the disputants" name arm) in (coerce (gethash "in_dispute" e) 'list))
                       (check-equal (format nil "~a ~a: Accused(grounds)" name arm) convicted (coerce (gethash "convicted_if_grounded" e) 'list))
                       (loop for w across (gethash "window_cuts" e)
                             do (check-equal (format nil "~a ~a: round ~a's cut of (~a, ~a]" name arm (gethash "round" w) (gethash "opens" w) (gethash "closes" w))
                                             (sort (mapcar (lambda (a) (list (u:bytes->hex (first a)) (sixth a)))
                                                           (nd::accused-cut (nd::pick-round-arms arms (gethash "round" w) (gethash "opens" w) (gethash "closes" w)) accused))
                                                   #'string< :key #'first)
                                             (loop for a across (gethash "arms" w) collect (list (gethash "armer" a) (gethash "seq" a)))))
                       ;; the arms of the disputants' forks after their counted fork points: a repeat
                       ;; entry must not move the fork point (dispute_arms; DISPUTE-FORK-POINT)
                       (when (gethash "dispute_arms" e)
                         (check-equal (format nil "~a ~a: the dispute's arms" name arm)
                                      (sort (mapcar (lambda (a) (list (u:bytes->hex (first a)) (sixth a))) arms)
                                            (lambda (x y) (or (string< (first x) (first y))
                                                              (and (string= (first x) (first y)) (< (second x) (second y))))))
                                      (loop for a across (gethash "dispute_arms" e) collect (list (gethash "armer" a) (gethash "seq" a)))))
                       (check-equal (format nil "~a ~a: the lottery's voters" name arm) voters
                                    (coerce (if (string= arm "final") (gethash "voters" (gethash "lottery" e)) (gethash "lottery_voters" e)) 'list))
                       (let* ((m (aref (gethash "manifests" c) 0))
                              (named (nd::manifest-arms arms (loop for a across (gethash "arms" m) collect (list (u:hex->bytes (aref a 0)) (aref a 1)))
                                                        (gethash "round" m) (gethash "opens" m) (gethash "closes" m)))
                              (lot (and named   ; NIL: an arm the manifest names takes no part
                                        (lot:build-lottery (loop for (pk commitment target) in named
                                                                 collect (lot:make-participant :pubkey (up:x-only pk) :commitment commitment :target target))
                                                           (mapcar #'u:hex->bytes voters) (lg:majority-threshold (length voters)) :network :regtest))))
                         (check-equal (format nil "~a ~a: the lottery pays the chain's output iff the rule is applied" name arm)
                                      (and lot (string= (u:bytes->hex (lot:lottery-spk lot)) (gethash "lottery_spk" (gethash "chain" c))))
                                      (string= arm "final"))))))))
             (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))
    (check-equal "every late_enter case ran" n 3)))

(report)
