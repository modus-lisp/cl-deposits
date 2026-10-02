;;;; inspect/lottery-test.lisp — the custody lottery, spent under cl-consensus.

(in-package #:cl-deposits.test)

(defun lot-keys (n) (loop for i from 1 to n collect (+ 424242424242 (* i 1000000007))))
(defun xonly-of (priv) (up:x-only (up:compressed-pubkey priv)))

(defun random-preimage (n)
  (let ((len (+ 17 (random n))))
    (let ((p (make-array len :element-type '(unsigned-byte 8)))) (dotimes (i len p) (setf (aref p i) (random 256))))))

(with-gate ("lottery: winner rule and preimage derivation")
  (check-equal "sum of contributions mod n" (lot:calculate-winner (list (make-array 18) (make-array 19) (make-array 17))) (mod (+ 2 3 1) 3))
  (check-signals "short preimage rejected" error (lot:calculate-winner (list (make-array 16) (make-array 17))))
  (let ((p (lot:derive-preimage (u:sha256 (hx "01")) 5)))
    (check "derived preimage length in 17..21" (<= 17 (length p) 21))
    (check-bytes "derivation is deterministic" (lot:derive-preimage (u:sha256 (hx "01")) 5) p))
  (check-equal "lengths spread over the range"
               (length (remove-duplicates (loop for i below 60 collect (length (lot:derive-preimage (u:sha256 (u:int->be i 4)) 5)))))
               5)
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
  (secp256k1-fast.schnorr:schnorr-sign priv (rot:tier-sighash tx 0 prevouts leaf)))

(dolist (n '(3 5 6 10 11))
  (with-gate ((format nil "lottery: N=~a full reveal, spent under consensus" n))
    (let* ((privs (lot-keys n))
           (preimages (loop repeat n collect (random-preimage n)))
           (participants (loop for priv in privs for p in preimages
                               collect (lot:make-participant :pubkey (xonly-of priv) :commitment (lot:commitment-of p) :target "tb1p")))
           (voters (mapcar #'xonly-of (lot-keys 3)))
           (l (lot:build-lottery participants voters 2))
           ;; canonical order is by pubkey: realign preimages/privs to it
           (order (mapcar (lambda (p) (position (lot:participant-pubkey p) participants :key #'lot:participant-pubkey :test #'equalp)) (lot:lottery-participants l)))
           (ordered-pre (mapcar (lambda (i) (nth i preimages)) order))
           (ordered-priv (mapcar (lambda (i) (nth i privs)) order))
           (winner (lot:calculate-winner ordered-pre))
           (amount 1000000))
      (check "address is p2tr" (string= "tb1p" (subseq (lot:lottery-address l) 0 4)))
      (check-equal "leaf count = 1 + partials + 4 recovery" (length (lot:lottery-leaves l)) (+ 1 n 4))
      (check (format nil "winner ~a's claim verifies" winner)
             (spend-lottery l amount (lambda (tx pv) (lot:claim-witness l (sig-for l tx pv (first (lot:lottery-leaves l)) (nth winner ordered-priv)) ordered-pre))))
      (check "every loser's claim fails"
             (loop for i below n
                   always (or (= i winner)
                              (not (spend-lottery l amount (lambda (tx pv) (lot:claim-witness l (sig-for l tx pv (first (lot:lottery-leaves l)) (nth i ordered-priv)) ordered-pre)))))))
      (check "a wrong preimage fails"
             (not (spend-lottery l amount (lambda (tx pv) (let ((bad (copy-list ordered-pre))) (setf (first bad) (random-preimage n))
                                                             (lot:claim-witness l (sig-for l tx pv (first (lot:lottery-leaves l)) (nth winner ordered-priv)) bad))))))
      (when (>= n 3)
        ;; Partial reveal: participant m stays silent; the other N-1 run a sub-lottery after CSV 72.
        (let* ((missing (mod (1+ winner) n))
               (revealers (loop for i below n unless (= i missing) collect i))
               (sub-pre (mapcar (lambda (i) (nth i ordered-pre)) revealers))
               (sub-winner (nth (lot:calculate-winner sub-pre :bounds-n n) revealers))
               (leaf (nth (1+ missing) (lot:lottery-leaves l))))
          ;; Reference quirk: the sub-lottery reduces the sum with N-1 conditional
          ;; subtractions of N-1, which is one short exactly when every revealer
          ;; contributed the maximum (sum = (N-1)*N).  That leaf is then unspendable.
          (let ((sum (loop for p in sub-pre sum (- (length p) 16))) (spends (spend-lottery l amount (lambda (tx pv) (lot:partial-reveal-witness l missing (sig-for l tx pv leaf (nth sub-winner ordered-priv)) sub-pre)) :sequence 72)))
            (if (= sum (* (1- n) n))
                (check (format nil "partial reveal (missing ~a): all-maximum contributions hit the reference's under-reduction (leaf unspendable)" missing) (not spends))
                (check (format nil "partial reveal (missing ~a): sub-winner ~a claims after CSV 72" missing sub-winner) spends)))
          (check "partial reveal without the CSV wait fails"
                 (not (spend-lottery l amount (lambda (tx pv) (lot:partial-reveal-witness l missing (sig-for l tx pv leaf (nth sub-winner ordered-priv)) sub-pre)))))))
      ;; Recovery cascade: 2-of-3 voters after 144; 1 voter after 1008 (T-1=1); escape hatch after 8064.
      (let* ((vprivs (lot-keys 3))
             (lowest (find (first (lot::sorted-keys voters)) vprivs :key #'xonly-of :test #'equalp))
             (other (find-if (lambda (p) (not (eql p lowest))) vprivs)))
        (flet ((rec (tier csv signers)
                 (spend-lottery l amount
                                (lambda (tx pv)
                                  (let* ((idx (lot::recovery-leaf-index l tier)) (leaf (nth idx (lot:lottery-leaves l)))
                                         (sorted (lot::sorted-keys voters))
                                         (sigs (mapcar (lambda (k) (let ((p (find k vprivs :key #'xonly-of :test #'equalp)))
                                                                     (and (member p signers) (sig-for l tx pv leaf p))))
                                                       sorted)))
                                    (lot:recovery-witness l tier sigs)))
                                :sequence csv)))
          (check "recovery tier 0: 2 of 3 voters after 144 blocks" (rec 0 144 (list (first vprivs) (third vprivs))))
          (check "recovery tier 0: 1 voter is not enough" (not (rec 0 144 (list (first vprivs)))))
          (check "recovery tier 0: too early fails" (not (rec 0 100 (list (first vprivs) (third vprivs)))))
          (check "recovery tier 1 (T-1=1): the lowest sorted voter after 1008" (rec 1 1008 (list lowest)))
          (check "recovery tier 1: another voter cannot use the single-key leaf" (not (rec 1 1008 (list other))))
          (check "escape hatch: the lowest sorted voter after 8064" (rec 3 8064 (list lowest)))
          (check "escape hatch: too early fails" (not (rec 3 8000 (list lowest)))))))))

(with-gate ("lottery: armer shares and forfeit sweep")
  (let* ((armer 55555) (pre (random-preimage 3)) (voters (mapcar #'xonly-of (lot-keys 3))) (vprivs (lot-keys 3))
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
             (not (spend (lambda (tx) (list (sig-for nil tx prevouts (first (lot:armer-share-leaves a)) armer) (random-preimage 3) (first (lot:armer-share-leaves a)) (lot:armer-share-control-block a 0))) #xfffffffd)))
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
    (check-equal "revealers are read back from a claim witness"
                 (lot:revealers-from-witness (list (u:octets 1 2) pre (make-array 40)) (list (cons (xonly-of armer) (lot:commitment-of pre))))
                 (list (xonly-of armer)))
    (check-equal "confiscation: punitive = everything to the lottery"
                 (lot:confiscation-outputs (hx "5120aa") 100000 500) (list (cons (hx "5120aa") 99500)))
    (check-equal "confiscation: respectful = obligations to lottery, change to operator p2wpkh"
                 (mapcar #'cdr (lot:confiscation-outputs (hx "5120aa") 100000 500 :respectful t :obligations-sats 40000 :operator-pubkey33 (up:compressed-pubkey 9)))
                 '(40000 59500))
    (check-equal "confiscation: respectful with dust change collapses to punitive"
                 (length (lot:confiscation-outputs (hx "5120aa") 40700 500 :respectful t :obligations-sats 40000 :operator-pubkey33 (up:compressed-pubkey 9)))
                 1)))

(with-gate ("reserves: the reference's pinned legacy-ruleset script")
  ;; deposits-core's snapshot test: operator + 3 members, legacy tiers, mainnet.
  (let ((r (rs:build-reserves :operator (hx "02b017e1288da93b90d9ca139d9fdb3310c4ba65d451803875471c2b6d57a4520f")
                              :members (list (hx "0206c4db20bda97893e99f843b0acf6bd61624baa09c72536841a974230f1e4995")
                                             (hx "036cba47c801a59c0792fd4a214ec6b37eb6f206a5be68a9d87064d5f89fd8a777")
                                             (hx "02208787bb5c2d2428d4055d353d4656642be7ef6550a3240b2063b4c073d8ae1a"))
                              :ledger-hash (hx "7fc25d5245e7003be4f1c4138fbf608bf0ecbb4eca7be4954529d42168473b76")
                              :quorum-expiry 0 :ruleset "legacy" :network :mainnet)))
    (check-bytes "scriptPubKey matches EXPECTED_CURRENT_SCRIPT_HEX" (rs:reserves-spk r)
                 (hx "51202da85682af56fd62b6fa106e30831a8dbfa05c74259bdca8e0cfad0242ff0e55"))))



(with-gate ("lottery: byte-for-byte against the reference builder")
  ;; inspect/vectors/lottery-reference.txt: deposits-core's LotteryScriptBuilder
  ;; for keys from secrets [i;32], commitments [i;20], voters 21..23 (2-of-3), signet.
  (let* ((lines (with-open-file (in (vector-path "lottery-reference.txt"))
                  (loop for l = (read-line in nil) while l collect l)))
         (vec (lambda (n key) (let ((pfx (format nil "VEC n=~a ~a=" n key)))
                                (subseq (find pfx lines :test (lambda (p l) (and (>= (length l) (length p)) (string= p (subseq l 0 (length p)))))) (length pfx)))))
         (seed-priv (lambda (i) (u:be->int (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))))
         (voters (mapcar (lambda (i) (xonly-of (funcall seed-priv i))) '(21 22 23))))
    (dolist (n '(3 6))
      (let* ((parts (loop for i from 1 to n collect (lot:make-participant :pubkey (xonly-of (funcall seed-priv i))
                                                                            :commitment (make-array 20 :element-type '(unsigned-byte 8) :initial-element i)
                                                                            :target (format nil "tb1p~a" i))))
             (l (lot:build-lottery parts voters 2 :network :signet)))
        (check-equal (format nil "n=~a primary script" n) (u:bytes->hex (first (lot:lottery-leaves l))) (funcall vec n "script"))
        (check-equal (format nil "n=~a partial-reveal leaf 0" n) (u:bytes->hex (second (lot:lottery-leaves l))) (funcall vec n "partial0"))
        (check-equal (format nil "n=~a recovery leaf (CSV 144)" n) (u:bytes->hex (nth (lot::recovery-leaf-index l 0) (lot:lottery-leaves l))) (funcall vec n "recovery144"))
        (check-equal (format nil "n=~a lottery address" n) (lot:lottery-address l) (funcall vec n "address"))
        (check-equal (format nil "n=~a control block of the primary leaf" n) (u:bytes->hex (lot:lottery-control-block l 0)) (funcall vec n "control0"))))
    (check-equal "armer share address"
                 (lot:armer-share-address (lot:build-armer-share (xonly-of (funcall seed-priv 1)) (make-array 20 :element-type '(unsigned-byte 8) :initial-element 1) voters 2 :network :signet))
                 (funcall vec 3 "armer_share"))))

;;; inspect/vectors/armer_eligibility.json: the DEP-03 replacement-collateral cut,
;;; shared with deposits-rust (deposits-node/tests/vectors/armer_eligibility.json).
(with-gate ("lottery: armer eligibility cut against the shared vector")
  (let ((v (com.inuoe.jzon:parse (uiop:read-file-string (vector-path "armer_eligibility.json")))))
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
                     (nd:split-armers armers (gethash "required_sats" case) pledge-fn)
                   (declare (ignore out))
                   (check-equal (format nil "~a: participants" (gethash "name" case))
                                (sort (mapcar (lambda (a) (gethash (first a) names)) in) #'string<)
                                (coerce (gethash "participants" (gethash "expect" case)) 'list))
                   (check-equal (format nil "~a: snapshot" (gethash "name" case)) snapshot (gethash "snapshot" (gethash "expect" case)))))))))

(report)
