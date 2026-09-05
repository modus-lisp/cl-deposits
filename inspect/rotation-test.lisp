;;;; inspect/rotation-test.lisp — spend the reserves on every tier, validated by
;;;; cl-consensus's script interpreter (the same code that validates blocks).

(in-package #:cl-deposits.test)

(defun test-keys (n) (loop for i from 1 to n collect (+ 1000000007 (* i 987654321))))

(with-gate ("rotation: reserves spends validated by cl-consensus")
  (let* ((privs (test-keys 4))
         (pubs (mapcar #'up:compressed-pubkey privs))
         (keyring (loop for priv in privs for pub in pubs collect (cons (up:x-only pub) priv)))
         (expiry 5000)
         (r (rs:build-reserves :operator (first pubs) :members (rest pubs) :ledger-hash (u:sha256 (hx "aa"))
                               :quorum-expiry expiry :network :signet))
         (amount 39000000)
         (prev-txid (u:sha256 (hx "f00d")))
         (r2 (rs:build-reserves :operator (first pubs) :members (rest pubs) :ledger-hash (u:sha256 (hx "bb"))
                                :quorum-expiry (+ expiry 4000) :network :signet))
         (prevouts (vector (cons amount (rs:reserves-spk r)))))
    (check "signet address is tb1p..." (string= "tb1p" (subseq (rs:reserves-address r) 0 4)))
    (flet ((spend (tier-index signers &key (locktime 0))
             (multiple-value-bind (tx fee)
                 (rot:build-spend :prev-txid prev-txid :prev-vout 0 :reserves-amount amount
                                  :destination-spk (rs:reserves-spk r2)
                                  :splits (list (cons (rot:op-return-script (u:sha256 (hx "cc"))) 0))
                                  :fee-rate 2 :locktime locktime)
               (let* ((ring (remove-if-not (lambda (kv) (member (cdr kv) signers)) keyring))
                      (sigs (rot:sign-tier tx 0 prevouts r tier-index ring))
                      (signed (rot:attach-tier-witness tx 0 r tier-index sigs)))
                 (values (rot:verify-spend signed 0 prevouts) signed fee)))))
      ;; Tier 0: 3-of-4 anytime.
      (multiple-value-bind (ok tx fee) (spend 0 (list (first privs) (second privs) (third privs)))
        (check "tier 0: operator + 2 members (3-of-4) verifies" ok)
        (check-equal "fee is 135+43*2 vbytes at 2 sat/vB" fee (* 2 (+ 135 86)))
        (check-equal "outputs: OP_RETURN anchor then new reserves"
                     (list (aref (btx:txout-script (first (btx:tx-outputs tx))) 0)
                           (equalp (btx:txout-script (second (btx:tx-outputs tx))) (rs:reserves-spk r2)))
                     (list #x6a t))
        (check "effective feerate >= 1 sat/vB despite the reference's optimistic estimate"
               (>= (/ fee (btx:tx-vsize tx)) 1) (format nil "fee ~a vsize ~a" fee (btx:tx-vsize tx))))
      (check "tier 0: 3 members without operator verifies" (spend 0 (rest privs)))
      (check "tier 0: only 2 signers fails" (not (spend 0 (list (second privs) (third privs)))))
      (check "tier 0: 3 sigs with one under a wrong key fails"
             (not (let* ((tx (rot:build-spend :prev-txid prev-txid :prev-vout 0 :reserves-amount amount
                                              :destination-spk (rs:reserves-spk r2) :fee-rate 2))
                         (sigs (rot:sign-tier tx 0 prevouts r 0 keyring)))
                    ;; swap two signatures so each sits under the other's key
                    (rotatef (first sigs) (second sigs))
                    (rot:verify-spend (rot:attach-tier-witness tx 0 r 0 (list (first sigs) (second sigs) (third sigs) nil)) 0 prevouts))))
      ;; Tier 1: 1-of-4 after expiry+720, needs nLockTime.
      (check "tier 1: single member with locktime >= expiry+720 verifies" (spend 1 (list (fourth privs)) :locktime (+ expiry 720)))
      (check "tier 1: single member WITHOUT locktime fails (CLTV)" (not (spend 1 (list (fourth privs)))))
      (check "tier 1: locktime one short fails" (not (spend 1 (list (fourth privs)) :locktime (+ expiry 719))))
      ;; Tier 2: any single voter after expiry+4032.
      (check "tier 2: single member after expiry+4032 verifies" (spend 2 (list (second privs)) :locktime (+ expiry 4032)))
      ;; Tier 3: operator only after expiry+8064.
      (check "tier 3: operator alone after expiry+8064 verifies" (spend 3 (list (first privs)) :locktime (+ expiry 8064)))
      (check "tier 3: a member cannot use the operator leaf" (not (spend 3 (list (second privs)) :locktime (+ expiry 8064))))
      ;; Commitment leaf is unspendable: it ends in OP_0.
      (check "commitment leaf cannot be spent"
             (not (let ((tx (rot:build-spend :prev-txid prev-txid :prev-vout 0 :reserves-amount amount
                                             :destination-spk (rs:reserves-spk r2) :fee-rate 2)))
                    (rot:verify-spend (rot:attach-tier-witness tx 0 r 4 '()) 0 prevouts)))))))


(report)
