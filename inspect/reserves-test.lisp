;;;; inspect/reserves-test.lisp — DEP-03 reserves against the fixture's real
;;;; mainnet QuorumBegin: same operator, members, ledger hash, expiry and
;;;; ruleset must yield the same Taproot address.

(in-package #:cl-deposits.test)

(with-gate ("reserves: script pieces")
  (check-bytes "script-num 720" (rs:script-num 720) (hx "d002"))
  (check-bytes "script-num 958719 (sign-bit padded)" (rs:script-num 958719) (hx "ffa00e"))
  (check-bytes "script-num 128 pads" (rs:script-num 128) (hx "8000"))
  (check-bytes "push-int 3 is OP_3" (rs:push-int 3) (hx "53"))
  (check-bytes "push-int 16 is OP_16" (rs:push-int 16) (hx "60"))
  (check-bytes "push-int 17 is a data push" (rs:push-int 17) (hx "0111")))

(with-gate ("reserves: reproduce the fixture's mainnet reserves address")
  (let* ((chain (chain-in-order *distinct*))
         (qb (find-if (lambda (x) (eq (op:operation-type (op:decode-operation (up:update-message x))) :quorum-begin)) chain))
         (o (op:decode-operation (up:update-message qb)))
         (expected (op:field o :reserves-id))
         (r (rs:build-reserves :operator (up:update-operator-id qb) :members (op:field o :quorum-members)
                               :ledger-hash (op:field o :ledger-hash) :quorum-expiry (op:field o :quorum-expiry)
                               :ruleset (op:field o :protocol-version) :network :mainnet)))
    (check-equal "ruleset pinned in QuorumBegin" (op:field o :protocol-version) "cltv-offset-v2")
    ;; Wire txids are internal byte order: reversed, this is a confirmed mainnet tx (block 953680).
    (check-equal "new_outpoint_txid reversed is the real mainnet txid"
                 (u:txid-hex (op:field o :new-outpoint-txid))
                 "6559ff37371d0933594129a93f6baa5d219a3b9d50c08b34b3e914a3f21a0f0b")
    (check-bytes "QuorumBegin.ledger_hash is the predecessor's chain_hash"
                 (op:field o :ledger-hash) (up:update-prev-hash qb))
    (check-equal "4 voters (operator + 3 members), 4 tiers" (list (length (rs:reserves-voters r)) (length (rs:reserves-tiers r))) '(4 4))
    (format t "      tiers: ~{~a~^, ~}~%" (mapcar (lambda (tr) (format nil "~a-of-~a@~a" (rs:tier-threshold tr) (if (rs:tier-tie-breaker-p tr) "op" 4) (rs:tier-locktime tr))) (rs:reserves-tiers r)))
    (format t "      leaf 0: ~a~%      leaf 3: ~a~%      commitment: ~a~%" (u:bytes->hex (first (rs:reserves-leaves r))) (u:bytes->hex (fourth (rs:reserves-leaves r))) (u:bytes->hex (fifth (rs:reserves-leaves r))))
    (unless (check-equal "address matches the on-chain reserves_id" (rs:reserves-address r) expected)
      ;; Diagnostics: alternative voter-set / tier-count assumptions.
      (dolist (variant `(("members only as voters"
                          ,(rs:build-reserves :operator (up:update-operator-id qb) :members (rest (op:field o :quorum-members))
                                              :ledger-hash (op:field o :ledger-hash) :quorum-expiry (op:field o :quorum-expiry)
                                              :ruleset (op:field o :protocol-version)))))
        (format t "      variant ~a -> ~a~%" (first variant) (rs:reserves-address (second variant)))))
    ;; Control blocks: each tier's path must recommit to the root.
    (let ((hashes (mapcar #'cl-consensus.taproot-script::tapleaf-hash (rs:reserves-leaves r))))
      (check "every tier's merkle path recomputes the root"
             (loop for i below (length (rs:reserves-tiers r))
                   always (let ((acc (nth i hashes)))
                            (dolist (sib (rs::vine-path hashes i)) (setf acc (cl-consensus.taproot-script::tapbranch-hash acc sib)))
                            (equalp acc (rs:reserves-root r)))))
      (check-equal "control block lengths" (mapcar (lambda (i) (length (rs:control-block-for-tier r i))) '(0 1 2 3))
                   '(65 97 129 161)))))

