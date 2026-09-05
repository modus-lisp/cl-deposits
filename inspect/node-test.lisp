;;;; inspect/node-test.lisp — four nodes and two wallets on one in-process bus:
;;;; quorum formation, QuorumBegin, deposits, a hash-locked transfer; every
;;;; published update re-verified with the same code that verified the fixture.

(in-package #:cl-deposits.test)

(defvar *height* 1000)

(with-gate ("nodes: quorum formation over the bus")
  (let* ((bus (bus:make-mock-bus))
         (hf (lambda () *height*))
         (mock-ln (ln:make-mock-ln))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf :ln mock-ln))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a" :reserves 15600000 :collateral 23400000))
         (lb (nd:open-ledger b :reserves-id "genesis:b")) (lc (nd:open-ledger c :reserves-id "genesis:c"))
         (ld (nd:open-ledger d :reserves-id "genesis:d")))
    (check "even-y protocol keys" (every (lambda (n) (= 2 (aref (nd:node-pubkey n) 0))) (list a b c d)))
    (check-equal "genesis applied" (lg:ledger-sequence (nd:record-ledger la)) 0)
    (dolist (m (list b c d)) (nd:add-member a la (nd:node-pubkey m)))
    (check-equal "three QuorumAddMember on A" (lg:ledger-sequence (nd:record-ledger la)) 3)
    (check-equal "three staged members" (length (lg:ledger-next-quorum-members (nd:record-ledger la))) 3)
    (check "each member recorded QuorumJoin on its own ledger"
           (every (lambda (rec) (and (= 1 (lg:ledger-sequence (nd:record-ledger rec)))
                                     (= 1 (length (lg:ledger-joined-quorums (nd:record-ledger rec))))))
                  (list lb lc ld)))
    (check "members replicate A's ledger at the same tip"
           (every (lambda (n) (let ((r (nd:find-record n (nd:record-id-hex la))))
                                (and r (not (nd:record-owned-p r))
                                     (equalp (lg:ledger-chain-tip (nd:record-ledger r)) (lg:ledger-chain-tip (nd:record-ledger la))))))
                  (list b c d)))
    ;; QuorumBegin: cosigned by a majority of the STAGED set.
    (multiple-value-bind (qb reserves)
        (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d")) :funding-vout 0
                              :amount-msats 15600000 :collateral-msats 23400000)
      (check "QuorumBegin carries >= 2 of 3 staged cosignatures" (>= (length (up:update-cosignatures qb)) 2))
      (check "reserves address is signet taproot" (string= "tb1p" (subseq (rs:reserves-address reserves) 0 4)))
      (check-equal "ledger quorum active with 3 members"
                   (list (lg:ledger-quorum-state (nd:record-ledger la)) (length (lg:ledger-quorum-members (nd:record-ledger la))))
                   '(:active 3))
      (check-bytes "reserves commit to the pre-QuorumBegin chain hash" (rs:reserves-ledger-hash reserves) (up:update-prev-hash qb)))
    ;; Deposits and a transfer.
    (let* ((w1 (nd:make-wallet :priv 55555555555555555555 :bus bus))
           (w2 (nd:make-wallet :priv 66666666666666666666 :bus bus))
           (id (nd:record-id-hex la))
           (d1 (nd:wallet-open-deposit w1 id)) (d2 (nd:wallet-open-deposit w2 id)))
      (check-equal "deposit ids derive from pk() descriptors"
                   (list d1 d2) (list (op:deposit-id (format nil "pk(~a)" (u:bytes->hex (nd:wallet-pubkey w1))))
                                      (op:deposit-id (format nil "pk(~a)" (u:bytes->hex (nd:wallet-pubkey w2))))))
      (nd:credit-onchain a la d1 100000 :txid (u:sha256 (hx "c0ffee")))
      (check-equal "balance after credit" (nd:wallet-balance w1 id d1) 100000)
      (multiple-value-bind (tid preimage) (nd:wallet-transfer w1 id d1 d2 40000 :height *height*)
        (check-equal "locked after TransferLock" (multiple-value-list (nd:wallet-balance w1 id d1)) '(100000 40000))
        (check "TransferComplete with the preimage" (nd:wallet-complete-transfer w1 id tid preimage))
        (check-equal "balances settle 60000 / 40000"
                     (list (nd:wallet-balance w1 id d1) (nd:wallet-balance w2 id d2)) '(60000 40000)))
      ;; Lightning: an invoice, cosigned attestation, payment, InvoiceCredit.
      (multiple-value-bind (bolt11 hash res) (nd:wallet-make-invoice w2 id d2 25000 :operator-pubkey (nd:node-pubkey a))
        (check "invoice minted by the (mock) Lightning node" (string= "lnmock1" (subseq bolt11 0 7)))
        (check "attestation cosigned by a quorum member" (and (w:jget res "cosign_signature") t))
        (check-equal "nothing credited before payment" (nd:credit-paid-invoices a) '())
        (ln:mock-ln-settle mock-ln hash)
        (check-equal "payment settled -> one InvoiceCredit" (nd:credit-paid-invoices a) (list hash))
        (check-equal "w2 balance includes the credit" (nd:wallet-balance w2 id d2) 65000)
        (check "InvoiceCredit carries the bolt11-derived invoice id"
               (let ((o (op:decode-operation (up:update-message (first (nd:record-history la))))))
                 (and (eq (op:operation-type o) :invoice-credit)
                      (string= (op:field o :invoice-id) (format nil "bolt11:~a" (subseq bolt11 0 32))))))
        (check-signals "the same payment cannot be credited twice" lg:ledger-error
          (lg:apply-operation (nd:record-ledger la)
                              (list :type :invoice-credit :payment-hash hash :deposit-id d2 :amount 1 :invoice-id "x" :sequence-number 99)))
        (check-signals "an invoice beyond reserves is refused" nd:node-error
          (nd:wallet-make-invoice w2 id d2 (* 2 (lg:ledger-reserves-amount (nd:record-ledger la))))))
      ;; Rejections.
      (check-signals "transfer signed by the wrong wallet is refused" nd:node-error
        (nd:wallet-transfer w2 id d1 d2 1000 :height *height*))
      (check-signals "insufficient balance is refused" nd:node-error
        (nd:wallet-transfer w1 id d1 d2 999999 :height *height*))
      (let ((forged (nd:make-wallet :priv 55555555555555555555 :bus bus)))  ; same key, stale nonce counter
        (check-signals "replayed nonce is refused" nd:node-error
          (nd:wallet-transfer forged id d1 d2 1000 :height *height*)))
      ;; Replicas agree, and everything published re-verifies from scratch.
      (check "all replicas at A's tip"
             (every (lambda (n) (equalp (lg:ledger-chain-tip (nd:record-ledger (nd:find-record n id)))
                                        (lg:ledger-chain-tip (nd:record-ledger la))))
                    (list b c d)))
      (let* ((events (bus:bus-fetch bus (cl-nostr.filter:make-filter :kinds (list w:+kind-update+) :tags (list (cons "d" (list (w:ledger-tag (u:hex->bytes id))))))))
             (updates (mapcar #'w:event->update events))
             (fresh (lg:make-ledger)) (members (mapcar #'lg:member-pubkey (lg:ledger-quorum-members (nd:record-ledger la)))))
        (check-equal "published updates cover the whole chain" (mapcar #'up:update-seq updates)
                     (loop for i to (lg:ledger-sequence (nd:record-ledger la)) collect i))
        (check "every Nostr event signature valid" (every #'cl-nostr.event:valid-event-p events))
        (check "every operator signature verifies (v1)" (every (lambda (u) (eq :v1 (up:verify-operator-signature u))) updates))
        (check "every post-QuorumBegin update has a member majority"
               (loop for u in updates
                     for o = (op:decode-operation (up:update-message u))
                     for after = nil then (or after (eq (op:operation-type (op:decode-operation (up:update-message (nth (1- (up:update-seq u)) updates)))) :quorum-begin))
                     always (or (not after) (up:verify-cosignatures u :quorum members :threshold 2))))
        (check "member_ledger_hash is each member's own tip content hash"
               (every (lambda (cs) (let ((n (find (up:cosig-pubkey cs) (list b c d) :key #'nd:node-pubkey :test #'equalp)))
                                    (equalp (up:cosig-member-ledger-hash cs)
                                            (up:content-hash (first (nd:record-history (nd:own-ledger n)))))))
                      (up:update-cosignatures (car (last updates)))))
        (dolist (u updates) (lg:apply-update fresh u))
        (check-bytes "fold of published updates reaches A's tip" (lg:ledger-chain-tip fresh) (lg:ledger-chain-tip (nd:record-ledger la)))
        (check-equal "obligations from the fold" (lg:total-obligations fresh) 125000))
      ;; Persistence round trip in the fixture format.
      (let* ((dir (format nil "/tmp/cl-deposits-test-~a/" (random 1000000)))
             (path (progn (setf (nd::node-data-dir a) dir) (nd:save-record a la)
                          (merge-pathnames (format nil "ledger_~a.json" (subseq id 0 16)) dir)))
             (bus2 (bus:make-mock-bus))
             (a2 (nd:make-node :priv 11111111111111111111 :bus bus2 :height-fn hf))
             (x (nd:make-node :priv 77777777777777777777 :bus bus2 :height-fn hf))
             (ra (nd:load-record a2 path :owned-p t))
             (rx (nd:load-record x path)))
        (check-bytes "reloaded owner at the same tip" (lg:ledger-chain-tip (nd:record-ledger ra)) (lg:ledger-chain-tip (nd:record-ledger la)))
        (check-bytes "stranger validates the file as a replica" (lg:ledger-chain-tip (nd:record-ledger rx)) (lg:ledger-chain-tip (nd:record-ledger la)))
        (check-equal "reloaded owner continues the chain (needs cosigs; none reachable -> fails cleanly)"
                     (handler-case (progn (nd:credit-onchain a2 ra d1 1 :txid (u:sha256 (hx "01"))) :committed)
                       (nd:node-error () :refused))
                     :refused)))
    (format t "      A log: ~{~a~^ | ~}~%" (reverse (nd:node-log a)))
    (format t "      B log: ~{~a~^ | ~}~%" (reverse (nd:node-log b)))))

(report)
