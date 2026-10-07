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
      (check "quorum_expiry does not exceed any member's commitment"
             (<= (rs::reserves-quorum-expiry reserves)
                 (reduce #'min (mapcar #'lg:member-membership-until (lg:ledger-quorum-members (nd:record-ledger la))))))
      (check "reserves address is signet taproot" (string= "tb1p" (subseq (rs:reserves-address reserves) 0 4)))
      (check-equal "ledger quorum active with 3 members"
                   (list (lg:ledger-quorum-state (nd:record-ledger la)) (length (lg:ledger-quorum-members (nd:record-ledger la))))
                   '(:active 3))
      (check-bytes "reserves commit to the pre-QuorumBegin chain hash" (rs:reserves-ledger-hash reserves) (up:update-prev-hash qb))
      (check-signals "a Q=2 QuorumBegin is refused by the fold" lg:ledger-error
        (lg:apply-operation (lg:make-ledger)
                            (list :type :quorum-begin :reserves-id "x" :spending-txid (u:sha256 (hx "01")) :new-outpoint-txid (u:sha256 (hx "01"))
                                  :new-outpoint-vout 0 :amount 1 :quorum-expiry 1 :ledger-hash (u:sha256 (hx "02"))
                                  :quorum-members (list (nd:node-pubkey b) (nd:node-pubkey c)) :collateral-amount 0))))
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
        (check "every operator signature verifies" (every #'up:verify-operator-signature updates))
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



(with-gate ("disputes: fraud proof, forks, confiscation, lottery, custody transfer")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a2" :reserves 15600000 :collateral 23400000))
         (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m))))
    (dolist (m (list b c d)) (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d2")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((w1 (nd:make-wallet :priv 55555555555555555555 :bus bus)) (d1 (nd:wallet-open-deposit w1 id)))
      (nd:credit-onchain a la d1 100000 :txid (u:sha256 (hx "c0ffee2")))
      ;; --- The operator equivocates: two different updates at the same sequence.
      (let* ((seq (1+ (lg:ledger-sequence (nd:record-ledger la))))
             (mk (lambda (amount)
                   (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id) :seq seq
                                                   :prev-hash (lg:ledger-chain-tip (nd:record-ledger la))
                                                   :message (op:encode-operation (list :type :onchain-credit :txid (u:sha256 (hx "ee")) :vout 0
                                                                                       :deposit-id d1 :amount amount :funding-address "x")))))
                     (up:sign-operator u (nd::node-priv a)) u)))
             (u1 (funcall mk 1)) (u2 (funcall mk 2))
             (proof (fr:make-equivocation-proof (nd:node-pubkey a) (u:hex->bytes id) u1 u2)))
        (check "equivocation proof verifies" (fr:verify-equivocation proof (reverse (nd:record-history la))))
        (check "a same-content pair is not an equivocation" (not (fr:verify-equivocation (fr:make-equivocation-proof (nd:node-pubkey a) (u:hex->bytes id) u1 u1) (reverse (nd:record-history la)))))
        (check-bytes "proof hash survives the JSON round trip" (fr:proof-hash (fr:json->proof (fr:proof->json proof))) (fr:proof-hash proof))
        (check-equal "proof discriminant" (fr:proof-discriminant :equivocation) 8)
        ;; A non-conforming update: crediting beyond... (a DepositClose on a funded deposit)
        (let ((bad (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id) :seq seq
                                                   :prev-hash (lg:ledger-chain-tip (nd:record-ledger la))
                                                   :message (op:encode-operation (list :type :deposit-close :deposit-id d1)))))
                     (up:sign-operator u (nd::node-priv a)) u)))
          (check "non-conforming update proof verifies against the canonical history"
                 (fr:verify-non-conforming-update (fr:make-non-conforming-update-proof (nd:node-pubkey a) (u:hex->bytes id) bad)
                                                  (reverse (nd:record-history la))))
          (check "a conforming update is not a valid proof"
                 (not (fr:verify-non-conforming-update (fr:make-non-conforming-update-proof (nd:node-pubkey a) (u:hex->bytes id) u1)
                                                       (reverse (nd:record-history la))))))
        ;; --- Relabelling (red team, the reference's bedabe0/f581dba): ledger_id is signed by
        ;; no one and A signs its other ledger with the same key, so any of that ledger's
        ;; updates carries a valid signature under this ledger's id.  None of them is proof.
        (let* ((lx (nd:open-ledger a :reserves-id "genesis:a2-other"))
               (history (reverse (nd:record-history la)))
               (relabel (lambda (u) (let ((c (up:decode-update (up:encode-update u)))) (setf (up:update-ledger-id c) (u:hex->bytes id)) c)))
               (x0 (funcall relabel (first (last (nd:record-history lx)))))
               (a0 (first history))
               (stray (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id) :seq seq
                                                      :prev-hash (u:sha256 (hx "e15e")) ; another ledger's tip
                                                      :message (op:encode-operation (list :type :deposit-close :deposit-id d1)))))
                        (up:sign-operator u (nd::node-priv a)) u))
               (rewind (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id) :seq seq
                                                       :prev-hash (up:chain-hash (nth (- seq 3) history))
                                                       :message (op:encode-operation (list :type :deposit-close :deposit-id d1)))))
                         (up:sign-operator u (nd::node-priv a)) u)))
          ;; v2 signs ledger_id: the relabelled copy no longer verifies at all.  The
          ;; chain-binding checks below stay as a second line (STRAY and REWIND are
          ;; signed as this ledger's, and still must bind to its chain).
          (check "a relabelled update no longer carries a valid operator signature (v2)" (not (up:verify-operator-signature x0)))
          (check "the other ledger's genesis, relabelled, is not an equivocation with this one's"
                 (not (fr:verify-equivocation (fr:make-equivocation-proof (nd:node-pubkey a) (u:hex->bytes id) a0 x0) history)))
          (check "an update following nothing in this ledger is not a non-conforming proof"
                 (not (fr:verify-non-conforming-update (fr:make-non-conforming-update-proof (nd:node-pubkey a) (u:hex->bytes id) stray) history)))
          (check "an update that rewinds this ledger's chain is a non-conforming proof"
                 (fr:verify-non-conforming-update (fr:make-non-conforming-update-proof (nd:node-pubkey a) (u:hex->bytes id) rewind) history))
          (check "the other ledger's genesis, relabelled, is not a non-conforming seq-0 proof"
                 (not (fr:verify-non-conforming-update (fr:make-non-conforming-update-proof (nd:node-pubkey a) (u:hex->bytes id) x0) history)))
          (ignore-errors (nd::accept-update b (nd:find-record b id) x0))   ; refused: bad signature
          (check "a member handed a relabelled update does not cry equivocation"
                 (notany (lambda (m) (nd:find-fork m id (nd:node-pubkey m))) (list b c d)))
          ;; The relabelled updates now sit on the relay beside the real ones at the
          ;; same sequences.  Rebuilding the ledger from the relay must follow the chain.
          (let* ((k (- seq 3))
                 (stray-k (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id) :seq k
                                                          :prev-hash (u:sha256 (hx "e15e"))
                                                          :message (op:encode-operation (list :type :deposit-close :deposit-id d1)))))
                            (up:sign-operator u (nd::node-priv a)) u))
                 (e (nd:make-node :priv 66666666666666666666 :bus bus :height-fn hf)))
            (bus:bus-publish bus (w:update-event (nd::node-keypair a) x0))
            (bus:bus-publish bus (w:update-event (nd::node-keypair a) stray-k))
            (let ((f (nd::follow-ledger e id)))
              (check-equal "a follower rebuilds the ledger itself past a relabelled genesis"
                           (list (nd:record-id-hex f) (lg:ledger-sequence (nd:record-ledger f)))
                           (list id (lg:ledger-sequence (nd:record-ledger la)))))
            (let* ((prefix (subseq history 0 k))
                   (behind (nd::make-record :id-hex id :ledger (lg:replay prefix) :history (reverse prefix))))
              (nd::catch-up e behind)
              (check-equal "catch-up steps over a relabelled update at its next sequence"
                           (lg:ledger-sequence (nd:record-ledger behind)) (lg:ledger-sequence (nd:record-ledger la))))))
        ;; --- Broadcast the proof: every member verifies it and forks.
        (nd:broadcast-fraud b proof)
        (check "all three members opened dispute forks"
               (every (lambda (m) (nd:find-fork m id (nd:node-pubkey m))) (list b c d)))
        (check "members replicate each other's forks"
               (every (lambda (m) (= 3 (length (nd:forks-of m id)))) (list b c d)))
        (check-equal "the operator sees its whole quorum disputing" (length (nd::disputing-members a la)) 3)
        (check "a disputing member refuses to extend the operator's base chain"
               (every (lambda (m) (search "ledger disputed" (handler-case (progn (nd::check-not-deposed m (nd:find-record m id)) "")
                                                                  (error (e) (princ-to-string e)))))
                      (list b c d)))
        (check "and stands down at once instead of soliciting cosignatures it cannot get"
               (search "ledger disputed" (handler-case (progn (nd:credit-onchain a la (nd:wallet-open-deposit (nd:make-wallet :priv 66666666666666666666 :bus bus) id) 5000 :txid (u:sha256 (hx "c0ffee3"))) "")
                                           (error (e) (princ-to-string e)))))
        (let ((f (nd::follow-ledger (nd:make-node :priv 77777777777777777777 :bus bus :height-fn hf) id)))
          (check-equal "rebuilding from the relay follows the operator's chain, not the forks' updates beside it"
                       (lg:ledger-sequence (nd:record-ledger f)) (lg:ledger-sequence (nd:record-ledger la))))
        (check-equal "fork state is disputed" (lg:ledger-dispute-state (nd:record-ledger (nd:find-fork b id (nd:node-pubkey b)))) :disputed)
        ;; --- Arm.
        (dolist (m (list b c d)) (nd:arm-dispute m (nd:find-fork m id (nd:node-pubkey m)) :replacement (list (u:sha256 (nd:node-pubkey m)) 0 10000000)))
        (check-equal "three armers visible to everyone" (mapcar (lambda (m) (length (nd:armers-of m id))) (list b c d)) '(3 3 3))
        ;; A re-arm (the same commitment, new collateral) replaces the first arm; it is not a fourth armer.
        (nd:arm-dispute b (nd:find-fork b id (nd:node-pubkey b)) :replacement (list (u:sha256 (hx "be")) 1 12000000))
        (check-equal "a re-arm is still three armers" (mapcar (lambda (m) (length (nd:armers-of m id))) (list b c d)) '(3 3 3))
        (check-equal "and the re-armed member's latest collateral counts"
                     (third (fourth (find (nd:node-pubkey b) (nd:armers-of c id) :key #'first :test #'equalp))) 12000000)
        ;; --- Confiscation, built by b, signed by the recovery quorum over the relay.
        (multiple-value-bind (ctx lottery)
            (handler-case (nd:confiscate b id)
              (error (e) (format t "      confiscate failed: ~a~%      c log: ~{~a~^ | ~}~%      d log: ~{~a~^ | ~}~%" e (reverse (nd:node-log c)) (reverse (nd:node-log d))) (error e)))
          (check "confiscation spends the reserves via tier 0 (verified under consensus)" (and ctx t))
          (check-equal "punitive: one output, to the lottery" (length (btx:tx-outputs ctx)) 1)
          (check "lottery output pays the lottery script" (equalp (btx:txout-script (first (btx:tx-outputs ctx))) (lot:lottery-spk lottery)))
          (check "other members rebuilt the same lottery" (every (lambda (m) (let ((f (nd:find-fork m id (nd:node-pubkey m)))) (and (nd:record-lottery f) (equalp (lot:lottery-spk (nd:record-lottery f)) (lot:lottery-spk lottery))))) (list c d)))
          (check "signers kept the unsigned confiscation (same txid as the broadcast one)"
                 (every (lambda (m) (equalp (btx:tx-txid (nd:record-confiscation (nd:find-fork m id (nd:node-pubkey m)))) (btx:tx-txid ctx))) (list c d)))
          (check "the vault watch excuses a confiscation it knows from its fork (not an unauthorised spend)"
                 (every (lambda (m) (member (btx:tx-txid ctx) (nd::authorised-spend-txids m (nd:find-record m id)) :test #'equalp)) (list b c d)))
          ;; The fork forgets its confiscation once the lottery output is spent (the winner's claim);
          ;; a confiscation the node saw confirmed must stay excused after that (regtest red team,
          ;; 2026-10-03: a disputant accused the signers of its own concluded confiscation).
          (nd::note-confiscation c id (btx:tx-txid ctx))
          (let ((f (nd:find-fork c id (nd:node-pubkey c))) (saved nil))
            (setf saved (nd:record-confiscation f) (nd:record-confiscation f) nil)
            (check "a confirmed confiscation stays excused after its fork forgets it (the lottery claimed)"
                   (member (btx:tx-txid ctx) (nd::authorised-spend-txids c (nd:find-record c id)) :test #'equalp))
            (setf (nd:record-confiscation f) saved))
          ;; --- Reveal.  Red team #7: once B has revealed, D publishes B's preimage as its
          ;; own (signed by D).  It opens B's commitment, not D's; honest nodes must not
          ;; count it, or D could pick, after seeing every reveal, the copy that makes it win.
          (nd:publish-reveal b id)
          (let* ((pre-b (nd:record-preimage (nd:find-fork b id (nd:node-pubkey b))))
                 (sig (secp:schnorr-sign (nd::node-priv d) (w:reveal-message id pre-b) (u:sha256 (hx "00")))))
            (bus:bus-publish bus (w:reveal-event (nd::node-keypair d) (nd:node-pubkey-hex d) id pre-b sig))
            (check "a member's copy of another's preimage is not its reveal"
                   (notany (lambda (m) (equalp (cdr (assoc (nd:node-pubkey d) (nd:reveals-of m id) :test #'equalp)) pre-b)) (list b c))))
          (dolist (m (list b c d)) (nd:publish-reveal m id))
          (check-equal "every member holds all three reveals" (mapcar (lambda (m) (length (nd:reveals-of m id))) (list b c d)) '(3 3 3))
          ;; --- Claim or yield.
          (let ((outcomes (mapcar (lambda (m) (multiple-value-list (nd:claim-or-yield m id))) (list b c d))))
            (check-equal "exactly one winner" (count :won outcomes :key #'first) 1)
            (check-equal "two yields" (count :yielded outcomes :key #'first) 2)
            (let* ((winner (nth (position :won outcomes :key #'first) (list b c d)))
                   (claim (second (find :won outcomes :key #'first)))
                   (wfork (nd:find-fork winner id (nd:node-pubkey winner))))
              (check "winner is the script-selected participant"
                     (equalp (up:x-only (nd:node-pubkey winner))
                             (lot:participant-pubkey (nth (lot:calculate-winner (mapcar (lambda (p) (cdr (find (lot:participant-pubkey p) (nd:reveals-of b id) :key (lambda (r) (up:x-only (car r))) :test #'equalp))) (lot:lottery-participants lottery))) (lot:lottery-participants lottery)))))
              (check "claim tx spends the lottery output (verified under consensus)" (equalp (btx:txin-prev-hash (first (btx:tx-inputs claim))) (btx:tx-txid ctx)))
              (check-equal "winner's fork: DisputeAcquire, custody transferred"
                           (list (lg:ledger-dispute-state (nd:record-ledger wfork)) (equalp (lg:ledger-operator-key (nd:record-ledger wfork)) (nd:node-pubkey winner)))
                           '(:normal t))
              (check "losers' forks tombstoned"
                     (every (lambda (m) (or (eq m winner) (eq :tombstoned (lg:ledger-dispute-state (nd:record-ledger (nd:find-fork m id (nd:node-pubkey m))))))) (list b c d)))
              (check "everyone replicates the winner's DisputeAcquire"
                     (every (lambda (m) (let ((f (nd:find-fork m id (nd:node-pubkey winner)))) (and f (equalp (lg:ledger-operator-key (nd:record-ledger f)) (nd:node-pubkey winner))))) (list b c d)))
              (check "the deposed operator sees custody moved to the winner"
                     (equalp (nd::custody-moved-to a la) (nd:node-pubkey winner))))))))))



(with-gate ("messaging: delivery escalation (DEP-12) and couriers (DEP-13)")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (e (nd:make-node :priv 99999999999999999999 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (kn (nd:make-node :priv 77777777777777777777 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a3" :reserves 15600000 :collateral 23400000))
         (le (nd:open-ledger e :reserves-id "genesis:e3" :reserves 15600000 :collateral 23400000))
         (ida (nd:record-id-hex la)) (ide (nd:record-id-hex le)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m))))
    (dolist (opnode (list a e))
      (let ((rec (if (eq opnode a) la le)))
        (dolist (m (list b c d)) (nd:add-member opnode rec (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
        (nd:begin-quorum opnode rec :funding-txid (u:sha256 (u:cat (hx "f00d") (nd:node-pubkey opnode))) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)))
    ;; Wallets: w1 on A, w2 on E; courier deposits on both, funded by the operators.
    (let* ((w1 (nd:make-wallet :priv 55555555555555555555 :bus bus)) (w2 (nd:make-wallet :priv 66666666666666666666 :bus bus))
           (kwa (nd:make-wallet :priv 77777777777777777777 :bus bus)) (kwe (nd:make-wallet :priv 77777777777777777777 :bus bus))
           (d1 (nd:wallet-open-deposit w1 ida)) (d2 (nd:wallet-open-deposit w2 ide))
           (ka (nd:wallet-open-deposit kwa ida)) (ke (nd:wallet-open-deposit kwe ide)))
      (nd:credit-onchain a la d1 500000 :txid (u:sha256 (hx "01")))
      (nd:credit-onchain e le ke 800000 :txid (u:sha256 (hx "02")))
      ;; --- DEP-12: A ignores w1's transfer; w1 escalates through member b.
      (setf (nd:node-ignore-actions a) '("transfer_lock"))
      (let* ((sign-lock (lambda (amount)   ; w1's signed TransferLock from d1 to the courier's deposit on A
                          (let ((o (list :type :transfer-lock :transfer-nonce (u:sha256 (u:int->be amount 8)) :source-deposit-id d1
                                         :destination-deposit-id ka :amount amount :fee 0 :completion-script "sha256(00)"
                                         :timeout-height (+ *height* 400) :transfer-id (u:sha256 (u:cat (u:int->be amount 8) d1))
                                         :nonce (+ 7000 amount) :expiry (+ *height* 400) :witness '())))
                            (setf (getf o :witness) (d17:sign-operation o (nd::wallet-priv w1)))
                            o)))
             (params (w:json-object "operation" (u:base64-encode (op:encode-operation (funcall sign-lock 100000)))))
             (h (nd:wallet-request-hash w1 ida "transfer_lock" params)))
        (multiple-value-bind (ok res err rh) (nd:wallet-request w1 ida "transfer_lock" params :timeout 1)
          (declare (ignore res))
          (check "operator silently ignored the request" (and (not ok) (string= err "timeout")))
          (check-bytes "request hash = sha256(content)" rh h))
        (let* ((lb (nd:own-ledger b))
               (reply (nd:wallet-escalate w1 (nd:record-id-hex lb) h ida (nd:node-pubkey-hex a)))
               (embed (first (nd:record-history lb))))
          (check-equal "member anchored a DeliveryEmbed on its ledger" (op:operation-type (op:decode-operation (up:update-message embed))) :delivery-embed)
          (check-equal "reply carries the embed sequence" (w:jget reply "sequence") (up:update-seq embed))
          ;; No causal link yet: b has not cosigned on A since the embed.
          (check-equal "no proof before the member cosigns again"
                       (nth-value 1 (fr:verify-censorship (w:json params) embed (reverse (nd:record-history lb)) (reverse (nd:record-history la))))
                       "no causal link: the member has not cosigned past the embed")
          ;; A keeps operating (b cosigns, carrying its post-embed ledger hash) and time passes.
          (setf (nd:node-ignore-actions a) '())
          (nd:credit-onchain a la d1 1 :txid (u:sha256 (hx "03")))
          (check-equal "deadline not reached yet"
                       (nth-value 1 (fr:verify-censorship (w:json params) embed (reverse (nd:record-history lb)) (reverse (nd:record-history la))))
                       "deadline not reached")
          (let ((*height* (+ *height* 100)))
            (nd:credit-onchain a la d1 1 :txid (u:sha256 (hx "04")))
            (check "past the service deadline with no answer: censorship proven"
                   (fr:verify-censorship (w:json params) embed (reverse (nd:record-history lb)) (reverse (nd:record-history la))
                                         :processed-p (lambda (o) (eq (op:operation-type o) :transfer-lock))))
            (check "not censorship if the operator answered before the member's causal link"
                   (not (fr:verify-censorship (w:json params) embed (reverse (nd:record-history lb)) (reverse (nd:record-history la))
                                              :processed-p (lambda (o) (eq (op:operation-type o) :deposit-open)))))
            (check "not censorship if the operator answered"
                   (not (fr:verify-censorship (w:json params) embed (reverse (nd:record-history lb)) (reverse (nd:record-history la))
                                              :processed-p (lambda (o) (eq (op:operation-type o) :onchain-credit)))))
            ;; A double spend: w3 escalates a 400000 lock, then spends 150000 (of 500000)
            ;; through the operator before the deadline.  At the deadline the escalated
            ;; lock can no longer be served, so it is not censorship.
            (let* ((w3 (nd:make-wallet :priv 88888888888888888888 :bus bus))
                   (d3 (nd:wallet-open-deposit w3 ida))
                   (o4 (list :type :transfer-lock :transfer-nonce (u:sha256 (hx "d4")) :source-deposit-id d3
                             :destination-deposit-id ka :amount 400000 :fee 0 :completion-script "sha256(00)"
                             :timeout-height (+ *height* 400) :transfer-id (u:sha256 (hx "d5"))
                             :nonce 9400 :expiry (+ *height* 400) :witness '())))
              (setf (getf o4 :witness) (d17:sign-operation o4 (nd::wallet-priv w3)))
              (nd:credit-onchain a la d3 500000 :txid (u:sha256 (hx "d3")))
              (let* ((p4 (w:json-object "operation" (u:base64-encode (op:encode-operation o4))))
                     (h4 (nd:wallet-request-hash w3 ida "transfer_lock" p4)))
                (nd:wallet-escalate w3 (nd:record-id-hex lb) h4 ida (nd:node-pubkey-hex a))
                (let ((embed4 (first (nd:record-history lb))))
                  (nd:wallet-transfer w3 ida d3 ka 150000 :height *height*)
                  (let ((*height* (+ *height* 100)))
                    (nd:credit-onchain a la d3 1 :txid (u:sha256 (hx "d6")))
                    (multiple-value-bind (ok why)
                        (fr:verify-censorship (w:json p4) embed4 (reverse (nd:record-history lb)) (reverse (nd:record-history la))
                                              :processed-p (lambda (o) (declare (ignore o)) nil))
                      (check "a request the depositor double-spent before the deadline is not censorship"
                             (and (not ok) (search "not servable" why)) why))))))
            (check "a request with no operation proves nothing"
                   (not (fr:verify-censorship (w:json (w:json-object "operation" "AAAA")) embed (reverse (nd:record-history lb)) (reverse (nd:record-history la))))))))
      ;; --- DEP-13: w1 (ledger A) pays w2 (ledger E) through courier k.
      (let ((k (cr:make-courier kn)))
        (cr:courier-serve k ida ka kwa) (cr:courier-serve k ide ke kwe)
        (cr:advertise-courier k)
        (let ((ad (cr:courier-advertisement k)))
          (check-equal "advertisement lists both ledgers" (length (w:jget ad "ledgers")) 2)
          (check-equal "courier liquidity on E" (cr::courier-balance k ide) 800000))
        (check-equal "route fee = fee_out(A) + fee_in(E)" (cr:route-fee k ida ide 100000) (+ 100 300 100 100))
        (multiple-value-bind (leg1 preimage forward) (cr:wallet-route w1 (nd:node-pubkey-hex kn) ida ide d1 d2 100000 :height *height*)
          (check-equal "forward amount = amount - fee" forward (- 100000 600))
          (check-equal "leg 1 locked on A" (multiple-value-list (nd:wallet-balance w1 ida d1)) '(500002 100000))
          ;; The courier saw leg 1 and locked leg 2 on E.
          (let ((leg2 (nd:wallet-pending-lock kn ide (u:sha256 preimage) d2)))
            (check "courier locked leg 2 to w2 on E behind the same hash" (and leg2 t))
            (check-equal "leg 2 amount is the forward amount" (getf leg2 :amount) forward)
            (check "leg 2 times out before leg 1" (< (getf leg2 :timeout-height) (+ *height* 144)))
            ;; w2 claims leg 2 with the preimage; the courier completes leg 1.
            (check "w2 completes leg 2" (nd:wallet-complete-transfer w2 ide (getf leg2 :transfer-id) preimage))
            (check-equal "w2 received the forward amount" (nd:wallet-balance w2 ide d2) forward)
            (check-equal "courier collected leg 1 on A" (nd:wallet-balance kwa ida ka) 100000)
            (check-equal "w1 paid the full amount" (multiple-value-list (nd:wallet-balance w1 ida d1)) '(400002 0))
            (check-equal "courier's E balance fell by the forward amount" (nd:wallet-balance kwe ide ke) (- 800000 forward))
            (check "route recorded the preimage" (equalp (getf (gethash (u:sha256 preimage) (cr:courier-routes k)) :preimage) preimage))))))))



(with-gate ("lightning pay path and reference-shaped requests")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*)) (mock-ln (ln:make-mock-ln))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf :ln mock-ln))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a4" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d4")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((w1 (nd:make-wallet :priv 55555555555555555555 :bus bus)) (w2 (nd:make-wallet :priv 66666666666666666666 :bus bus))
           (d1 (nd:wallet-open-deposit w1 id)) (d2 (nd:wallet-open-deposit w2 id)))
      (nd:credit-onchain a la d1 100000 :txid (u:sha256 (hx "05")))
      ;; bolt11 decoding against a real invoice (cl-payments minted, from the devnet)
      (check-bytes "payment hash read from a real BOLT11"
                   (cl-deposits.lightning.decode:payment-hash "lntbs1230n1p4fe4mnpp5xsy0ed6dr4tum0066kf468m57d8nzdwfym2ct9mm0ghmkxaeq6xqsp5mrgjknqahtx4lj3mphpjf7el9vdatm4p4sm50uuld3ny3zzlj73qdq2wejkxar0wgxqrrsscqpj9qrsgqsc30p2g88av7u6gg040kvdps454u54xgemdqls346l7dhe8x4krs9jz0je67a3n2a3yak3ty5ztgpr47qsfgj5wwevk2yr9sw5hpg6qpj77x6e")
                   (hx "3408fcb74d1d57cdbdfad5935d1f74f34f3135c926d585977b7a2fbb1bb9068c"))
      (check-equal "amount read from the hrp (1230n = 123000 msat)" (cl-deposits.lightning.decode:invoice-amount-msat "lntbs1230n1p4fe4mnpp5xsy0ed6dr4tum0066kf468m57d8nzdwfym2ct9mm0ghmkxaeq6xqsp5mrgjknqahtx4lj3mphpjf7el9vdatm4p4sm50uuld3ny3zzlj73qdq2wejkxar0wgxqrrsscqpj9qrsgqsc30p2g88av7u6gg040kvdps454u54xgemdqls346l7dhe8x4krs9jz0je67a3n2a3yak3ty5ztgpr47qsfgj5wwevk2yr9sw5hpg6qpj77x6e") 123000)
      ;; Pay an external invoice the mock can settle.
      (multiple-value-bind (bolt11 hash preimage) (ln:mock-ln-external-invoice mock-ln 30000)
        (multiple-value-bind (ok pre err) (nd:wallet-pay-invoice w1 id d1 bolt11 30000 :fee 100 :height *height*)
          (check "pay_invoice succeeded" ok err)
          (check-bytes "wallet learns the preimage" pre preimage)
          (check-equal "deposit debited amount + fee, nothing locked" (multiple-value-list (nd:wallet-balance w1 id d1)) '(69900 0))
          (check-equal "fee accumulated" (lg:ledger-fees-accumulated (nd:record-ledger la)) 100)
          (check "InvoiceFulfill carries the preimage"
                 (let ((o (op:decode-operation (up:update-message (first (nd:record-history la))))))
                   (and (eq (op:operation-type o) :invoice-fulfill) (equalp (op:field o :preimage) preimage) (equalp (op:field o :payment-id) hash))))))
      ;; A payment that fails: lock released, InvoiceFail on the chain.
      (multiple-value-bind (ok pre err) (nd:wallet-pay-invoice w1 id d1 (format nil "lnmock19~a" (u:bytes->hex (u:sha256 (hx "dead")))) 5000 :height *height*)
        (declare (ignore pre))
        (check "failed payment reported" (and (not ok) (search "failed" err)))
        (check-equal "funds released after InvoiceFail" (multiple-value-list (nd:wallet-balance w1 id d1)) '(69900 0))
        (check-equal "InvoiceFail recorded" (op:operation-type (op:decode-operation (up:update-message (first (nd:record-history la))))) :invoice-fail))
      ;; Reference-shaped transfer_lock / transfer_complete (field by field, signature).
      (let* ((preimage (u:sha256 (hx "77"))) (hash (u:sha256 preimage)) (nonce (u:sha256 (hx "88")))
             (tid (u:sha256 (u:cat nonce d1 d2)))
             (o (list :type :transfer-lock :transfer-nonce nonce :source-deposit-id d1 :destination-deposit-id d2 :amount 10000 :fee 0
                      :completion-script (format nil "sha256(~a)" (u:bytes->hex hash)) :timeout-height (+ *height* 144) :transfer-id tid
                      :nonce 424242 :expiry (+ *height* 144) :witness '()))
             (sig (first (d17:sign-operation o (nd::wallet-priv w1)))))
        (multiple-value-bind (ok res err)
            (nd:wallet-request w1 id "transfer_lock"
                               (w:json-object "transfer_nonce" (u:bytes->hex nonce) "source_deposit_id" (u:bytes->hex d1) "destination_deposit_id" (u:bytes->hex d2)
                                              "amount" 10000 "fee" 0 "completion_script" (op:field o :completion-script) "timeout_height" (+ *height* 144)
                                              "transfer_id" (u:bytes->hex tid) "op_nonce" 424242 "op_expiry" (+ *height* 144) "signature" (u:bytes->hex sig)))
          (declare (ignore res))
          (check "reference-shaped transfer_lock accepted" ok err))
        (multiple-value-bind (ok res err)
            (nd:wallet-request w2 id "transfer_complete" (w:json-object "transfer_id" (u:bytes->hex tid) "preimage" (u:bytes->hex preimage)))
          (declare (ignore res))
          (check "reference-shaped transfer_complete accepted" ok err))
        (check-equal "balances after the field-by-field transfer" (list (nd:wallet-balance w1 id d1) (nd:wallet-balance w2 id d2)) '(59900 10000))))))



(with-gate ("descriptor deposits: a spending cap enforced by the calculus")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a5" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d5")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((w1 (nd:make-wallet :priv 55555555555555555555 :bus bus)) (w2 (nd:make-wallet :priv 66666666666666666666 :bus bus))
           (desc (format nil "wsh(and(pk(~a), amount_at_most(60000), blocks_since_open_at_least(5)))" (u:bytes->hex (nd:wallet-pubkey w1))))
           (d1 (nd:wallet-open-deposit w1 id :descriptor desc)) (d2 (nd:wallet-open-deposit w2 id)))
      (check-bytes "deposit id is the descriptor's hash" d1 (op:deposit-id desc))
      (nd:credit-onchain a la d1 200000 :txid (u:sha256 (hx "06")))
      (check-signals "spend too soon after opening is refused" nd:node-error (nd:wallet-transfer w1 id d1 d2 10000 :height *height*))
      (let ((*height* (+ *height* 10)))
        (check-signals "spend above the cap is refused" nd:node-error (nd:wallet-transfer w1 id d1 d2 70000 :height *height*))
        (multiple-value-bind (tid pre) (nd:wallet-transfer w1 id d1 d2 50000 :height *height*)
          (check "spend within the cap after the wait is authorized" (and tid t))
          (nd:wallet-complete-transfer w1 id tid pre)
          (check-equal "balances" (list (nd:wallet-balance w1 id d1) (nd:wallet-balance w2 id d2)) '(150000 50000))))
      (check-signals "an unparseable descriptor cannot open a deposit" nd:node-error
        (nd:wallet-open-deposit w2 id :descriptor "wsh(frob(1))")))))



(with-gate ("respectful dispute on quorum expiry; the winner re-establishes a quorum on its fork")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a6" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m) :membership-blocks 100))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d6")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000 :expiry-blocks 100)
    (let* ((expiry (lg:ledger-quorum-expiry (nd:record-ledger la)))
           (w (nd:make-wallet :priv 55555555555555555555 :bus bus)) (dw (nd:wallet-open-deposit w id)))
      (check-equal "nothing to dispute before expiry" (nd:check-expired-quorums b) '())
      (let ((*height* (+ expiry 1)))
        (check-signals "past expiry, value-moving operations are uncosignable" nd:node-error
          (nd:credit-onchain a la dw 1 :txid (u:sha256 (hx "78"))))
        (check-equal "member b disputes the expired quorum" (nd:check-expired-quorums b) (list id))
        (check "the QuorumExpired proof made c and d fork too"
               (every (lambda (m) (nd:find-fork m id (nd:node-pubkey m))) (list c d)))
        (check "respectful proof type" (fr:respectful-p (fr:make-quorum-expired-proof (nd:node-pubkey a) (u:hex->bytes id) (make-array 32) expiry)))
        ;; Run the lottery through (respectful: obligations to the lottery, change back to the operator).
        (dolist (m (list b c d)) (nd:arm-dispute m (nd:find-fork m id (nd:node-pubkey m)) :replacement (list (u:sha256 (nd:node-pubkey m)) 0 10000000)))
        (multiple-value-bind (ctx lottery) (nd:confiscate b id :respectful t)
          (declare (ignore lottery))
          (check-equal "respectful confiscation: lottery output + operator change" (length (btx:tx-outputs ctx)) 2)
          (dolist (m (list b c d)) (nd:publish-reveal m id))
          (let* ((outcomes (mapcar (lambda (m) (multiple-value-list (nd:claim-or-yield m id))) (list b c d)))
                 (winner (nth (position :won outcomes :key #'first) (list b c d)))
                 (wfork (nd:find-fork winner id (nd:node-pubkey winner))))
            (check "a winner took custody" (and winner t))
            ;; Re-establishment: the new custodian stages the other members and begins a quorum on the fork.
            (let ((e (nd:make-node :priv 99999999999999999999 :bus bus :height-fn hf)))
              (nd:open-ledger e :reserves-id "genesis:e6")
              (dolist (m (cons e (remove winner (list b c d))))
                (nd:add-member winner wfork (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m))))
            ;; The deposed operator cannot join: its own expired ledger takes no QuorumJoin.
            (check-signals "the deposed operator's consent fails on its expired ledger" nd:node-error
              (nd:add-member winner wfork (nd:node-pubkey a) :member-ledger-id (nd:record-id-hex la)))
            (check-equal "three members staged on the fork" (length (lg:ledger-next-quorum-members (nd:record-ledger wfork))) 3)
            (multiple-value-bind (qb reserves) (nd:begin-quorum winner wfork :funding-txid (u:sha256 (hx "f00d7")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
              (check "QuorumBegin on the fork cosigned by the staged majority" (>= (length (up:update-cosignatures qb)) 2))
              (check-equal "fork quorum active under the new custodian"
                           (list (lg:ledger-quorum-state (nd:record-ledger wfork)) (equalp (lg:ledger-operator-key (nd:record-ledger wfork)) (nd:node-pubkey winner)))
                           '(:active t))
              (check "new reserves belong to the winner's voter set" (equalp (rs:reserves-operator reserves) (nd:node-pubkey winner))))
            (check "every node replicates the fork at the winner's tip"
                   (every (lambda (m) (let ((f (nd:find-fork m id (nd:node-pubkey winner))))
                                        (and f (equalp (lg:ledger-chain-tip (nd:record-ledger f)) (lg:ledger-chain-tip (nd:record-ledger wfork))))))
                          (remove winner (list a b c d))))))))))



(with-gate ("replacement collateral: declared, verified, and spent into the new vault by the winner")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (chain (make-hash-table :test #'equalp))      ; "txid:vout" -> sats  (a mock chain view)
         (cf (lambda (txid vout) (let ((v (gethash (cons (coerce txid 'list) vout) chain))) (and v (list :value-sats v :confirmations 3)))))
         ;; The DEP-03 cut's view: confirmed at block 1, unspent while on the mock chain.
         (pf (lambda (txid vout scan-from) (declare (ignore scan-from))
               (let ((v (gethash (cons (coerce txid 'list) vout) chain)))
                 (list :created 1 :value-sats (or v 1) :spend (if v :unspent :before)))))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf :chain-fn cf :pledge-fn pf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf :chain-fn cf :pledge-fn pf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf :chain-fn cf :pledge-fn pf))
         (la (nd:open-ledger a :reserves-id "genesis:a7" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (setf (gethash (cons (coerce (u:sha256 (hx "f00d8")) 'list) 0) chain) (floor (+ 15600000 23400000) 1000))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d8")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((w (nd:make-wallet :priv 55555555555555555555 :bus bus)) (dw (nd:wallet-open-deposit w id)))
      (nd:credit-onchain a la dw 4000000 :txid (u:sha256 (hx "09")))
      (let ((floor-sats (nd:collateral-floor-sats la)))
        (check-equal "collateral floor = obligations x ratio + claim fee" floor-sats (+ (ceiling (* 4000 3/2)) 5000))
        ;; Members fund their own collateral UTXOs (key-path P2TR) on the mock chain, then dispute.
        (dolist (m (list b c d))
          (setf (gethash (cons (coerce (u:sha256 (nd:node-pubkey m)) 'list) 1) chain) (+ floor-sats 1000)))
        (dolist (m (list b c d)) (nd:enter-dispute m la (lg:ledger-sequence (nd:record-ledger la)) :reason "test"))
        (dolist (m (list b c d))
          (nd:arm-dispute m (nd:find-fork m id (nd:node-pubkey m)) :replacement (list (u:sha256 (nd:node-pubkey m)) 1 (+ floor-sats 1000))))
        (check "every armer's collateral is visible" (every (lambda (x) (fourth x)) (nd:armers-of b id)))
        ;; A too-small declaration is refused by the cosigners' rebuild.
        (let ((short (nd:make-node :priv 88888888888888888888 :bus bus :height-fn hf :chain-fn cf)))
          (declare (ignore short)))
        (multiple-value-bind (ctx lottery) (nd:confiscate b id)
          (declare (ignore lottery))
          (check "confiscation signed with collateral checks passing" (and ctx t))
          (dolist (m (list b c d)) (nd:publish-reveal m id))
          (let* ((outcomes (mapcar (lambda (m) (multiple-value-list (nd:claim-or-yield m id))) (list b c d)))
                 (won (find :won outcomes :key #'first)) (claim (second won)))
            (check-equal "claim has two inputs: lottery output + replacement collateral" (length (btx:tx-inputs claim)) 2)
            (check-equal "claim pays lottery + collateral - fee into the new vault"
                         (btx:txout-value (first (btx:tx-outputs claim)))
                         (- (+ (btx:txout-value (first (btx:tx-outputs ctx))) (+ floor-sats 1000)) lot:+claim-fee-floor+))
            (check "second input is a key-path spend with a 64-byte signature" (= 64 (length (first (second (btx:tx-witnesses claim))))))))
        ;; DEP-03: a pledge spent before the snapshot excludes its armer; it no
        ;; longer blocks the confiscation (one armer could veto the dispute).
        (remhash (cons (coerce (u:sha256 (nd:node-pubkey c)) 'list) 1) chain)
        (multiple-value-bind (in out) (nd:lottery-armers b id)
          (check-equal "a spent pledge excludes only its armer"
                       (list (length in) (mapcar (lambda (x) (first (car x))) out))
                       (list 2 (list (nd:node-pubkey c)))))
        (check "the confiscation still builds over the other two" (nd:build-confiscation b id))
        ;; One honest armer left (the veto case the floor of 2 reintroduced): it takes custody alone.
        (remhash (cons (coerce (u:sha256 (nd:node-pubkey b)) 'list) 1) chain)
        (check-equal "one eligible armer is the sole participant"
                     (mapcar #'first (nd:lottery-armers b id)) (list (nd:node-pubkey d)))
        (check "and its confiscation builds over a one-participant lottery"
               (= 1 (length (lot:lottery-participants (nth-value 1 (nd:build-confiscation b id))))))
        ;; None left: no confiscation; an armer re-arms with a fresh pledge to reopen the window.
        (remhash (cons (coerce (u:sha256 (nd:node-pubkey d)) 'list) 1) chain)
        (check "no eligible armer: no confiscation is built" (null (ignore-errors (nd:build-confiscation b id))))
        (setf (gethash (cons (coerce (u:sha256 (hx "dd2")) 'list) 0) chain) (+ floor-sats 1000))
        (nd:arm-dispute d (nd:find-fork d id (nd:node-pubkey d)) :replacement (list (u:sha256 (hx "dd2")) 0 (+ floor-sats 1000)))
        (check-equal "a re-arm with a fresh pledge reopens it"
                     (mapcar #'first (nd:lottery-armers b id)) (list (nd:node-pubkey d)))
        ;; Arms 3..6 declare 1..4 sats: only arms 3 and 4 count, so the latest counted is 2.
        (loop for sats from 1 to 4
              do (nd:arm-dispute d (nd:find-fork d id (nd:node-pubkey d)) :replacement (list (u:sha256 (hx "dd2")) 0 sats)))
        (check-equal "arms beyond the fourth are ignored (a griefer cannot keep moving E)"
                     (third (fourth (find (nd:node-pubkey d) (nd:armers-of b id) :key #'first :test #'equalp)))
                     2)))))



(with-gate ("couriers: a PTLC route (point locks, courier blinding)")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (e (nd:make-node :priv 99999999999999999999 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (kn (nd:make-node :priv 77777777777777777777 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a8" :reserves 15600000 :collateral 23400000))
         (le (nd:open-ledger e :reserves-id "genesis:e8" :reserves 15600000 :collateral 23400000))
         (ida (nd:record-id-hex la)) (ide (nd:record-id-hex le)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m))))
    (dolist (opnode (list a e))
      (let ((rec (if (eq opnode a) la le)))
        (dolist (m (list b c d)) (nd:add-member opnode rec (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
        (nd:begin-quorum opnode rec :funding-txid (u:sha256 (u:cat (hx "f00d8") (nd:node-pubkey opnode))) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)))
    (let* ((w1 (nd:make-wallet :priv 55555555555555555555 :bus bus)) (w2 (nd:make-wallet :priv 66666666666666666666 :bus bus))
           (kwa (nd:make-wallet :priv 77777777777777777777 :bus bus)) (kwe (nd:make-wallet :priv 77777777777777777777 :bus bus))
           (d1 (nd:wallet-open-deposit w1 ida)) (d2 (nd:wallet-open-deposit w2 ide))
           (ka (nd:wallet-open-deposit kwa ida)) (ke (nd:wallet-open-deposit kwe ide))
           (k (cr:make-courier kn)))
      (nd:credit-onchain a la d1 500000 :txid (u:sha256 (hx "11")))
      (nd:credit-onchain e le ke 800000 :txid (u:sha256 (hx "12")))
      (cr:courier-serve k ida ka kwa) (cr:courier-serve k ide ke kwe)
      (check "pointlock completion accepts the right scalar"
             (nd:completion-satisfied-p (format nil "pointlock(~a)" (u:bytes->hex (up:compressed-pubkey 4242))) (list (u:int->be 4242 32))))
      (check "pointlock completion rejects a wrong scalar"
             (not (nd:completion-satisfied-p (format nil "pointlock(~a)" (u:bytes->hex (up:compressed-pubkey 4242))) (list (u:int->be 4243 32)))))
      (multiple-value-bind (leg1 s forward point-p) (cr:wallet-route w1 (nd:node-pubkey-hex kn) ida ide d1 d2 100000 :height *height* :ptlc t)
        (declare (ignore leg1))
        (let ((leg2 (nd:wallet-pending-lock kn ide nil d2 :point point-p)))
          (check "leg 2 locked to P itself on the destination ledger" (and leg2 t))
          (check "leg 1 and leg 2 lock to different points (unlinkable on the relay)"
                 (let ((l1 (find-if (lambda (p) (equalp (getf p :destination) ka))
                                    (loop for p being the hash-values of (lg:ledger-pending-transfers (nd:record-ledger la)) collect p))))
                   (and l1 (not (string= (getf l1 :completion-script) (format nil "pointlock(~a)" (u:bytes->hex point-p)))))))
          (check "receiver completes leg 2 with s" (nd:wallet-complete-transfer w2 ide (getf leg2 :transfer-id) (u:int->be (u:be->int s) 32)))
          (check-equal "receiver got the forward amount" (nd:wallet-balance w2 ide d2) forward)
          (check-equal "courier completed leg 1 with s + t" (nd:wallet-balance kwa ida ka) 100000)
          (check-equal "sender paid in full" (multiple-value-list (nd:wallet-balance w1 ida d1)) '(400000 0)))))))

(with-gate ("rotation: a ledger that moves between prepare and begin still rotates")
  ;; The soak's cl ledgers never rotated under traffic: funding the reserves
  ;; takes confirmations, transfers chain meanwhile, and begin-quorum refused
  ;; "ledger moved since the reserves were prepared".  The QuorumBegin anchors
  ;; the hash the reserves commit to, which need not be the tip.
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a9" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d9")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((w (nd:make-wallet :priv 55555555555555555555 :bus bus)) (dw (nd:wallet-open-deposit w id)))
      (dolist (m (list b c d)) (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
      (let* ((reserves (nd:prepare-quorum a la :ruleset "fee-cap-v3")) (anchor (rs:reserves-ledger-hash reserves)))
        (nd:credit-onchain a la dw 1000 :txid (u:sha256 (hx "79")))
        (check "the ledger moved after prepare" (not (equalp anchor (up:chain-hash (nd::tip la)))))
        (multiple-value-bind (qb r2) (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00da")) :funding-vout 0
                                                          :amount-msats 15600000 :collateral-msats 23400000)
          (let ((o (op:decode-operation (up:update-message qb))))
            (check "rotation commits" (eq (op:operation-type o) :quorum-begin))
            (check-equal "QuorumBegin anchors the prepared hash" (op:field o :ledger-hash) anchor)
            (check-equal "and the reserves it promotes are the prepared ones" (rs:reserves-address r2) (rs:reserves-address reserves))
            (check-equal "it names the prepared ruleset, not begin-quorum's default" (op:field o :protocol-version) "fee-cap-v3")
            (check-equal "so a verifier rebuilding from it gets the funded address"
                         (rs:reserves-address (nd::disputed-reserves b (nd:find-record b id))) (rs:reserves-address reserves))
            (check-equal "cosigners replicated it" (lg:ledger-sequence (nd:record-ledger (nd:find-record b id)))
                         (up:update-seq qb))))))))

(with-gate ("expiry watch: members dispute a lapsed quorum by themselves, after a grace")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:ab" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m) :membership-blocks 100))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00db")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000 :expiry-blocks 100)
    (let ((expiry (lg:ledger-quorum-expiry (nd:record-ledger la))))
      (let ((*height* (+ expiry 1)))
        (check-equal "inside the grace, nobody disputes" (nd:dispute-expired-quorums b :grace 3) '()))
      (let ((*height* (+ expiry 4)))
        (check-equal "past the grace, member b disputes on its own" (nd:dispute-expired-quorums b :grace 3) (list id))
        (check "b forked" (nd:find-fork b id (nd:node-pubkey b)))
        (check-equal "and does not dispute twice" (nd:dispute-expired-quorums b :grace 3) '())
        (check-equal "the operator never disputes its own ledger" (nd:dispute-expired-quorums a :grace 3) '())
        ;; c's replica is behind the relay (it missed the tail): it must not judge.
        (let* ((rec (nd:find-record c id))
               (stale (nd::make-record :id-hex id :ledger (lg:replay (reverse (rest (nd::record-history rec))))
                                       :history (rest (nd::record-history rec)))))
          (setf (gethash id (nd:node-ledgers c)) stale)
          (check-equal "a replica behind the relay does not judge" (nd:dispute-expired-quorums c :grace 3) '())
          (setf (gethash id (nd:node-ledgers c)) rec))
        ;; The operator re-establishes (establishment ops stay cosignable past expiry):
        ;; b, which disputed, stands down.
        (let ((*height* (+ expiry 5)))
          (dolist (m (list c d)) (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
          (nd:add-member a la (nd:node-pubkey b) :member-ledger-id (nd::node-member-ledger-hex b))
          (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00dbb")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
          (check "the quorum was re-established" (> (lg:ledger-quorum-expiry (nd:record-ledger (nd:find-record b id))) *height*))
          (nd:drive-disputes b)
          (check-equal "the DisputeEnter reason is the reference's" 
                       (op:field (nth-value 1 (nd::fork-op (nd:find-fork b id (nd:node-pubkey b)) :dispute-enter)) :reason) "quorum_expired")
          (check "b yielded its now-baseless dispute" (nd::fork-op (nd:find-fork b id (nd:node-pubkey b)) :dispute-yield)))))))

(with-gate ("confiscation signs the tier open at the height: a minority past expiry + 720")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:ac" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m) :membership-blocks 100))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00dc")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000 :expiry-blocks 100)
    (let* ((expiry (lg:ledger-quorum-expiry (nd:record-ledger la)))
           (reserves (nd::disputed-reserves b (nd:find-record b id))))
      (check-equal "just past expiry: Tier 0 (majority)" (nd::confiscation-tier reserves (+ expiry 1)) 0)
      (check-equal "at expiry + 720: Tier 1 (minority)" (nd::confiscation-tier reserves (+ expiry 720)) 1)
      (check "the operator's tie-breaker tier is never chosen"
             (not (rs:tier-tie-breaker-p (nth (nd::confiscation-tier reserves (+ expiry 9000)) (rs:reserves-tiers reserves)))))
      (let ((*height* (+ expiry 721)))
        ;; Only b and c dispute and arm; d stays out.  A majority of four voters is
        ;; out of reach, the Tier-1 minority (one) is not.
        (dolist (m (list b c)) (nd:dispute-expired-quorums m :grace 3) (nd:arm-dispute m (nd:find-fork m id (nd:node-pubkey m)) :replacement (list (u:sha256 (nd:node-pubkey m)) 0 10000000)))
        (multiple-value-bind (ctx lottery) (nd:confiscate b id :respectful t)
          (declare (ignore lottery))
          (check-equal "nLockTime is Tier 1's CLTV" (btx:tx-locktime ctx) (+ expiry 720))
          (check "the one-signature Tier-1 spend verifies"
                 (rot:verify-spend ctx 0 (vector (cons (floor (+ 15600000 23400000) 1000) (rs:reserves-spk reserves))))))))))

(with-gate ("collateral wallet: pledge a whole confirmed UTXO, never twice; consolidate when none fits")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (utxos '())
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf :utxos-fn (lambda (addr) (declare (ignore addr)) utxos)))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:ad" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00dd")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((w (nd:make-wallet :priv 55555555555555555555 :bus bus)) (dw (nd:wallet-open-deposit w id)))
      (nd:credit-onchain a la dw 1000000 :txid (u:sha256 (hx "c0ffeed"))))
    (let ((need (nd:required-replacement-sats (nd:find-record b id))))
      (check-equal "the reference's floor binds: 1000 sats x 1.5 + 5000" need 6500)
      (flet ((utxo (tag sats conf) (list :txid (u:sha256 (hx tag)) :vout 0 :sats sats :confirmations conf)))
        (setf utxos (list (utxo "01" 4000 3) (utxo "02" 9000 0) (utxo "03" 20000 2) (utxo "04" 7000 5)))
        (let ((p (nd:pledge-collateral b id)))
          (check-equal "smallest confirmed UTXO that covers it, at its full value" (third p) 7000)
          (check-equal "asked again for the same dispute: the same pledge" (nd:pledge-collateral b id) p)
          (let ((other (nd:pledge-collateral b (nd::node-member-ledger-hex b))))
            (check "another dispute gets a different UTXO" (and other (not (equalp (first other) (first p)))))))
        (nd:release-pledges b (nd::node-member-ledger-hex b))
        ;; Nothing single fits, but together they do: consolidate, pledge nothing yet.
        (setf utxos (list (utxo "05" 4000 3) (utxo "06" 3500 1) (utxo "07" 2000 4)))
        (nd:release-pledges b id)
        (check-equal "no single UTXO fits: nothing pledged yet" (nd:pledge-collateral b id) nil)
        (let ((tx (first (nd::node-broadcasts b))))
          (check-equal "a consolidation of all three was broadcast" (length (btx:tx-inputs tx)) 3)
          (check-equal "back to our own key-path address" (btx:txout-script (first (btx:tx-outputs tx)))
                       (lot:key-path-spk (up:x-only (nd:node-pubkey b)))))
        (setf utxos (list (utxo "08" 1000 3)))
        (check-equal "too little altogether: declined" (nd:pledge-collateral b id) nil)))))

(with-gate ("dispute driver: an expired quorum is armed, confiscated, revealed and claimed without a command")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (chain (make-hash-table :test #'equalp))   ; (txid-list . vout) -> (sats . spk)
         (cf (lambda (txid vout) (let ((v (gethash (cons (coerce txid 'list) vout) chain))) (and v (list :value-sats (car v) :confirmations 3)))))
         (bf (lambda (bytes)   ; the mock mempool confirms at once: spend the inputs, add the outputs
               (let ((tx (btx:parse-tx (cl-consensus.wire:make-reader bytes))))
                 (dolist (in (btx:tx-inputs tx)) (remhash (cons (coerce (btx:txin-prev-hash in) 'list) (btx:txin-prev-index in)) chain))
                 (loop for o in (btx:tx-outputs tx) for i from 0
                       do (setf (gethash (cons (coerce (btx:tx-txid tx) 'list) i) chain) (cons (btx:txout-value o) (btx:txout-script o))))
                 (btx:tx-txid tx))))
         (uf-for (lambda (priv)
                   (let ((spk (lot:key-path-spk (up:x-only (up:compressed-pubkey (w:even-y-privkey priv))))))
                     (lambda (addr) (declare (ignore addr))
                       (loop for k being the hash-keys of chain using (hash-value v)
                             when (equalp (cdr v) spk)
                               collect (list :txid (coerce (car k) '(vector (unsigned-byte 8))) :vout (cdr k) :sats (car v) :confirmations 3))))))
         (mk (lambda (priv) (nd:make-node :priv priv :bus bus :height-fn hf :chain-fn cf :broadcast-fn bf :utxos-fn (funcall uf-for priv))))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (funcall mk 22222222222222222222)) (c (funcall mk 33333333333333333333)) (d (funcall mk 44444444444444444444))
         (la (nd:open-ledger a :reserves-id "genesis:ae" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m) :membership-blocks 100))
    (setf (gethash (cons (coerce (u:sha256 (hx "f00de")) 'list) 0) chain) (cons (floor (+ 15600000 23400000) 1000) nil))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00de")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000 :expiry-blocks 100)
    ;; The reserves spk, now that the vault exists.
    (let ((r (nd::disputed-reserves b (nd:find-record b id))))
      (setf (cdr (gethash (cons (coerce (u:sha256 (hx "f00de")) 'list) 0) chain)) (rs:reserves-spk r)))
    ;; Each member's wallet: one coin at its own key-path address.
    (dolist (m (list b c d))
      (setf (gethash (cons (coerce (u:sha256 (nd:node-pubkey m)) 'list) 0) chain) (cons 50000 (lot:key-path-spk (up:x-only (nd:node-pubkey m))))))
    (let ((expiry (lg:ledger-quorum-expiry (nd:record-ledger la))))
      (let ((*height* (+ expiry 4)))
        (dolist (m (list b c d)) (nd:dispute-expired-quorums m :grace 3))
        (dolist (m (list b c d)) (nd:drive-disputes m))
        (check "every member armed by itself, pledging its coin" (= 3 (count-if #'fourth (nd:armers-of b id))))
        (check "each pledge is recorded" (every (lambda (m) (plusp (hash-table-count (nd:node-pledges m)))) (list b c d)))
        (clrhash (nd:node-pledges b))   ; as after a restart that lost pledges.sexp
        (check-equal "a coin declared in our DisputeArmed is never pledged again" (nd:pledge-collateral b (nd::node-member-ledger-hex b)) nil)
        (dolist (m (list b c d)) (nd:drive-disputes m))
        (check "nobody confiscates inside the arm window" (gethash (cons (coerce (u:sha256 (hx "f00de")) 'list) 0) chain)))
      (let ((*height* (+ (nd:dispute-arm-closes b (nd:find-record b id)) 1)))
        (dolist (m (list b c d)) (nd:drive-disputes m))
        (check "the reserves were confiscated" (null (gethash (cons (coerce (u:sha256 (hx "f00de")) 'list) 0) chain)))
        ;; A restart forgets the confiscation and lottery: each member must rebuild
        ;; the (respectful, tiered) transaction from public state to reveal and claim.
        (dolist (m (list b c d))
          (dolist (f (nd::forks-of m id)) (setf (nd::record-confiscation f) nil (nd::record-lottery f) nil)))
        (check "after a restart the confiscation still rebuilds" (nd::confiscation-on-chain c id))
        ;; A signer keeps every proposal it signed; one that never confirmed must not
        ;; hide the one that did.
        (multiple-value-bind (stale sl) (nd:build-confiscation d id :tier-index 1 :respectful t)
          (dolist (f (nd::forks-of d id)) (setf (nd::record-confiscation f) stale (nd::record-lottery f) sl))
          (multiple-value-bind (tx l state) (nd::fork-lottery d id)
            (declare (ignore l))
            (check "a stale cached proposal is dropped for the confiscation on chain"
                   (and (eq state :pending) (equalp (btx:tx-txid tx) (btx:tx-txid (nd::confiscation-on-chain c id)))))))
        (let* ((conf (nd::confiscation-on-chain c id)) (bytes (u:hex->bytes (nd::unsigned-tx-hex conf))))
          (check "an unsigned tx goes out without the segwit marker (BIP-144)" (/= 0 (aref bytes 4)))
          (check "and parses back to the same txid"
                 (equalp (btx:tx-txid (btx:parse-tx (cl-consensus.wire:make-reader bytes))) (btx:tx-txid conf))))
        (loop repeat 3 do (dolist (m (list b c d)) (nd:drive-disputes m)))
        (check "every member revealed" (= 3 (length (nd:reveals-of b id))))
        (let ((acquired (count-if (lambda (m) (nd::fork-op (nd:find-fork m id (nd:node-pubkey m)) :dispute-acquire)) (list b c d)))
              (yielded (count-if (lambda (m) (nd::fork-op (nd:find-fork m id (nd:node-pubkey m)) :dispute-yield)) (list b c d))))
          (check-equal "one winner claimed, the others yielded" (list acquired yielded) '(1 2)))
        (check "every pledge released" (every (lambda (m) (zerop (hash-table-count (nd:node-pledges m)))) (list b c d)))))))

(with-gate ("withheld reveal: past the deadline the revealer claims its subset leaf, attested; never the operator")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (depth 3)
         (chain (make-hash-table :test #'equalp))   ; (txid-list . vout) -> (sats . spk)
         (cf (lambda (txid vout) (let ((v (gethash (cons (coerce txid 'list) vout) chain))) (and v (list :value-sats (car v) :confirmations depth)))))
         (bf (lambda (bytes)
               (let ((tx (btx:parse-tx (cl-consensus.wire:make-reader bytes))))
                 (dolist (in (btx:tx-inputs tx)) (remhash (cons (coerce (btx:txin-prev-hash in) 'list) (btx:txin-prev-index in)) chain))
                 (loop for o in (btx:tx-outputs tx) for i from 0
                       do (setf (gethash (cons (coerce (btx:tx-txid tx) 'list) i) chain) (cons (btx:txout-value o) (btx:txout-script o))))
                 (btx:tx-txid tx))))
         (uf-for (lambda (priv)
                   (let ((spk (lot:key-path-spk (up:x-only (up:compressed-pubkey (w:even-y-privkey priv))))))
                     (lambda (addr) (declare (ignore addr))
                       (loop for k being the hash-keys of chain using (hash-value v)
                             when (equalp (cdr v) spk)
                               collect (list :txid (coerce (car k) '(vector (unsigned-byte 8))) :vout (cdr k) :sats (car v) :confirmations 3))))))
         (mk (lambda (priv) (nd:make-node :priv priv :bus bus :height-fn hf :chain-fn cf :broadcast-fn bf :utxos-fn (funcall uf-for priv))))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (funcall mk 22222222222222222222)) (c (funcall mk 33333333333333333333)) (d (funcall mk 44444444444444444444))
         (la (nd:open-ledger a :reserves-id "genesis:af" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la))
         (reserves-key (cons (coerce (u:sha256 (hx "f00df")) 'list) 0)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m) :membership-blocks 100))
    (setf (gethash reserves-key chain) (cons (floor (+ 15600000 23400000) 1000) nil))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00df")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000 :expiry-blocks 100)
    (setf (cdr (gethash reserves-key chain)) (rs:reserves-spk (nd::disputed-reserves b (nd:find-record b id))))
    (dolist (m (list b c d))
      (setf (gethash (cons (coerce (u:sha256 (nd:node-pubkey m)) 'list) 0) chain) (cons 50000 (lot:key-path-spk (up:x-only (nd:node-pubkey m))))))
    (flet ((drive () (dolist (m (list b c d)) (nd:drive-disputes m))))
      (let ((expiry (lg:ledger-quorum-expiry (nd:record-ledger la))))
        (let ((*height* (+ expiry 4)))
          (dolist (m (list b c)) (nd:dispute-expired-quorums m :grace 3))
          ;; Q = 3, but only b and c arm; c will withhold its reveal.
          (nd:arm-dispute b (nd:find-fork b id (nd:node-pubkey b)) :replacement (nd:pledge-collateral b id))
          (nd:arm-dispute c (nd:find-fork c id (nd:node-pubkey c)) :replacement (nd:pledge-collateral c id))
          (setf (getf (nd:node-adversary c) :withhold-reveal) t))
        (let* ((closes (nd:dispute-arm-closes b (nd:find-record b id))))
          (let ((*height* (+ closes 1)))
            (drive)
            (check "two of three armed: they confiscate without waiting for the third" (null (gethash reserves-key chain)))
            (drive)
            (check "b revealed, c withheld" (and (assoc (nd:node-pubkey b) (nd:reveals-of d id) :test #'equalp)
                                                 (not (assoc (nd:node-pubkey c) (nd:reveals-of d id) :test #'equalp))))
            (multiple-value-bind (conf lottery) (nd::fork-lottery b id)
              (check "the lottery has a leaf for each proper revealer subset" (= 2 (length (lot:lottery-subsets lottery))))
              (drive)
              (check "before the reveal deadline nobody claims" (gethash (cons (coerce (btx:tx-txid conf) 'list) 0) chain))
              (setf depth 80)
              (drive)
              (check "past it the sole revealer claims through its subset leaf" (null (gethash (cons (coerce (btx:tx-txid conf) 'list) 0) chain)))
              (check "b took custody" (nd::fork-op (nd:find-fork b id (nd:node-pubkey b)) :dispute-acquire))
              (multiple-value-bind (witver program)
                  (cl-consensus.encoding:segwit-decode (nd::our-target-address b) "tb")
                (let ((spk (u:cat (u:octets (if (zerop witver) 0 (+ #x50 witver)) (length program)) program))
                      (lottery-sats (btx:txout-value (first (btx:tx-outputs conf)))))
                  (check "the lottery output went to b's declared target, less the claim fee"
                         (loop for v being the hash-values of chain thereis (and (equalp (cdr v) spk) (> (car v) (- lottery-sats 1000))))))))
            (check "the withholder did not take custody" (null (nd::fork-op (nd:find-fork c id (nd:node-pubkey c)) :dispute-acquire)))))))))

(with-gate ("DEP-02 sequence: a skip on our chain is disputed as non-conforming, a gap is fetched")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111171 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222272 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333373 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444474 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:skip" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "5c1f")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((rb (nd:find-record b id)) (lb (nd:record-ledger rb))
           (stray (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id)
                                                  :seq (+ 5 (lg:ledger-sequence lb)) :prev-hash (u:sha256 (hx "e15e"))
                                                  :message (op:encode-operation (list :type :deposit-close :deposit-id (subseq (u:sha256 (hx "01")) 0 16))))))
                    (up:sign-operator u (nd::node-priv a)) u))
           (skip (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id)
                                                 :seq (+ 2 (lg:ledger-sequence lb)) :prev-hash (lg:ledger-chain-tip lb)
                                                 :message (op:encode-operation (list :type :deposit-close :deposit-id (subseq (u:sha256 (hx "01")) 0 16))))))
                   (up:sign-operator u (nd::node-priv a)) u)))
      (ignore-errors (nd::handle-update b (w:update-event (nd::node-keypair a) stray)))
      (check "a gap (previous_hash names nothing we hold) is not disputed" (null (nd:find-fork b id (nd:node-pubkey b))))
      (ignore-errors (nd::handle-update b (w:update-event (nd::node-keypair a) skip)))
      (let ((fork (nd:find-fork b id (nd:node-pubkey b))))
        (check "a skip chained onto our tip is disputed" (and fork t))
        (when fork
          (check-equal "as a non-conforming update" (op:field (nth-value 1 (nd::fork-op fork :dispute-enter)) :reason) "non_conforming_update")))
      (check "the skip proof verifies against the canonical history"
             (fr:verify-non-conforming-update (fr:make-non-conforming-update-proof (nd:node-pubkey a) (u:hex->bytes id) skip)
                                              (reverse (nd:record-history rb)))))))

(with-gate ("red team #1: a majority-cosigned invalid update is reported and disputed by every replica")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:b1" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "b1f0")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((w (nd:make-wallet :priv 55555555555555555555 :bus bus)) (dw (nd:wallet-open-deposit w id))
           (before (lg:ledger-sequence (nd:record-ledger (nd:find-record d id)))))
      ;; Honest cosigners: the over-reserves credit gathers no cosignature.
      (setf (getf (nd:node-adversary a) :sign-invalid) t)
      (check-signals "honest quorum: the invalid credit cannot be cosigned" nd:node-error
        (nd:credit-onchain a la dw 999999999999 :txid (u:sha256 (hx "b1c1"))))
      ;; b and c collude (cosign blind): it commits and is published.
      (dolist (m (list b c)) (setf (getf (nd:node-adversary m) :cosign-blind) t))
      (nd:credit-onchain a la dw 999999999999 :txid (u:sha256 (hx "b1c2")))
      (check "the colluding operator published it" (> (lg:ledger-sequence (nd:record-ledger la)) before))
      (check "the honest replica did not apply it" (= (lg:ledger-sequence (nd:record-ledger (nd:find-record d id))) before))
      (let ((fork (nd:find-fork d id (nd:node-pubkey d))))
        (check "the honest minority disputed" (and fork t))
        (check-equal "for non-conformance, in the reference's words"
                     (op:field (nth-value 1 (nd::fork-op fork :dispute-enter)) :reason) "non_conforming_update")
        (check-equal "from the last valid sequence" (lg:ledger-sequence (nd:record-ledger fork)) (1+ before)))
      (let ((logged (lambda () (count-if (lambda (l) (search "stopped at seq" l)) (nd::node-log d)))))
        (nd:catch-up d (nd:find-record d id))
        (let ((once (funcall logged)))
          (nd:catch-up d (nd:find-record d id)) (nd:catch-up d (nd:find-record d id))
          (check-equal "the refusal is logged once" once 1)
          (check "catch-up does not retry an update the rules rejected" (= once (funcall logged)))))
      (check "so did the colluders' own replicas (their validation is honest)"
             (every (lambda (m) (nd:find-fork m id (nd:node-pubkey m))) (list b c)))
      ;; 9c: the proof of it is self-evident — it goes out with no embedding at all.
      (let* ((fault (first (nd::record-history la)))
             (proof (fr:make-non-conforming-update-proof (nd:node-pubkey a) (u:hex->bytes id) fault)))
        (check "a self-evident proof is broadcast without an embedding"
               (null (nth-value 1 (gethash "embedding" (fr:broadcast->json proof)))))
        (check "an off-ledger proof still carries one"
               (nth-value 1 (gethash "embedding" (fr:broadcast->json (list :type :uncredited-onchain-payment :accused "00" :ledger-id id :evidence '()))))))
      ;; Finding 10: an armer that declares no replacement collateral is never a
      ;; lottery participant (it could win custody with no bond).  DEP-03 excludes
      ;; it rather than refusing; here that leaves one participant.
      (nd:arm-dispute d (nd:find-fork d id (nd:node-pubkey d)) :replacement (list (u:sha256 (hx "b1d0")) 0 10000000))
      (nd:arm-dispute b (nd:find-fork b id (nd:node-pubkey b)))
      (check-equal "an armer with no replacement collateral is excluded"
                   (mapcar (lambda (x) (first (car x))) (nth-value 1 (nd:lottery-armers d id))) (list (nd:node-pubkey b)))
      (check "the sole participant's confiscation builds (it takes custody without a draw)"
             (= 1 (length (lot:lottery-participants (nth-value 1 (nd:build-confiscation d id)))))))))


(with-gate ("red team: an operator cannot spend a depositor's funds without its authorization")
  ;; Depositor authorization (the witness), the nonce window and the operation's
  ;; expiry are ledger rules (DEP-16), not operator courtesy: cosigners refuse an
  ;; update that breaks them.  A (operator) plays the adversary: it builds updates
  ;; straight through APPEND-OPERATION, skipping its own request checks.
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111171 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222272 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333373 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444474 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a7" :reserves 15600000 :collateral 23400000))
         (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m))))
    (dolist (m (list b c d)) (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d7")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((w1 (nd:make-wallet :priv 55555555555555555575 :bus bus)) (w2 (nd:make-wallet :priv 66666666666666666676 :bus bus))
           (d1 (nd:wallet-open-deposit w1 id)) (d2 (nd:wallet-open-deposit w2 id))
           (balance (lambda () (lg:deposit-balance (lg:find-deposit (nd:record-ledger la) d1)))))
      (nd:credit-onchain a la d1 100000 :txid (u:sha256 (hx "c0ffee7")))
      ;; 1. No witness at all.
      (let ((forged (list :type :transfer-lock :transfer-nonce (u:sha256 (hx "a1")) :source-deposit-id d1 :destination-deposit-id d2
                          :amount 50000 :fee 0 :completion-script "sha256(00)" :timeout-height (+ *height* 100)
                          :transfer-id (u:sha256 (hx "a2")) :nonce 424242 :expiry (+ *height* 144) :witness '())))
        (check-signals "a TransferLock without the depositor's witness is refused" nd:node-error (nd:append-operation a la forged))
        (check-equal "the depositor's balance is untouched" (funcall balance) 100000))
      ;; 2. Replay the depositor's own, validly signed TransferLock.
      (multiple-value-bind (tid pre) (nd:wallet-transfer w1 id d1 d2 30000 :height *height*)
        (nd:wallet-complete-transfer w1 id tid pre))
      (check-equal "the genuine transfer settled" (funcall balance) 70000)
      (let ((signed (find-if (lambda (u) (eq :transfer-lock (op:operation-type (op:decode-operation (up:update-message u)))))
                             (nd:record-history la))))
        (check-signals "a replay of the depositor's signed TransferLock is refused" nd:node-error
                       (nd:append-operation a la (op:decode-operation (up:update-message signed))))
        (check-equal "the replay moved nothing" (funcall balance) 70000))
      ;; 3. A validly signed lock whose expiry has passed.
      (let ((*height* (- *height* 300)))   ; the wallet signs expiry = its height + 144
        (handler-case (nd:wallet-transfer w1 id d1 d2 1000 :height *height*) (error () nil)))
      (check-equal "an expired signed operation moved nothing" (funcall balance) 70000)
      ;; 4. A colluding majority (B, C cosign blind) commits a lock with no witness.
      ;;    The honest replica (D) must prove it and dispute.
      (dolist (m (list b c)) (setf (getf (nd::node-adversary m) :cosign-blind) t))
      (let ((forged (list :type :transfer-lock :transfer-nonce (u:sha256 (hx "b1")) :source-deposit-id d1 :destination-deposit-id d2
                          :amount 60000 :fee 0 :completion-script "sha256(00)" :timeout-height (+ *height* 100)
                          :transfer-id (u:sha256 (hx "b2")) :nonce 515151 :expiry (+ *height* 144) :witness '())))
        (let ((u (nd:append-operation a la forged)))
          (dolist (m (list b c)) (setf (getf (nd::node-adversary m) :cosign-blind) nil))
          (check "the colluding majority committed it" (and u (= (up:update-seq u) (lg:ledger-sequence (nd:record-ledger la)))))
          (check "the honest replica disputes the ledger" (nd:find-fork d id (nd:node-pubkey d)))
          (check "a NonConformingUpdate proof of it verifies on the history before it"
                 (fr:verify-non-conforming-update (fr:make-non-conforming-update-proof (nd:node-pubkey a) (u:hex->bytes id) u)
                                                  (remove u (reverse (nd:record-history la)))))
          (check "the same update, signed by the depositor, would not be proof"
                 (not (fr:verify-non-conforming-update
                       (fr:make-non-conforming-update-proof (nd:node-pubkey a) (u:hex->bytes id) (find-if (lambda (x) (eq :transfer-lock (op:operation-type (op:decode-operation (up:update-message x))))) (nd:record-history la) :from-end t))
                       (reverse (nd:record-history la))))))))))


(with-gate ("red team: a member cannot freeze an honest ledger by 'equivocating' itself")
  ;; B, a quorum member of A's ledger, signs two different updates at the next
  ;; sequence, chained onto A's tip and carrying A's id, and broadcasts an
  ;; equivocation proof accusing itself.  Only the operator's equivocation is
  ;; fraud on a ledger: C and D must not dispute A.
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111181 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222282 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333383 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444484 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a8" :reserves 15600000 :collateral 23400000))
         (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m))))
    (dolist (m (list b c d)) (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d8")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let* ((tip (first (nd:record-history la)))
           (mk (lambda (tag)
                 (let ((u (up:make-signed-update :operator-id (nd:node-pubkey b) :ledger-id (u:hex->bytes id)
                                                 :seq (1+ (up:update-seq tip)) :prev-hash (up:chain-hash tip) :block-height *height*
                                                 :message (op:encode-operation (list :type :deposit-close :deposit-id (subseq (u:sha256 (hx tag)) 0 16))))))
                   (up:sign-operator u (nd::node-priv b)) u)))
           (proof (fr:make-equivocation-proof (nd:node-pubkey b) (u:hex->bytes id) (funcall mk "01") (funcall mk "02"))))
      (check "the pair is two different, validly signed updates by B on A's chain"
             (and (up:verify-operator-signature (funcall mk "01")) (not (equalp (up:content-hash (funcall mk "01")) (up:content-hash (funcall mk "02"))))))
      (check "the proof does not verify: B is not A's operator"
             (not (fr:verify-equivocation proof (reverse (nd:record-history la)))))
      ;; The same with a non-conforming update: B signs one that breaks the rules.
      (let* ((bad (funcall mk "03"))
             (nc (fr:make-non-conforming-update-proof (nd:node-pubkey b) (u:hex->bytes id) bad)))
        (check "a non-conforming update signed by a member is not proof against the ledger"
               (not (fr:verify-non-conforming-update nc (reverse (nd:record-history la)))))
        (nd:broadcast-fraud b nc))
      (nd:broadcast-fraud b proof)
      (check "no honest member disputes A" (notany (lambda (m) (nd:find-fork m id (nd:node-pubkey m))) (list c d)))
      ;; And the operator's own equivocation still is.
      (let* ((mk-a (lambda (tag)
                     (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id)
                                                     :seq (1+ (up:update-seq tip)) :prev-hash (up:chain-hash tip) :block-height *height*
                                                     :message (op:encode-operation (list :type :deposit-close :deposit-id (subseq (u:sha256 (hx tag)) 0 16))))))
                       (up:sign-operator u (nd::node-priv a)) u))))
        (check "the operator's equivocation still verifies"
               (fr:verify-equivocation (fr:make-equivocation-proof (nd:node-pubkey a) (u:hex->bytes id) (funcall mk-a "01") (funcall mk-a "02"))
                                       (reverse (nd:record-history la))))))))



(defvar *l3* nil "The contagion gate's second ledger of the attacking operator.")

(with-gate ("contagion: a colluding cosigner is disputed on the ledger it operates (DEP-19 §5-6)")
  ;; L1: A operates; B, C, D cosign.  L2: B operates; C, D, E cosign (honest majority D, E).
  ;; B and C cosign blind, so A's witness-less lock on L1 commits.  D (an honest
  ;; replica of L1) proves it, and proves B's cosignature against L2: L2's honest
  ;; members D and E dispute B's own ledger.  E holds no replica of L1: it rebuilds
  ;; the fault's prefix from the relay.
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111191 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222292 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333393 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444494 :bus bus :height-fn hf))
         (e (nd:make-node :priv 55555555555555555595 :bus bus :height-fn hf))
         (l1 (nd:open-ledger a :reserves-id "genesis:c1" :reserves 15600000 :collateral 15600000))
         (l2 (nd:open-ledger b :reserves-id "genesis:c2" :reserves 15600000 :collateral 15600000))
         (id1 (nd:record-id-hex l1)) (id2 (nd:record-id-hex l2)))
    (dolist (m (list c d e)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m))))
    (dolist (m (list b c d)) (nd:add-member a l1 (nd:node-pubkey m) :member-ledger-id (if (eq m b) id2 (nd::node-member-ledger-hex m))))
    (nd:begin-quorum a l1 :funding-txid (u:sha256 (hx "c1")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 15600000)
    (dolist (m (list c d e)) (nd:add-member b l2 (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum b l2 :funding-txid (u:sha256 (hx "c2")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 15600000)
    ;; L3: A's second ledger (C, D, E cosign; honest majority D, E).  Operator contagion.
    (setf *l3* (nd:open-ledger a :reserves-id "genesis:c6" :reserves 15600000 :collateral 15600000))
    (dolist (m (list c d e)) (nd:add-member a *l3* (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a *l3* :funding-txid (u:sha256 (hx "c7")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 15600000)
    (let* ((w (nd:make-wallet :priv 66666666666666666696 :bus bus)) (w2 (nd:make-wallet :priv 77777777777777777797 :bus bus))
           (d1 (nd:wallet-open-deposit w id1)) (d2 (nd:wallet-open-deposit w2 id1)))
      (nd:credit-onchain a l1 d1 100000 :txid (u:sha256 (hx "c3")))
      (dolist (m (list b c)) (setf (getf (nd::node-adversary m) :cosign-blind) t))
      (let ((forged (list :type :transfer-lock :transfer-nonce (u:sha256 (hx "c4")) :source-deposit-id d1 :destination-deposit-id d2
                          :amount 90000 :fee 0 :completion-script "sha256(00)" :timeout-height (+ *height* 100)
                          :transfer-id (u:sha256 (hx "c5")) :nonce 818181 :expiry (+ *height* 144) :witness '())))
        (let ((u (nd:append-operation a l1 forged)))
          (dolist (m (list b c)) (setf (getf (nd::node-adversary m) :cosign-blind) nil))
          (check "B and C's cosignatures committed the forged lock on L1"
                 (and u (subsetp (list (nd:node-pubkey b) (nd:node-pubkey c)) (mapcar #'up:cosig-pubkey (up:update-cosignatures u)) :test #'equalp)))
          (check "the honest replica D disputes L1" (nd:find-fork d id1 (nd:node-pubkey d)))
          (check "contagion: D disputes L2, the ledger B operates" (nd:find-fork d id2 (nd:node-pubkey d)))
          (check "contagion: E, with no replica of L1, disputes L2 too" (nd:find-fork e id2 (nd:node-pubkey e)))
          (check "operator contagion: D and E dispute L3, the operator A's other ledger"
                 (every (lambda (m) (nd:find-fork m (nd:record-id-hex *l3*) (nd:node-pubkey m))) (list d e)))
          (check "and L1 itself keeps its own dispute, from before the fault"
                 (= (lg:ledger-sequence (nd:record-ledger (nd:find-fork d id1 (nd:node-pubkey d)))) (1+ (1- (up:update-seq u)))))
          (let* ((prefix (remove u (reverse (nd:record-history l1))))
                 (qb (nd::governing-quorum-begin-seq l1 (up:update-seq u))))
            (check "the proof against B verifies"
                   (fr:verify-non-conforming-cosignature (fr:make-non-conforming-cosignature-proof (nd:node-pubkey b) (u:hex->bytes id2) u qb) prefix))
            (check "the proof against A, its operator, presented on L3, verifies"
                   (fr:verify-non-conforming-cosignature (fr:make-non-conforming-cosignature-proof (nd:node-pubkey a) (u:hex->bytes (nd:record-id-hex *l3*)) u qb) prefix))
            (check "a proof against D, who did not cosign it, does not"
                   (not (fr:verify-non-conforming-cosignature (fr:make-non-conforming-cosignature-proof (nd:node-pubkey d) (u:hex->bytes id2) u qb) prefix)))
            (check "nor one against a conforming update B cosigned"
                   (not (fr:verify-non-conforming-cosignature
                         (fr:make-non-conforming-cosignature-proof (nd:node-pubkey b) (u:hex->bytes id2) (second (nd:record-history l1)) qb)
                         (remove-if (lambda (x) (>= (up:update-seq x) (up:update-seq (second (nd:record-history l1))))) prefix))))))))))



(with-gate ("dereliction: a member that ignores a fraud proof is provably derelict (DEP-19 §6)")
  ;; A operates L1 (B, C, D cosign).  A fraud proof on L1 becomes visible at block V.
  ;; D keeps operating its own ledger well past V + dispute_response_blocks without
  ;; disputing L1 -> derelict.  C disputes L1 promptly -> not derelict.
  (let* ((bus (bus:make-mock-bus))
         (heights (make-hash-table :test #'equalp))        ; block-hash -> height, for height-of-block
         (hob (lambda (h) (gethash h heights)))
         (a (nd:make-node :priv 11111111111111111201 :bus bus :height-fn (lambda () *height*) :height-of-block hob))
         (b (nd:make-node :priv 22222222222222222202 :bus bus :height-fn (lambda () *height*) :height-of-block hob))
         (c (nd:make-node :priv 33333333333333333303 :bus bus :height-fn (lambda () *height*) :height-of-block hob))
         (d (nd:make-node :priv 44444444444444444404 :bus bus :height-fn (lambda () *height*) :height-of-block hob))
         (la (nd:open-ledger a :reserves-id "genesis:dl1" :reserves 15600000 :collateral 15600000))
         (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m))))
    (dolist (m (list b c d)) (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "d100")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 15600000)
    ;; the fraud became visible at block V
    (let* ((v-hash (u:sha256 (hx "deadbeef"))) (v-height 1000) (required 144)
           (fraud-hash (u:sha256 (hx "f00f"))))
      (setf (gethash v-hash heights) v-height)
      ;; D operates its own ledger up to block V + 200 (past the window) without disputing L1
      (let* ((dl (nd:own-ledger d)))
        (let ((*height* (+ v-height 200)))
          (nd:credit-onchain d dl (nd:wallet-open-deposit (nd:make-wallet :priv 55555555555555555505 :bus bus) (nd:record-id-hex dl)) 1000 :txid (u:sha256 (hx "dd"))))
        (nd::follow-ledger b (nd:record-id-hex dl))              ; b picks up d's own ledger from the bus
        (let* ((dmrec (nd:find-record b (nd:record-id-hex dl)))
               (newest (first (nd::record-history dmrec))))
          (check "b replicates d's own ledger, advanced past the window"
                 (and dmrec (>= (- (up:update-block-height newest) v-height) required)))
          (let ((proof (fr:make-dispute-dereliction-proof (nd:node-pubkey d) (u:hex->bytes (nd:record-id-hex dl))
                                                          fraud-hash v-hash required newest)))
            (check "a dereliction proof against d verifies"
                   (fr:verify-dispute-dereliction proof (reverse (nd::record-history dmrec)) hob))
            (check "its proof hash round-trips through JSON"
                   (equalp (fr:proof-hash (fr:json->proof (fr:proof->json proof))) (fr:proof-hash proof)))
            ;; a member still inside the window is not derelict
            (let ((early (fr:make-dispute-dereliction-proof (nd:node-pubkey d) (u:hex->bytes (nd:record-id-hex dl))
                                                            fraud-hash (progn (setf (gethash (u:sha256 (hx "bb")) heights) (+ v-height 100)) (u:sha256 (hx "bb")))
                                                            required newest)))
              (check "not derelict while inside the response window"
                     (not (fr:verify-dispute-dereliction early (reverse (nd::record-history dmrec)) hob))))
            ;; wrong signer: a proof naming c against d's update does not verify
            (check "the member-active update must be signed by the accused"
                   (not (fr:verify-dispute-dereliction
                         (fr:make-dispute-dereliction-proof (nd:node-pubkey c) (u:hex->bytes (nd:record-id-hex dl)) fraud-hash v-hash required newest)
                         (reverse (nd::record-history dmrec)) hob))))
          ;; producer: b scans and reports d (who never disputed L1)
          (let ((before (length (bus:bus-fetch bus (cl-nostr.filter:make-filter :kinds (list w:+kind-fraud-proof+))))))
            (nd::report-derelict-members b (nd:find-record b id) fraud-hash v-hash)
            (check "b broadcast a dereliction proof naming d"
                   (> (length (bus:bus-fetch bus (cl-nostr.filter:make-filter :kinds (list w:+kind-fraud-proof+)))) before))))))))



(with-gate ("dereliction: self-detect arms the watch, drive-dereliction produces the proof")
  (let* ((bus (bus:make-mock-bus))
         (heights (make-hash-table :test #'equalp))
         (bhf (lambda (h) (let ((hash (u:sha256 (u:int->be h 4)))) (setf (gethash hash heights) h) hash)))
         (hob (lambda (hash) (gethash hash heights)))
         (a (nd:make-node :priv 11111111111111111211 :bus bus :height-fn (lambda () *height*) :height-of-block hob :block-hash-fn bhf))
         (b (nd:make-node :priv 22222222222222222212 :bus bus :height-fn (lambda () *height*) :height-of-block hob :block-hash-fn bhf))
         (c (nd:make-node :priv 33333333333333333313 :bus bus :height-fn (lambda () *height*) :height-of-block hob :block-hash-fn bhf))
         (d (nd:make-node :priv 44444444444444444414 :bus bus :height-fn (lambda () *height*) :height-of-block hob :block-hash-fn bhf))
         (la (nd:open-ledger a :reserves-id "genesis:dw1" :reserves 15600000 :collateral 15600000))
         (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m))))
    (dolist (m (list b c d)) (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m) :dispute-response-blocks 5))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "d001")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 15600000)
    (let* ((w (nd:make-wallet :priv 55555555555555555515 :bus bus)) (dep (nd:wallet-open-deposit w id)))
      (nd:credit-onchain a la dep 100000 :txid (u:sha256 (hx "d002")))
      ;; d keeps operating its own ledger well past the window; b replicates it
      (let ((dl (nd:own-ledger d)))
        (let ((*height* (+ *height* 200)))
          (nd:credit-onchain d dl (nd:wallet-open-deposit (nd:make-wallet :priv 66666666666666666616 :bus bus) (nd:record-id-hex dl)) 1000 :txid (u:sha256 (hx "d003"))))
        (nd::follow-ledger b (nd:record-id-hex dl))
        (setf (getf (nd::node-adversary d) :ignore-fraud) t)   ; d ignores the fraud -> derelict
        ;; b self-detects a forged witness-less lock from a (chains onto b's tip at next seq)
        (let* ((rec (nd:find-record b id)) (ledger (nd:record-ledger rec))
               (forged (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id)
                                                       :seq (1+ (lg:ledger-sequence ledger)) :prev-hash (lg:ledger-chain-tip ledger) :block-height *height*
                                                       :message (op:encode-operation (list :type :transfer-lock :transfer-nonce (u:sha256 (hx "d004"))
                                                                                           :source-deposit-id dep :destination-deposit-id dep :amount 10000 :fee 0
                                                                                           :completion-script "sha256(00)" :timeout-height (+ *height* 100)
                                                                                           :transfer-id (u:sha256 (hx "d005")) :nonce 7777 :expiry (+ *height* 144) :witness '())))))
                         (up:sign-operator u (nd::node-priv a)) u)))
          (check "b has no derelict-watch before the fault" (null (nd::node-derelict-watch-keys b)))
          (nd::report-non-conforming b rec forged "test: witness-less lock")
          (check "b disputed la and armed a derelict-watch" (and (nd:find-fork b id (nd:node-pubkey b)) (nd::node-derelict-watch-keys b)))
          ;; d never disputed la (it ignored the fraud); drive-dereliction reports it
          (let ((before (length (bus:bus-fetch bus (cl-nostr.filter:make-filter :kinds (list w:+kind-fraud-proof+))))))
            (nd::drive-dereliction b)
            (let* ((after (bus:bus-fetch bus (cl-nostr.filter:make-filter :kinds (list w:+kind-fraud-proof+))))
                   (new (subseq after before))
                   (der (remove-if-not (lambda (e) (eq :dispute-dereliction (getf (fr:json->broadcast (w:parse-json (cl-nostr.event:event-content e))) :type))) new)))
              (check "drive-dereliction broadcast a DisputeDereliction naming d"
                     (some (lambda (e) (string= (getf (fr:json->broadcast (w:parse-json (cl-nostr.event:event-content e))) :accused) (nd:node-pubkey-hex d))) der))
              (check "a second pass does not re-report (dedup)"
                     (progn (nd::drive-dereliction b)
                            (= (length (bus:bus-fetch bus (cl-nostr.filter:make-filter :kinds (list w:+kind-fraud-proof+)))) (length after)))))))))))


;; Shape of a reference operator's auto_rotation: a 1-in/1-out spend of the current
;; vault at a tier into the next quorum's reserves.  A cl member rebuilds both ends.
(with-gate ("rotation_sign: a cl member signs a reference-shaped vault rotation, and only that")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (a (nd:make-node :priv 11111111111111111111 :bus bus :height-fn hf))
         (b (nd:make-node :priv 22222222222222222222 :bus bus :height-fn hf))
         (c (nd:make-node :priv 33333333333333333333 :bus bus :height-fn hf))
         (d (nd:make-node :priv 44444444444444444444 :bus bus :height-fn hf))
         (la (nd:open-ledger a :reserves-id "genesis:a10" :reserves 15600000 :collateral 23400000)) (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m)))
      (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00e1")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    (let ((rb (nd:find-record b id)) (hash (u:sha256 (hx "a5"))) (expiry (+ *height* 4320)))
      (multiple-value-bind (cur txid vout sats operator) (nd::disputed-reserves b rb)
        (let* ((next (rs:build-reserves :operator operator :members (rs:reserves-members cur) :ledger-hash hash
                                        :quorum-expiry expiry :network :signet))
               (prevouts (vector (cons sats (rs:reserves-spk cur)))))
          (flet ((tx (&key (spk (rs:reserves-spk next)) (prev txid) (locktime 0) (feerate 2) extras)
                   (rot:build-rotation :vault-txid prev :vault-vout vout :vault-sats sats :voters (length (rs:reserves-voters cur))
                                       :feerate feerate :locktime locktime :new-vault-spk spk :extras extras))
                 (refused (tx) (handler-case (progn (nd::check-rotation b rb tx 0 hash expiry) nil) (error () t))))
            (check-equal "the rotation's tier-0 sighash is what the member signs"
                         (nd::check-rotation b rb (tx) 0 hash expiry)
                         (rot:tier-sighash (tx) 0 prevouts (first (rs:reserves-leaves cur))))
            (check "a different destination is refused" (refused (tx :spk (rs:reserves-spk cur))))
            (check "a different input is refused" (refused (tx :prev (u:sha256 (hx "beef")))))
            (check "a lock_time not the tier's is refused" (refused (tx :locktime 99)))
            (check "a fee other than DEP-03's is refused" (refused (tx :feerate 5)))
            (check "an output the replica records no exit for is refused"
                   (refused (tx :extras (list (cons (rs:reserves-spk cur) 1000)))))
            (check "a claimed expiry the output was not built for is refused"
                   (handler-case (progn (nd::check-rotation b rb (tx) 0 hash (1+ expiry)) nil) (error () t)))))))))

(with-gate ("arming waits for its pledge's height: a stale cached height never excludes the armer")
  ;; regtest smoke flake: each pledge mined, then armed at once with a cached height one
  ;; block behind, so every arm named a height before its own pledge and the cut dropped all.
  (let* ((h 100) (pledge (list (u:sha256 (hx "a1")) 0 1000000))
         (node (nd:make-node :priv 66666666666666666666 :bus (bus:make-mock-bus) :height-fn (lambda () h)
                             :pledge-fn (lambda (txid vout from) (declare (ignore txid vout from))
                                          (list :created 101 :value-sats 1000000 :spend :unspent))))
         (nd::*pledge-height-wait-seconds* 1))
    (check "with the node's height behind the pledge, arming refuses"
           (handler-case (progn (nd::await-pledge-height node pledge) nil) (error () t)))
    (setf h 101)
    (check "once the height reaches the pledge's block, arming proceeds"
           (handler-case (progn (nd::await-pledge-height node pledge) t) (error () nil)))
    (check "and the cut includes the armer at that snapshot"
           (null (nd::pledge-failure (nd:node-pledge-fn node) pledge 101 1000 101)))))

(report)
