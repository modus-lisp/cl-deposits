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
        (check "equivocation proof verifies" (fr:verify-equivocation proof))
        (check "a same-content pair is not an equivocation" (not (fr:verify-equivocation (fr:make-equivocation-proof (nd:node-pubkey a) (u:hex->bytes id) u1 u1))))
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
        ;; --- Broadcast the proof: every member verifies it and forks.
        (nd:broadcast-fraud b proof)
        (check "all three members opened dispute forks"
               (every (lambda (m) (nd:find-fork m id (nd:node-pubkey m))) (list b c d)))
        (check "members replicate each other's forks"
               (every (lambda (m) (= 3 (length (nd:forks-of m id)))) (list b c d)))
        (check-equal "fork state is disputed" (lg:ledger-dispute-state (nd:record-ledger (nd:find-fork b id (nd:node-pubkey b)))) :disputed)
        ;; --- Arm.
        (dolist (m (list b c d)) (nd:arm-dispute m (nd:find-fork m id (nd:node-pubkey m))))
        (check-equal "three armers visible to everyone" (mapcar (lambda (m) (length (nd:armers-of m id))) (list b c d)) '(3 3 3))
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
          ;; --- Reveal.
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
                     (every (lambda (m) (let ((f (nd:find-fork m id (nd:node-pubkey winner)))) (and f (equalp (lg:ledger-operator-key (nd:record-ledger f)) (nd:node-pubkey winner))))) (list b c d))))))))))



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
      (let* ((params (w:json-object "operation" "AAAA"))   ; content of the ignored request (any signed request)
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
            (check "not censorship if the operator answered"
                   (not (fr:verify-censorship (w:json params) embed (reverse (nd:record-history lb)) (reverse (nd:record-history la))
                                              :processed-p (lambda (o) (eq (op:operation-type o) :onchain-credit))))))))
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

(report)
