;;;; inspect/restart-test.lisp — a node is a process: it dies mid-flow and comes
;;;; back from its data dir.  Every phase below restarts nodes from disk before
;;;; the next one, and the next one must work exactly as if nothing happened.
(in-package #:cl-deposits.test)
(defvar *height* 1000)

(defvar *dirs* (make-hash-table))
(defvar *run* (random 1000000000 (make-random-state t)))   ; a fresh image's RANDOM repeats: dirs would be reused across runs

(defun dir-for (priv)
  (or (gethash priv *dirs*)
      (setf (gethash priv *dirs*) (format nil "/tmp/cl-deposits-restart-~a/~a/" *run* priv))))

(defun boot (priv bus hf)
  "A fresh node (process) for PRIV, reloading whatever its data dir holds."
  (let ((n (nd:make-node :priv priv :bus bus :height-fn hf :data-dir (dir-for priv))))
    (nd:load-data-dir n)
    n))

(defun restart-all (nodes privs bus hf)
  "Stop NODES and boot fresh ones from the same keys and data dirs.  (The node
   normalizes its key to even-Y, so the original PRIVS name the dirs.)"
  (mapcar (lambda (n priv) (nd:stop-node n) (boot priv bus hf)) nodes privs))

(with-gate ("restart: quorum, deposits, transfer, and a dispute across node restarts")
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*))
         (pa 11111111111111111111) (pb 22222222222222222222) (pc 33333333333333333333) (pd 44444444444444444444)
         (a (boot pa bus hf)) (b (boot pb bus hf)) (c (boot pc bus hf)) (d (boot pd bus hf))
         (la (nd:open-ledger a :reserves-id "genesis:restart" :reserves 15600000 :collateral 23400000))
         (id (nd:record-id-hex la)))
    (dolist (m (list b c d)) (nd:open-ledger m :reserves-id (format nil "genesis:~a" (nd:node-pubkey-hex m))))
    (dolist (m (list b c d)) (nd:add-member a la (nd:node-pubkey m) :member-ledger-id (nd::node-member-ledger-hex m)))
    (nd:begin-quorum a la :funding-txid (u:sha256 (hx "f00d5")) :funding-vout 0 :amount-msats 15600000 :collateral-msats 23400000)
    ;; --- Phase 1: everyone restarts right after QuorumBegin.
    (destructuring-bind (a b c d) (restart-all (list a b c d) (list pa pb pc pd) bus hf)
      (let ((la (nd:find-record a id)))
        (check "operator reloaded its ledger as owned" (and la (nd:record-owned-p la)))
        (check-equal "operator's member-ledger pointer restored" (nd::node-member-ledger-hex a) id)
        (check "members reloaded their own ledger pointer"
               (every (lambda (m) (and (nd::node-member-ledger-hex m) (nd:record-owned-p (nd:own-ledger m)))) (list b c d)))
        (check "members hold A as a replica at the same tip"
               (every (lambda (m) (equalp (lg:ledger-chain-tip (nd:record-ledger (nd:find-record m id))) (lg:ledger-chain-tip (nd:record-ledger la)))) (list b c d)))
        (let* ((w1 (nd:make-wallet :priv 55555555555555555555 :bus bus)) (w2 (nd:make-wallet :priv 66666666666666666666 :bus bus))
               (d1 (nd:wallet-open-deposit w1 id)) (d2 (nd:wallet-open-deposit w2 id)))
          (check "credit after restart needs cosignatures and gets them"
                 (nd:credit-onchain a la d1 100000 :txid (u:sha256 (hx "c0ffee5"))))
          ;; --- Phase 2: restart again, then a wallet transfer (lock + complete, both cosigned).
          (destructuring-bind (a b c d) (restart-all (list a b c d) (list pa pb pc pd) bus hf)
            (let ((la (nd:find-record a id)))
              (check-equal "d1 balance survives the restart" (nd:wallet-balance w1 id d1) 100000)
              (multiple-value-bind (tid pre) (nd:wallet-transfer w1 id d1 d2 40000 :height *height*)
                (check "transfer locked after restart" tid)
                (check-equal "balance and locked part" (multiple-value-list (nd:wallet-balance w1 id d1)) '(100000 40000))
                ;; Everyone restarts with the transfer in flight; the wallet then completes it.
                (destructuring-bind (a2 b2 c2 d2n) (restart-all (list a b c d) (list pa pb pc pd) bus hf)
                  (setf a a2 b b2 c c2 d d2n la (nd:find-record a id)))
                (check "transfer completed after a mid-transfer restart" (nd:wallet-complete-transfer w1 id tid pre))
                (check-equal "balances after the transfer" (list (nd:wallet-balance w1 id d1) (nd:wallet-balance w2 id d2)) '(60000 40000)))
              (check "members' replicas at A's tip"
                     (every (lambda (m) (equalp (lg:ledger-chain-tip (nd:record-ledger (nd:find-record m id))) (lg:ledger-chain-tip (nd:record-ledger la)))) (list b c d)))
              ;; --- Phase 3: the operator equivocates; members dispute and arm; then the disputants restart.
              (let* ((seq (1+ (lg:ledger-sequence (nd:record-ledger la))))
                     (mk (lambda (amount)
                           (let ((u (up:make-signed-update :operator-id (nd:node-pubkey a) :ledger-id (u:hex->bytes id) :seq seq
                                                           :prev-hash (lg:ledger-chain-tip (nd:record-ledger la))
                                                           :message (op:encode-operation (list :type :onchain-credit :txid (u:sha256 (hx "ee")) :vout 0
                                                                                               :deposit-id d1 :amount amount :funding-address "x")))))
                             (up:sign-operator u (nd::node-priv a)) u)))
                     (proof (fr:make-equivocation-proof (nd:node-pubkey a) (u:hex->bytes id) (funcall mk 1) (funcall mk 2))))
                (nd:broadcast-fraud b proof)
                (dolist (m (list b c d)) (nd:arm-dispute m (nd:find-fork m id (nd:node-pubkey m))))
                (check-equal "three armers before the restart" (mapcar (lambda (m) (length (nd:armers-of m id))) (list b c d)) '(3 3 3))
                (nd:stop-node a)                          ; the operator is gone for good
                (destructuring-bind (b c d) (restart-all (list b c d) (list pb pc pd) bus hf)
                  (check "forks reloaded, own fork owned" (every (lambda (m) (let ((f (nd:find-fork m id (nd:node-pubkey m)))) (and f (nd:record-owned-p f)))) (list b c d)))
                  (check-equal "every fork replicated after the restart" (mapcar (lambda (m) (length (nd:forks-of m id))) (list b c d)) '(3 3 3))
                  (check "preimages re-derived from the node key"
                         (every (lambda (m) (nd:record-preimage (nd:find-fork m id (nd:node-pubkey m)))) (list b c d)))
                  (check-equal "armers visible after the restart" (mapcar (lambda (m) (length (nd:armers-of m id))) (list b c d)) '(3 3 3))
                  ;; --- Confiscation, then restart before revealing.
                  (multiple-value-bind (ctx lottery)
                      (handler-case (nd:confiscate b id)
                        (error (e) (format t "      confiscate failed: ~a~%" e) (dolist (m (list b c d)) (format t "      log: ~{~a~^ | ~}~%" (reverse (nd:node-log m)))) (error e)))
                    (check "confiscation built and signed by restarted members" (and ctx lottery t))
                    (destructuring-bind (b c d) (restart-all (list b c d) (list pb pc pd) bus hf)
                      (check "lottery and confiscation forgotten by the restart" (every (lambda (m) (null (nd:record-lottery (nd:find-fork m id (nd:node-pubkey m))))) (list b c d)))
                      (dolist (m (list b c d)) (nd:publish-reveal m id))
                      (check-equal "every member holds all three reveals" (mapcar (lambda (m) (length (nd:reveals-of m id))) (list b c d)) '(3 3 3))
                      ;; --- Restart once more: reveals must come back from disk, the lottery from public state.
                      (destructuring-bind (b c d) (restart-all (list b c d) (list pb pc pd) bus hf)
                        (check-equal "reveals reloaded from disk" (mapcar (lambda (m) (length (nd:reveals-of m id))) (list b c d)) '(3 3 3))
                        (let ((outcomes (mapcar (lambda (m) (handler-case (multiple-value-list (nd:claim-or-yield m id))
                                                              (error (e) (list :error e))))
                                                (list b c d))))
                          (check-equal "exactly one winner after the restarts" (count :won outcomes :key #'first) 1)
                          (check-equal "two yields" (count :yielded outcomes :key #'first) 2)
                          (let ((claim (second (find :won outcomes :key #'first))))
                            (check "claim spends the confiscation rebuilt from public state"
                                   (and claim (equalp (btx:txin-prev-hash (first (btx:tx-inputs claim))) (btx:tx-txid ctx)))))
                          (check "everyone replicates the winner's DisputeAcquire"
                                 (let ((winner (nth (position :won outcomes :key #'first) (list b c d))))
                                   (every (lambda (m) (let ((f (nd:find-fork m id (nd:node-pubkey winner)))) (and f (equalp (lg:ledger-operator-key (nd:record-ledger f)) (nd:node-pubkey winner))))) (list b c d)))))))))))))))))

(report)
