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
  (let ((n (nd:make-node :priv (tk priv) :bus bus :height-fn hf :data-dir (dir-for priv))))
    (nd:load-data-dir n)
    n))

(defun restart-all (nodes privs bus hf)
  "Stop NODES and boot fresh ones from the same keys and data dirs.  (The node
   normalizes its key to even-Y, so the original PRIVS name the dirs.)"
  (mapcar (lambda (n priv) (nd:stop-node n) (boot priv bus hf)) nodes privs))

(with-gate ("restart: a ledger of one update (its file is one line, [\"...\"]) reloads")
  ;; The startup scan read the first line for the owner and trimmed "[", quote and "," but not
  ;; "]": a ledger holding only its LedgerOpen failed to load ("bad base64 char"), and a fresh
  ;; member lost its own ledger at its first restart (regtest, 2026-10-24).
  (let* ((bus (bus:make-mock-bus)) (hf (lambda () *height*)) (p 77777777777777777777)
         (n (boot p bus hf))
         (id (nd:record-id-hex (nd:open-ledger n :reserves-id "genesis:one-update"))))
    (let ((n2 (progn (nd:stop-node n) (boot p bus hf))))
      (check "the one-update ledger reloads, owned" (let ((r (nd:find-record n2 id))) (and r (nd:record-owned-p r))))
      (nd:stop-node n2))))

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
        (let* ((w1 (nd:make-wallet :priv (tk 55555555555555555555) :bus bus)) (w2 (nd:make-wallet :priv (tk 66666666666666666666) :bus bus))
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
                (dolist (m (list b c d)) (nd:arm-dispute m (nd:find-fork m id (nd:node-pubkey m)) :replacement (list (u:sha256 (nd:node-pubkey m)) 0 10000000)))
                (check-equal "three armers before the restart" (mapcar (lambda (m) (length (nd:armers-of m id))) (list b c d)) '(3 3 3))
                (nd:stop-node a)                          ; the operator is gone for good
                (destructuring-bind (b c d) (restart-all (list b c d) (list pb pc pd) bus hf)
                  (check "forks reloaded, own fork owned" (every (lambda (m) (let ((f (nd:find-fork m id (nd:node-pubkey m)))) (and f (nd:record-owned-p f)))) (list b c d)))
                  (check-equal "every fork replicated after the restart" (mapcar (lambda (m) (length (nd:forks-of m id))) (list b c d)) '(3 3 3))
                  (check "preimages re-derived from the node key"
                         (every (lambda (m) (nd:record-preimage (nd:find-fork m id (nd:node-pubkey m)))) (list b c d)))
                  ;; DEP-06: fresh per dispute and per round.  The recovered preimage is the
                  ;; fork-bound one, not the ledger-only v1 seed every dispute of a ledger reused.
                  (check "the recovered preimage is the fork-bound seed's, and opens the arm's commitment"
                         (every (lambda (m) (let* ((f (nd:find-fork m id (nd:node-pubkey m)))
                                                   (armed (op:update-op (nd::fork-op f :dispute-armed))))
                                              (and (equalp (nd:record-preimage f) (lot:derive-preimage (nd:lottery-seed m f 1)))
                                                   (equalp (lot:commitment-of (nd:record-preimage f)) (op:field armed :commitment-hash))
                                                   (not (equalp (nd:record-preimage f) (lot:derive-preimage (nd::lottery-seed-v1 m id 1)))))))
                                (list b c d)))
                  (let* ((f (nd:find-fork b id (nd:node-pubkey b))) (priv (nd::node-priv b)))
                    (multiple-value-bind (lvs point) (nd::fork-identity f)
                      (let ((seed (nd::fork-lottery-seed priv id lvs point 1)))
                        (check-equal "the seed is the fork's: its DisputeEnter's last_valid_sequence"
                                     lvs (op:field (op:update-op (nd::fork-op f :dispute-enter)) :last-valid-sequence))
                        (check "a dispute of the same ledger at another fork point draws a fresh seed"
                               (not (equalp seed (nd::fork-lottery-seed priv id (1+ lvs) point 1))))
                        (check "a different fork at the same sequence (another chain) draws a fresh seed"
                               (not (equalp seed (nd::fork-lottery-seed priv id lvs (u:sha256 point) 1))))
                        (check "a re-arm round draws a fresh seed"
                               (not (equalp seed (nd::fork-lottery-seed priv id lvs point 2)))))))
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
                        (let* ((armed-files      ; each fork file as it stands at its arm, before the lottery
                                 (mapcar (lambda (m priv)
                                           (let ((p (merge-pathnames (nd::record-file-name (nd:find-fork m id (nd:node-pubkey m))) (dir-for priv))))
                                             (cons p (uiop:read-file-string p :external-format :latin-1))))
                                         (list b c d) (list pb pc pd)))
                               (outcomes (mapcar (lambda (m) (handler-case (multiple-value-list (nd:claim-or-yield m id))
                                                              (error (e) (list :error e))))
                                                (list b c d))))
                          (check-equal "exactly one winner after the restarts" (count :won outcomes :key #'first) 1)
                          (check-equal "two yields" (count :yielded outcomes :key #'first) 2)
                          (let ((claim (second (find :won outcomes :key #'first))))
                            (check "claim spends the confiscation rebuilt from public state"
                                   (and claim (equalp (btx:txin-prev-hash (first (btx:tx-inputs claim))) (btx:tx-txid ctx)))))
                          (check "everyone replicates the winner's DisputeAcquire"
                                 (let ((winner (nth (position :won outcomes :key #'first) (list b c d))))
                                   (every (lambda (m) (let ((f (nd:find-fork m id (nd:node-pubkey winner)))) (and f (equalp (lg:ledger-operator-key (nd:record-ledger f)) (nd:node-pubkey winner))))) (list b c d))))
                          ;; ref6's disk (regtest 1120-next4): a loser whose yield is on the relay
                          ;; while its own fork file still ends at its arm (here: killed between the
                          ;; publish and the save).  Booting again and rerunning the lottery must not
                          ;; sign a second, different yield at that sequence: it adopts the published
                          ;; one or signs nothing.
                          (let* ((li (position :yielded outcomes :key #'first))
                                 (l (nth li (list b c d))) (lpriv (nth li (list pb pc pd)))
                                 (lpk (nd:node-pubkey l))
                                 (y (first (nd:record-history (nd:find-fork l id lpk))))
                                 (ours-at (lambda ()
                                            (remove-duplicates
                                             (loop for e in (bus:mock-bus-events bus)
                                                   when (= (cl-nostr.event:event-kind e) w:+kind-update+)
                                                     do (setf e (ignore-errors (w:event->update e)))
                                                     and when (and e (equalp (up:update-operator-id e) lpk)
                                                                   (equalp (up:update-ledger-id e) (u:hex->bytes id))
                                                                   (= (up:update-seq e) (up:update-seq y)))
                                                           collect (up:encode-update e))
                                             :test #'equalp))))
                            (check-equal "the loser's yield is its fork's tip, and on the relay"
                                         (list (getf (op:update-op y) :type) (length (funcall ours-at))) '(:dispute-yield 1))
                            (nd:stop-node l)
                            (incf *height* 7)    ; it comes back later: a yield signed now would carry another header
                            (destructuring-bind (p . text) (nth li armed-files)
                              (with-open-file (out p :direction :output :if-exists :supersede :external-format :latin-1)
                                (write-string text out)))
                            (let* ((l2 (boot lpriv bus hf)) (f (nd:find-fork l2 id lpk))
                                   (booted (and f (getf (op:update-op (first (nd:record-history f))) :type))))
                              (check "booted with its fork at the arm on disk (ref6's shape)"
                                     (member booted '(:dispute-armed :dispute-yield)))
                              (let ((again (handler-case (multiple-value-list (nd:claim-or-yield l2 id)) (error (e) (list :error e)))))
                                (format t "      booted tip ~s; rerun: ~s~%" booted (first again)))
                              (check-equal "no second update of ours at the yield's sequence" (length (funcall ours-at)) 1)
                              (let ((tip (first (nd:record-history (nd:find-fork l2 id lpk)))))
                                (check "the fork ends at the published yield, byte for byte"
                                       (equalp (up:encode-update tip) (up:encode-update y))))
                              ;; The property, over everything on the relay: no two signatures of any
                              ;; member share (ledger, seq) with different content.
                              (let ((seen (make-hash-table :test #'equalp)) (twice 0))
                                (dolist (e (bus:mock-bus-events bus))
                                  (let ((u (and (= (cl-nostr.event:event-kind e) w:+kind-update+) (ignore-errors (w:event->update e)))))
                                    (when (and u (member (up:update-operator-id u) (list (nd:node-pubkey b) (nd:node-pubkey c) (nd:node-pubkey d)) :test #'equalp))
                                      (let* ((k (list (up:update-operator-id u) (up:update-ledger-id u) (up:update-seq u)))
                                             (v (up:encode-update u)) (old (gethash k seen)))
                                        (if (and old (not (equalp old v))) (incf twice) (setf (gethash k seen) v))))))
                                (check-equal "no two of a member's signatures share (ledger, seq) with different content" twice 0))
                              (nd:stop-node l2))))))))))))))))

;;; DEP-03 §When the set is final, after a restart (vector rearm_round_agree.json, late_enter:
;;; 12bc96d2, a DisputeEnter signed at 34763 above the confiscation at 23996).  The block C was
;;; noted only when the confiscation was found, in memory, so a restarted node judged its first
;;; passes with every DisputeEnter counted.  Here the node knows the confiscation only as its txid
;;; (confiscations.txt) and the chain: C must be derived before the first judge, from the lottery
;;; output's confirmations while it is unspent, else the txid's own (once claimed).  The control:
;;; a node that cannot ask the chain counts the late enter, as cld364 did.
(with-gate ("restart: a DisputeEnter above the confiscation takes no part from the first pass (shared vector, 12bc96d2)")
  (let* ((v (json-simple:parse (uiop:read-file-string (vector-path "rearm_round_agree.json"))))
         (c (aref (gethash "late_enter" v) 0))
         (id (gethash "ledger_id" c))
         (chain (gethash "chain" c))
         (txid (reverse (u:hex->bytes (gethash "confiscation_txid" chain))))
         (cheight (gethash "confiscation_height" chain))
         (tip 35000) (confs (1+ (- tip cheight)))
         (final (gethash "final" c)) (control (gethash "control" c))
         (dir (uiop:ensure-directory-pathname (format nil "/tmp/cl-deposits-restart-~a/late-enter/" *run*)))
         (dec (loop for h across (gethash "updates" c) for b = (u:hex->bytes h) collect (cons b (up:decode-update b))))
         (origin (up:update-operator-id (cdr (find 0 dec :key (lambda (x) (up:update-seq (cdr x)))))))
         (by (make-hash-table :test #'equalp)))
    (ensure-directories-exist dir)
    ;; the replica files a node keeps: the base chain, then a file per fork
    (dolist (x dec) (push x (gethash (up:update-operator-id (cdr x)) by)))
    (maphash (lambda (op xs)
               (with-open-file (o (merge-pathnames (if (equalp op origin)
                                                       (format nil "ledger_~a.json" (subseq id 0 16))
                                                       (format nil "ledger_~a_fork_~a.json" (subseq id 0 16) (subseq (u:bytes->hex op) 0 16)))
                                                   dir)
                                  :direction :output :if-exists :supersede)
                 (format o "[~{\"~a\"~^,~%~}]~%" (mapcar (lambda (x) (u:base64-encode (car x))) (sort (copy-list xs) #'< :key (lambda (x) (up:update-seq (cdr x))))))))
             by)
    (unwind-protect
         (flet ((boot (&key chain-fn tx-confs-fn)
                  (let ((n (nd:make-node :priv (tk 4343434343434343) :bus (bus:make-mock-bus) :network "regtest" :data-dir dir
                                         :height-fn (lambda () tip) :chain-fn chain-fn :tx-confs-fn tx-confs-fn)))
                    (nd:load-data-dir n :log-fn (lambda (&rest a) (declare (ignore a))))
                    ;; every carried proof taken as grounded (each verifies on regtest)
                    (dolist (f (nd::forks-of n id))
                      (dolist (u (nd::fork-own-updates f :dispute-enter))
                        (when (op:field (op:update-op u) :fraud-proof)
                          (setf (gethash (up:chain-hash u) (nd::node-grounds-verdicts n)) (cons :grounded "taken as grounded")))))
                    n))
                (judged (n)
                  (list (sort (mapcar (lambda (f) (u:bytes->hex (nd::record-fork-operator f))) (nd::dispute-forks n id)) #'string<)
                        (sort (mapcar #'u:bytes->hex (nd::dispute-accused-keys n id)) #'string<)
                        (sort (mapcar #'u:bytes->hex (nd::lottery-voters n id)) #'string<)))
                (expected (e voters) (list (coerce (gethash "in_dispute" e) 'list) (coerce (gethash "convicted_if_grounded" e) 'list)
                                           (coerce voters 'list))))
           ;; before the restart: the confiscation was seen confirm, and only its txid is on disk
           (let ((a (boot)))
             (nd::note-confiscation a id txid)
             (nd:stop-node a))
           (let ((b (boot :chain-fn (lambda (tx vout) (and (equalp tx txid) (zerop vout) (list :confirmations confs))))))
             (check "restarted: the confiscation is known, by txid" (member txid (gethash id (nd::node-known-confiscations b)) :test #'equalp))
             (check "and no block C is held in memory" (null (gethash id (nd::node-confiscation-heights b))))
             (check-equal "the first judge: disputants, Accused(grounds) and voters are the final set's (C from the lottery output)"
                          (judged b) (expected final (gethash "voters" (gethash "lottery" final))))
             (check-equal "C was derived from the chain" (gethash id (nd::node-confiscation-heights b)) cheight)
             (nd:stop-node b))
           (let ((b (boot :tx-confs-fn (lambda (tx) (and (equalp tx txid) confs)))))
             (check-equal "the lottery output claimed: C from the confiscation's own confirmations, the same first judge"
                          (judged b) (expected final (gethash "voters" (gethash "lottery" final))))
             (nd:stop-node b))
           (let ((b (boot)))
             (check-equal "control: a node that cannot ask the chain counts the late enter"
                          (judged b) (expected control (gethash "lottery_voters" control)))
             (nd:stop-node b)))
      (uiop:delete-directory-tree dir :validate (lambda (p) (search "cl-deposits-restart-" (namestring p))) :if-does-not-exist :ignore))))

(report)
