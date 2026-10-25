;;;; inspect/gen-confiscation-ladder.lisp — writes inspect/vectors/confiscation_ladder.json, the
;;;; DEP-03 §Confiscation ladder vector shared with deposits-rust.  Run after loading harness.lisp:
;;;;   sbcl --load inspect/harness.lisp --load inspect/gen-confiscation-ladder.lisp

(in-package #:cl-deposits.test)

(defun ladder-vector-case (name &key (vault-sats 50000000) swept (voters 8) (locktime 0) respectful
                                     (obligations 0) (residue 0) splice-outs (feerate 2) (collateral-msats 20000000000))
  (let* ((lottery-spk (u:hex->bytes "51200819b81e404befa68fbb532b15f54908f86bdaf83eae73704eed16ccd2ccc1f3"))
         (operator (up:compressed-pubkey (tk 9)))
         (anchor (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xe5))
         (vault (list (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11) 1 vault-sats))
         (rungs (lot:confiscation-ladder :vault vault :swept swept :lottery-spk lottery-spk :voters voters :locktime locktime
                                         :respectful respectful :obligations-sats obligations :residue-sats residue
                                         :splice-outs splice-outs :operator-pubkey33 operator :anchor anchor
                                         :feerate feerate :collateral-msats collateral-msats))
         (inputs (+ vault-sats (reduce #'+ swept :key #'third))))
    (values
     (list :name name :params
           (list :vault (list :txid (u:bytes->hex (first vault)) :vout 1 :sats vault-sats)
                 :swept (loop for (tx vo sats) in swept collect (list :txid (u:bytes->hex tx) :vout vo :sats sats))
                 :voters voters :lock-time locktime :respectful respectful :obligations-sats obligations
                 :residue-sats residue
                 :splice-outs (loop for (spk . sats) in splice-outs collect (list :spk (u:bytes->hex spk) :sats sats))
                 :operator (u:bytes->hex operator) :lottery-spk (u:bytes->hex lottery-spk) :anchor (u:bytes->hex anchor)
                 :feerate feerate :collateral-msats collateral-msats)
           :rungs (mapcar (lambda (r) (u:bytes->hex (btx:serialize-tx r :witness nil))) rungs)
           :fees (mapcar (lambda (r) (- inputs (reduce #'+ (btx:tx-outputs r) :key #'btx:txout-value))) rungs))
     rungs)))

(defun plist->json (x)
  "Plists become objects (keys in snake_case), lists arrays, T/NIL true/false where a key says so."
  (cond ((and (consp x) (keywordp (first x)))
         (let ((h (make-hash-table :test #'equal)))
           (loop for (k v) on x by #'cddr
                 do (setf (gethash (substitute #\_ #\- (string-downcase (symbol-name k))) h)
                          (cond ((member k '(:respectful :subset :accept)) (and v t))
                                (t (plist->json v)))))
           h))
        ((consp x) (coerce (mapcar #'plist->json x) 'vector))
        ((null x) #())
        (t x)))

(let* ((p2tr (lambda (b) (u:hex->bytes (format nil "5120~64,'0x" b))))
       (cases '()) (decoys '()) (claim nil))
  (flet ((add (name &rest args)
           (multiple-value-bind (c rungs) (apply #'ladder-vector-case name args)
             (push c cases) rungs)))
    (let* ((punitive (add "punitive"))
           (respectful (add "respectful" :respectful t :locktime 1234 :obligations 10000000))
           (obligations (add "obligations" :feerate 5
                                           :swept (list (list (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22) 1 300000))
                                           :splice-outs (list (cons (funcall p2tr #xaa) 120000) (cons (funcall p2tr #xbb) 50000))
                                           :residue 7000))
           (cut (add "collateral-cut" :collateral-msats 2000000))
           (change-floor (add "respectful-change-floor" :respectful t :vault-sats 10002100 :obligations 10000000))
           (collapsed (add "respectful-collapsed-reference-feerate" :respectful t :vault-sats 10000500 :obligations 10000000 :feerate 7)))
      (declare (ignore respectful collapsed))
      ;; Decoys: transactions no ladder of these cases contains.
      (flet ((decoy (case why tx) (push (list :case case :why why :tx (u:bytes->hex (btx:serialize-tx tx :witness nil))) decoys)))
        (let ((base (list :vault (list (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11) 1 50000000)
                          :lottery-spk (u:hex->bytes "51200819b81e404befa68fbb532b15f54908f86bdaf83eae73704eed16ccd2ccc1f3")
                          :voters 8 :locktime 0 :operator-pubkey33 (up:compressed-pubkey (tk 9))
                          :anchor (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xe5))))
          (decoy "punitive" "three times rung 0's fee (between rungs 1 and 2)" (apply #'lot:confiscation-tx :fee (* 3 806) base))
          (decoy "punitive" "rung 4, past k" (apply #'lot:confiscation-tx :fee (* 16 806) base))
          (decoy "punitive" "rung 1 with another anchor"
                 (apply #'lot:confiscation-tx :fee (* 2 806)
                        :anchor (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xe6)
                        (loop for (k v) on base by #'cddr unless (eq k :anchor) append (list k v))))
          (decoy "collateral-cut" "rung 2, beyond the collateral cap" (apply #'lot:confiscation-tx :fee (* 4 806) base))
          (decoy "respectful-change-floor" "rung 2 collapsed to the punitive shape"
                 (lot:confiscation-tx :vault (list (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11) 1 10002100)
                                      :lottery-spk (getf base :lottery-spk) :voters 8 :locktime 0 :respectful t
                                      :obligations-sats 10000000 :operator-pubkey33 (getf base :operator-pubkey33)
                                      :anchor (getf base :anchor) :fee (* 4 806)))))
      (assert (= 4 (length punitive))) (assert (= 2 (length cut))) (assert (= 2 (length change-floor)))
      ;; The claim of a higher rung: it spends that rung's output 0 at that rung's value.
      (let* ((r2 (third obligations))
             (collateral (list (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x33) 0 2000000))
             (dest (funcall p2tr #xcc))
             (tx (lot:claim-tx (btx:tx-txid r2) 0 (btx:txout-value (first (btx:tx-outputs r2))) collateral dest :subset t)))
        (setf claim (list :case "obligations" :rung 2 :collateral (list :txid (u:bytes->hex (first collateral)) :vout 0 :sats 2000000)
                          :destination-spk (u:bytes->hex dest) :fee lot:+claim-fee-floor+ :subset t
                          :tx (u:bytes->hex (btx:serialize-tx tx :witness nil)))))))
  (with-open-file (o "inspect/vectors/confiscation_ladder.json" :direction :output :if-exists :supersede)
    (write-string (json-simple:stringify
                   (plist->json (list :description "DEP-03 §Confiscation ladder: every rung of each case (unsigned, legacy serialization; txids in internal byte order), the decoys no ladder contains, and the claim of a higher rung. Generated by cl-deposits inspect/gen-confiscation-ladder.lisp."
                                      :cases (reverse cases) :decoys (reverse decoys) :claim claim))
                   :pretty t)
                  o))
  (format t "~&wrote inspect/vectors/confiscation_ladder.json~%"))
