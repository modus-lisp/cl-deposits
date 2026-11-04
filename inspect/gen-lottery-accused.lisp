;;;; inspect/gen-lottery-accused.lisp — writes inspect/vectors/lottery_accused.txt, the DEP-03
;;;; §Lottery "accused keys never win" vector shared with deposits-rust.  Run after harness.lisp:
;;;;   sbcl --load inspect/harness.lisp --load inspect/gen-lottery-accused.lisp
;;;; SOAK_FORKS names a directory holding the signet soak's ledger_6056fb385fd9bbad_fork_*.json
;;;; files (the Nov 4 invalid-credit run, where colluder cld26 armed and won).

(in-package #:cl-deposits.test)

(defvar *la-soak-armers* nil)
(defvar *la-soak-accused* nil)
(defun la-key-hex (k) (u:bytes->hex k))

(defun la-update (operator-k cosigner-ks &key (seq 7) (ledger (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42)))
  "An update by OPERATOR-K cosigned by COSIGNER-KS; signatures are placeholders (accused keys are
   read from a proof that has already verified)."
  (up:make-signed-update
   :operator-id (up:compressed-pubkey (tk operator-k)) :ledger-id ledger :seq seq
   :prev-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element seq)
   :message (u:hex->bytes "0000") :block-height 100
   :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x77)
   :operator-sig (make-array 64 :element-type '(unsigned-byte 8) :initial-element 1)
   :cosignatures (mapcar (lambda (k) (up:make-cosignature :pubkey (up:compressed-pubkey (tk k))
                                                           :signature (make-array 64 :element-type '(unsigned-byte 8) :initial-element 2)
                                                           :member-ledger-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)))
                         cosigner-ks)))

(defun la-proof-line (proof)
  (w:json (fr:broadcast->json proof)))

(defun la-uvs-tx (keys signed)
  "A spend whose tapscript witness has a leaf over KEYS (x-only, CHECKSIG/CHECKSIGADD) and a
   64-byte signature for each key in SIGNED, an empty item for the rest."
  (let* ((leaf (apply #'u:cat (loop for k in keys for i from 0
                                    collect (u:cat (u:octets 32) k (u:octets (if (zerop i) #xac #xba))))))
         (stack (append (reverse (mapcar (lambda (k) (if (member k signed :test #'equalp)
                                                         (make-array 64 :element-type '(unsigned-byte 8) :initial-element 5)
                                                         (make-array 0 :element-type '(unsigned-byte 8))))
                                         keys))
                        (list leaf (make-array 33 :element-type '(unsigned-byte 8) :initial-element #xc0)))))
    (btx:make-tx :version 2 :locktime 0 :segwit-p t
                 :inputs (list (btx:make-txin :prev-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)
                                              :prev-index 0 :script (u:octets)
                                              :sequence #xfffffffd))
                 :outputs (list (btx:make-txout :value 1000 :script (u:hex->bytes "51200819b81e404befa68fbb532b15f54908f86bdaf83eae73704eed16ccd2ccc1f3")))
                 :witnesses (list stack))))

(let* ((ledger (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42))
       (target (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x43))
       (cases '()))
  (flet ((accused (name proof)
           (push (list :accused name (la-proof-line proof)
                       (sort (mapcar #'la-key-hex (fr:proof-accused-keys proof)) #'string<))
                 cases)))
    ;; Synthetic, one per proof class.
    (accused "non-conforming-update"
             (fr:make-non-conforming-update-proof (up:compressed-pubkey (tk 1)) ledger (la-update 1 '(2 3 4))))
    (accused "non-conforming-cosignature"
             (fr:make-non-conforming-cosignature-proof (up:compressed-pubkey (tk 3)) target (la-update 1 '(2 3)) 5))
    (accused "equivocation-common-signers"
             (fr:make-equivocation-proof (up:compressed-pubkey (tk 1)) ledger (la-update 1 '(2 3 4)) (la-update 1 '(3 4 5))))
    (let* ((keys (mapcar (lambda (k) (up:x-only (up:compressed-pubkey (tk k)))) '(6 7 8)))
           (tx (la-uvs-tx keys (list (first keys) (third keys)))))
      (accused "vault-spend-witness-signers"
               (fr:make-unauthorized-vault-spend-proof (up:compressed-pubkey (tk 6)) target ledger 3 tx
                                                       (list (cons 50000 (u:hex->bytes "5120aa"))) (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))))
    (accused "quorum-expired-accused-only"
             (fr:make-quorum-expired-proof (up:compressed-pubkey (tk 1)) ledger (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8) 1000))
    ;; The soak's real proofs: the 6056fb38 forks (cld26 cosigned the fault and armed).
    (let ((dir (uiop:getenv "SOAK_FORKS")))
      (when dir
        (dolist (f (directory (merge-pathnames "ledger_6056fb385fd9bbad_fork_*.json" (uiop:ensure-directory-pathname dir))))
          (dolist (b (read-json-string-array f))
            (let* ((u (up:decode-update (u:base64-decode b)))
                   (o (ignore-errors (op:decode-operation (up:update-message u)))))
              (when (and o (eq (op:operation-type o) :dispute-enter) (op:field o :fraud-proof))
                (let ((proof (fr:json->broadcast (w:parse-json (op:field o :fraud-proof)))))
                  (setf *la-soak-accused* (append (mapcar #'la-key-hex (fr:proof-accused-keys proof)) *la-soak-accused*))
                  (accused (format nil "soak-6056fb38-~a" (subseq (u:bytes->hex (up:update-operator-id u)) 0 8)) proof)))
              (when (and o (eq (op:operation-type o) :dispute-armed))
                (push (la-key-hex (up:x-only (up:update-operator-id u))) *la-soak-armers*))))))))
  ;; The cut: armers minus accused, keeping order.
  (flet ((cut (name accused armers)
           (push (list :cut name accused armers (remove-if (lambda (a) (member a accused :test #'string=)) armers)) cases)))
    (let ((k (lambda (n) (la-key-hex (up:x-only (up:compressed-pubkey (tk n)))))))
      (cut "one-accused-armer" (list (funcall k 2)) (list (funcall k 2) (funcall k 5) (funcall k 6)))
      (cut "none-accused" '() (list (funcall k 5) (funcall k 6)))
      (cut "all-accused-reopens" (list (funcall k 2) (funcall k 3)) (list (funcall k 2) (funcall k 3)))
      (when *la-soak-armers*
        (cut "soak-6056fb38-cld26"
             (sort (remove-duplicates *la-soak-accused* :test #'string=) #'string<)
             (sort (remove-duplicates *la-soak-armers* :test #'string=) #'string<)))))
  (with-open-file (out (vector-path "lottery_accused.txt") :direction :output :if-exists :supersede)
    (format out "# DEP-03 §Lottery: a key the dispute's own grounds convict never wins.  Shared with~%")
    (format out "# deposits-rust (deposits-protocol/tests/lottery_accused_vector.rs).  Generated by~%")
    (format out "# inspect/gen-lottery-accused.lisp; the soak-* cases are the Nov 4 signet soak's own proofs.~%#~%")
    (format out "# accused <name>   the x-only keys a proof convicts (FraudProof::accused_keys / fr:proof-accused-keys)~%")
    (format out "#   proof <the DEP-06 JSON form of a broadcast, one line>~%#   expect <x-only hex keys, sorted> | expect none~%#   end~%#~%")
    (format out "# cut <name>        armers without the accused, order kept~%")
    (format out "#   accused <keys> | accused none~%#   armers <keys>~%#   expect <keys> | expect none   (none: nobody eligible, the window reopens)~%#   end~%")
    (dolist (c (reverse cases))
      (ecase (first c)
        (:accused (destructuring-bind (name line keys) (rest c)
                    (format out "accused ~a~%proof ~a~%expect ~:[none~;~:*~{~a~^ ~}~]~%end~%" name line keys)))
        (:cut (destructuring-bind (name accused armers kept) (rest c)
                (format out "cut ~a~%accused ~:[none~;~:*~{~a~^ ~}~]~%armers ~{~a~^ ~}~%expect ~:[none~;~:*~{~a~^ ~}~]~%end~%"
                        name accused armers kept))))))
  (format t "~&wrote ~a cases~%" (length cases)))
