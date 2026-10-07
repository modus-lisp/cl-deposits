;;;; redteam/fuzz-proofs.lisp — malformed fraud proofs at a ledger's members.
;;;;   sbcl --non-interactive --load redteam/fuzz-proofs.lisp -- LEDGER-HEX OPERATOR-HEX
;;;;   env: CLD_RELAYS
;;;; Publishes Kind 9101 events under the ledger's tag from a throwaway key: raw
;;;; garbage, then mutations of a well-formed (but unverifiable) equivocation
;;;; proof.  PASS = every node stays up, answers, and disputes nothing.
(require :asdf)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-deposits"))
(let* ((args (cdr (member "--" sb-ext:*posix-argv* :test #'string=)))
       (lid (first args)) (opx (second args))
       (bus (cl-deposits.nostr-bus:make-nostr-bus (uiop:split-string (or (uiop:getenv "CLD_RELAYS") "ws://127.0.0.1:7777") :separator ",")))
       (kp (cl-deposits.wire:nostr-keypair (cl-deposits.util:be->int (cl-deposits.node::random-aux))))
       (hexs (lambda (n) (make-string n :initial-element #\a)))
       (valid (json-simple:stringify
               (cl-deposits.fraud:broadcast->json
                (list :type :equivocation :accused opx :ledger-id lid
                      :evidence (list :sequence 5 :update-a-hex "00" :update-b-hex "00")))))
       (sub (lambda (from to) (let ((i (search from valid))) (if i (concatenate 'string (subseq valid 0 i) to (subseq valid (+ i (length from)))) valid))))
       (cases
         (list (cons "not json" "{{{{ not json")
               (cons "empty object" "{}")
               (cons "json null" "null")
               (cons "proof is a number" "{\"proof\": 7}")
               (cons "unknown proof type" "{\"proof\": {\"proof_type\": \"Nonsense\", \"accused\": \"00\"}}")
               (cons "template" valid)
               (cons "update hex not hex" (funcall sub "\"00\"" "\"zz\""))
               (cons "update hex 1 MB" (funcall sub "\"00\"" (format nil "\"~a\"" (funcall hexs 1000000))))
               (cons "sequence negative" (funcall sub ":5" ":-1"))
               (cons "sequence 2^80" (funcall sub ":5" ":1208925819614629174706176"))
               (cons "sequence a string" (funcall sub ":5" ":\"five\""))
               (cons "ledger id short" (funcall sub lid "abcd"))
               (cons "accused not hex" (funcall sub opx "nothex"))
               (cons "nested 10000 deep" (format nil "{\"proof\": ~a~a}" (make-string 10000 :initial-element #\[) (make-string 10000 :initial-element #\])))
               (cons "causal_chain huge" (funcall sub "\"causal_chain\":[]" (format nil "\"causal_chain\":[~{~a~^,~}]" (loop repeat 50000 collect "{}"))))))
       (*print-pretty* nil))
  (cl-deposits.nostr-bus:wait-for-bus bus)
  (dolist (c cases)
    (let ((e (cl-nostr.event:build-event kp cl-deposits.wire:+kind-fraud-proof+ (cdr c)
                                         :tags (list (list "d" (subseq lid 0 16)) (list "p" (subseq opx 2))))))
      (cl-deposits.bus:bus-publish bus e)
      (format t "~s~%" (list :sent (car c) :bytes (length (cdr c))))
      (sleep 0.5)))
  (sleep 3) (cl-deposits.nostr-bus:close-nostr-bus bus))
