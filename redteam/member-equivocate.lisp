;;;; redteam/member-equivocate.lisp — a quorum member "equivocates" itself on another's ledger.
;;;;   sbcl --non-interactive --load redteam/member-equivocate.lisp -- KEYFILE LEDGER-FILE LEDGER-HEX HEIGHT [nc]
;;;;   env: CLD_RELAYS
;;;; Signs two different updates at the ledger's next sequence with the MEMBER's key,
;;;; chained onto the tip under the ledger's id, and broadcasts an equivocation proof
;;;; accusing itself (with "nc": a non-conforming-update proof instead).  Only the
;;;; operator's equivocation is fraud on a ledger; PASS = no honest member disputes.
(require :asdf)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-deposits"))
(let* ((args (cdr (member "--" sb-ext:*posix-argv* :test #'string=)))
       (priv (cl-deposits.util:be->int (cl-deposits.util:hex->bytes (string-trim '(#\Newline #\Space) (uiop:read-file-string (first args))))))
       (priv (cl-deposits.wire:even-y-privkey priv))
       (pub (cl-deposits.update:compressed-pubkey priv))
       (updates (sort (mapcar (lambda (b) (cl-deposits.update:decode-update (cl-deposits.util:base64-decode b)))
                              (coerce (json-simple:parse (uiop:read-file-string (second args))) 'list))
                      #'> :key #'cl-deposits.update:update-seq))
       (tip (first updates)) (id (cl-deposits.util:hex->bytes (third args))) (height (parse-integer (fourth args)))
       (mk (lambda (tag)
             (let ((u (cl-deposits.update:make-signed-update
                       :operator-id pub :ledger-id id :seq (1+ (cl-deposits.update:update-seq tip))
                       :prev-hash (cl-deposits.update:chain-hash tip) :block-height height
                       :message (cl-deposits.operation:encode-operation
                                 (list :type :deposit-close :deposit-id (subseq (cl-deposits.util:sha256 (cl-deposits.util:ascii->bytes tag)) 0 16))))))
               (cl-deposits.update:sign-operator u priv) u)))
       (proof (if (equal (fifth args) "nc")
                  (cl-deposits.fraud::make-non-conforming-update-proof pub id (funcall mk "nc"))
                  (cl-deposits.fraud:make-equivocation-proof pub id (funcall mk "one") (funcall mk "two"))))
       (bus (cl-deposits.nostr-bus:make-nostr-bus (uiop:split-string (or (uiop:getenv "CLD_RELAYS") "ws://127.0.0.1:7777") :separator ",")))
       (*print-pretty* nil))
  (cl-deposits.nostr-bus:wait-for-bus bus)
  (let ((e (cl-deposits.bus:bus-publish bus (cl-deposits.wire:fraud-event (cl-deposits.wire:nostr-keypair priv) (getf proof :ledger-id) (getf proof :accused)
                                                                         (cl-deposits.fraud:broadcast->json proof)))))
    (format t "~s~%" (list :published (getf proof :type) :accused (subseq (getf proof :accused) 0 16)
                           :seq (1+ (cl-deposits.update:update-seq tip)) :event (cl-nostr.event:event-id e))))
  (sleep 3) (cl-deposits.nostr-bus:close-nostr-bus bus))
