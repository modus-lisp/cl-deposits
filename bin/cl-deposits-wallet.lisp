;;;; bin/cl-deposits-wallet.lisp — a one-shot wallet.
;;;;   sbcl --script bin/cl-deposits-wallet.lisp KEYFILE LEDGER ACTION ARGS...
;;;;   actions: pubkey | open | balance DEPOSIT | transfer FROM TO MSAT [HEIGHT] [FEE] | complete TRANSFER PREIMAGE
;;;;            invoice DEPOSIT MSAT [DESCRIPTION] | pay DEPOSIT BOLT11 MSAT [FEE] [HEIGHT]
;;;;   env: CLD_RELAYS
(require :asdf)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-deposits"))
(defun env (name &optional default) (or (uiop:getenv name) default))
(let* ((args (cdr (member "--" sb-ext:*posix-argv* :test #'string=)))
       (keyfile (or (first args) (error "usage: KEYFILE LEDGER ACTION ...")))
       (ledger (second args)) (action (third args)) (rest (cdddr args)))
  (unless (probe-file keyfile)
    (with-open-file (s keyfile :direction :output)
      (format s "~a~%" (cl-deposits.util:bytes->hex (cl-deposits.node::random-aux)))))
  (let* ((priv (cl-deposits.util:be->int (cl-deposits.util:hex->bytes (string-trim '(#\Newline #\Space) (uiop:read-file-string keyfile)))))
         (bus (and (not (string= action "pubkey"))
                   (cl-deposits.nostr-bus:make-nostr-bus (uiop:split-string (env "CLD_RELAYS" "ws://127.0.0.1:7777") :separator ","))))
         (wal (cl-deposits.node:make-wallet :priv priv :bus (or bus (cl-deposits.bus:make-mock-bus))))
         ;; One process per command: operation nonces must still climb across
         ;; invocations (an operator refuses a nonce it accepted within the expiry window).
         (_ (setf (cl-deposits.node::wallet-nonce wal) (get-universal-time)))
         (hx #'cl-deposits.util:hex->bytes) (hex #'cl-deposits.util:bytes->hex)
         (*print-pretty* nil))
    (handler-case
        (cond
          ((string= action "pubkey") (format t "~s~%" (list :pubkey (funcall hex (cl-deposits.node:wallet-pubkey wal))
                                                            :descriptor (cl-deposits.node::wallet-descriptor wal))))
          ((string= action "open") (format t "~s~%" (list :deposit (funcall hex (cl-deposits.node:wallet-open-deposit wal ledger)))))
          ((string= action "balance")
           (multiple-value-bind (b l) (cl-deposits.node:wallet-balance wal ledger (funcall hx (first rest)))
             (format t "~s~%" (list :balance b :locked l))))
          ((string= action "transfer")
           (multiple-value-bind (tid pre)
               (cl-deposits.node:wallet-transfer wal ledger (funcall hx (first rest)) (funcall hx (second rest))
                                                 (parse-integer (third rest)) :height (parse-integer (or (fourth rest) "0"))
                                                 :fee (parse-integer (or (fifth rest) "0")))
             (format t "~s~%" (list :transfer (funcall hex tid) :preimage (funcall hex pre)))))
          ((string= action "invoice")
           (multiple-value-bind (bolt11 hash res)
               (cl-deposits.node:wallet-make-invoice wal ledger (funcall hx (first rest)) (parse-integer (second rest))
                                                     :description (third rest))
             (format t "~s~%" (list :bolt11 bolt11 :payment-hash (funcall hex hash)
                                    :cosigned (and (cl-deposits.wire:jget res "cosign_signature") t)))))
          ((string= action "pay")
           (multiple-value-bind (ok pre err)
               (cl-deposits.node:wallet-pay-invoice wal ledger (funcall hx (first rest)) (second rest) (parse-integer (third rest))
                                                    :fee (parse-integer (or (fourth rest) "0")) :height (parse-integer (or (fifth rest) "0")))
             (format t "~s~%" (if ok (list :status :ok :preimage (funcall hex pre)) (list :status :error :message err)))))
          ((string= action "complete")
           (cl-deposits.node:wallet-complete-transfer wal ledger (funcall hx (first rest)) (funcall hx (second rest)))
           (format t "~s~%" (list :status :ok)))
          ((string= action "escalate")   ; DEP-12: anchor an unanswered transfer through a member
           ;; escalate FROM TO MSAT MEMBER-LEDGER OPERATOR-HEX — computes the request
           ;; hash of a transfer_lock request (the same fields wallet-transfer sends)
           ;; and asks the member to embed it.  The red-team script passes the member
           ;; ledger and the operator's pubkey explicitly.
           (let* ((from (funcall hx (first rest))) (to (funcall hx (second rest)))
                  (amount (parse-integer (third rest)))
                  (member-ledger (or (fourth rest) (error "escalate: MEMBER-LEDGER required")))
                  (operator (or (fifth rest) (error "escalate: OPERATOR-HEX required")))
                  (params (cl-deposits.wire:json-object "operation" "" "transfer_nonce" ""
                                                         "source_deposit_id" (funcall hex from)
                                                         "destination_deposit_id" (funcall hex to)
                                                         "amount" amount "fee" 0
                                                         "completion_script" "" "timeout_height" 0 "transfer_id" ""
                                                         "op_nonce" 0 "op_expiry" 0 "signature" ""))
                  (h (funcall hex (cl-deposits.node:wallet-request-hash wal ledger "transfer_lock" params)))
                  (res (cl-deposits.node:wallet-escalate wal member-ledger (funcall hx h) ledger operator)))
             (format t "~s~%" (list :status :ok :request-hash h :reply res))))
          (t (error "unknown action ~a" action)))
      (error (e) (format t "~s~%" (list :status :error :message (princ-to-string e)))))
    (when bus (ignore-errors (cl-deposits.nostr-bus:close-nostr-bus bus)))
    (finish-output)))
