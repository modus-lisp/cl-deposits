;;;; devnet/hostile-wallet.lisp — one hostile depositor request against a soak ledger.
;;;;   sbcl --load devnet/hostile-wallet.lisp -- KEYFILE LEDGER ACTION
;;;; actions (each should be refused by an honest operator; the line printed says what happened):
;;;;   bad-descriptor   DepositOpen with a descriptor no rule accepts (DEP-16: pk(v6-1234))
;;;;   overdraw         TransferLock of 1 BTC out of a fresh, empty deposit
;;;;   dust-exit        ExitRequest of 1 msat to a valid address, out of an empty deposit
;;;;   nonce-reuse      two different ExitRequests under one nonce (DEP-17: the second is refused)
;;;;   replay           DEP-17 duplicate delivery: one ExitRequest sent twice, identical, then a
;;;;                    different one under the same nonce.  Behaves = the duplicate gets the
;;;;                    original's result and the different one is refused (printed as :refused T)
;;;;   open             open a deposit and print its id (the soak loop then funds it: HOSTILE_DEPOSIT)
;;;; With HOSTILE_DEPOSIT set, overdraw/dust-exit/nonce-reuse use that (funded) deposit instead of
;;;; a fresh empty one, so they meet their own rule rather than the balance check.
;;;; Prints (:action A :refused T/NIL :detail "...").  env: CLD_RELAYS, HOSTILE_HEIGHT (chain tip), HOSTILE_ADDRESS
(require :asdf)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-deposits"))
(defun env (name &optional default) (or (uiop:getenv name) default))
(let* ((args (cdr (member "--" sb-ext:*posix-argv* :test #'string=)))
       (keyfile (first args)) (ledger (second args)) (action (third args)))
  (ensure-directories-exist keyfile)
  (unless (probe-file keyfile) (cl-deposits.wire:write-new-key-file keyfile))
  (let* ((priv (cl-deposits.wire:read-key-file keyfile))
         (bus (cl-deposits.nostr-bus:make-nostr-bus (uiop:split-string (env "CLD_RELAYS" "ws://127.0.0.1:7777") :separator ",")))
         (wal (cl-deposits.node:make-wallet :priv priv :bus bus))
         (*print-pretty* nil)
         (addr (env "HOSTILE_ADDRESS" "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhesqc"))
         (h (parse-integer (env "HOSTILE_HEIGHT" "0"))))   ; the chain tip: operations expire relative to it
    (gossamer:free priv)
    (setf (cl-deposits.node::wallet-nonce wal) (get-universal-time))
    (flet ((try (thunk) (handler-case (values nil (princ-to-string (funcall thunk)))
                          (error (e) (values t (princ-to-string e)))))
           (fresh () (let ((d (env "HOSTILE_DEPOSIT"))) (if (and d (plusp (length d))) (cl-deposits.util:hex->bytes d) (cl-deposits.node:wallet-open-deposit wal ledger)))))
      (multiple-value-bind (refused detail)
          (cond
            ((string= action "open")
             (try (lambda () (cl-deposits.util:bytes->hex (cl-deposits.node:wallet-open-deposit wal ledger)))))
            ((string= action "bad-descriptor")
             (try (lambda () (cl-deposits.node:wallet-open-deposit wal ledger :descriptor "pk(v6-1234)"))))
            ((string= action "overdraw")
             (try (lambda () (let ((d (fresh))) (cl-deposits.node:wallet-transfer wal ledger d d 100000000000 :height h)))))
            ((string= action "dust-exit")
             (try (lambda () (let ((d (fresh))) (cl-deposits.node:wallet-exit wal ledger d 1 addr :height h)))))
            ((string= action "nonce-reuse")
             (try (lambda ()
                    (let ((d (fresh)) (n (cl-deposits.node::wallet-nonce wal)))
                      (ignore-errors (cl-deposits.node:wallet-exit wal ledger d 600000 addr :height h))
                      (setf (cl-deposits.node::wallet-nonce wal) n)     ; the same nonce, a different request
                      (cl-deposits.node:wallet-exit wal ledger d 700000 addr :height h)))))
            ((string= action "replay")
             (let* ((d (fresh)) (n (cl-deposits.node::wallet-nonce wal)))
               (multiple-value-bind (e1 r1) (try (lambda () (cl-deposits.node:wallet-exit wal ledger d 600000 addr :height h)))
                 (setf (cl-deposits.node::wallet-nonce wal) n)       ; the same request again
                 (multiple-value-bind (e2 r2) (try (lambda () (cl-deposits.node:wallet-exit wal ledger d 600000 addr :height h)))
                   (setf (cl-deposits.node::wallet-nonce wal) n)     ; the same nonce, a different request
                   (multiple-value-bind (e3 r3) (try (lambda () (cl-deposits.node:wallet-exit wal ledger d 700000 addr :height h)))
                     (values (and (not e1) (not e2) (string= r1 r2) e3)
                             (format nil "original ~a; duplicate ~a~a; different ~a ~a"
                                     (if e1 "ERR" "ok") (if e2 "ERR" "ok") (if (string= r1 r2) " (same)" " (DIFFERS)")
                                     (if e3 "refused" "ACCEPTED") (subseq r3 0 (min 80 (length r3))))))))))
            (t (values nil (format nil "unknown action ~a" action))))
        (format t "~s~%" (list :action action :refused refused :detail (subseq detail 0 (min 200 (length detail)))))))
    (ignore-errors (cl-deposits.nostr-bus:close-nostr-bus bus))
    (finish-output)))
