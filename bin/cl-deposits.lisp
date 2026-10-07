;;;; bin/cl-deposits.lisp — the daemon.
;;;;   CLD_DIR           data dir: node.key (hex privkey, created if absent), ledger_*.json, cld.pid
;;;;   CLD_RELAYS        comma-separated relay URLs
;;;;   CLD_CONTROL_PORT  localhost control socket
;;;;   CLD_NETWORK       signet | testnet | regtest | mainnet   (default signet)
;;;;   CLD_BITCOIN_CLI   e.g. "bitcoin-cli -signet -datadir=/x"  (chain height + outpoint checks)
;;;;   CLD_MIN_CONFS     confirmations a cosigner requires on a QuorumBegin outpoint (default 1)
;;;;   CLD_LN_CONTROL    host:port of a cl-payments daemon's control socket (the Lightning rail)
(require :asdf)
(require :sb-posix)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-deposits"))
(defun env (name &optional default) (or (uiop:getenv name) default))
(let* ((dir (uiop:ensure-directory-pathname (or (env "CLD_DIR") (error "set CLD_DIR"))))
       (keyfile (merge-pathnames "node.key" dir)))
  (ensure-directories-exist dir)
  (unless (probe-file keyfile)
    (with-open-file (s keyfile :direction :output)
      (format s "~a~%" (cl-deposits.util:bytes->hex (cl-deposits.node::random-aux)))))
  (let* ((priv (cl-deposits.util:be->int (cl-deposits.util:hex->bytes
                                          (string-trim '(#\Newline #\Space) (uiop:read-file-string keyfile)))))
         (relays (uiop:split-string (env "CLD_RELAYS" "ws://127.0.0.1:7777") :separator ","))
         (bus (cl-deposits.nostr-bus:make-nostr-bus relays))
         (cli (env "CLD_BITCOIN_CLI"))
         (node (cl-deposits.node:make-node
                :priv priv :bus bus :network (env "CLD_NETWORK" "signet") :data-dir dir :relays relays
                :height-fn (and cli (cl-deposits.daemon:bitcoin-cli-height-fn cli))
                :chain-fn (and cli (cl-deposits.daemon:bitcoin-cli-chain-fn cli))
                :pledge-fn (and cli (cl-deposits.daemon:bitcoin-cli-pledge-fn cli))
                :spender-fn (and cli (cl-deposits.daemon:bitcoin-cli-spender-fn cli))
                :feerate-fn (and cli (cl-deposits.daemon:bitcoin-cli-feerate-fn cli))
                :utxos-fn (and cli (cl-deposits.daemon:bitcoin-cli-utxos-fn cli))
                :broadcast-fn (and cli (cl-deposits.daemon:bitcoin-cli-broadcast-fn cli))
                :height-of-block (and cli (cl-deposits.daemon:bitcoin-cli-height-of-block-fn cli))
                :block-hash-fn (and cli (cl-deposits.daemon:bitcoin-cli-block-hash-fn cli))
                :min-confs (parse-integer (env "CLD_MIN_CONFS" "1"))
                :ln (let ((hp (env "CLD_LN_CONTROL")))
                      (and hp (let ((i (position #\: hp)))
                                (cl-deposits.lightning:make-clp-backend (subseq hp 0 i) (parse-integer hp :start (1+ i)))))))))
    (when (cl-deposits.node:node-ln node)
      (cl-deposits.node:start-invoice-poller node)
      (format t "~&lightning rail: ~a~%" (env "CLD_LN_CONTROL")))
    (with-open-file (s (merge-pathnames "cld.pid" dir) :direction :output :if-exists :supersede)
      (format s "~d~%" (sb-posix:getpid)))
    (cl-deposits.node:load-data-dir node :log-fn (lambda (fmt &rest args) (format t "~&~?~%" fmt args)))
    ;; catch-up needs the relay: the pool connects asynchronously, and a catch-up that
    ;; ran first silently did nothing (cld2 sat at seq 11605 of 84k).
    (unless (cl-deposits.nostr-bus:wait-for-bus bus :seconds 20) (format t "~&relay not connected after 20 s; catching up later on demand~%"))
    (cl-deposits.node:catch-up-all node)   ; replicas may have missed updates while we were down
    (cl-deposits.node:start-transfer-timeout-poller node)   ; DEP-11: TransferFail past timeout_height
    (cl-deposits.node:start-expiry-watch node)   ; DEP-19: dispute a quorum its operator let lapse
    (dolist (line (reverse (cl-deposits.node:node-log node))) (when (search "caught up" line) (format t "~&~a~%" line)))
    (format t "~&cl-deposits ~a on ~{~a~^,~}~%" (cl-deposits.node:node-pubkey-hex node) relays)
    (let ((cp (env "CLD_CONTROL_PORT")))
      (when cp (cl-deposits.daemon:start-control-server node (parse-integer cp))
        (format t "~&control socket on 127.0.0.1:~a~%" cp)))
    (finish-output)
    (loop (sleep 3600))))
