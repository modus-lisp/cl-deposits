;;;; src/courier.lisp — DEP-13 couriers: carrying a transfer between two ledgers.
;;;;
;;;; A courier holds a deposit on each ledger it serves.  Leg 1: the sender
;;;; locks to the courier's deposit on ledger A behind sha256(H).  Leg 2: the
;;;; courier locks the forward amount to the receiver's deposit on ledger B
;;;; behind the same hash, with a shorter timeout.  The receiver reveals the
;;;; preimage on B; the courier sees it and completes leg 1 on A.

(defpackage #:cl-deposits.courier
  (:use #:cl #:cl-deposits.util)
  (:local-nicknames (#:nd #:cl-deposits.node) (#:w #:cl-deposits.wire) (#:op #:cl-deposits.operation)
                    (#:lg #:cl-deposits.ledger) (#:ev #:cl-nostr.event) (#:bus #:cl-deposits.bus) (#:k #:cl-nostr.keys)
                    (#:up #:cl-deposits.update) (#:d17 #:cl-deposits.dep17) (#:secp #:secp256k1-fast))
  (:export #:courier #:make-courier #:courier-node #:courier-serve #:advertise-courier #:courier-routes
           #:route-fee #:courier-advertisement #:wallet-route #:+kind-courier-ad+ #:+leg-delta+ #:point-add #:scalar-add))
(in-package #:cl-deposits.courier)

(defconstant +kind-courier-ad+ 39102)
(defconstant +leg-delta+ 36 "Leg 2 times out this many blocks before leg 1.")

(defstruct (courier (:constructor %make-courier))
  node
  (ledgers (make-hash-table :test #'equal))   ; ledger hex -> plist (:deposit-id :wallet :fee-in-fixed :fee-in-bps :fee-out-fixed :fee-out-bps)
  (routes (make-hash-table :test #'equalp)))  ; hash32 -> plist (:source :dest :dest-deposit :amount :fee :forward :leg1 :leg2 :preimage)

(defun make-courier (node)
  (let ((c (%make-courier :node node)))
    (nd:add-hook node (lambda (rec update o) (courier-observe c rec update o)))
    (setf (gethash "request_route" (nd::extra-actions node)) (lambda (event params) (handle-route-request c event params)))
    c))

(defun courier-serve (c ledger-hex deposit-id wallet &key (fee-in-fixed 100) (fee-in-bps 10) (fee-out-fixed 100) (fee-out-bps 30))
  "Serve LEDGER-HEX from DEPOSIT-ID, which WALLET controls.  The node follows the ledger."
  (nd:follow-ledger (courier-node c) ledger-hex)
  (setf (gethash ledger-hex (courier-ledgers c))
        (list :deposit-id deposit-id :wallet wallet :fee-in-fixed fee-in-fixed :fee-in-bps fee-in-bps
              :fee-out-fixed fee-out-fixed :fee-out-bps fee-out-bps)))

(defun route-fee (c source dest amount)
  (let ((a (gethash source (courier-ledgers c))) (b (gethash dest (courier-ledgers c))))
    (unless (and a b) (error "courier does not serve both ledgers"))
    (+ (getf a :fee-out-fixed) (floor (* amount (getf a :fee-out-bps)) 10000)
       (getf b :fee-in-fixed) (floor (* amount (getf b :fee-in-bps)) 10000))))

(defun courier-advertisement (c &key (network "signet"))
  (w:json-object "courier_pubkey" (nd:node-pubkey-hex (courier-node c)) "service" "htlc_routing" "network" network
                 "ledgers" (coerce (loop for id being the hash-keys of (courier-ledgers c) using (hash-value l)
                                         collect (w:json-object "ledger_id" id "deposit_id" (bytes->hex (getf l :deposit-id))
                                                                "balance_msats" (courier-balance c id)
                                                                "fee_in_fixed_msats" (getf l :fee-in-fixed) "fee_in_rate_bps" (getf l :fee-in-bps)
                                                                "fee_out_fixed_msats" (getf l :fee-out-fixed) "fee_out_rate_bps" (getf l :fee-out-bps)))
                                   'vector)))

(defun courier-balance (c ledger-hex)
  (let* ((rec (nd:find-record (courier-node c) ledger-hex)) (l (gethash ledger-hex (courier-ledgers c)))
         (d (and rec (gethash (getf l :deposit-id) (lg:ledger-deposits (nd:record-ledger rec))))))
    (if d (lg:deposit-available-balance d) 0)))

(defun advertise-courier (c &key (network "signet"))
  (let ((node (courier-node c)))
    (bus:bus-publish (nd::node-bus node)
                     (ev:build-event (nd::node-keypair node) +kind-courier-ad+ (w:json (courier-advertisement c :network network))
                                     :tags (list (list "d" (nd:node-pubkey-hex node)) (list "service" "htlc_routing") (list "n" network))))))

;;; Point arithmetic for PTLC legs

(defun point-add (p33 q33)
  "Compressed P + Q."
  (secp:secp-init)
  (let ((r (secp:secp-add-points (d17:parse-pubkey p33) (d17:parse-pubkey q33))))
    (cat (octets (if (evenp (secp:secp-y r)) 2 3)) (int->be (secp:secp-x r) 32))))

(defun scalar-add (a32 b32) (int->be (mod (+ (be->int a32) (be->int b32)) secp:*secp256k1-n*) 32))

(defun route-key (route) (or (getf route :point-b) (getf route :hash)))

;;; The route request (DEP-13 §Route Request Protocol)

(defun handle-route-request (c event params)
  (let ((node (courier-node c)))
    (handler-case
        (let* ((source (w:jget params "source_ledger")) (dest (w:jget params "dest_ledger"))
               (dest-deposit (hex->bytes (w:jget params "dest_deposit_id")))
               (amount (w:jget params "amount_msats"))
               (lock-type (or (w:jget params "lock_type") "htlc"))
               (ptlc (string= lock-type "ptlc"))
               (hash (and (not ptlc) (hex->bytes (w:jget params "hash"))))
               (point-p (and ptlc (hex->bytes (w:jget params "point_p"))))
               (fee (route-fee c source dest amount)))
          (unless (member lock-type '("htlc" "ptlc") :test #'string=) (error "unknown lock_type"))
          (when (and hash (/= (length hash) 32)) (error "hash must be 32 bytes"))
          (when (and point-p (/= (length point-p) 33)) (error "point_p must be a 33-byte point"))
          (when (<= amount fee) (error "amount too small to cover fees"))
          (when (> (- amount fee) (courier-balance c dest)) (error "insufficient courier liquidity on the destination ledger"))
          (let* ((t-scalar (and ptlc (nd::random-aux)))
                 (point-t (and ptlc (up:compressed-pubkey (be->int t-scalar))))
                 (point-b (and ptlc (point-add point-p point-t)))     ; P_b = P + T: what leg 1 locks to
                 (route (list :source source :dest dest :dest-deposit dest-deposit :amount amount :fee fee :forward (- amount fee)
                              :hash hash :point-p point-p :point-b point-b :blinding t-scalar)))
            (setf (gethash (route-key route) (courier-routes c)) route)
            (nd::respond node event t
                         :result (apply #'w:json-object
                                        "courier_deposit_id" (bytes->hex (getf (gethash source (courier-ledgers c)) :deposit-id))
                                        "lock_type" lock-type "fee_msats" fee "forward_amount_msats" (- amount fee)
                                        (if ptlc (list "point_p" (bytes->hex point-p) "blinding_point" (bytes->hex point-t))
                                            (list "hash" (bytes->hex hash)))))))
      (error (e) (nd::respond node event nil :error (princ-to-string e))))))

;;; Watching both ledgers

(defun courier-observe (c rec update o)
  (declare (ignore update))
  (let ((id (nd:record-id-hex rec)))
    (case (op:operation-type o)
      (:transfer-lock
       ;; Leg 1 arrived?  Lock leg 2.
       (let* ((script (op:field o :completion-script))
              (arg (and (position #\( script) (hex->bytes (subseq script (1+ (position #\( script)) (position #\) script)))))
              (hash arg)                                    ; sha256(H) or pointlock(P_b): both key the route
              (route (and arg (gethash arg (courier-routes c)))))
         (when (and route (string= id (getf route :source)) (null (getf route :leg1))
                    (equalp (op:field o :destination-deposit-id) (getf (gethash id (courier-ledgers c)) :deposit-id))
                    (>= (op:field o :amount) (getf route :amount)))
           (setf (getf route :leg1) (op:field o :transfer-id))
           (let* ((dest (getf route :dest)) (l (gethash dest (courier-ledgers c)))
                  (timeout (- (op:field o :timeout-height) +leg-delta+ (nd:height (courier-node c)))))
             (when (<= timeout 0) (error "leg 1 timeout leaves no room for leg 2"))
             (setf (getf route :leg2)
                   (nd:wallet-lock-to (getf l :wallet) dest (getf l :deposit-id) (getf route :dest-deposit) (getf route :forward)
                                      (getf route :hash) :point (getf route :point-p)      ; leg 2 locks to P itself
                                      :timeout-blocks timeout :height (nd:height (courier-node c))))
             (setf (gethash hash (courier-routes c)) route)))))
      (:transfer-complete
       ;; Leg 2 completed with the preimage?  Complete leg 1 with it.
       (let* ((tid (op:field o :transfer-id))
              (hash (loop for h being the hash-keys of (courier-routes c) using (hash-value r)
                          when (equalp (getf r :leg2) tid) return h))
              (route (and hash (gethash hash (courier-routes c)))))
         (when (and route (string= id (getf route :dest)) (null (getf route :preimage)))
           (let* ((revealed (first (op:field o :script-witness)))
                  ;; HTLC: relay the preimage.  PTLC: leg 1 wants s + t.
                  (opening (if (getf route :blinding) (scalar-add revealed (getf route :blinding)) revealed)))
             (setf (getf route :preimage) revealed)
             (nd:wallet-complete-transfer (getf (gethash (getf route :source) (courier-ledgers c)) :wallet)
                                          (getf route :source) (getf route :leg1) opening)
             (setf (gethash hash (courier-routes c)) route))))))))


;;; The sender's side

(defun wallet-route (wal courier-pubkey-hex source dest from-deposit dest-deposit amount &key (height 0) preimage ptlc)
  "Request a route, lock leg 1 to the courier.  HTLC: returns (values leg1-id preimage forward).
   PTLC: the secret is a scalar s; leg 1 locks to P_b = P + T, leg 2 to P = s*G.
   Returns (values leg1-id s forward point-p)."
  (let* ((secret (or preimage (nd::random-aux)))
         (hash (and (not ptlc) (sha256 secret)))
         (point-p (and ptlc (up:compressed-pubkey (be->int secret)))))
    (multiple-value-bind (ok res err)
        (nd:wallet-request wal (make-string 64 :initial-element #\0) "request_route"
                           (apply #'w:json-object "source_ledger" source "dest_ledger" dest "dest_deposit_id" (bytes->hex dest-deposit)
                                  "amount_msats" amount "lock_type" (if ptlc "ptlc" "htlc")
                                  (if ptlc (list "point_p" (bytes->hex point-p)) (list "hash" (bytes->hex hash))))
                           :extra-tags (list (list "p" (subseq courier-pubkey-hex 2))))
      (unless ok (error "request_route: ~a" err))
      (when ptlc (unless (equalp (hex->bytes (w:jget res "point_p")) point-p) (error "courier substituted our point")))
      (let* ((point-b (and ptlc (point-add point-p (hex->bytes (w:jget res "blinding_point")))))
             (tid (nd:wallet-lock-to wal source from-deposit (hex->bytes (w:jget res "courier_deposit_id")) amount hash
                                     :point point-b :height height)))
        (values tid secret (w:jget res "forward_amount_msats") point-p)))))
