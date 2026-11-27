;;;; src/nostr-bus.lisp — the BUS over real Nostr relays (cl-nostr's pool).

(defpackage #:cl-deposits.nostr-bus
  (:use #:cl)
  (:local-nicknames (#:bus #:cl-deposits.bus) (#:pool #:cl-nostr.pool) (#:ev #:cl-nostr.event) (#:own #:cl-deposits.owner))
  (:export #:bus-ready-p #:wait-for-bus #:nostr-bus #:make-nostr-bus #:nostr-bus-pool #:close-nostr-bus))
(in-package #:cl-deposits.nostr-bus)

(defclass nostr-bus (bus:bus)
  ((pool :initarg :pool :reader nostr-bus-pool)))

(defun make-nostr-bus (urls &key (timeout 10))
  "Connect to every relay URL (ws:// or wss://).  Plain ws:// is what a local
   devnet relay speaks; verification only matters for wss://."
  (make-instance 'nostr-bus :pool (pool:make-pool urls :verify t :timeout timeout)))

(defun close-nostr-bus (bus) (pool:close-pool (nostr-bus-pool bus)))

(defmethod bus:bus-publish ((bus nostr-bus) event)
  (pool:pool-publish (nostr-bus-pool bus) event)
  event)

(defvar *subscribers* (make-hash-table) "Subscription id -> handler (the owner's, cl-deposits.owner).")
(defvar *next-subscriber* 0)

(defun deliver (id json)
  "On the owner: hand the event JSON to subscription ID's handler."
  (let ((fn (gethash id *subscribers*)))
    (when fn (funcall fn (ev:json->event json)))))

(defmethod bus:bus-subscribe ((bus nostr-bus) filter fn)
  ;; The pool calls ON-EVENT on a relay's reader thread.  The handler changes a node, which only
  ;; the owner thread may do, so the event goes to the owner as JSON (plain data: messages are
  ;; copied) and the owner runs the handler when it pumps.
  (let ((id (incf *next-subscriber*)))
    (setf (gethash id *subscribers*) fn)
    (pool:pool-subscribe (nostr-bus-pool bus) filter
                         :on-event (lambda (event relay) (declare (ignore relay))
                                     (when (ev:valid-event-p event)
                                       (own:owner-post 'deliver (list id (ev:event->json event)))))))
  fn)

(defmethod bus:bus-unsubscribe ((bus nostr-bus) fn)
  (loop for id being the hash-keys of *subscribers* using (hash-value f)
        when (eq f fn) do (remhash id *subscribers*)))

(defmethod bus:bus-fetch ((bus nostr-bus) filter)
  (reverse (pool:fetch-events (nostr-bus-pool bus) filter :timeout 5)))

(defun bus-ready-p (bus)
  "T once at least one relay of the pool is connected."
  (some #'cl-nostr.relay:relay-connected-p (cl-nostr.pool::%relays (nostr-bus-pool bus))))

(defun wait-for-bus (bus &key (seconds 15))
  "Block until BUS-READY-P or SECONDS pass; returns the readiness."
  (loop repeat (round (* 2 seconds)) until (bus-ready-p bus) do (own:pause-for 0.5))
  (bus-ready-p bus))
