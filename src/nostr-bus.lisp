;;;; src/nostr-bus.lisp — the BUS over real Nostr relays (cl-nostr's pool).

(defpackage #:cl-deposits.nostr-bus
  (:use #:cl)
  (:local-nicknames (#:bus #:cl-deposits.bus) (#:pool #:cl-nostr.pool) (#:ev #:cl-nostr.event))
  (:export #:nostr-bus #:make-nostr-bus #:nostr-bus-pool #:close-nostr-bus))
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

(defmethod bus:bus-subscribe ((bus nostr-bus) filter fn)
  (pool:pool-subscribe (nostr-bus-pool bus) filter
                       :on-event (lambda (event relay) (declare (ignore relay))
                                   (when (ev:valid-event-p event) (funcall fn event))))
  fn)

(defmethod bus:bus-fetch ((bus nostr-bus) filter)
  (reverse (pool:fetch-events (nostr-bus-pool bus) filter :timeout 5)))
