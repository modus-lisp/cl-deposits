;;;; src/bus.lisp — where events go.  A BUS publishes events and delivers
;;;; subscriptions; the in-process MOCK-BUS lets several nodes talk in one
;;;; image (the daemon gate), a NOSTR-BUS wraps cl-nostr relays (the devnet).

(defpackage #:cl-deposits.bus
  (:use #:cl)
  (:local-nicknames (#:ev #:cl-nostr.event) (#:flt #:cl-nostr.filter))
  (:export #:bus #:bus-publish #:bus-subscribe #:bus-fetch #:mock-bus #:make-mock-bus
           #:mock-bus-events #:ephemeral-kind-p))
(in-package #:cl-deposits.bus)

(defclass bus () ())
(defgeneric bus-publish (bus event))
(defgeneric bus-subscribe (bus filter fn) (:documentation "FN is called with each matching event."))
(defgeneric bus-fetch (bus filter) (:documentation "Stored events matching FILTER, oldest first."))

(defun ephemeral-kind-p (kind) (<= 20000 kind 29999))

(defclass mock-bus (bus)
  ((subscriptions :initform '() :accessor subscriptions)
   (events :initform '() :accessor mock-bus-events)
   (lock :initform (bt:make-lock "mock-bus") :reader lock)))

(defun make-mock-bus () (make-instance 'mock-bus))

(defmethod bus-publish ((bus mock-bus) event)
  (let (subs)
    (bt:with-lock-held ((lock bus))
      (unless (ephemeral-kind-p (ev:event-kind event))
        (push event (mock-bus-events bus)))
      (setf subs (copy-list (subscriptions bus))))
    ;; Deliver outside the lock: handlers publish in turn.
    (dolist (s subs)
      (when (flt:filter-matches-p (car s) event)
        (funcall (cdr s) event)))
    event))

(defmethod bus-subscribe ((bus mock-bus) filter fn)
  (bt:with-lock-held ((lock bus)) (push (cons filter fn) (subscriptions bus)))
  fn)

(defmethod bus-fetch ((bus mock-bus) filter)
  (bt:with-lock-held ((lock bus))
    (reverse (remove-if-not (lambda (e) (flt:filter-matches-p filter e)) (mock-bus-events bus)))))
