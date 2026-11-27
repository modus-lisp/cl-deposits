;;;; src/bus.lisp — where events go.  A BUS publishes events and delivers
;;;; subscriptions; the in-process MOCK-BUS lets several nodes talk in one
;;;; image (the daemon gate), a NOSTR-BUS wraps cl-nostr relays (the devnet).

(defpackage #:cl-deposits.bus
  (:use #:cl)
  (:local-nicknames (#:ev #:cl-nostr.event) (#:flt #:cl-nostr.filter) (#:own #:cl-deposits.owner))
  (:export #:bus #:bus-publish #:bus-subscribe #:bus-fetch #:bus-unsubscribe #:mock-bus #:make-mock-bus
           #:mock-bus-events #:ephemeral-kind-p #:bus-async-p #:chaos-bus #:make-chaos-bus #:bus-settle #:bus-add-idle-hook))
(in-package #:cl-deposits.bus)

(defclass bus () ())
(defgeneric bus-publish (bus event))
(defgeneric bus-subscribe (bus filter fn) (:documentation "FN is called with each matching event."))
(defgeneric bus-fetch (bus filter) (:documentation "Stored events matching FILTER, oldest first."))
(defgeneric bus-unsubscribe (bus fn) (:documentation "Stop delivering to the handler FN.")
  (:method ((bus t) fn) (declare (ignore fn)) nil))
(defgeneric bus-async-p (bus)
  (:documentation "T when subscriptions fire on the bus's own threads (so handlers must not block on it).")
  (:method ((bus bus)) t))

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

(defmethod bus-unsubscribe ((bus mock-bus) fn)
  (bt:with-lock-held ((lock bus)) (setf (subscriptions bus) (remove fn (subscriptions bus) :key #'cdr))))

(defmethod bus-fetch ((bus mock-bus) filter)
  (bt:with-lock-held ((lock bus))
    (reverse (remove-if-not (lambda (e) (flt:filter-matches-p filter e)) (mock-bus-events bus)))))

(defmethod bus-async-p ((bus mock-bus)) nil)

;;; ---------------------------------------------------------------------------
;;; The chaos bus: what a relay does to you.  Delivery never happens inside BUS-PUBLISH: each
;;; event is delivered later, by a timer on the owner (cl-deposits.owner), after a random delay
;;; of up to MAX-DELAY, so events published close together arrive reordered; some arrive twice.
;;; BUS-SETTLE pumps until nothing is in flight -- scenarios assert only then.
;;;   It had a delivery thread of its own, which ran every subscriber's handler there: on modus a
;;; thread may not change what another thread made, and every handler changes a node.

(defclass chaos-bus (mock-bus)
  ((in-flight :initform 0 :accessor in-flight)
   (seed :initarg :seed :initform 1 :accessor seed)
   (state :accessor state)
   (max-delay :initarg :max-delay :initform 0.02 :accessor max-delay)     ; seconds
   (window :initarg :window :initform 3 :accessor window)                  ; kept for callers; the delays reorder
   (dup-rate :initarg :dup-rate :initform 0.1 :accessor dup-rate)
   (idle-hooks :initform '() :accessor idle-hooks)))                       ; (lambda ()) -> T when a node is idle

(defun make-chaos-bus (&key (seed 1) (max-delay 0.02) (window 3) (dup-rate 0.1))
  (let ((b (make-instance 'chaos-bus :seed seed :max-delay max-delay :window window :dup-rate dup-rate)))
    (setf (state b) (sb-ext:seed-random-state seed))
    b))

(defmethod bus-async-p ((bus chaos-bus)) t)

(defun %chaos-deliver (bus event)
  (unwind-protect
       (dolist (s (copy-list (subscriptions bus)))
         (when (flt:filter-matches-p (car s) event)
           (handler-case (funcall (cdr s) event) (error () nil))))
    (decf (in-flight bus))))

(defmethod bus-publish ((bus chaos-bus) event)
  (unless (ephemeral-kind-p (ev:event-kind event)) (push event (mock-bus-events bus)))
  (loop repeat (if (< (random 1.0 (state bus)) (dup-rate bus)) 2 1)
        do (incf (in-flight bus))
           (own:after-seconds (random (max-delay bus) (state bus)) (lambda () (%chaos-deliver bus event))
                              :name "chaos-bus"))
  event)

(defun bus-settle (bus &key (timeout 30))
  "Pump until the bus has nothing in flight and every idle hook says idle."
  (flet ((quiet () (and (zerop (in-flight bus)) (every #'funcall (idle-hooks bus)))))
    (own:wait-until (lambda ()
                      ;; stay quiet for a moment: a handler may be about to publish
                      (and (quiet) (progn (own:pause-for 0.05) (quiet))))
                    :timeout timeout :step 0.02)))

(defun bus-add-idle-hook (bus fn) (push fn (idle-hooks bus)))
