;;;; src/bus.lisp — where events go.  A BUS publishes events and delivers
;;;; subscriptions; the in-process MOCK-BUS lets several nodes talk in one
;;;; image (the daemon gate), a NOSTR-BUS wraps cl-nostr relays (the devnet).

(defpackage #:cl-deposits.bus
  (:use #:cl)
  (:local-nicknames (#:ev #:cl-nostr.event) (#:flt #:cl-nostr.filter))
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
;;; The chaos bus: what a relay does to you.  Delivery happens on the bus's own
;;; thread (handlers never run on the publisher's thread), events may be delayed,
;;; reordered within a window, and delivered twice.  BUS-SETTLE waits until
;;; nothing is in flight — scenarios assert only then.

(defclass chaos-bus (mock-bus)
  ((queue :initform '() :accessor queue)
   (in-flight :initform 0 :accessor in-flight)
   (cv :initform (bt:make-condition-variable) :reader cv)
   (thread :initform nil :accessor thread)
   (seed :initarg :seed :initform 1 :accessor seed)
   (state :accessor state)
   (max-delay :initarg :max-delay :initform 0.02 :accessor max-delay)     ; seconds
   (window :initarg :window :initform 3 :accessor window)                  ; reorder window
   (dup-rate :initarg :dup-rate :initform 0.1 :accessor dup-rate)
   (idle-hooks :initform '() :accessor idle-hooks)))                       ; (lambda ()) -> T when a node is idle

(defun make-chaos-bus (&key (seed 1) (max-delay 0.02) (window 3) (dup-rate 0.1))
  (let ((b (make-instance 'chaos-bus :seed seed :max-delay max-delay :window window :dup-rate dup-rate)))
    (setf (state b) (sb-ext:seed-random-state seed))
    (setf (thread b) (bt:make-thread (lambda () (chaos-loop b)) :name "chaos-bus"))
    b))

(defmethod bus-async-p ((bus chaos-bus)) t)

(defmethod bus-publish ((bus chaos-bus) event)
  (bt:with-lock-held ((lock bus))
    (unless (ephemeral-kind-p (ev:event-kind event)) (push event (mock-bus-events bus)))
    (setf (queue bus) (append (queue bus) (list event)))
    (when (< (random 1.0 (state bus)) (dup-rate bus)) (setf (queue bus) (append (queue bus) (list event))))
    (bt:condition-notify (cv bus)))
  event)

(defun chaos-loop (bus)
  (loop
    (let (batch)
      (bt:with-lock-held ((lock bus))
        (loop until (queue bus) do (bt:condition-wait (cv bus) (lock bus)))
        ;; take up to WINDOW events and shuffle them
        (let ((n (min (window bus) (length (queue bus)))))
          (setf batch (subseq (queue bus) 0 n) (queue bus) (nthcdr n (queue bus)))
          (incf (in-flight bus) n)))
      (let ((v (coerce batch 'vector)))
        (loop for i from (1- (length v)) downto 1 do (rotatef (aref v i) (aref v (random (1+ i) (state bus)))))
        (loop for event across v
              do (let ((d (random (max-delay bus) (state bus)))) (when (plusp d) (sleep d)))
                 (dolist (s (bt:with-lock-held ((lock bus)) (copy-list (subscriptions bus))))
                   (when (flt:filter-matches-p (car s) event)
                     (handler-case (funcall (cdr s) event) (error () nil))))
                 (bt:with-lock-held ((lock bus)) (decf (in-flight bus))))))))

(defun bus-settle (bus &key (timeout 30))
  "Wait until the bus has nothing queued or in flight and every idle hook says idle."
  (loop with deadline = (+ (get-internal-real-time) (* timeout internal-time-units-per-second))
        do (let ((quiet (and (bt:with-lock-held ((lock bus)) (and (null (queue bus)) (zerop (in-flight bus))))
                             (every #'funcall (idle-hooks bus)))))
             (when quiet
               ;; stay quiet for a moment: a handler may be about to publish
               (sleep 0.05)
               (when (and (bt:with-lock-held ((lock bus)) (and (null (queue bus)) (zerop (in-flight bus))))
                          (every #'funcall (idle-hooks bus)))
                 (return t))))
           (when (> (get-internal-real-time) deadline) (return nil))
           (sleep 0.02)))

(defun bus-add-idle-hook (bus fn) (push fn (idle-hooks bus)))
