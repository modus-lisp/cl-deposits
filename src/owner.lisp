;;;; src/owner.lisp — one thread owns the nodes; everything else reaches them by message.
;;;;
;;;; THE MODEL.  modus threads share no state: a thread may not store an object it made into
;;;; anything another thread can reach (it may not even add a fixnum to a hash table it did not
;;;; make: the table grows in the storer's heap).  A node is hash tables, records and logs that
;;;; every lane, drive, watch and control client used to mutate from a thread of its own; that
;;;; cannot work there.  So, on every Lisp:
;;;;
;;;;   - ONE OWNER THREAD -- the thread that loaded the system, normally the main thread --
;;;;     holds every node and runs everything that reads or changes one.
;;;;   - What used to be a thread is a LANE (a queue of work run one item at a time: a node's
;;;;     two relay lanes, each drive slot, a proof catch-up) or a TIMER (the expiry watch, the
;;;;     vault watch, the invoice poller, the transfer timeouts, the chaos relay's deliveries).
;;;;     Both run on the owner when it PUMPS.
;;;;   - The owner pumps whenever it waits: PAUSE-FOR and WAIT-UNTIL replace SLEEP and
;;;;     CONDITION-WAIT everywhere a node waits for a peer or for time.  So a lane waiting for
;;;;     cosignatures lets the other lanes, the drives and the timers run meanwhile: waits
;;;;     overlap as they did with threads.  Computation does not: it runs on one thread.
;;;;   - FOREIGN THREADS (a control client, a relay reader) never touch a node: OWNER-CALL sends
;;;;     a named function and plain arguments to the owner, which runs it while pumping and
;;;;     sends the value back.  Blocking I/O the owner should not wait on (bitcoind RPC) goes to
;;;;     a WORK thread the same way in reverse (RUN-WORK): plain data out, plain data back.
;;;;     Messages travel on bobbin channels, which copy them.
;;;;
;;;; WAITS NEST.  A wait pumps, the pump runs another lane's item, and that item may wait in its
;;;; turn: the first wait cannot return before the second does.  So a long wait inside a short
;;;; one holds the short one back, and work that would have WAITED for a lock another task holds
;;;; cannot wait here (the holder is suspended below it on the same stack).  OWNER-LOCK is that
;;;; lock: re-entrant for the task holding it, and for any other task it signals OWNER-BUSY at
;;;; once.  A lane item or timer refused that way is run again later (WITH-OWNER-LOCK's caller
;;;; decides; the lane and timer runners retry it).  Nesting is bounded (+MAX-DEPTH+): past it a
;;;; pump only delivers messages and starts nothing.

(defpackage #:cl-deposits.owner
  (:use #:cl)
  (:local-nicknames (#:bob #:bobbin))
  (:export #:owner-p #:pump #:pause-for #:wait-until #:*task* #:task-name #:pump-depth
           #:lane #:make-lane #:lane-p #:lane-name #:lane-items #:lane-push #:lane-push-front #:lane-close
           #:lane-busy-p #:lane-idle-p #:lane-live-p #:lane-depth #:lane-runs
           #:timer #:every-seconds #:after-seconds #:cancel-timer #:timer-live-p #:timer-runs
           #:owner-lock #:with-owner-lock #:owner-busy #:owner-lock-held-p
           #:owner-call #:owner-post #:owner-call-error #:owner-call-error-message
           #:run-work #:work-error #:work-local
           #:work-quiet-p))
(in-package #:cl-deposits.owner)

(defvar *owner-thread* sb-thread:*current-thread*
  "The thread that owns every node: the one that loaded this file.")

(defun owner-p () (eq sb-thread:*current-thread* *owner-thread*))

(defconstant +max-depth+ 48 "Nested pumps past this deliver messages only.")
(defvar *depth* 0 "How many pumps are running on the owner's stack.")
(defun pump-depth () *depth*)

(defvar *task* :top
  "The task running now: :TOP for the owner's own code, else the lane item or timer run that
   a pump started.  OWNER-LOCK is re-entrant per task.")

(define-condition owner-busy (condition)
  ((key :initarg :key :reader owner-busy-key))
  (:report (lambda (c s) (format s "~a is held by a task suspended in a wait" (owner-busy-key c))))
  (:documentation "An OWNER-LOCK another task holds.  Not an ERROR: handlers for errors do not
   swallow it, so it reaches the lane or timer runner, which runs the work again later."))

;;; ---------------------------------------------------------------------------
;;; Owner locks

(defvar *owner-locks* (make-hash-table :test #'equal) "key -> (task . depth)")

(defun owner-lock-held-p (key) (and (gethash key *owner-locks*) t))

(defun %owner-lock-acquire (key)
  (let ((h (gethash key *owner-locks*)))
    (cond ((null h) (setf (gethash key *owner-locks*) (cons *task* 1)) t)
          ((eq (car h) *task*) (incf (cdr h)) t)
          (t nil))))

(defun %owner-lock-release (key)
  (let ((h (gethash key *owner-locks*)))
    (when h (if (> (cdr h) 1) (decf (cdr h)) (remhash key *owner-locks*)))))

(defmacro with-owner-lock ((key &key (busy '(error 'owner-busy :key k))) &body body)
  "Run BODY holding the owner lock KEY (compared with EQUAL).  Re-entrant for this task; held
   by another (suspended) task, evaluate BUSY instead (default: signal OWNER-BUSY)."
  (let ((k (gensym "KEY")))
    `(let ((,k ,key))
       (if (%owner-lock-acquire ,k)
           (unwind-protect (progn ,@body) (%owner-lock-release ,k))
           (let ((k ,k)) (declare (ignorable k)) ,busy)))))

(defun owner-lock (key) "Try to take KEY: T, or NIL when another task holds it." (%owner-lock-acquire key))

;;; ---------------------------------------------------------------------------
;;; Lanes and timers (owner-side; made and run on the owner only)

(defstruct (lane (:constructor %make-lane))
  name
  (items '())                    ; queued work, first to run first; the owner may reorder it
  (run nil)                      ; (lambda (item)) -> how an item is run (default: FUNCALL it)
  (ready nil)                    ; (lambda ()) -> NIL while the lane must not start (a node loading)
  (busy nil) (deferred-until 0) (live t) (close-when-empty nil)
  (runs 0))

(defvar *lanes* '() "Every live lane.")
(defvar *timers* '() "Every live timer.")

(defun make-lane (&key name run ready close-when-empty)
  "A lane: its items run one at a time, in order, on the owner when it pumps.  RUN is called
   with each item (default FUNCALL); READY, when given, holds the lane while it answers NIL.
   CLOSE-WHEN-EMPTY: the lane closes itself once it has run its last item."
  (let ((l (%make-lane :name name :run run :ready ready :close-when-empty close-when-empty)))
    (setf *lanes* (append *lanes* (list l)))
    l))

(defun lane-push (lane item) (setf (lane-items lane) (append (lane-items lane) (list item))) item)
(defun lane-push-front (lane item) (push item (lane-items lane)) item)
(defun lane-close (lane)
  "Stop LANE: nothing more of it runs (an item running now finishes)."
  (setf (lane-live lane) nil (lane-items lane) '())
  (setf *lanes* (remove lane *lanes*))
  lane)
(defun lane-depth (lane) (length (lane-items lane)))
(defun lane-busy-p (lane) (lane-busy lane))
(defun lane-live-p (lane) (and lane (lane-live lane)))
(defun lane-idle-p (lane) (and (not (lane-busy lane)) (null (lane-items lane))))

(defstruct (timer (:constructor %make-timer))
  name fn interval (due 0) (running nil) (live t) (once nil) (runs 0))

(defun %now () (/ (get-internal-real-time) internal-time-units-per-second))

(defun every-seconds (interval fn &key name (first interval))
  "Run FN on the owner every INTERVAL seconds, measured from the end of its last run (as a
   thread doing (loop (sleep interval) (fn)) did), the first time FIRST seconds from now.
   Never two runs of one timer at once.  Returns the timer (CANCEL-TIMER)."
  (let ((tm (%make-timer :name name :fn fn :interval interval :due (+ (%now) first))))
    (push tm *timers*)
    tm))

(defun after-seconds (seconds fn &key name)
  "Run FN on the owner once, SECONDS from now."
  (let ((tm (%make-timer :name name :fn fn :interval 0 :due (+ (%now) seconds) :once t)))
    (push tm *timers*)
    tm))

(defun cancel-timer (tm)
  (when tm (setf (timer-live tm) nil) (setf *timers* (remove tm *timers*)))
  tm)
(defun timer-live-p (tm) (and tm (timer-live tm)))

(defun %warn (fmt &rest args)
  (ignore-errors (format *error-output* "~&[owner] ~?~%" fmt args) (force-output *error-output*)))

(defun %run-timer (tm)
  (setf (timer-running tm) t)
  (let ((*task* tm) (again nil))
    (unwind-protect
         (handler-case (funcall (timer-fn tm))
           (owner-busy () (setf again t))           ; run again soon
           (error (e) (%warn "timer ~a: ~a" (timer-name tm) e)))
      (setf (timer-running tm) nil)
      (incf (timer-runs tm))
      (cond ((and (timer-once tm) (not again)) (cancel-timer tm))
            (t (setf (timer-due tm) (+ (%now) (if again (max 0.05 (min 1 (timer-interval tm))) (timer-interval tm))))))))
  t)

(defun %run-lane (lane)
  (let ((item (pop (lane-items lane))) (*task* lane))
    (setf (lane-busy lane) t)
    (let ((done nil))
      (unwind-protect
           (handler-case (progn (if (lane-run lane) (funcall (lane-run lane) item) (funcall item))
                                (setf done t))
             (owner-busy ()
               ;; refused for a lock a suspended task holds: first in line again, a little later
               (when (lane-live lane)
                 (push item (lane-items lane))
                 (setf (lane-deferred-until lane) (+ (%now) 0.05))))
             (error (e) (setf done t) (%warn "lane ~a: ~a" (lane-name lane) e)))
        (setf (lane-busy lane) nil)
        (when done (incf (lane-runs lane)))
        (when (and (lane-close-when-empty lane) (null (lane-items lane))) (lane-close lane)))))
  t)

;;; What the task running now is called: a lane's or timer's name, "owner" for the owner's own code.
(defun task-name (&optional (task *task*))
  (cond ((lane-p task) (or (lane-name task) "lane"))
        ((timer-p task) (or (timer-name task) "timer"))
        ((consp task) (format nil "~(~{~a~^ ~}~)" task))
        (t "owner")))

;;; ---------------------------------------------------------------------------
;;; Messages from other threads: OWNER-CALL in, RUN-WORK results back

(defconstant +call-slots+ 16 "OWNER-CALLs in flight at once.")
(defconstant +chan-bytes+ (* 4 1024 1024))

(defvar *inbox* (bob:make-channel :capacity +chan-bytes+ :name "cl-deposits owner inbox")
  "Messages to the owner: (:call slot tag fname args) and (:work ticket status value).")
(defvar *call-free* (let ((c (bob:make-channel :capacity 4096 :name "cl-deposits owner-call slots")))
                      (dotimes (i +call-slots+) (bob:channel-send c i))
                      c))
(defvar *call-replies* (let ((v (make-array +call-slots+)))
                         (dotimes (i +call-slots+) (setf (aref v i) (bob:make-channel :capacity +chan-bytes+ :name "owner-call reply")))
                         v))
(defvar *work-results* (make-hash-table) "ticket -> (status . value), owner-side.")

(defun %handle-message (m)
  (case (first m)
    (:call (destructuring-bind (slot tag fname args) (rest m)
             (let ((reply (let ((*task* (list :call fname)))
                            (handler-case (list :ok tag (apply fname args))
                              (owner-busy (c) (list :busy tag (princ-to-string c)))
                              (serious-condition (e) (list :error tag (princ-to-string e)))))))
               (unless (ignore-errors (bob:channel-send (aref *call-replies* slot) reply :timeout 5))
                 (%warn "could not answer an owner-call of ~a" fname)))))
    (:post (destructuring-bind (fname args) (rest m)
             (let ((*task* (list :post fname)))
               (handler-case (apply fname args)
                 (serious-condition (e) (%warn "owner-post of ~a: ~a" fname e))))))
    (:work (destructuring-bind (ticket status value) (rest m)
             (setf (gethash ticket *work-results*) (cons status value))))
    (t (%warn "unknown message ~s" (first m)))))

(defun owner-post (fname args &key (timeout 60))
  "Have the owner run (APPLY FNAME ARGS) the next time it pumps, and return at once (T; NIL if
   the owner's inbox stayed full for TIMEOUT s).  FNAME a symbol, ARGS plain data.  On the owner
   it is a plain call."
  (if (owner-p)
      (progn (apply fname args) t)
      (bob:channel-send *inbox* (list :post fname args) :timeout timeout)))

(define-condition owner-call-error (error)
  ((message :initarg :message :reader owner-call-error-message))
  (:report (lambda (c s) (write-string (owner-call-error-message c) s))))

(defun owner-call (fname args &key (timeout 60))
  "Run (APPLY FNAME ARGS) on the owner, the next time it pumps, and return its value.  For a
   thread that is NOT the owner (on the owner it is a plain call).  FNAME is a symbol; ARGS and
   the value are plain data (they are copied).  An error there, or no answer within TIMEOUT
   seconds, signals OWNER-CALL-ERROR here.  A call refused for an OWNER-LOCK is sent again."
  (when (owner-p) (return-from owner-call (apply fname args)))
  (multiple-value-bind (slot ok) (bob:channel-receive *call-free* :timeout timeout)
    (unless ok (error 'owner-call-error :message "every owner-call slot is busy"))
    (unwind-protect
         (let ((reply-chan (aref *call-replies* slot))
               (deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
           (loop
             (let ((tag (get-internal-real-time)))
               (bob:channel-send *inbox* (list :call slot tag fname args))
               (loop
                 (multiple-value-bind (r got)
                     (bob:channel-receive reply-chan
                                          :timeout (max 0 (/ (- deadline (get-internal-real-time))
                                                             internal-time-units-per-second)))
                   (cond ((not got)
                          (error 'owner-call-error :message (format nil "the owner did not run ~a within ~ds" fname timeout)))
                         ((not (eql (second r) tag)))   ; a late answer to an earlier, timed-out call
                         ((eq (first r) :ok) (return-from owner-call (third r)))
                         ((eq (first r) :busy)
                          (when (> (get-internal-real-time) deadline)
                            (error 'owner-call-error :message (third r)))
                          (sleep 0.05) (return))          ; ask again
                         (t (error 'owner-call-error :message (third r)))))))))
      (bob:channel-send *call-free* slot))))

;;; Work threads: blocking calls (bitcoind RPC) off the owner.  A fixed pool, started on first
;;; use (by the owner: a work thread is started on a named function and channels, so it holds
;;; nothing of the owner's).  A work function is a symbol; its arguments and value plain data.

(defparameter *work-threads* 3 "Work threads (modus has 15 thread slots in all).")
(defvar *work-jobs* (bob:make-channel :capacity +chan-bytes+ :name "cl-deposits work"))
(defvar *work-pool* '())
(defvar *work-ticket* 0)
(defvar *work-pending* 0 "RUN-WORK calls waiting now (owner-side).")

(defvar *work-local* nil "On a work thread: that thread's own table (WORK-LOCAL).")

(defun work-local (key make)
  "On a work thread, that thread's own value for KEY, made by (FUNCALL MAKE) the first time (a
   connection pool kept across calls).  NIL elsewhere."
  (when *work-local*
    (multiple-value-bind (v found) (gethash key *work-local*)
      (if found v (setf (gethash key *work-local*) (funcall make))))))

(defun %work-loop (jobs inbox)
  (let ((*work-local* (make-hash-table :test #'equal)))   ; bound here: this thread's own
   (loop (multiple-value-bind (job ok) (bob:channel-receive jobs)
          (when ok
            (destructuring-bind (ticket fname args) job
              (let ((reply (handler-case (list :work ticket :ok (apply fname args))
                             (serious-condition (e) (list :work ticket :error (princ-to-string e))))))
                (handler-case (bob:channel-send inbox reply :timeout 60)
                  (error ()   ; a value that cannot travel
                    (ignore-errors (bob:channel-send inbox (list :work ticket :error "unsendable value") :timeout 60)))))))))))

(define-condition work-error (error)
  ((message :initarg :message :reader work-error-message))
  (:report (lambda (c s) (write-string (work-error-message c) s))))

(defun run-work (fname args &key (timeout 120))
  "(APPLY FNAME ARGS) on a work thread, pumping meanwhile; its value.  Off the owner it is a
   plain call.  An error there signals WORK-ERROR here (its message), as does no answer within
   TIMEOUT seconds."
  (unless (owner-p) (return-from run-work (apply fname args)))
  (when (null *work-pool*)
    (setf *work-pool* (loop repeat *work-threads*
                            collect (sb-thread:make-thread #'%work-loop :name "cl-deposits work"
                                                                        :arguments (list *work-jobs* *inbox*)))))
  (let ((ticket (incf *work-ticket*)) (*work-pending* (1+ *work-pending*)))
    (bob:channel-send *work-jobs* (list ticket fname args))
    (unless (wait-until (lambda () (nth-value 1 (gethash ticket *work-results*))) :timeout timeout :step 0.2)
      (error 'work-error :message (format nil "~a did not answer within ~ds" fname timeout)))
    (destructuring-bind (status . value) (gethash ticket *work-results*)
      (remhash ticket *work-results*)
      (if (eq status :ok) value (error 'work-error :message value)))))

(defun work-quiet-p () (zerop *work-pending*))

;;; ---------------------------------------------------------------------------
;;; The pump

(defun %next-due ()
  (let ((due nil))
    (dolist (tm *timers*) (unless (timer-running tm) (setf due (if due (min due (timer-due tm)) (timer-due tm)))))
    (dolist (l *lanes*)
      (when (and (lane-items l) (not (lane-busy l)) (> (lane-deferred-until l) 0))
        (setf due (if due (min due (lane-deferred-until l)) (lane-deferred-until l)))))
    due))

(defun %runnable-lane-p (l now)
  (and (lane-live l) (lane-items l) (not (lane-busy l)) (<= (lane-deferred-until l) now)
       (or (null (lane-ready l)) (funcall (lane-ready l)))))

(defun pump (&optional (timeout 0))
  "On the owner: deliver what other threads sent, run the timers that are due and one item of
   every lane that can start, waiting up to TIMEOUT seconds for something to do when nothing
   was.  T if anything ran.  Off the owner it only waits TIMEOUT."
  (unless (owner-p)
    (when (plusp timeout) (sleep timeout))
    (return-from pump nil))
  (let ((*depth* (1+ *depth*)) (any nil))
    (flet ((drain ()
             (loop (multiple-value-bind (m ok) (bob:channel-try-receive *inbox*)
                     (unless ok (return))
                     (setf any t)
                     (%handle-message m)))))
      (drain)
      (when (< *depth* +max-depth+)
        (let ((now (%now)))
          (dolist (tm (copy-list *timers*))
            (when (and (timer-live tm) (not (timer-running tm)) (<= (timer-due tm) now))
              (setf any t) (%run-timer tm) (drain)))
          (let ((ls (copy-list *lanes*)))
            ;; rotate, so no lane always goes first
            (when ls (setf *lanes* (append (rest *lanes*) (list (first *lanes*)))))
            (dolist (l ls)
              (when (%runnable-lane-p l (%now))
                (setf any t) (%run-lane l) (drain))))))
      (when (and (not any) (plusp timeout))
        (let* ((due (%next-due))
               (wait (if due (max 0 (min timeout (- due (%now)))) timeout)))
          (multiple-value-bind (m ok) (bob:channel-receive *inbox* :timeout wait)
            (when ok (setf any t) (%handle-message m) (drain)))))
      any)))

(defun pause-for (seconds)
  "Wait SECONDS, pumping meanwhile (on the owner; elsewhere a SLEEP).  Use this, not SLEEP,
   wherever a node waits for a peer or for time."
  (if (not (owner-p))
      (when (plusp seconds) (sleep seconds))
      (let ((deadline (+ (get-internal-real-time) (* seconds internal-time-units-per-second))))
        (loop (let ((left (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))
                (when (<= left 0) (return))
                (pump (min left 0.05)))))))

(defun wait-until (predicate &key (timeout 5) (step 0.05))
  "Call PREDICATE until it is true or TIMEOUT seconds pass, pumping between tries; its last
   value."
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (loop (let ((v (funcall predicate)))
            (when (or v (> (get-internal-real-time) deadline)) (return v)))
          (if (owner-p)
              (unless (pump 0) (pump (min step (max 0 (/ (- deadline (get-internal-real-time)) internal-time-units-per-second)))))
              (sleep step)))))
