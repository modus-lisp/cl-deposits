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
;;;;     CONDITION-WAIT everywhere a node waits for a peer or for time.
;;;;   - FOREIGN THREADS (a control client, a relay reader) never touch a node: OWNER-CALL /
;;;;     OWNER-POST send a named function and plain arguments to the owner.  Blocking I/O the
;;;;     owner should not wait on (bitcoind RPC) goes to a WORK thread (RUN-WORK).
;;;;
;;;; ALL OF IT IS BOBBIN'S OWNER LOOP (BOBBIN.OWNER, bobbin's src/owner.lisp, which documents
;;;; it, OWNER-LOCK and nested waits included): this package re-exports it under the names
;;;; cl-deposits has always used.  It is one loop per process, so cl-consensus's net layer
;;;; (loaded with us) is drained by the same pump: a lane waiting in PAUSE-FOR delivers network
;;;; input too, and a net wait (a handshake's read) runs our lanes and timers.

(defpackage #:cl-deposits.owner
  (:use #:cl)
  (:import-from #:bobbin.owner
                #:owner-p #:pump #:pause-for #:wait-until #:*task* #:task-name #:pump-depth
                #:lane #:make-lane #:lane-p #:lane-name #:lane-items #:lane-push #:lane-push-front
                #:lane-close #:lane-busy-p #:lane-idle-p #:lane-live-p #:lane-depth #:lane-runs
                #:timer #:every-seconds #:after-seconds #:cancel-timer #:timer-live-p #:timer-runs
                #:owner-lock #:with-owner-lock #:owner-busy #:owner-lock-held-p
                #:owner-call #:owner-post #:owner-call-error #:owner-call-error-message
                #:run-work #:work-error #:work-local #:work-quiet-p)
  (:export #:owner-p #:pump #:pause-for #:wait-until #:*task* #:task-name #:pump-depth
           #:lane #:make-lane #:lane-p #:lane-name #:lane-items #:lane-push #:lane-push-front #:lane-close
           #:lane-busy-p #:lane-idle-p #:lane-live-p #:lane-depth #:lane-runs
           #:timer #:every-seconds #:after-seconds #:cancel-timer #:timer-live-p #:timer-runs
           #:owner-lock #:with-owner-lock #:owner-busy #:owner-lock-held-p
           #:owner-call #:owner-post #:owner-call-error #:owner-call-error-message
           #:run-work #:work-error #:work-local
           #:work-quiet-p))
(in-package #:cl-deposits.owner)

;;; The thread that loads cl-deposits owns the nodes (and bobbin's owner loop).
(bobbin.owner:start-owner)
