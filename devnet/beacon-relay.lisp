;;;; devnet/beacon-relay.lisp — the devnet relay: beacon, configured for the devnet.
;;;;
;;;;   sbcl --load devnet/beacon-relay.lisp            serve (env below)
;;;;   sbcl --load devnet/beacon-relay.lisp import F   load relay.py's JSONL store F into the beacon store, then exit
;;;;
;;;; Env: RELAY_PORT (7777), BEACON_DIR (beacon data), RELAY_FAULTS (red-team rules).
;;;;
;;;; What the devnet needs beyond a stock relay, all of it relay.py behaviour:
;;;;  - no result cap: a node fetching a ledger's history asks for every update (no limit);
;;;;  - no rate limits: one bot connection publishes hundreds of events a second;
;;;;  - ephemeral responses (20102) kept 10 min for REQs with `since`: the reference
;;;;    daemon polls for its confiscation_sign replies instead of subscribing first.
;;;;    Requests (20101) are never kept: a node handed stale requests re-executes them;
;;;;  - fault injection: RELAY_FAULTS is a JSON list of rules, re-read when it changes,
;;;;    {"kind": 20101, "author": "hexprefix", "action": "theft_sign", "to": "hex",
;;;;     "drop": true, "delay": 30} — all fields optional, every matching rule applies.
;;;;    drop: refuse (OK false); delay: accept now, deliver/store that many seconds late.
;;;;    action is the "action" tag of 20101/20102 (or "action" in a response's content).

(load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname)))
(let ((*compile-verbose* nil)) (funcall (intern "QUICKLOAD" "QL") :beacon :silent t))

(defpackage #:devnet-relay (:use #:cl))
(in-package #:devnet-relay)

(defun env (k default) (or (sb-posix:getenv k) default))

(setf beacon::*default-limit* 100000000
      beacon::*max-limit* 100000000
      beacon::*max-scan* 100000000
      beacon::*max-content-chars* (* 4 1024 1024))

;;; ---- fault rules ------------------------------------------------------------------

(defvar *faults-path* (env "RELAY_FAULTS" "/tmp/cld-relay.jsonl.faults.json"))
(defvar *faults* '())
(defvar *faults-mtime* nil)
(defvar *faults-lock* (sb-thread:make-mutex :name "faults"))

(defun faults ()
  (sb-thread:with-mutex (*faults-lock*)
    (let ((mtime (ignore-errors (file-write-date *faults-path*))))
      (unless (eql mtime *faults-mtime*)
        (setf *faults-mtime* mtime
              *faults* (or (ignore-errors
                            (let ((v (beacon::json-parse-string
                                      (with-open-file (s *faults-path* :external-format :utf-8)
                                        (let ((str (make-string (file-length s))))
                                          (subseq str 0 (read-sequence str s)))))))
                              (and (simple-vector-p v) (coerce v 'list))))
                           '()))
        (format *error-output* "~&relay: ~d fault rules loaded~%" (length *faults*)))
      *faults*)))

(defun tag-values (e name)
  (loop for tag across (beacon:event-tags e)
        when (and (>= (length tag) 2) (string= (svref tag 0) name)) collect (svref tag 1)))

(defun event-action (e)
  (when (member (beacon:event-kind e) '(20101 20102))
    (or (first (tag-values e "action"))
        (ignore-errors (let ((v (beacon::json-get (beacon::json-parse-string (beacon:event-content e)) "action")))
                         (and (stringp v) v)))
        "")))

(defun rule-matches-p (r e)
  (flet ((field (k) (beacon::json-get r k)))
    (and (or (null (field "kind")) (eql (field "kind") (beacon:event-kind e)))
         (or (null (field "author"))
             (let ((pk (beacon:hex-encode (beacon:event-pubkey e))))
               (and (<= (length (field "author")) 64) (string= (field "author") pk :end2 (length (field "author"))))))
         (or (null (field "action")) (equal (field "action") (event-action e)))
         (or (null (field "to")) (member (field "to") (tag-values e "p") :test #'string=)))))

(defun fault-policy (e)
  (let ((drop nil) (delay 0))
    (dolist (r (faults))
      (when (and (listp r) (rule-matches-p r e))
        (when (eq (beacon::json-get r "drop") :true) (setf drop t))
        (let ((d (beacon::json-get r "delay"))) (when (realp d) (setf delay (max delay d))))))
    (cond (drop '(:drop "policy"))
          ((plusp delay) delay))))

;;; ---- import relay.py's store ----------------------------------------------------------

(defun import-jsonl (path dir)
  (let ((store (beacon:open-store dir :sync :never)) (batch '()) (n 0) (bad 0))
    (flet ((flush () (when batch (beacon::store-insert-batch store (nreverse batch)) (setf batch '()))))
      (with-open-file (s path :external-format :utf-8)
        (loop for line = (read-line s nil) while line do
          (let ((e (ignore-errors (beacon:parse-event-json line))))
            (cond ((null e) (incf bad))
                  ((<= 20000 (beacon:event-kind e) 29999))
                  (t (push e batch) (incf n) (when (>= (length batch) 4096) (flush)))))))
      (flush))
    (format t "imported ~:d events (~:d unparseable) into ~a; store holds ~:d~%"
            n bad dir (beacon:store-event-count store))
    (beacon::store-fsync store)
    (beacon:close-store store)))

;;; ---- main ---------------------------------------------------------------------------

(defun serve ()
  (setf (sb-ext:bytes-consed-between-gcs) (* 256 1024 1024))
  (let ((relay (beacon:start-relay
                (beacon:make-config :port (parse-integer (env "RELAY_PORT" "7777"))
                                    :dir (env "BEACON_DIR" "./beacon-data/")
                                    :max-message (* 4 1024 1024)
                                    :max-subscriptions 10000 :max-filters 100
                                    :events-per-second 1000000 :event-burst 1000000
                                    :reqs-per-second 1000000 :req-burst 1000000
                                    :io-threads 4 :verify-threads 4 :query-threads 8
                                    :name "cl-deposits devnet"
                                    :event-policy #'fault-policy
                                    :retain-ephemeral (lambda (e) (/= (beacon:event-kind e) 20101))
                                    :ephemeral-ttl 600))))
    (faults)
    (loop (sleep 60)
          (format *error-output* "~&relay: ~a~%" (sb-ext:octets-to-string (beacon::relay-stats-json relay)))
          (finish-output *error-output*))))

(let ((args (uiop:command-line-arguments)))
  (if (equal (first args) "import")
      (import-jsonl (second args) (env "BEACON_DIR" "./beacon-data/"))
      (serve)))
