;;;; inspect/harness.lisp — the tiny check/report harness shared by every gate
;;;; (same shape as cl-consensus's and cl-payments's inspect/ suites).

(defpackage #:cl-deposits.test
  (:use #:cl)
  (:local-nicknames (#:u #:cl-deposits.util) (#:tlv #:cl-deposits.tlv)
                    (#:up #:cl-deposits.update) (#:op #:cl-deposits.operation)
                    (#:lg #:cl-deposits.ledger) (#:d17 #:cl-deposits.dep17) (#:rs #:cl-deposits.reserves) (#:rot #:cl-deposits.rotation) (#:lot #:cl-deposits.lottery)
                    (#:btx #:cl-consensus.tx) (#:nd #:cl-deposits.node) (#:w #:cl-deposits.wire)
                    (#:bus #:cl-deposits.bus) (#:ln #:cl-deposits.lightning) (#:fr #:cl-deposits.fraud)
                    (#:secp #:secp256k1-fast.schnorr))
  (:export #:check #:check-equal #:check-bytes #:check-signals #:with-gate #:report
           #:*failures* #:*checks* #:hx #:read-json-string-array #:vector-path))
(in-package #:cl-deposits.test)

(defvar *checks* 0)
(defvar *failures* '())
(defvar *gate* "")

(defun hx (s) (u:hex->bytes (remove-if (lambda (ch) (member ch '(#\Space #\Newline))) s)))

(defun vector-path (name)
  (merge-pathnames (concatenate 'string "inspect/vectors/" name)
                   (asdf:system-source-directory "cl-deposits")))

(defun read-json-string-array (path)
  "The fixtures are JSON arrays of plain strings; this reads exactly that, and
   nothing more, so the gate needs no JSON library."
  (let ((text (with-open-file (in path) (let ((s (make-string (file-length in)))) (subseq s 0 (read-sequence s in)))))
        (out '()) (pos 0))
    (loop for start = (position #\" text :start pos)
          while start
          do (let ((end (position #\" text :start (1+ start))))
               (push (subseq text (1+ start) end) out)
               (setf pos (1+ end))))
    (nreverse out)))

(defun %fail (label detail)
  (push (format nil "~a / ~a: ~a" *gate* label detail) *failures*)
  (format t "~&    FAIL  ~a — ~a~%" label detail))

(defun check (label ok &optional detail)
  (incf *checks*)
  (if ok (format t "~&    ok    ~a~%" label) (%fail label (or detail "assertion failed")))
  ok)

(defun check-equal (label actual expected)
  (check label (equalp actual expected) (format nil "expected ~s, got ~s" expected actual)))

(defun check-bytes (label actual expected)
  (check label (equalp actual expected)
         (format nil "expected ~a, got ~a" (u:bytes->hex expected) (and actual (u:bytes->hex actual)))))

(defmacro check-signals (label condition &body body)
  `(check ,label (handler-case (progn ,@body nil) (,condition () t)) "did not signal"))

(defmacro with-gate ((name) &body body)
  `(let ((*gate* ,name))
     (format t "~&== ~a ==~%" ,name)
     (handler-case (progn ,@body)
       (error (e) (%fail "gate aborted" (princ-to-string e))))))

(defun report ()
  (format t "~&~%~a checks, ~a failures~%" *checks* (length *failures*))
  (dolist (f (reverse *failures*)) (format t "  ~a~%" f))
  (finish-output)
  (uiop:quit (if *failures* 1 0)))
