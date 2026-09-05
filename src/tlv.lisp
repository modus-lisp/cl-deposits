;;;; src/tlv.lisp — DEP-02 TLV streams.
;;;;
;;;; The Deposits wire format is Lightning's TLV: BigSize type, BigSize length,
;;;; value; records in strictly ascending type order.  Every layer of a
;;;; SignedLedgerUpdate (the outer update, the inner operation, the nested fee
;;;; structures) is one of these streams.

(defpackage #:cl-deposits.tlv
  (:use #:cl #:cl-deposits.util)
  (:export #:read-bigsize #:bigsize-bytes #:decode #:encode #:tlv-error
           #:field #:u8 #:u16 #:u32 #:u64))
(in-package #:cl-deposits.tlv)

(define-condition tlv-error (error)
  ((detail :initarg :detail :reader detail))
  (:report (lambda (c s) (format s "TLV: ~a" (detail c)))))

(defun read-bigsize (bytes pos)
  "Returns (values n new-pos).  Rejects non-minimal encodings, as BOLT #1 does."
  (when (>= pos (length bytes)) (error 'tlv-error :detail "truncated BigSize"))
  (let ((b (aref bytes pos)))
    (flet ((take (len min)
             (when (> (+ pos 1 len) (length bytes)) (error 'tlv-error :detail "truncated BigSize"))
             (let ((n (be->int bytes :start (1+ pos) :end (+ pos 1 len))))
               (when (< n min) (error 'tlv-error :detail "non-minimal BigSize"))
               (values n (+ pos 1 len)))))
      (cond ((< b #xfd) (values b (1+ pos)))
            ((= b #xfd) (take 2 #xfd))
            ((= b #xfe) (take 4 #x10000))
            (t (take 8 #x100000000))))))

(defun bigsize-bytes (n)
  (cond ((< n #xfd) (octets n))
        ((< n #x10000) (cat (octets #xfd) (int->be n 2)))
        ((< n #x100000000) (cat (octets #xfe) (int->be n 4)))
        (t (cat (octets #xff) (int->be n 8)))))

(defun decode (bytes)
  "A TLV stream as an alist of (type . value-bytes), in wire order.  Types must
   ascend strictly; the stream must end exactly on a record boundary."
  (let ((pos 0) (out '()) (last -1))
    (loop while (< pos (length bytes))
          do (multiple-value-bind (type p) (read-bigsize bytes pos)
               (multiple-value-bind (len p2) (read-bigsize bytes p)
                 (when (<= type last)
                   (error 'tlv-error :detail (format nil "type ~a out of order after ~a" type last)))
                 (when (> (+ p2 len) (length bytes))
                   (error 'tlv-error :detail (format nil "type ~a: length ~a overruns stream" type len)))
                 (push (cons type (subseq bytes p2 (+ p2 len))) out)
                 (setf last type pos (+ p2 len)))))
    (nreverse out)))

(defun encode (alist)
  "The canonical stream for an alist of (type . value-bytes): sorted by type."
  (apply #'cat
         (loop for (type . value) in (sort (copy-list alist) #'< :key #'car)
               collect (cat (bigsize-bytes type) (bigsize-bytes (length value)) value))))

(defun field (alist type) (cdr (assoc type alist)))
(defun u8 (bytes) (be->int bytes))
(defun u16 (bytes) (be->int bytes))
(defun u32 (bytes) (be->int bytes))
(defun u64 (bytes) (be->int bytes))
