;;;; src/bolt11.lisp — just enough BOLT #11 to read an invoice's payment hash.

(defpackage #:cl-deposits.lightning.decode
  (:use #:cl #:cl-deposits.util)
  (:export #:payment-hash #:invoice-amount-msat))
(in-package #:cl-deposits.lightning.decode)

(defparameter +charset+ "qpzry9x8gf2tvdw0s3jn54khce6mua7l")

(defun %data (bolt11)
  "The 5-bit data groups after the hrp, minus the 6-group checksum and the 7-group timestamp."
  (let* ((s (string-downcase bolt11)) (sep (position #\1 s :from-end t))
         (groups (loop for ch across (subseq s (1+ sep)) collect (or (position ch +charset+) (error "bad bech32 char")))))
    (values (subseq s 0 sep) (subseq groups 7 (- (length groups) 6)))))

(defun %bytes (groups)
  "Convert 5-bit groups to bytes, dropping the incomplete tail bits."
  (let ((acc 0) (bits 0) (out '()))
    (dolist (g groups) (setf acc (logior (ash acc 5) g)) (incf bits 5)
      (when (>= bits 8) (decf bits 8) (push (ldb (byte 8 bits) acc) out) (setf acc (ldb (byte bits 0) acc))))
    (coerce (nreverse out) 'octets)))

(defun payment-hash (bolt11)
  (multiple-value-bind (hrp groups) (%data bolt11)
    (declare (ignore hrp))
    (loop while (>= (length groups) 3)
          do (let* ((type (first groups)) (len (+ (* 32 (second groups)) (third groups)))
                    (field (subseq groups 3 (+ 3 len))))
               (when (= type 1) (return (subseq (%bytes field) 0 32)))
               (setf groups (subseq groups (+ 3 len))))
          finally (error "no payment hash in invoice"))))

(defun invoice-amount-msat (bolt11)
  "The amount encoded in the hrp, in msat, or NIL."
  (let* ((hrp (string-downcase (subseq bolt11 0 (position #\1 bolt11 :from-end t))))
         (digits (position-if #'digit-char-p hrp)))
    (when digits
      (let* ((num-end (position-if-not #'digit-char-p hrp :start digits))
             (n (parse-integer hrp :start digits :end num-end))
             (mult (and num-end (char hrp num-end))))
        (* n (case mult (#\m 100000000) (#\u 100000) (#\n 100) (#\p 1/10) (t 100000000000)))))))
