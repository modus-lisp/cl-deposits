;;;; src/util.lisp — byte-level helpers shared by every layer.

(defpackage #:cl-deposits.util
  (:use #:cl)
  (:export #:octets #:cat #:hex->bytes #:bytes->hex #:sha256 #:tagged-hash
           #:be->int #:le->int #:int->be #:int->le #:bytes< #:zero-bytes-p
           #:ascii->bytes #:bytes->ascii #:base64-decode #:base64-encode))
(in-package #:cl-deposits.util)

(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(defun octets (&rest bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes))

(defun cat (&rest vecs)
  (let ((out (make-array (reduce #'+ vecs :key #'length) :element-type '(unsigned-byte 8)))
        (pos 0))
    (dolist (v vecs out)
      (replace out v :start1 pos)
      (incf pos (length v)))))

(defun hex->bytes (hex)
  (let ((out (make-array (floor (length hex) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer hex :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun bytes->hex (bytes)
  (with-output-to-string (s)
    (loop for b across bytes do (format s "~(~2,'0x~)" b))))

(defun sha256 (bytes)
  (ironclad:digest-sequence :sha256 (coerce bytes 'octets)))

(defun ascii->bytes (string)
  (map 'octets #'char-code string))

(defun bytes->ascii (bytes)
  (map 'string #'code-char bytes))

(defun tagged-hash (tag &rest msgs)
  "BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msgs...)."
  (let ((th (sha256 (ascii->bytes tag))))
    (sha256 (apply #'cat th th msgs))))

(defun be->int (bytes &key (start 0) end)
  (let ((n 0))
    (loop for i from start below (or end (length bytes))
          do (setf n (logior (ash n 8) (aref bytes i))))
    n))

(defun le->int (bytes)
  (let ((n 0))
    (loop for i from (1- (length bytes)) downto 0
          do (setf n (logior (ash n 8) (aref bytes i))))
    n))

(defun int->be (n size)
  (let ((out (make-array size :element-type '(unsigned-byte 8))))
    (loop for i from (1- size) downto 0
          do (setf (aref out i) (ldb (byte 8 0) n) n (ash n -8)))
    (unless (zerop n) (error "~a does not fit in ~a bytes" n size))
    out))

(defun int->le (n size)
  (reverse (int->be n size)))

(defun bytes< (a b)
  "Lexicographic byte-vector order, the order Rust's Vec<u8> / [u8; N] sort in."
  (loop for i from 0 below (min (length a) (length b))
        do (cond ((< (aref a i) (aref b i)) (return t))
                 ((> (aref a i) (aref b i)) (return nil)))
        finally (return (< (length a) (length b)))))

(defun zero-bytes-p (bytes) (every #'zerop bytes))

(defparameter +b64+ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun base64-decode (string)
  (let ((bits 0) (nbits 0) (out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for ch across string
          for v = (position ch +b64+)
          do (cond (v (setf bits (logior (ash bits 6) v)) (incf nbits 6)
                      (when (>= nbits 8)
                        (decf nbits 8)
                        (vector-push-extend (ldb (byte 8 nbits) bits) out)
                        (setf bits (ldb (byte nbits 0) bits))))
                   ((member ch '(#\= #\Newline #\Space)))
                   (t (error "bad base64 char ~s" ch))))
    (coerce out 'octets)))

(defun base64-encode (bytes)
  (with-output-to-string (s)
    (loop for i from 0 below (length bytes) by 3
          do (let* ((n (min 3 (- (length bytes) i)))
                    (v (logior (ash (aref bytes i) 16)
                               (if (> n 1) (ash (aref bytes (+ i 1)) 8) 0)
                               (if (> n 2) (aref bytes (+ i 2)) 0))))
               (write-char (char +b64+ (ldb (byte 6 18) v)) s)
               (write-char (char +b64+ (ldb (byte 6 12) v)) s)
               (write-char (if (> n 1) (char +b64+ (ldb (byte 6 6) v)) #\=) s)
               (write-char (if (> n 2) (char +b64+ (ldb (byte 6 0) v)) #\=) s)))))
