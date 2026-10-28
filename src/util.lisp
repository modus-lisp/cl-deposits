;;;; src/util.lisp — byte-level helpers shared by every layer.

(defpackage #:cl-deposits.util
  (:use #:cl)
  (:export #:octets #:cat #:hex->bytes #:bytes->hex #:sha256 #:tagged-hash
           #:be->int #:le->int #:int->be #:int->le #:bytes< #:zero-bytes-p
           #:ascii->bytes #:bytes->ascii #:base64-decode #:base64-encode #:txid-bytes #:txid-hex))
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

(defparameter +b64-values+
  (let ((v (make-array 128 :element-type '(signed-byte 8) :initial-element -1)))
    (loop for i from 0 for ch across +b64+ do (setf (aref v (char-code ch)) i))
    (loop for ch in '(#\= #\Newline #\Space #\Return #\Tab) do (setf (aref v (char-code ch)) -2))
    v)
  "char code -> 6-bit value; -2 for padding and whitespace (skipped); -1 for anything else.")

(defun base64-decode (string)
  "Table lookup into a preallocated vector.  The old POSITION-in-the-alphabet per character
   and VECTOR-PUSH-EXTEND per byte were two thirds of a soaked node's 3-minute restart."
  (let* ((string (if (simple-string-p string) string (coerce string 'simple-string)))
         (n (length string))
         (out (make-array (* 3 (ceiling n 4)) :element-type '(unsigned-byte 8)))
         (table +b64-values+) (bits 0) (nbits 0) (j 0))
    (declare (simple-string string) (fixnum n j nbits) (type (unsigned-byte 32) bits)
             (type (simple-array (signed-byte 8) (128)) table) (type octets out)
             (optimize speed (safety 1)))
    (dotimes (i n)
      (let* ((ch (schar string i)) (code (char-code ch))
             (v (if (< code 128) (aref table code) -1)))
        (cond ((>= v 0)
               (setf bits (logior (logand (ash bits 6) #xffffff) v)) (incf nbits 6)
               (when (>= nbits 8)
                 (decf nbits 8)
                 (setf (aref out j) (ldb (byte 8 nbits) bits)) (incf j)))
              ((= v -2))
              (t (error "bad base64 char ~s" ch)))))
    (if (= j (length out)) out (subseq out 0 j))))

(defun base64-encode (bytes)
  (let* ((bytes (if (typep bytes 'octets) bytes (coerce bytes 'octets)))
         (n (length bytes))
         (out (make-string (* 4 (ceiling n 3)) :element-type 'base-char))
         (alphabet (coerce +b64+ 'simple-base-string)))
    (declare (type octets bytes) (fixnum n) (simple-base-string out alphabet) (optimize speed (safety 1)))
    (loop for i fixnum from 0 below n by 3
          for o fixnum from 0 by 4
          do (let* ((k (min 3 (- n i)))
                    (v (logior (ash (aref bytes i) 16)
                               (if (> k 1) (ash (aref bytes (+ i 1)) 8) 0)
                               (if (> k 2) (aref bytes (+ i 2)) 0))))
               (declare (fixnum k v))
               (setf (schar out o) (schar alphabet (ldb (byte 6 18) v))
                     (schar out (+ o 1)) (schar alphabet (ldb (byte 6 12) v))
                     (schar out (+ o 2)) (if (> k 1) (schar alphabet (ldb (byte 6 6) v)) #\=)
                     (schar out (+ o 3)) (if (> k 2) (schar alphabet (ldb (byte 6 0) v)) #\=))))
    out))

;;; Transaction ids on the wire are in INTERNAL byte order (what rust-bitcoin's
;;; Txid::as_ref() yields); the hex people read is the reverse.  The fixture's
;;; QuorumBegin proves it: its new_outpoint_txid, reversed, is a confirmed
;;; mainnet transaction.
(defun txid-bytes (display-hex) (reverse (hex->bytes display-hex)))
(defun txid-hex (bytes) (bytes->hex (reverse bytes)))
