;;;; inspect/update-test.lisp — DEP-02 signed updates, v2 signing.
;;;;
;;;; The cross-implementation vector, inspect/vectors/dep02-signing-v2.json, is
;;;; the spec's (deposits vectors/dep02-signing-v2.json): one update with two
;;;; cosigners, built and signed by the reference.  We rebuild it from the same
;;;; inputs and must match every digest, signature and hash byte for byte.
;;;; The v1 audit fixture (a real reference ledger) retired with v1 signing.

(in-package #:cl-deposits.test)

(with-gate ("tlv")
  (check-equal "bigsize 1 byte" (multiple-value-list (tlv:read-bigsize (hx "fc") 0)) '(252 1))
  (check-equal "bigsize 3 byte" (multiple-value-list (tlv:read-bigsize (hx "fd00fd") 0)) '(253 3))
  (check-signals "bigsize non-minimal" tlv:tlv-error (tlv:read-bigsize (hx "fd00fc") 0))
  (check-bytes "bigsize encode 65536" (tlv:bigsize-bytes 65536) (hx "fe00010000"))
  (check-equal "decode stream" (tlv:decode (hx "000101 0202abcd")) `((0 . ,(hx "01")) (2 . ,(hx "abcd"))))
  (check-signals "out of order" tlv:tlv-error (tlv:decode (hx "0201aa 0001bb")))
  (check-signals "duplicate" tlv:tlv-error (tlv:decode (hx "0001aa 0001bb")))
  (check-signals "overrun" tlv:tlv-error (tlv:decode (hx "0005aa")))
  (check-bytes "encode sorts" (tlv:encode `((2 . ,(hx "abcd")) (0 . ,(hx "01")))) (hx "000101 0202abcd"))
  (check-bytes "base64 roundtrip" (u:base64-decode (u:base64-encode (hx "00ff10"))) (hx "00ff10")))


;;; The vector's inputs (DEP-02 §Signing, test vector).
(defun vector-update ()
  (let* ((key (lambda (b) (u:be->int (make-array 32 :element-type '(unsigned-byte 8) :initial-element b))))
         (fill (lambda (b) (make-array 32 :element-type '(unsigned-byte 8) :initial-element b)))
         (aux (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (u (up:make-signed-update :operator-id (up:compressed-pubkey (funcall key #x11)) :ledger-id (funcall fill #xaa)
                                   :seq 7 :block-height 850000 :block-hash (funcall fill #xbb)
                                   :prev-hash (funcall fill #xcc) :message (hx "00012a"))))
    (setf (up:update-cosignatures u)
          (list (up:sign-cosignature u (funcall key #x22) (up:compressed-pubkey (funcall key #x22)) (funcall fill #x01) :aux aux)
                (up:sign-cosignature u (funcall key #x33) (up:compressed-pubkey (funcall key #x33)) (funcall fill #x02) :aux aux)))
    (setf (up:update-cosignatures u) (up:sorted-cosignatures u))
    (up:sign-operator u (funcall key #x11) :aux aux)
    u))

(defun pget (plist key) (second (member key plist :test #'equal)))

(defun vector-json (u)
  "The vector's fields, as the spec's JSON names them."
  (let ((h #'u:bytes->hex))
    (list "cosign_data" (funcall h (up::cosign-data u))
          "cosigners" (loop for c in (up:update-cosignatures u)
                            collect (list "pubkey" (funcall h (up:cosig-pubkey c))
                                          "member_ledger_hash" (funcall h (up:cosig-member-ledger-hash c))
                                          "digest" (funcall h (up:cosign-digest u (up:cosig-member-ledger-hash c)))
                                          "signature" (funcall h (up:cosig-signature c))))
          "operator_digest" (funcall h (up:operator-digest u))
          "operator_signature" (funcall h (up:update-operator-sig u))
          "current_hash" (funcall h (up:content-hash u))
          "chain_hash" (funcall h (up:chain-hash u))
          "update_tlv" (funcall h (up:encode-update u)))))

(with-gate ("signed-update: the v2 cross-implementation vector")
  (let* ((u (vector-update)) (ours (vector-json u))
         (path (vector-path "dep02-signing-v2.json")))
    (check "the vector update's signatures verify" (and (up:verify-operator-signature u) (up:verify-cosignatures u :threshold 2)))
    (check-bytes "cosign_data layout: seq, ledger_id, height, block_hash, prev, len, message"
                 (up::cosign-data u)
                 (hx (concatenate 'string "0700000000000000" (make-string 64 :initial-element #\a) "50f80c00"
                                  (make-string 64 :initial-element #\b) (make-string 64 :initial-element #\c) "03000000" "00012a")))
    (let ((back (up:decode-update (up:encode-update u))))
      (check-bytes "decode/encode round trip preserves the chain hash" (up:chain-hash back) (up:chain-hash u)))
    (if (probe-file path)
        (let ((theirs (com.inuoe.jzon:parse (uiop:read-file-string path))))
          (dolist (k '("cosign_data" "operator_digest" "operator_signature" "current_hash" "chain_hash" "update_tlv"))
            (check-equal (format nil "~a matches the reference" k) (pget ours k) (gethash k theirs)))
          (loop for c in (pget ours "cosigners") for tc across (gethash "cosigners" theirs) for i from 1
                do (dolist (k '("pubkey" "member_ledger_hash" "digest" "signature"))
                     (check-equal (format nil "cosigner ~a ~a matches the reference" i k) (pget c k) (gethash k tc)))))
        (progn (format t "      no ~a yet: ours is~%" path)
               (format t "~a~%" (com.inuoe.jzon:stringify
                                 (let ((h (make-hash-table :test #'equal)))
                                   (loop for (k v) on ours by #'cddr
                                         do (setf (gethash k h)
                                                  (if (listp v)
                                                      (map 'vector (lambda (c) (let ((hh (make-hash-table :test #'equal)))
                                                                                 (loop for (a b) on c by #'cddr do (setf (gethash a hh) b)) hh))
                                                           v)
                                                      v)))
                                   h)))))))

(with-gate ("signed-update: every field but the signatures is signed")
  (let ((u (vector-update)))
    (flet ((tampered (setter)
             (let ((c (up:decode-update (up:encode-update u)))) (funcall setter c) c)))
      (dolist (case (list (list "ledger_id (relabelled)" (lambda (c) (setf (up:update-ledger-id c) (u:sha256 (hx "0f")))))
                          (list "block_height (re-dated)" (lambda (c) (setf (up:update-block-height c) 850001)))
                          (list "block_hash" (lambda (c) (setf (up:update-block-hash c) (u:sha256 (hx "0e")))))
                          (list "sequence" (lambda (c) (setf (up:update-seq c) 8)))
                          (list "previous_hash" (lambda (c) (setf (up:update-prev-hash c) (u:sha256 (hx "0d")))))
                          (list "message" (lambda (c) (setf (up:update-message c) (hx "00012b"))))))
        (destructuring-bind (what setter) case
          (let ((c (tampered setter)))
            (check (format nil "changing ~a breaks the operator signature" what) (not (up:verify-operator-signature c)))
            (check (format nil "changing ~a breaks every cosignature" what)
                   (notany (lambda (s) (up:verify-cosignature c s)) (up:update-cosignatures c)))
            (check (format nil "changing ~a changes the content hash" what)
                   (not (equalp (up:content-hash c) (up:content-hash u))))))))
    (let ((z (up:decode-update (up:encode-update u))))
      (setf (up:update-cosignatures z) (list (first (up:update-cosignatures z)) (first (up:update-cosignatures z))))
      (check "duplicate cosigner rejected" (not (up:verify-cosignatures z))))
    (check "threshold enforced" (not (up:verify-cosignatures u :threshold 3)))
    (check "quorum membership enforced" (not (up:verify-cosignatures u :quorum (list (up:update-operator-id u)))))))

(with-gate ("signed-update: one encoding per update")
  (let* ((u (vector-update))
         (fields (tlv:decode (up:encode-update u)))
         (with (lambda (type value) (tlv:encode (cons (cons type value) (remove type fields :key #'car))))))
    (check-signals "an explicit zero block_height is refused" tlv:tlv-error
                   (up:decode-update (funcall with 10 (hx "00000000"))))
    (check-signals "an explicit zero block_hash is refused" tlv:tlv-error
                   (up:decode-update (funcall with 12 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
    (dolist (tag '(14 16 18))
      (check-signals (format nil "retired single-cosignature tag ~a is refused" tag) tlv:tlv-error
                     (up:decode-update (funcall with tag (hx "00")))))
    (let ((bare (up:make-signed-update :operator-id (up:update-operator-id u) :ledger-id (up:update-ledger-id u)
                                       :seq 0 :prev-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                       :message (hx "00012a") :operator-sig (make-array 64 :element-type '(unsigned-byte 8) :initial-element 1))))
      (check "zero block fields are omitted, not written"
             (null (intersection '(10 12) (mapcar #'car (tlv:decode (up:encode-update bare))))))
      (check-bytes "an absent block_hash is signed as zero"
                   (subseq (up::cosign-data (up:decode-update (up:encode-update bare))) 44 76)
                   (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))))

(with-gate ("signed-update: a signed chain")
  ;; 52 updates, cosignature sets of 0, 2 and 3, each chaining on the last.
  (let* ((op 12345678901234567890) (cos (list 98765432109876543210 1111111111111111111 2222222222222222222))
         (lid (u:sha256 (hx "01"))) (prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (chain (loop for seq below 52
                      collect (let ((x (up:make-signed-update :operator-id (up:compressed-pubkey op) :ledger-id lid :seq seq
                                                              :prev-hash prev :message (hx (format nil "0001~2,'0x" seq))
                                                              :block-height (+ 800000 seq))))
                                (dolist (c (subseq cos 0 (case (mod seq 3) (0 0) (1 2) (t 3))))
                                  (push (up:sign-cosignature x c (up:compressed-pubkey c) (u:sha256 (u:int->be seq 4))) (up:update-cosignatures x)))
                                (up:sign-operator x op)
                                (setf prev (up:chain-hash x))
                                x))))
    (check "every update round-trips byte for byte"
           (every (lambda (x) (equalp (up:encode-update (up:decode-update (up:encode-update x))) (up:encode-update x))) chain))
    (check "every prev_hash is the chain hash of the update before"
           (loop for (a b) on chain while b always (equalp (up:update-prev-hash b) (up:chain-hash a))))
    (check "every operator signature and cosignature verifies"
           (every (lambda (x) (and (up:verify-operator-signature x) (up:verify-cosignatures x))) chain))
    (defparameter *chain* chain)))

(with-gate ("signed-update: signatures verify under concurrent threads")
  ;; A relay reader and a ledger worker verify at the same time in a daemon;
  ;; secp256k1-fast's scratch buffers must be per-thread for that to be sound.
  (let* ((sample (subseq *chain* 0 40))
         (failures (make-array 4 :initial-element 0))
         (threads (loop for i below 4
                        collect (let ((i i))
                                  (bt:make-thread
                                   (lambda ()
                                     (dotimes (round 3)
                                       (dolist (x sample)
                                         (unless (and (up:verify-operator-signature x)
                                                      (every (lambda (c) (up:verify-cosignature x c)) (up:update-cosignatures x)))
                                           (incf (aref failures i)))))))))))
    (mapc #'bt:join-thread threads)
    (check-equal "4 threads x 3 rounds x 40 updates: no false rejections" (reduce #'+ failures) 0)))

;;; A real v2 ledger: the first 52 updates of the devnet's ledger B (ref2 operates;
;;; cl and reference members cosign, Q = 7, cltv-offset-v2), from cld3's replica after
;;; the 2026-10-02 devnet reset.
(defvar *v2-raw* (read-json-string-array (vector-path "ledger_ffc73cfcc120b84d.json")))
(defvar *v2* (mapcar (lambda (s) (up:decode-update (u:base64-decode s))) *v2-raw*))

(with-gate ("signed-update: a reference-built v2 ledger")
  (check-equal "52 updates" (length *v2*) 52)
  (check-equal "re-encode is byte-identical"
               (loop for raw in *v2-raw* for x in *v2* count (not (equalp (u:base64-decode raw) (up:encode-update x)))) 0)
  (let* ((tips (make-hash-table :test #'equalp))
         (chain (progn (dolist (x *v2*) (setf (gethash (up:update-prev-hash x) tips) x))
                       (loop for x = (gethash (make-array 32 :element-type '(unsigned-byte 8)) tips)
                               then (gethash (up:chain-hash x) tips)
                             while x collect x))))
    (check-equal "the hash chain walks all 52 from genesis" (mapcar #'up:update-seq chain) (loop for i below 52 collect i))
    (check "every operator signature verifies" (every #'up:verify-operator-signature *v2*))
    (check "every cosignature verifies" (every #'up:verify-cosignatures *v2*))
    (check "every update carries the ledger's id" (every (lambda (x) (equalp (up:update-ledger-id x) (up:update-ledger-id (first chain)))) *v2*))
    (check "past the genesis LedgerOpen, every update is stamped with a height and a block hash"
           (every (lambda (x) (and (plusp (up:update-block-height x)) (notevery #'zerop (up:update-block-hash x)))) (rest chain)))
    (let ((replay (lg:make-ledger)) (violations '()) (seen-begin nil))
      (dolist (x chain)
        (let ((o (op:decode-operation (up:update-message x))))
          (when (and seen-begin (not (eq (op:operation-type o) :quorum-begin)))
            (let ((members (mapcar #'lg:member-pubkey (lg:ledger-quorum-members replay))))
              (multiple-value-bind (ok why) (up:verify-cosignatures x :quorum members :threshold (lg:majority-threshold (length members)))
                (unless ok (push (format nil "seq ~a: ~a" (up:update-seq x) why) violations)))))
          (lg:apply-update replay x)
          (when (eq (op:operation-type o) :quorum-begin) (setf seen-begin t))))
      (check "a QuorumBegin is in the first 52" seen-begin)
      (check-equal "after QuorumBegin, every update carries a member majority" (reverse violations) '())
      (check-bytes "the fold's tip is the chain's" (lg:ledger-chain-tip replay) (up:chain-hash (car (last chain)))))))
