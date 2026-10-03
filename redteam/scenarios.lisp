;;;; redteam/scenarios.lisp — the red-team scenario suite against the live devnet.
;;;;   redteam/run-all.sh [--list] [--only a,b] [--skip a,b] [--tags safe,contagion] [--dry-run]
;;;;
;;;; Each scenario is one redteam/attack-*.sh run (with an arm, where it has two) on a fresh
;;;; test ledger (its REDTEAM_x variable gets a per-run name), under a hard timeout.  The
;;;; verdict comes from the script: a line starting PASS, FAIL or SKIP, else its exit status
;;;; (124 = timed out).  After every scenario, pass or fail, every adversary switch on every
;;;; cl node is turned off.  Logs: $CLD_ROOT/soak/scenarios/RUN/NAME.log; summary.tsv beside.
;;;;
;;;; Tags: safe        touches only its own test ledger, or nothing
;;;;       contagion   proofs it provokes dispute SOAK ledgers (the signers' / operator's own)
;;;;       disruptive  stops and restarts nodes
;;;;       slow        > 15 min
;;;; Default order: safe, then contagion, then disruptive.  Mind the soak: a contagion
;;;; scenario confiscates soak ledgers, which soak-rotate must then replace.
;;;;
;;;; Flakiness (the scripts are shell over the control port and log greps, not events):
;;;;  - attack1-invalid-credit / attack-forge-lock read ref2/ref3's node.log by timestamp and
;;;;    sleep fixed intervals; slow relays or a log rotation miss the line.
;;;;  - attack-vault-spend / attack-collude-q7 with reference members: add-member to a busy
;;;;    reference node times out (60 s); the suite forms cl-only quorums for vault spend (REFS="").
;;;;  - attack-dereliction needs RESP blocks with the derelict idle; the soak miner's pace sets it.
;;;;  - attack-withhold-reveal / -missed-confiscation wait for auto-arming, which waits on blocks.
;;;;  - attack-rollback-depth stops cld6 ref6 ref7; a cl restart can take minutes (big histories).
(require :sb-bsd-sockets)
(require :sb-posix)

(defparameter *src* (or (sb-posix:getenv "CLD_SRC") (namestring (merge-pathnames "../" (directory-namestring *load-truename*)))))

(defstruct sc name script (args '()) ledger-var (env '()) (timeout 900) (tags '(:safe)) note)

(defparameter *scenarios*
  (list
   (make-sc :name "invalid-credit-honest" :script "attack1-invalid-credit.sh" :args '("honest") :ledger-var "REDTEAM_IC" :timeout 600)
   (make-sc :name "forge-lock-honest" :script "attack-forge-lock.sh" :args '("honest") :ledger-var "REDTEAM_FL" :timeout 600)
   (make-sc :name "relabel" :script "attack-relabel.sh" :timeout 300)
   (make-sc :name "fuzz-proofs" :script "attack-fuzz-proofs.sh" :timeout 900)
   (make-sc :name "censor-hold-honest" :script "attack-censor-hold.sh" :args '("honest") :ledger-var "REDTEAM_CH" :timeout 600)
   (make-sc :name "censor-hold" :script "attack-censor-hold.sh" :args '("censor") :ledger-var "REDTEAM_CH" :timeout 600
            :note "finding: the escalation lands and nothing acts on it")
   (make-sc :name "vault-rotate-grace" :script "attack-vault-rotate-grace.sh" :args '("inside")
            :ledger-var "REDTEAM_RG" :timeout 900)
   (make-sc :name "invalid-credit-collude" :script "attack1-invalid-credit.sh" :args '("collude")
            :ledger-var "REDTEAM_IC"
            :timeout 600 :tags '(:contagion))
   (make-sc :name "forge-lock-collude" :script "attack-forge-lock.sh" :args '("collude")
            :ledger-var "REDTEAM_FL"
            :timeout 600 :tags '(:contagion))
   (make-sc :name "collude-q7" :script "attack-collude-q7.sh" :ledger-var "REDTEAM_M"
            :env '("WAIT=300") :timeout 1800 :tags '(:contagion))
   (make-sc :name "vault-spend" :script "attack-vault-spend.sh" :ledger-var "REDTEAM_V"
            :env '("REFS=" "WAIT=300") :timeout 1200 :tags '(:contagion))
   (make-sc :name "vault-recovery-tier" :script "attack-vault-recovery-tier.sh" :ledger-var "REDTEAM_RT"
            :timeout 1800 :tags '(:contagion :disruptive :slow) :note "mines past expiry + 720")
   (make-sc :name "vault-rotate-late" :script "attack-vault-rotate-grace.sh" :args '("late")
            :ledger-var "REDTEAM_RG" :timeout 900 :tags '(:contagion) :note "documents the grace bound")
   (make-sc :name "vault-missed-confiscation" :script "attack-vault-missed-confiscation.sh"
            :ledger-var "REDTEAM_MC" :env '("WAIT=900") :timeout 1500 :tags '(:contagion :slow))
   (make-sc :name "withhold-reveal" :script "attack-withhold-reveal.sh" :ledger-var "REDTEAM_W"
            :env '("REFS=" "WAIT=600") :timeout 5400 :tags '(:contagion :slow))
   (make-sc :name "veto-pledge" :script "attack-veto-pledge.sh" :ledger-var "REDTEAM_VP"
            :timeout 2400 :tags '(:contagion) :note "one armer spends its pledge; the confiscation must still land")
   (make-sc :name "veto-pledge-sole" :script "attack-veto-pledge.sh" :args '("sole") :ledger-var "REDTEAM_VPS"
            :timeout 2400 :tags '(:contagion) :note "one eligible armer takes custody without a draw")
   (make-sc :name "veto-pledge-reopen" :script "attack-veto-pledge.sh" :args '("reopen") :ledger-var "REDTEAM_VPR"
            :timeout 3000 :tags '(:contagion) :note "nobody eligible: the honest armer re-arms")
   (make-sc :name "dereliction" :script "attack-dereliction.sh" :ledger-var "REDTEAM_D"
            :timeout 3600 :tags '(:contagion :slow))
   (make-sc :name "rollback-depth" :script "attack-rollback-depth.sh" :ledger-var "REDTEAM_R"
            :timeout 2400 :tags '(:contagion :disruptive :slow))))

(defparameter *switches* '(:cosign-blind :ignore-fraud :ignore-requests :sign-invalid :spend-pledge :theft-sign :withhold-reveal))

;;; --- the devnet, as devnet/_common.sh describes it -------------------------------------

(defun sh (cmd)
  (string-right-trim '(#\Newline)
   (with-output-to-string (s)
     (sb-ext:run-program "/bin/bash" (list "-c" cmd) :output s :error nil :directory *src*))))

(defun split-lines (s)
  (loop for start = 0 then (1+ end) for end = (position #\Newline s :start start)
        collect (subseq s start end) while end))

(defun devnet ()
  "(values cld-root ((name . port) ...))"
  (let ((lines (split-lines (sh "source devnet/_common.sh >/dev/null 2>&1; echo \"$CLD_ROOT\"; printf '%s\\n' \"${CLD_NODES[@]}\""))))
    (values (first lines)
            (loop for e in (rest lines)
                  for c = (position #\: e :from-end t)
                  when c collect (cons (subseq e 0 (position #\: e)) (parse-integer e :start (1+ c) :junk-allowed t))))))

(defun control (port form &key (timeout 30))
  "One request/response on a cl node's control port; NIL if it does not answer."
  (handler-case
      (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
        (unwind-protect
             (progn
               (sb-bsd-sockets:socket-connect s #(127 0 0 1) port)
               (let ((io (sb-bsd-sockets:socket-make-stream s :input t :output t :external-format :utf-8 :timeout timeout)))
                 (write-line form io) (finish-output io)
                 (read-line io nil nil)))
          (sb-bsd-sockets:socket-close s)))
    (error () nil)))

(defun disarm-all (nodes)
  "Every adversary switch off (a scenario killed by its timeout never runs its own restore)."
  (let ((form (format nil "(:adversary :set~{ ~s nil~})" *switches*)))
    (loop for (name . port) in nodes
          unless (search ":STATUS :OK" (or (control port form) ""))
            collect name)))

;;; --- running ------------------------------------------------------------------------------

(defun now () (get-universal-time))

(defun excerpt (file &optional (n 4))
  (let ((lines (with-open-file (in file :if-does-not-exist nil :external-format :utf-8)
                 (and in (loop for l = (read-line in nil) while l collect l)))))
    (last (remove-if (lambda (l) (zerop (length (string-trim " " l)))) lines) n)))

(defun verdict (file exit)
  (let ((lines (with-open-file (in file :if-does-not-exist nil :external-format :utf-8)
                 (and in (loop for l = (read-line in nil) while l collect l)))))
    (flet ((starts (p) (find-if (lambda (l) (and (>= (length l) (length p)) (string= p l :end2 (length p)))) lines :from-end t)))
      (cond ((eql exit 124) :timeout)
            ((starts "FAIL") :fail)
            ((starts "SKIP") :skip)
            ((and (starts "PASS") (eql exit 0)) :pass)
            ((starts "NOTE") :note)
            (t :fail)))))

(defun run-one (sc run-id dir nodes)
  (let* ((log (format nil "~a/~a.log" dir (sc-name sc)))
         (env (append (sc-env sc)
                      (and (sc-ledger-var sc) (list (format nil "~a=~a-~a" (sc-ledger-var sc) (sc-name sc) run-id)))))
         (cmd (format nil "env ~{~a ~}timeout --kill-after=15 ~a bash redteam/~a~{ ~a~} >~a 2>&1"
                      env (sc-timeout sc) (sc-script sc) (sc-args sc) log))
         (t0 (now)) exit)
    (format t "~&-- ~a (~{~(~a~)~^,~}) ... " (sc-name sc) (sc-tags sc)) (finish-output)
    (unwind-protect
         (setf exit (sb-ext:process-exit-code (sb-ext:run-program "/bin/bash" (list "-c" cmd) :directory *src* :output nil :error nil)))
      (let ((stuck (disarm-all nodes)))
        (when stuck (format t "~&   (could not disarm: ~{~a~^ ~})~%" stuck))))
    (let ((v (verdict log exit)) (dt (- (now) t0)))
      (format t "~a  ~ds~%" v dt)
      (unless (eq v :pass) (dolist (l (excerpt log)) (format t "     | ~a~%" (subseq l 0 (min 160 (length l))))))
      (list (sc-name sc) v dt exit log))))

(defun split (s)
  (and s (loop for start = 0 then (1+ end)
               for end = (position #\, s :start start)
               for part = (string-trim " " (subseq s start end))
               unless (string= part "") collect part
               while end)))

(defun option (args name) (let ((m (member name args :test #'string=))) (and m (second m))))

(defun select (args)
  (let ((only (split (option args "--only"))) (skip (split (option args "--skip")))
        (tags (mapcar (lambda (x) (intern (string-upcase x) :keyword)) (split (option args "--tags")))))
    (remove-if-not (lambda (sc)
                     (and (or (null only) (member (sc-name sc) only :test #'string=))
                          (not (member (sc-name sc) skip :test #'string=))
                          (or (null tags) (intersection tags (sc-tags sc)))))
                   *scenarios*)))

(defun main (args)
  (let ((chosen (select args)))
    (when (member "--list" args :test #'string=)
      (dolist (sc *scenarios*)
        (format t "~28a ~22a ~{~(~a~)~^,~}~@[  — ~a~]~%" (sc-name sc)
                (format nil "~a~{ ~a~}" (sc-script sc) (sc-args sc)) (sc-tags sc) (sc-note sc)))
      (return-from main 0))
    (multiple-value-bind (root nodes) (devnet)
      (let* ((run-id (multiple-value-bind (s m h d mo) (decode-universal-time (now) 0)
                       (format nil "~2,'0d~2,'0d-~2,'0d~2,'0d~2,'0d" mo d h m s)))
             (dir (format nil "~a/soak/scenarios/~a" root run-id))
             (down (loop for (name . port) in nodes unless (control port "(:info)" :timeout 10) collect name)))
        (format t "scenario run ~a: ~d scenario~:p~@[; cl nodes not answering: ~{~a~^ ~}~]~%" run-id (length chosen) down)
        (when (member "--dry-run" args :test #'string=)
          (dolist (sc chosen) (format t "  would run ~a~%" (sc-name sc)))
          (return-from main 0))
        (ensure-directories-exist (format nil "~a/" dir))
        (let ((results (mapcar (lambda (sc) (run-one sc run-id dir nodes)) chosen)))
          (with-open-file (o (format nil "~a/summary.tsv" dir) :direction :output :if-exists :supersede)
            (dolist (r results) (format o "~{~a~^	~}~%" r)))
          (format t "~%~28a ~8a ~6a~%" "scenario" "verdict" "secs")
          (dolist (r results) (format t "~28a ~8a ~6d~%" (first r) (second r) (third r)))
          (let ((bad (count-if-not (lambda (r) (member (second r) '(:pass :skip))) results)))
            (format t "~%~d passed, ~d not; logs in ~a~%" (count :pass results :key #'second) bad dir)
            (if (zerop bad) 0 1)))))))

(sb-ext:exit :code (main (rest (member "--" sb-ext:*posix-argv* :test #'string=))))
