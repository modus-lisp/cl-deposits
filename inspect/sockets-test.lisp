;;;; inspect/sockets-test.lisp — the daemon's three socket paths, over real loopback TCP.
;;;;
;;;; 1. bitcoind JSON-RPC (RPC-CALL-TEXT / RPC-EXCHANGE): against a fake bitcoind that is
;;;;    NOT ours -- Python's http.server, HTTP/1.1 keep-alive -- so the pooled connection
;;;;    is reused for real, and a server that closes after one answer forces the retry.
;;;; 2. the control socket (START-CONTROL-SERVER): one s-expression a line, a character
;;;;    stream each way.
;;;; 3. cl-payments' control socket (CLP-CALL): against a stand-in speaking its protocol.
;;;;
;;;; 127.0.0.1 and ephemeral ports only.  The fake bitcoind exits by itself.

(in-package #:cl-deposits.test)

(defun %byte-line (s)
  "One line of a byte stream, without its CRLF."
  (let ((out (make-string-output-stream)))
    (loop for b = (read-byte s nil) until (or (null b) (= b 10))
          unless (= b 13) do (write-char (code-char b) out))
    (get-output-stream-string out)))

(defun %free-port ()
  (let ((l (cl-transport.sockets:tcp-listen :port 0))) (prog1 (cl-transport.sockets:tcp-listener-port l) (cl-transport.sockets:tcp-listener-close l))))

(defparameter +fake-bitcoind+ "
import http.server, json, sys, base64, signal
signal.alarm(60)   # exits by itself whatever happens to the test
port = int(sys.argv[1]); served = 0
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def do_POST(self):
        global served
        n = int(self.headers['Content-Length']); req = json.loads(self.rfile.read(n))
        auth = self.headers.get('Authorization', '')
        ok_auth = auth == 'Basic ' + base64.b64encode(b'u:p').decode()
        served += 1
        if not ok_auth: res = {'result': None, 'error': {'code': -1, 'message': 'auth'}, 'id': req['id']}
        elif req['method'] == 'getblockcount': res = {'result': 812345, 'error': None, 'id': req['id']}
        elif req['method'] == 'echo': res = {'result': req['params'], 'error': None, 'id': req['id']}
        elif req['method'] == 'conn': res = {'result': '%s:%d' % self.client_address, 'error': None, 'id': req['id']}
        else: res = {'result': None, 'error': {'code': -32601, 'message': 'no'}, 'id': req['id']}
        body = json.dumps(res, separators=(',', ':')).encode()   # bitcoind's compact form
        if served >= 6: self.close_connection = True
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
s = http.server.HTTPServer(('127.0.0.1', port), H)
s.timeout = 20
print('ready', flush=True)
while served < 6: s.handle_request()
s.server_close()
")

(with-gate ("sockets")
  ;; --- 1. JSON-RPC to an independent HTTP/1.1 server ---
  (let* ((port (%free-port))
         (proc (sb-ext:run-program "python3" (list "-I" "-c" +fake-bitcoind+ (princ-to-string port))
                                   :search t :wait nil :output :stream :error nil)))
    (unwind-protect
         (progn
           (check "the fake bitcoind came up" (equal (read-line (sb-ext:process-output proc) nil) "ready"))
           (let ((e (cl-deposits.daemon::make-rpc-endpoint :host "127.0.0.1" :port port :user "u" :password "p")))
             (check-equal "getblockcount over JSON-RPC" (cl-deposits.daemon::rpc-call-text e "getblockcount" nil) "812345")
             (check-equal "a structured result as bitcoind's text"
                          (cl-deposits.daemon::rpc-call-text e "echo" (list "1" "abc")) "[1,\"abc\"]")
             (let ((a (cl-deposits.daemon::rpc-call-text e "conn" nil))
                   (b (cl-deposits.daemon::rpc-call-text e "conn" nil)))
               (check-equal "the pooled keep-alive connection is reused (same client port)" a b))
             (check-equal "an RPC error is \"\", as bitcoin-cli's stdout"
                          (cl-deposits.daemon::rpc-call-text e "nosuch" nil) "")
             ;; the same endpoint (this one-connection fake serves the pooled socket only)
             (setf (cl-deposits.daemon::rpc-endpoint-password e) "x")
             (check-equal "the credentials are what decide" (cl-deposits.daemon::rpc-call-text e "getblockcount" nil) "")))
      (sb-ext:process-wait proc)
      (sb-ext:process-close proc)))
  ;; a server that closes after each answer: the pooled connection is dead, the retry dials
  (let* ((listener (cl-transport.sockets:tcp-listen :port 0)) (port (cl-transport.sockets:tcp-listener-port listener))
         (server (sb-thread:make-thread
                  (lambda ()
                    (dotimes (i 2)
                      (let* ((c (cl-transport.sockets:tcp-accept listener :timeout-ms 10000)) (s (cl-transport.sockets:tcp-socket-stream c)))
                        (loop for line = (%byte-line s) until (zerop (length line)))
                        (let ((body (sb-ext:string-to-octets (format nil "{\"result\":~d,\"error\":null,\"id\":\"cl\"}" i))))
                          (write-sequence (sb-ext:string-to-octets
                                           (format nil "HTTP/1.1 200 OK~c~cContent-Length: ~d~c~c~c~c" #\Return #\Newline
                                                   (length body) #\Return #\Newline #\Return #\Newline)) s)
                          (write-sequence body s))
                        (cl-transport.sockets:tcp-close c)))
                    (cl-transport.sockets:tcp-listener-close listener)))))
    (let ((e (cl-deposits.daemon::make-rpc-endpoint :host "127.0.0.1" :port port :user "u" :password "p")))
      (check-equal "first call" (cl-deposits.daemon::rpc-call-text e "x" nil) "0")
      (check-equal "a closed pooled connection is redialled" (cl-deposits.daemon::rpc-call-text e "x" nil) "1"))
    (sb-thread:join-thread server :default nil))
  ;; --- 2. the control socket ---
  (let* ((port (%free-port)))
    (cl-deposits.daemon:start-control-server nil port)
    (let* ((c (cl-transport.sockets:tcp-connect "127.0.0.1" port)) (s (cl-transport.sockets:tcp-socket-stream c :element-type 'character)))
      (unwind-protect
           (progn (write-line "((( not a form" s) (finish-output s)
                  (check-equal "the control socket answers a line with a line" (read-line s nil)
                               "(:status :error :message \"unreadable\")"))
        (cl-transport.sockets:tcp-close c))))
  ;; --- 3. cl-payments' control socket ---
  (let* ((listener (cl-transport.sockets:tcp-listen :port 0)) (port (cl-transport.sockets:tcp-listener-port listener))
         (server (sb-thread:make-thread
                  (lambda ()
                    (let* ((c (cl-transport.sockets:tcp-accept listener :timeout-ms 10000))
                           (s (cl-transport.sockets:tcp-socket-stream c :element-type 'character))
                           (form (let ((*read-eval* nil)) (read-from-string (read-line s)))))
                      (format s "(:status :ok :echo ~s)~%" (getf (rest form) :amount-msat)) (finish-output s)
                      (cl-transport.sockets:tcp-close c)
                      (cl-transport.sockets:tcp-listener-close listener))))))
    (check-equal "clp-call: one form out, one form back"
                 (cl-deposits.lightning::clp-call (ln:make-clp-backend "127.0.0.1" port) "(:invoice :amount-msat 2100 :description \"x\")")
                 '(:status :ok :echo 2100))
    (sb-thread:join-thread server :default nil))
  (check "usocket is not loaded" (not (find-package "USOCKET"))))

(report)
