;;;; SCRAM functions.
(in-package #:cl-scram)

(defun gen-client-initial-message (&key username nonce)
  (check-type username string)
  (check-type nonce string)
  "Generate the SCRAM-SHA1 initial SASL message."
  (format nil "n,,n=~a,r=~a" username nonce))

(defun gen-client-final-message
    (&key password client-nonce client-initial-message server-response)
  (check-type client-nonce string)
  (check-type client-initial-message string)
  (check-type server-response string)
  (check-type password string)
  "Takes a password, the initial client nonce, the initial client message & the server response.
   Generates the final client message, and returns it along with the server signature."
  (progn
    (if (eq nil (parse-server-nonce :nonce client-nonce :response server-response)) NIL)
    (let* ((final-message-bare (format nil "c=biws,r=~a" (parse-server-nonce :nonce client-nonce
                                                                             :response server-response)))
           (salted-password    (ironclad:pbkdf2-hash-password
                                 (ironclad:ascii-string-to-byte-array password)
                                 :salt       (ironclad:ascii-string-to-byte-array
                                               (parse-server-salt :response server-response))
                                 :digest     :sha1
                                 :iterations (parse-server-iterations :response server-response)))
           (client-key         (gen-hmac-digest :key salted-password
                                                :message (ironclad:ascii-string-to-byte-array "Client Key")))
           (stored-key         (gen-sha1-digest :key client-key))
           (auth-message       (format nil "~a,~a,~a"
                                       client-initial-message
                                       server-response
                                       final-message-bare))
           (client-signature   (gen-hmac-digest :key stored-key
                                                :message (ironclad:ascii-string-to-byte-array auth-message)))
           (client-proof       (logxor (bit-vector->integer client-key)
                                       (bit-vector->integer client-signature)))
           (server-key         (gen-hmac-digest :key salted-password
                                                :message (ironclad:ascii-string-to-byte-array "Server Key")))
           (server-signature   (gen-hmac-digest :key server-key
                                                :message (ironclad:ascii-string-to-byte-array auth-message)))
           (final-message      (format nil "~a,p=~a" final-message-bare (base64-encode
                                                                          (write-to-string client-proof)))))
      (pairlis '(final-message server-signature) (list final-message server-signature)))))

(defun gen-client-encoded-initial-message (&key username nonce)
  (check-type username string)
  (check-type nonce string)
  "Generate a base64-encoded initial request message."
  (base64-encode (gen-client-initial-message :username username :nonce nonce)))

(defun parse-server-response (&key response)
  (check-type response string)
  "Takes a non-encoded server response, & returns three values:
   - The server nonce,
   - The (base64-encoded) salt,
   - The number of iterations."
  (loop :for entry :in (split-sequence:split-sequence #\, response)
     :collect (let ((split-marker (position #\= entry)))
                (cons (subseq entry 0 split-marker)
                      (subseq entry (1+ split-marker))))))

(defun parse-server-nonce (&key response nonce)
  (check-type response string)
  (check-type nonce string)
  "Gets the server nonce from the base64-decoded response string.
   Validates that the server nonce starts with the client nonce."
  (let ((server-nonce
         (cdr (assoc "r"
                     (parse-server-response :response response)
                     :test #'equal))))
    (if (= 0 (search nonce server-nonce))
        server-nonce)))

(defun parse-server-salt (&key response)
  (check-type response string)
  "Gets the base64-decoded salt from the base64-decoded response string."
  (base64-decode (cdr (assoc "s"
                             (parse-server-response :response response)
                             :test #'equal))))

(defun parse-server-iterations (&key response)
  (check-type response string)
  "Gets the number of iterations from the base64-decoded response string."
  (parse-integer (cdr (assoc "i"
                      (parse-server-response :response response)
                      :test #'equal))))
