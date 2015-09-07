;;;; Utility functions required to implement SCRAM-SHA1.
(in-package #:cl-scram)

(defun base64-encode (string)
  (check-type string string)
  (cl-base64:string-to-base64-string string))

(defun base64-decode (string)
  (check-type string string)
  (cl-base64:base64-string-to-string string))

; Function taken from cl-sasl library.
(defun gen-sasl-password (password)
  (check-type password string)
  "Get a normalized SASL password."
  (etypecase password
    (string password)
    (function
      (funcall password))))

(defun gen-client-nonce ()
  "Generate a random 32-character nonce."
    (let ((chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        (length 32)
        (password (make-string 32)))
    (dotimes (i length)
      (setf (aref password i) (aref chars (secure-random:number (length chars)))))
        password))

(defun gen-hmac-digest (&key key message)
  (check-type key string)
  (check-type message string)
  "Takes a key & a message, and generates a HMAC digest."
  (ironclad:byte-array-to-hex-string
    (ironclad:hmac-digest
      (ironclad:update-hmac
        (ironclad:make-hmac
          (ironclad:ascii-string-to-byte-array key) :sha1)
          (ironclad:ascii-string-to-byte-array message)))))

(defun gen-sha1-digest (&key key)
  (check-type key string)
  "Takes a key, and generates a SHA1 digest."
  (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :sha1
                                                               (ironclad:ascii-string-to-byte-array key))))
