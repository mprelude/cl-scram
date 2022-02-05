;;;; Define the package & its dependencies.
(defpackage #:cl-scram
  (:use     #:cl
            #:split-sequence)
  (:export  #:base64-decode
            #:base64-encode
            #:base64-encode-octets
            #:gen-client-nonce
            #:gen-client-encoded-initial-message
            #:gen-client-initial-message
            #:gen-client-final-message
            #:gen-sasl-password
            #:parse-server-nonce
            #:parse-server-salt
            #:parse-server-iterations
            #:parse-server-signature))
