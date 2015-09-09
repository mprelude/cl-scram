;;;; Conditions

;;; Signalled when the server returns a nonce which
;;; doesn't start with the client nonce.
(define-condition unexpected-nonce (error)
  ((text :initarg :text :reader text)))
