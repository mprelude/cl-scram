;;;; System definition for cl-scram-sha1
(in-package #:cl-user)
(defpackage #:cl-scram-asd
  (:use #:cl #:asdf))
(in-package #:cl-scram-asd)

(asdf:defsystem #:cl-scram
    :name        "cl-scram"
    :author      "Matt Prelude <me@mprelu.de>"
    :version     "0.1"
    :license     "Revised BSD License (see LICENSE)"
    :description "Common lisp library to implement SCRAM-SHA1 SASL mechanism."
    :depends-on  (:cl-sasl
                  :cl-base64
                  :ironclad
                  :secure-random
                  :split-sequence)
    :components  ((:module "src"
                           :serial T
                           :components ((:file "packages")
                                        (:file "utils")
                                        (:file "scram")))
                  (:static-file "README.md")
                  (:static-file "LICENSE")))
