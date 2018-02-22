#lang racket

;; This is added to my AES implementation
;; Let's just see the result

(module+ test
  (require "../aes/aes.rkt"
           "../set1/c1.rkt")

  (aes-128-ctr
   (base64->ascii #"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
   #"YELLOW SUBMARINE"
   0)
  )