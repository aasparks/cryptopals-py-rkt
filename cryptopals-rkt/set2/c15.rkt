#lang racket

(require "c9.rkt")
; Challenge 15
;; PKCS7 Padding Validation

;; Already did this for challenge 9 just because.
;; Let's just run some tests.

(module+ test
  (require rackunit)

  (check-equal? (pkcs7-unpad #"ICE ICE BABY\x04\x04\x04\x04")
                #"ICE ICE BABY")
  (check-exn exn:fail? (λ () (pkcs7-unpad #"ICE ICE BABY\x05\x05\x05\0x5")))
  (check-exn exn:fail? (λ () (pkcs7-unpad #"ICE ICE BABY\x01\x02\x03\x04"))))