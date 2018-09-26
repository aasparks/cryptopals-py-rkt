#lang racket

; Challenge 28
;; Implement a SHA-1 keyed MAC

;;; Find a SHA-1 implementation in the language
;;; you code in. (I made it).
(require "../sha1/sha1.rkt"
         "../set1/c1.rkt"
         racket/random)

(provide mac)

;;; Write a function to authenticate a message
;;; under a secret key by using a secret-prefix
;;; MAC, which is simply:
;;;    SHA1(key || message)
(define KEY (crypto-random-bytes 16))

(define (mac msg)
  (sha-1 (bytes-append KEY msg)))

;;; Verify you cannot tamper with the message without breaking
;;; the MAC you've produced, and that you can't produce a new
;;; MAC without knowing the key.
(module+ test
  (ascii->hex (mac #"Attack at dawn!")))