#lang racket/base

; Challenge 28
;; Implement a SHA-1 keyed MAC

#|
   Find a SHA-1 implementation in the language
   you code in. (I made it).

   Write a function to authenticate a message
   under a secret key by using a secret-prefix
   MAC, which is simply:
      SHA1(key || message)

   Verify you cannot tamper with the message without breaking
   the MAC you've produced, and that you can't produce a new
   MAC without knowing the key.
|#
(require "../util/sha1.rkt"
         "../util/conversions.rkt"
         racket/random)

(provide sha1-mac)

(define KEY (crypto-random-bytes 16))

; mac : bytes -> bytes
;; creates a sha-1 keyed MAC
(define (sha1-mac msg)
  (sha-1 (bytes-append KEY msg)))

(module+ test
  (require rackunit)
  (check-equal?
   (sha1-mac #"Attack at dawn!")
   (sha-1 (bytes-append KEY #"Attack at dawn!")))
  (check-not-equal?
   (sha1-mac #"Attack at dawn!")
   (sha1-mac #"attack at dawn!"))
  (check-not-equal?
   (sha1-mac #"Attack at dawn!")
   (sha1-mac #"Attack at noon!")))