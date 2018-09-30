#lang racket

; Challenge 24
;; Create the MT19937 stream cipher and break it
(require
  racket/random
  "../set1/c2.rkt"
  "c21.rkt")

#|
    You can create a trivial stream cipher out of any PRNG; use it to
    generate a sequence of 8 bit outputs and call those outputs a keystream.
    XOR each byte of plaintext with each successive byte of keystream.

    Write the function that does this for MT19937 using a 16-bit seed.
    Verify that you can encrypt and decrypt properly. This code should  look
    similar to your CTR code.
|#

; encrypt: bytes bytes -> bytes
;; encrypts the pt under the key using MT19937 as a stream cipher
(define (encrypt pt key)
  (define mt (new MT19937% [seed key]))
  (xorstrs
   pt
   (apply
    bytes
    ; generates the key
    (for/list ([i (in-range (bytes-length pt))])
      (bitwise-and (send mt generate-number) #xFF)))))

; decrypt: bytes bytes -> bytes
;; decrypts the MT19937 cipher, same as encrypt
(define (decrypt ct key)
  (encrypt ct key))

#|
   Use your function to encrypt a known plaintext prefixed by a random
   number of random characters.
   From the ciphertext, recover the 'key' (seed).
|#

; get-seed: void -> integer
;; get the key from a known plaintext 
(define (get-seed)
  (define orig #"AAAAAAAAAAAAAA")
  (define txt
    (encrypt
     (bytes-append
      (crypto-random-bytes (random 20))
      orig)
     243))
   (for/last ([i (in-range (expt 2 16))]
              #:final (let ([ct (decrypt txt i)])
                        (bytes=? orig
                                 (subbytes ct (- (bytes-length ct) 14) (bytes-length ct)))))
    i))

#|
   Use the same idea to generate a random 'password reset token' using
   MT19937 seeded from the current time.
|#

; reset-token: void -> bytes
;; generate a reset token using MT19937 seeded with the current time
(define (reset-token)
  (define mt (new MT19937% [seed (current-milliseconds)]))
  (list->bytes
   (for/list ([i (in-range 6)])
     (bitwise-and (send mt generate-number) #xFF))))

#|
   Write a function to check if any given password token is actually
   the product of an MT19937 PRNG seeded with the current time.
|#

; check-token: bytes -> boolean
;; determines if a token was created by seeding MT19937
;; with the current time
(define (check-token token)
  (define start-time (current-milliseconds))
  (for/or ([i (in-range 2000)])
    (define mt (new MT19937% [seed (- start-time i)]))
    (define tok
      (list->bytes
       (for/list ([i (in-range 6)])
         (bitwise-and (send mt generate-number) #xFF))))
    (bytes=? tok token)))

(module+ test
  (require rackunit)
  (define secret #"Attack at dawn")
  (define key 123)
  (check-equal? (decrypt (encrypt secret key) key) secret)
  (check-equal? (get-seed) 243)
  (define tok (reset-token))
  (sleep 0.25)
  (check-true (check-token tok))
  (check-false (check-token #"123456")))