#lang racket/base

; Challenge 24
;; Create the MT19937 stream cipher and break it

(require racket/random
         racket/class
         "../util/conversions.rkt"
         "../util/mt19937.rkt")
(provide encryption-oracle
         get-seed
         reset-token
         check-token)

#|
    You can create a trivial stream cipher out of any PRNG; use it to
    generate a sequence of 8 bit outputs and call those outputs a keystream.
    XOR each byte of plaintext with each successive byte of keystream.

    Write the function that does this for MT19937 using a 16-bit seed.
    Verify that you can encrypt and decrypt properly. This code should  look
    similar to your CTR code.

   Use your function to encrypt a known plaintext prefixed by a random
   number of random characters.

   From the ciphertext, recover the 'key' (seed)

   Use the same idea to generate a random 'password reset token' using
   MT19937 seeded from the current time.

   Write a function to check if any given password token is actually
   the product of an MT19937 PRNG seeded with the current time.
|#

; encrypt: bytes integer -> bytes
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

; encryption-oracle: bytes -> bytes
;; encrypts a plaintext with a prefixed with
;; random bytes
(define KEY 234)
(define (encryption-oracle pt)
  (encrypt
   (bytes-append (crypto-random-bytes (random 20)) pt)
   KEY))

; get-seed: void -> integer
;; get the key from a known plaintext 
(define (get-seed)
  (define orig #"AAAAAAAAAAAAAA")
  (define ctxt (encryption-oracle orig))
  (for/last ([i (in-range (expt 2 16))])
    (define txt (decrypt ctxt i))
    (define txt-len (bytes-length txt))
    #:final (bytes=? orig (subbytes txt (- txt-len 14) txt-len))
    i))

; reset-token: void -> bytes
;; generate a reset token using MT19937 seeded with the current time
(define (reset-token)
  (define mt (new MT19937% [seed (current-milliseconds)]))
  (list->bytes
   (for/list ([i (in-range 6)])
     (bitwise-and (send mt generate-number) #xFF))))

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
  (require rackunit
           "../util/test.rkt")
  (define secret #"Attack at dawn")
  (define key 123)
  (time-test
   (test-suite
    "Part 1"
    (check-equal? (decrypt (encrypt secret key) key) secret)
    (check-equal? (get-seed) 234)))
  (define tok (reset-token))
  (sleep 0.25)
  (time-test
   (test-suite
    "Part 2"
    (check-true (check-token tok))
    (check-false (check-token #"123456")))))